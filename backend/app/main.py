"""Dark-Path-Guardians API."""
import asyncio
import contextlib
import logging
from urllib.parse import quote

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import ValidationError

from .classifier import classify, drop_containers, risk_score
from .config import settings
from .sandbox import SandboxBusy, SandboxError, SandboxUnavailable, Session, manager
from .schemas import (AnalyzeRequest, AnalyzeResponse, PageElement, SandboxRequest, SandboxSession, ThreatReport,
                      ThreatRequest)
from .threat import UnsafeURL, threat_report
from .verdict import decide, network_features

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dpg")
_tasks: set[asyncio.Task] = set()  # keep references so background tasks aren't garbage-collected


async def _reaper() -> None:
    while True:
        try:
            removed = await asyncio.to_thread(manager.reap)
            if removed:
                log.info("reaped sandbox sessions: %s", removed)
        except SandboxUnavailable:
            pass  # Docker not available: nothing to reap
        except Exception:
            log.exception("sandbox reaper failed")
        await asyncio.sleep(10)


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    task = asyncio.create_task(_reaper())  # also removes leftovers from a previous run on startup
    yield
    task.cancel()


app = FastAPI(title="Dark-Path-Guardians", version="2.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origin_regex=settings.cors_origin_regex,
                   allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type", "X-DPG-Client"])


def require_client(x_dpg_client: str = Header(default="")) -> None:
    """A custom header forces a CORS preflight, so ordinary web pages can't trigger
    LLM calls, outbound checks or sandbox sessions on the user's machine."""
    if not x_dpg_client:
        raise HTTPException(status_code=403, detail="Missing X-DPG-Client header.")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "llm_enabled": settings.llm_enabled, "llm_model": settings.llm_model,
            "sandbox_enabled": settings.sandbox_enabled}


async def _safe_threat(url: str) -> ThreatReport | None:
    try:
        return await threat_report(url)
    except UnsafeURL as e:
        log.info("threat checks skipped for %s: %s", url, e)
        return None


async def _analyze(elements: list[PageElement], url: str, mode: str = "hybrid",
                   include_threat: bool = True) -> AnalyzeResponse:
    tasks = [asyncio.to_thread(classify, elements, mode)]
    if include_threat:
        tasks.append(_safe_threat(url))
    results = await asyncio.gather(*tasks)
    findings, llm_used, llm_error = results[0]
    findings = drop_containers(findings, elements)
    threat = results[1] if include_threat else None
    return AnalyzeResponse(url=url, risk_score=risk_score(findings, threat), findings=findings,
                           threat=threat, llm_used=llm_used, llm_error=llm_error)


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(require_client)])
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    return await _analyze(req.elements, req.url, req.mode, req.include_threat)


@app.post("/threat", response_model=ThreatReport, dependencies=[Depends(require_client)])
async def threat(req: ThreatRequest) -> ThreatReport:
    try:
        return await threat_report(req.url)
    except UnsafeURL as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------- sandbox

def _public(session: Session) -> SandboxSession:
    view_url = None
    if session.status == "ready":
        # Capability URL: the token is in the path, so noVNC's relative asset URLs and its
        # WebSocket path carry it without cookies.
        base = f"sandbox/{session.id}/{session.token}"
        view_url = (f"/{base}/view/vnc.html?autoconnect=1&resize=scale&reconnect=1"
                    f"&path={quote(base + '/websockify', safe='')}&password={session.vnc_password}")
    return SandboxSession(id=session.id, token=session.token, url=session.url, status=session.status,
                          expires_at=session.expires, verdict=session.verdict, findings=session.findings,
                          final_url=(session.report or {}).get("final_url"), events=session.events,
                          error=session.error, view_url=view_url)


async def _run_pipeline(session: Session) -> None:
    """Wait for the sandbox's page report, then run detection + threat checks on it."""
    try:
        report = await asyncio.to_thread(manager.wait_report, session)
        if report is None:
            session.status = "error"
            return
        session.report = report
        session.status = "analyzing"
        elements = []
        for raw in report.get("elements", [])[:500]:
            with contextlib.suppress(ValidationError):
                elements.append(PageElement(**raw))
        final_url = report.get("final_url") or session.url
        analysis = await _analyze(elements, final_url)
        features = network_features(report.get("network", {}), session.url)
        session.findings = analysis.findings
        session.verdict = decide(analysis, features, report.get("error"))
        session.status = "ready"
    except Exception as e:
        log.exception("sandbox pipeline failed for %s", session.id)
        session.error = f"Analysis failed ({type(e).__name__})."
        session.status = "error"


@app.post("/sandbox", response_model=SandboxSession, dependencies=[Depends(require_client)])
async def create_sandbox(req: SandboxRequest) -> SandboxSession:
    try:
        session = await asyncio.to_thread(manager.create, req.url)
    except UnsafeURL as e:
        raise HTTPException(status_code=400, detail=str(e))
    except SandboxBusy as e:
        raise HTTPException(status_code=429, detail=str(e))
    except SandboxError as e:
        raise HTTPException(status_code=503, detail=str(e))
    task = asyncio.create_task(_run_pipeline(session))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return _public(session)


def _session_or_404(sid: str, token: str) -> Session:
    session = manager.get(sid, token)
    if session is None:
        raise HTTPException(status_code=404, detail="Unknown session or wrong token.")
    return session


@app.get("/sandbox/{sid}", response_model=SandboxSession)
async def get_sandbox(sid: str, token: str = "") -> SandboxSession:
    session = _session_or_404(sid, token)
    if session.status == "ready":
        with contextlib.suppress(SandboxError):
            _, session.events, _ = await asyncio.to_thread(manager.read_logs, session)
    return _public(session)


@app.delete("/sandbox/{sid}", dependencies=[Depends(require_client)])
async def delete_sandbox(sid: str, token: str = "") -> dict:
    _session_or_404(sid, token)
    await asyncio.to_thread(manager.destroy, sid)
    return {"status": "ended"}


def _view_session(sid: str, token: str) -> Session | None:
    session = manager.get(sid, token)
    return session if session is not None and session.status == "ready" else None


@app.get("/sandbox/{sid}/{token}/view/{path:path}")
async def view_proxy(sid: str, token: str, path: str) -> Response:
    """Serve the session's noVNC client through the API (the container publishes no ports)."""
    session = _view_session(sid, token)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not available.")
    if ".." in path:
        raise HTTPException(status_code=400)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            upstream = await client.get(f"http://{session.hostname}:6080/{path}")
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Sandbox display not reachable yet.")
    resp = Response(content=upstream.content, status_code=upstream.status_code,
                    media_type=upstream.headers.get("content-type"))
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"   # keep the capability URL out of Referer headers
    return resp


@app.websocket("/sandbox/{sid}/{token}/websockify")
async def view_socket(websocket: WebSocket, sid: str, token: str) -> None:
    from websockets.asyncio.client import connect

    session = _view_session(sid, token)
    if session is None:
        await websocket.close(code=4404)
        return
    await websocket.accept(subprotocol="binary" if "binary" in websocket.scope.get("subprotocols", []) else None)
    try:
        async with connect(f"ws://{session.hostname}:6080/websockify", subprotocols=["binary"],
                           max_size=None, open_timeout=10) as upstream:
            async def to_upstream():
                while True:
                    msg = await websocket.receive()
                    if msg["type"] == "websocket.disconnect":
                        break
                    await upstream.send(msg.get("bytes") or msg.get("text") or b"")

            async def to_client():
                async for data in upstream:
                    if isinstance(data, bytes):
                        await websocket.send_bytes(data)
                    else:
                        await websocket.send_text(data)

            done, pending = await asyncio.wait([asyncio.create_task(to_upstream()),
                                                asyncio.create_task(to_client())],
                                               return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
    except (OSError, WebSocketDisconnect, asyncio.TimeoutError) as e:
        log.info("sandbox %s view socket closed: %s", sid, type(e).__name__)
    finally:
        with contextlib.suppress(RuntimeError, WebSocketDisconnect):
            await websocket.close()

