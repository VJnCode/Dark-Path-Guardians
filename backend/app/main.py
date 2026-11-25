"""Dark-Path-Guardians API."""
import asyncio
import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .classifier import classify, risk_score
from .config import settings
from .schemas import AnalyzeRequest, AnalyzeResponse, ThreatReport, ThreatRequest
from .threat import UnsafeURL, threat_report

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("dpg")

app = FastAPI(title="Dark-Path-Guardians", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origin_regex=settings.cors_origin_regex,
                   allow_methods=["GET", "POST", "DELETE"], allow_headers=["Content-Type"])


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "llm_enabled": settings.llm_enabled, "llm_model": settings.llm_model}


async def _safe_threat(url: str) -> ThreatReport | None:
    try:
        return await threat_report(url)
    except UnsafeURL as e:
        log.info("threat checks skipped for %s: %s", url, e)
        return None


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest) -> AnalyzeResponse:
    tasks = [asyncio.to_thread(classify, req.elements, req.mode)]
    if req.include_threat:
        tasks.append(_safe_threat(req.url))
    results = await asyncio.gather(*tasks)
    findings, llm_used, llm_error = results[0]
    threat = results[1] if req.include_threat else None
    return AnalyzeResponse(url=req.url, risk_score=risk_score(findings, threat), findings=findings,
                           threat=threat, llm_used=llm_used, llm_error=llm_error)


@app.post("/threat", response_model=ThreatReport)
async def threat(req: ThreatRequest) -> ThreatReport:
    try:
        return await threat_report(req.url)
    except UnsafeURL as e:
        raise HTTPException(status_code=400, detail=str(e))
