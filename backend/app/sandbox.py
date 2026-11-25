"""Disposable sandbox browser sessions (one hardened Docker container per session).

The backend reaches Docker through a socket proxy that only allows container operations.
Each session container:
  * has no volumes or host mounts, a read-only root filesystem and a small tmpfs,
  * runs as an unprivileged user with every Linux capability dropped and no-new-privileges,
  * is limited in memory, CPU and process count,
  * sits on an internal network whose only exit is a filtering proxy (no private addresses),
  * is removed when the session ends or its timeout passes, whichever comes first.
"""
import json
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .config import settings
from .threat import assert_public_url

log = logging.getLogger("dpg.sandbox")
LABEL = "dpg.session"
SESSION_ID = re.compile(r"^[0-9a-f]{12}$")


class SandboxError(Exception):
    pass


class SandboxBusy(SandboxError):
    pass


class SandboxUnavailable(SandboxError):
    pass


@dataclass
class Session:
    id: str
    token: str
    vnc_password: str
    url: str
    container_id: str
    created: float
    expires: float
    status: str = "starting"          # starting -> analyzing -> ready | error; ended when removed
    report: Optional[dict] = None
    verdict: Optional[dict] = None
    findings: list = field(default_factory=list)
    events: list = field(default_factory=list)
    error: Optional[str] = None

    @property
    def hostname(self) -> str:
        return container_name(self.id)


def container_name(session_id: str) -> str:
    return f"dpg-sbx-{session_id}"


def container_options(session_id: str, url: str, vnc_password: str, expires: float) -> dict:
    """Everything passed to `docker run` for a session. Kept in one place so it is easy to review."""
    return {
        "image": settings.sandbox_image,
        "name": container_name(session_id),
        "detach": True,
        "environment": {
            "TARGET_URL": url,
            "PROXY_URL": settings.sandbox_proxy_url,
            "VNC_PASSWORD": vnc_password,
            "SESSION_SECONDS": str(settings.sandbox_session_seconds),
        },
        "network": settings.sandbox_network,          # internal network; exits only via the proxy
        "user": "10001:10001",                        # non-root
        "read_only": True,                            # read-only root filesystem
        "tmpfs": {"/tmp": "rw,nosuid,nodev,size=512m"},
        "shm_size": "256m",                           # Chromium needs a larger /dev/shm
        "volumes": {},                                # no host mounts
        "mem_limit": settings.sandbox_memory,
        "memswap_limit": settings.sandbox_memory,     # no swap on top of the memory limit
        "nano_cpus": int(settings.sandbox_cpus * 1e9),
        "pids_limit": 512,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "privileged": False,
        "ipc_mode": "private",
        "labels": {LABEL: session_id, "dpg.expires": str(int(expires))},
        "auto_remove": False,                         # we read logs first, then remove it ourselves
    }


def parse_logs(raw: str) -> tuple[Optional[dict], list[dict]]:
    report, events = None, []
    for line in raw.splitlines():
        try:
            if line.startswith("DPG_REPORT "):
                report = json.loads(line[len("DPG_REPORT "):])
            elif line.startswith("DPG_EVENT "):
                events.append(json.loads(line[len("DPG_EVENT "):]))
        except json.JSONDecodeError:
            continue
    return report, events[-100:]


class SandboxManager:
    def __init__(self, client=None):
        self._client = client
        self.sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    @property
    def client(self):
        if self._client is None:
            try:
                import docker  # imported lazily: the API works without Docker for detection only
                self._client = docker.from_env(timeout=30)
                self._client.ping()
            except Exception as e:
                self._client = None
                raise SandboxUnavailable(f"Docker is not reachable ({type(e).__name__}).") from e
        return self._client

    # ------------------------------------------------------------ lifecycle

    def create(self, url: str) -> Session:
        if not settings.sandbox_enabled:
            raise SandboxUnavailable("Sandbox is disabled (SANDBOX_ENABLED=false).")
        assert_public_url(url)  # raises UnsafeURL
        with self._lock:
            active = [s for s in self.sessions.values() if s.status not in ("ended",)]
            if len(active) >= settings.sandbox_max_sessions:
                raise SandboxBusy(f"Too many sandbox sessions running (max {settings.sandbox_max_sessions}).")
            sid = secrets.token_hex(6)
            now = time.time()
            expires = now + settings.sandbox_session_seconds
            vnc_password = secrets.token_hex(4)  # VNC passwords are limited to 8 characters
            container = self.client.containers.run(**container_options(sid, url, vnc_password, expires))
            session = Session(id=sid, token=secrets.token_urlsafe(24), vnc_password=vnc_password, url=url,
                              container_id=container.id, created=now, expires=expires)
            self.sessions[sid] = session
        log.info("sandbox %s started for %s", sid, url)
        return session

    def get(self, sid: str, token: str) -> Optional[Session]:
        session = self.sessions.get(sid) if SESSION_ID.match(sid or "") else None
        if session and token and secrets.compare_digest(session.token, token):
            return session
        return None

    def _container(self, session: Session):
        import docker
        try:
            return self.client.containers.get(session.container_id)
        except docker.errors.NotFound:
            return None

    def read_logs(self, session: Session) -> tuple[Optional[dict], list[dict], Optional[str]]:
        """Return (report, events, container_status)."""
        container = self._container(session)
        if container is None:
            return session.report, session.events, None
        raw = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
        report, events = parse_logs(raw)
        container.reload()
        return report, events, container.status

    def wait_report(self, session: Session) -> Optional[dict]:
        deadline = time.time() + settings.sandbox_report_timeout_s
        while time.time() < deadline and session.status != "ended":
            report, events, status = self.read_logs(session)
            session.events = events
            if report:
                return report
            if status in (None, "exited", "dead"):
                session.error = "The sandbox stopped before the page finished loading."
                return None
            time.sleep(1)
        session.error = session.error or "Timed out waiting for the page to load in the sandbox."
        return None

    def destroy(self, sid: str) -> None:
        session = self.sessions.get(sid)
        if not session:
            return
        container = self._container(session)
        if container is not None:
            container.remove(force=True)
        session.status = "ended"
        log.info("sandbox %s removed", sid)

    def reap(self) -> list[str]:
        """Remove every session container whose timeout has passed (also ones from a previous run)."""
        with self._lock:  # create() registers the session under the same lock
            return self._reap()

    def _reap(self) -> list[str]:
        removed = []
        now = time.time()
        for c in self.client.containers.list(all=True, filters={"label": LABEL}):
            expires = float(c.labels.get("dpg.expires", "0"))
            sid = c.labels.get(LABEL, "")
            known = sid in self.sessions and self.sessions[sid].status != "ended"
            if now > expires or not known:
                c.remove(force=True)
                removed.append(sid)
                if sid in self.sessions:
                    self.sessions[sid].status = "ended"
        # Forget ended sessions after a while.
        for sid, s in list(self.sessions.items()):
            if s.status == "ended" and now - s.expires > 600:
                del self.sessions[sid]
        return removed


manager = SandboxManager()
