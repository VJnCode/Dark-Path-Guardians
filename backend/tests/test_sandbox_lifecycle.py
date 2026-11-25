"""Integration test: one full sandbox session against real Docker.

Needs the stack's network, proxy and sandbox image:
    docker compose up -d proxy && docker compose build sandbox-image
    pytest -m integration
"""
import dataclasses
import time

import pytest

from app import sandbox
from app.config import settings
from app.schemas import AnalyzeResponse
from app.verdict import decide, network_features

pytestmark = pytest.mark.integration
SESSION_SECONDS = 45


@pytest.fixture
def manager(monkeypatch):
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env(timeout=30)
        client.ping()
        client.images.get(settings.sandbox_image)
        client.networks.get(settings.sandbox_network)
    except Exception as e:  # noqa: BLE001
        pytest.skip(f"sandbox prerequisites missing: {e}")
    # Short session so the timeout path runs inside the test.
    monkeypatch.setattr(sandbox, "settings", dataclasses.replace(settings, sandbox_session_seconds=SESSION_SECONDS))
    m = sandbox.SandboxManager(client=client)
    yield m
    for sid in list(m.sessions):
        try:
            m.destroy(sid)
        except Exception:  # noqa: BLE001
            pass


def test_sandbox_lifecycle(manager):
    session = manager.create("https://example.com/")
    container = manager.client.containers.get(session.container_id)
    container.reload()
    host_config, config = container.attrs["HostConfig"], container.attrs["Config"]

    # Hardening as actually applied by Docker.
    assert config["User"] == "10001:10001"
    assert host_config["ReadonlyRootfs"] is True
    assert host_config["CapDrop"] == ["ALL"]
    assert host_config["Privileged"] is False
    assert "no-new-privileges:true" in host_config["SecurityOpt"]
    assert host_config["Memory"] > 0 and host_config["NanoCpus"] > 0 and host_config["PidsLimit"] > 0
    assert not host_config.get("Binds") and not container.attrs.get("Mounts")
    assert not host_config.get("PortBindings")

    # The page loads through the proxy and the runner reports back.
    report = manager.wait_report(session)
    assert report is not None, session.error
    assert "example.com" in report["final_url"]
    assert report["elements"], "extractor returned nothing"
    assert report["network"]["request_count"] >= 1

    # Inside the container: not root, no direct internet, proxy refuses internal addresses.
    exit_code, out = container.exec_run(["id", "-u"])
    assert out.decode().strip() == "10001"
    direct = ("import urllib.request as u\n"
              "try:\n u.build_opener(u.ProxyHandler({})).open('http://example.com', timeout=5); print('OPEN')\n"
              "except Exception as e: print('BLOCKED', type(e).__name__)")
    _, out = container.exec_run(["python", "-c", direct])
    assert out.decode().startswith("BLOCKED"), out
    via_proxy = ("import urllib.request as u\n"
                 "p=u.build_opener(u.ProxyHandler({'http':'http://proxy:3128'}))\n"
                 "try:\n p.open('http://169.254.169.254/latest/meta-data/', timeout=10); print('OPEN')\n"
                 "except Exception as e: print('BLOCKED', getattr(e, 'code', type(e).__name__))")
    _, out = container.exec_run(["python", "-c", via_proxy])
    assert out.decode().startswith("BLOCKED"), out

    # Verdict from the report.
    features = network_features(report["network"], session.url)
    verdict = decide(AnalyzeResponse(url=session.url, risk_score=0, findings=[]), features)
    assert verdict.level == "safe"
    assert features["download_attempts"] == 0

    # Timeout: the reaper removes the container once the session expires.
    time.sleep(max(0, session.expires - time.time()) + 1)
    assert session.id in manager.reap()
    remaining = manager.client.containers.list(all=True, filters={"label": f"{sandbox.LABEL}={session.id}"})
    assert remaining == []
