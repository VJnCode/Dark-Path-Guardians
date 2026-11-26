"""Runs inside a disposable sandbox container.

1. Start a virtual display and Chromium (Playwright) behind the egress proxy.
2. Load TARGET_URL, record redirects / requests / popups / download attempts, and run the
   extension's extract() on the page.
3. Print one `DPG_REPORT {json}` line on stdout. The backend reads it from the container logs
   (the container never connects to the backend).
4. Start x11vnc + noVNC so the user can look at the page once the verdict is shown.
5. Keep logging later events as `DPG_EVENT {json}` lines until SESSION_SECONDS runs out.
"""
import json
import os
import subprocess
import sys
import time
from urllib.parse import urlsplit

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import sync_playwright

TARGET_URL = os.environ["TARGET_URL"]
PROXY_URL = os.environ.get("PROXY_URL", "http://proxy:3128")
VNC_PASSWORD = os.environ.get("VNC_PASSWORD", "")
SESSION_SECONDS = int(os.environ.get("SESSION_SECONDS", "300"))
WIDTH, HEIGHT = 1280, 800
CONTENT_JS = open("/app/content.js", encoding="utf-8").read()
START = time.time()


def emit(kind: str, data: dict) -> None:
    print(f"{kind} {json.dumps(data, ensure_ascii=False)}", flush=True)


def host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def start_display() -> subprocess.Popen:
    os.makedirs(os.environ["HOME"], exist_ok=True)
    os.makedirs("/tmp/.X11-unix", mode=0o1777, exist_ok=True)  # non-root Xvfb won't create it
    xvfb = subprocess.Popen(["Xvfb", os.environ["DISPLAY"], "-screen", "0", f"{WIDTH}x{HEIGHT}x24", "-nolisten", "tcp"])
    time.sleep(1)
    return xvfb


def start_vnc() -> list[subprocess.Popen]:
    passwd_file = "/tmp/vncpass"
    subprocess.run(["x11vnc", "-storepasswd", VNC_PASSWORD, passwd_file], check=True, capture_output=True)
    vnc = subprocess.Popen(["x11vnc", "-display", os.environ["DISPLAY"], "-rfbport", "5900", "-localhost",
                            "-rfbauth", passwd_file, "-forever", "-shared", "-quiet", "-noxdamage"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    web = subprocess.Popen(["websockify", "--web", "/usr/share/novnc", "6080", "localhost:5900"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return [vnc, web]


def main() -> int:
    xvfb = start_display()
    log = {"requests": 0, "hosts": set(), "failed": [], "downloads": [], "popups": [], "navigations": []}
    reported = False

    def on_request(req):
        log["requests"] += 1
        log["hosts"].add(host(req.url))

    def on_request_failed(req):
        entry = {"url": req.url[:300], "error": (req.failure or "")[:120]}
        if len(log["failed"]) < 50:
            log["failed"].append(entry)

    def on_response(resp):
        # Only navigations count: APIs (e.g. Google Sign-In) send "attachment" on JSON as an anti-XSS measure.
        if not resp.request.is_navigation_request():
            return
        disposition = (resp.headers.get("content-disposition") or "").lower()
        if "attachment" in disposition:
            on_download_attempt(resp.url, "content-disposition: attachment")

    def on_download_attempt(url, how):
        entry = {"url": url[:300], "how": how, "t": round(time.time() - START, 1)}
        log["downloads"].append(entry)
        if reported:
            emit("DPG_EVENT", {"type": "download_blocked", **entry})

    def on_frame_navigated(frame):
        if frame == frame.page.main_frame and frame.url not in ("about:blank", ""):
            log["navigations"].append(frame.url[:300])
            if reported:
                emit("DPG_EVENT", {"type": "navigation", "url": frame.url[:300]})

    def on_popup(page):
        log["popups"].append(page.url[:300])
        if reported:
            emit("DPG_EVENT", {"type": "popup", "url": page.url[:300]})

    report = {"target_url": TARGET_URL, "final_url": TARGET_URL, "title": "", "status": None, "error": None,
              "elements": []}
    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=False,
            proxy={"server": PROXY_URL},
            args=[f"--window-size={WIDTH},{HEIGHT}", "--window-position=0,0", "--start-fullscreen",
                  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-features=WebRtcHideLocalIpsWithMdns",
                  "--no-first-run", "--disable-background-networking"],
        )
        context = browser.new_context(accept_downloads=False, viewport={"width": WIDTH, "height": HEIGHT},
                                      locale="en-US", service_workers="block")
        context.on("request", on_request)
        context.on("requestfailed", on_request_failed)
        context.on("response", on_response)
        context.on("page", lambda p: p.on("download", lambda d: on_download_attempt(d.url, "download event")))
        page = context.new_page()  # gets its download listener from the context "page" handler above
        page.on("framenavigated", on_frame_navigated)
        page.on("popup", on_popup)

        redirect_chain = []
        try:
            response = page.goto(TARGET_URL, wait_until="domcontentloaded", timeout=30000)
            if response:
                report["status"] = response.status
                req = response.request
                while req.redirected_from:
                    req = req.redirected_from
                    redirect_chain.insert(0, req.url[:300])
            try:
                page.wait_for_load_state("networkidle", timeout=8000)
            except PlaywrightError:
                pass
            page.wait_for_timeout(2000)
            report["final_url"] = page.url
            report["title"] = page.title()[:200]
            page.evaluate(CONTENT_JS)
            report["elements"] = page.evaluate("window.__dpgExtract()")
        except PlaywrightError as e:
            report["error"] = str(e).splitlines()[0][:300]

        target_host = host(TARGET_URL)
        report["network"] = {
            "redirect_chain": redirect_chain + [report["final_url"][:300]],
            "navigations": log["navigations"][:20],
            "request_count": log["requests"],
            "hosts": sorted(log["hosts"])[:200],
            "third_party_hosts": sorted(h for h in log["hosts"] if h and not h.endswith(target_host))[:200],
            "failed_requests": log["failed"],
            "download_attempts": list(log["downloads"]),
            "popups": list(log["popups"]),
        }
        emit("DPG_REPORT", report)
        reported = True

        procs = start_vnc()
        try:
            while time.time() - START < SESSION_SECONDS:
                page.wait_for_timeout(1000)  # keeps Playwright's event loop running
        except PlaywrightError:
            pass  # browser closed
        finally:
            for p in procs:
                p.terminate()
            browser.close()
    xvfb.terminate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
