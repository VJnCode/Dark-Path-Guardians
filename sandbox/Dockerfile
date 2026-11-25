# Disposable browser session: Chromium (Playwright) on a virtual display, viewable via noVNC.
# Build context is the repo root so the extension's content.js can be reused for extraction.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers \
    DISPLAY=:99 HOME=/tmp/home

RUN apt-get update \
 && apt-get install -y --no-install-recommends libatomic1 xvfb x11vnc novnc python3-websockify \
      fonts-noto-core fonts-noto-color-emoji \
 && rm -rf /var/lib/apt/lists/* \
 && echo '{"version": "debian"}' > /usr/share/novnc/package.json   # noVNC's UI fetches it on startup

RUN pip install --no-cache-dir playwright==1.65.2 \
 && playwright install --with-deps chromium \
 && rm -rf /var/lib/apt/lists/*

# Defense in depth on top of Playwright's accept_downloads=False: Chromium policy blocks all downloads.
COPY sandbox/chromium-policy.json /etc/chromium/policies/managed/dpg.json
COPY sandbox/runner.py /app/runner.py
COPY extension/content.js /app/content.js

# Unprivileged user; the container runs with a read-only root filesystem and tmpfs /tmp.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin sandbox
USER 10001:10001

EXPOSE 6080
ENTRYPOINT ["python", "/app/runner.py"]
