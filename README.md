# Dark-Path Guardians

Detects dark patterns (fake urgency, fake scarcity, pre-checked boxes, hidden fees, confirmshaming,
forced consent, disguised ads) and threat signals on the page you are viewing.

> v2 is in progress on branch `v2-sandbox`. Full docs (architecture diagram, metrics, limitations)
> arrive in a later phase.

## Quick start

```bash
cp .env.example .env          # optional: add SAFE_BROWSING_API_KEY
docker compose up --build     # API on http://127.0.0.1:8000, pulls the LLM on first run
```

Load the extension: `chrome://extensions` → enable *Developer mode* → *Load unpacked* → select `extension/`.
Open any page and click the toolbar icon.

### Running the backend without Docker

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate    # Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
ollama pull qwen3:4b                              # optional; without it the API falls back to rules only
LLM_BASE_URL=http://localhost:11434/v1 uvicorn app.main:app --port 8000
pytest                                            # unit tests
```

## How detection works

1. The extension injects `content.js` only when you open the popup. It extracts checkboxes, buttons,
   links, text, prices, live countdown timers and consent banners, each with a CSS selector.
2. `POST /analyze` runs the **rule engine** (`backend/app/rules.py`). Strong hits (confidence ≥ 0.8)
   are accepted.
3. Ambiguous hits, and elements that contain cue words but matched no rule, go to a **local open-weight
   LLM** through Ollama (`backend/app/llm.py`). If the LLM is unreachable, the API falls back to rules only.
4. Threat signals run in parallel: Google Safe Browsing, domain age (WHOIS), TLS certificate, and the
   redirect chain. Outbound checks are restricted to public IPs (SSRF guard).
5. The popup shows a 0–100 risk score, the findings and the threat signals. Flagged elements are outlined
   on the page; click a finding to scroll to it.
