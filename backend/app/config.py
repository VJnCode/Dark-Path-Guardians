"""Runtime settings, read from environment variables (see .env.example)."""
import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    # LLM: any OpenAI-compatible endpoint. Default is a local Ollama server.
    llm_enabled: bool = _bool("LLM_ENABLED", True)
    llm_base_url: str = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
    llm_model: str = os.getenv("LLM_MODEL", "qwen3:4b")
    llm_api_key: str = os.getenv("LLM_API_KEY", "ollama")  # Ollama ignores it
    llm_timeout_s: float = float(os.getenv("LLM_TIMEOUT_S", "60"))
    llm_max_items: int = int(os.getenv("LLM_MAX_ITEMS", "40"))
    # Turn off "thinking" on reasoning models (Qwen3 etc.); faster and plenty for labeling.
    llm_no_think: bool = _bool("LLM_NO_THINK", True)

    # Threat signals
    safe_browsing_api_key: str = os.getenv("SAFE_BROWSING_API_KEY", "")
    threat_timeout_s: float = float(os.getenv("THREAT_TIMEOUT_S", "6"))

    # CORS: only our extension needs to call the API.
    cors_origin_regex: str = os.getenv("CORS_ORIGIN_REGEX", r"chrome-extension://.*")


settings = Settings()
