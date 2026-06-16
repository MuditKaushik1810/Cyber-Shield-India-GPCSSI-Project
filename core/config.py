"""Environmental configuration wrapper for Cyber Shield India.

Loads the local ``.env`` file via python-dotenv and validates that the
``GOOGLE_API_KEY`` target is present and non-placeholder before any
service module attempts a Gemini connection. Per CLAUDE.md security
protocols, no authentication key is ever hardcoded.
"""

import os
from pathlib import Path
from typing import Final, Optional

from dotenv import load_dotenv

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
ENV_FILE: Final[Path] = PROJECT_ROOT / ".env"

_PLACEHOLDER: Final[str] = "your-google-api-key-here"

# Single source of truth for the Gemini Flash model. gemini-3.5-flash is
# validated available with its own free-tier daily quota bucket (the prior
# gemini-2.5-flash hit per-model 429 daily caps). Override with the GEMINI_MODEL
# environment variable if needed.
_DEFAULT_GEMINI_MODEL: Final[str] = "gemini-3.5-flash"

# Unified threat-domain taxonomy spanning financial and non-financial cyber
# threats. Used by the extractor, schema, and dashboard so all domains display
# together in one continuous flow.
THREAT_DOMAINS: Final[tuple] = (
    "Financial Fraud",
    "Data Leak",
    "Deepfake/Extortion",
    "Phishing/Spam",
    "MITM/Infrastructure",
)
DEFAULT_THREAT_DOMAIN: Final[str] = "Financial Fraud"


class ConfigurationError(RuntimeError):
    """Raised when a required environment target is missing or invalid."""


def load_environment() -> None:
    """Load the project ``.env`` file into the process environment."""
    load_dotenv(dotenv_path=ENV_FILE)


def get_gemini_model() -> str:
    """Return the configured Gemini Flash model id (env-overridable)."""
    load_environment()
    return os.environ.get("GEMINI_MODEL", "").strip() or _DEFAULT_GEMINI_MODEL


GEMINI_FLASH_MODEL: str = get_gemini_model()


def get_google_api_key() -> str:
    """Return the validated ``GOOGLE_API_KEY`` environment target.

    Raises:
        ConfigurationError: If the key is absent, empty, or still set to
            the template placeholder value.
    """
    load_environment()
    key: str = os.environ.get("GOOGLE_API_KEY", "").strip()
    if not key or key == _PLACEHOLDER:
        raise ConfigurationError(
            "GOOGLE_API_KEY is not configured. Copy .env.example to .env "
            "and set a valid Google AI Studio API key."
        )
    return key


def _get_optional(name: str) -> Optional[str]:
    """Return an optional environment value, stripped, or None if unset."""
    load_environment()
    value: str = os.environ.get(name, "").strip().strip('"').strip("'")
    return value or None


def get_news_api_key() -> Optional[str]:
    """Return the NewsAPI key for the dynamic media tier, or None."""
    return _get_optional("NEWS_API_KEY")


def get_custom_search_key() -> Optional[str]:
    """Return the Google Programmable Search key for OSINT, or None."""
    return _get_optional("GOOGLE_CUSTOM_SEARCH_KEY")


def get_search_engine_id() -> Optional[str]:
    """Return the Google Programmable Search engine (cx) id, or None."""
    return _get_optional("GOOGLE_SEARCH_ENGINE_ID")
