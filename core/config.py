"""Environmental configuration wrapper for Cyber Shield India.

Loads the local ``.env`` file via python-dotenv and validates that the
``GOOGLE_API_KEY`` target is present and non-placeholder before any
service module attempts a Gemini connection. Per CLAUDE.md security
protocols, no authentication key is ever hardcoded.
"""

import os
from pathlib import Path
from typing import Final

from dotenv import load_dotenv

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
ENV_FILE: Final[Path] = PROJECT_ROOT / ".env"

_PLACEHOLDER: Final[str] = "your-google-api-key-here"


class ConfigurationError(RuntimeError):
    """Raised when a required environment target is missing or invalid."""


def load_environment() -> None:
    """Load the project ``.env`` file into the process environment."""
    load_dotenv(dotenv_path=ENV_FILE)


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
