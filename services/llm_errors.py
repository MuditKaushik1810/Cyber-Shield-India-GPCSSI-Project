"""Shared LLM error classification & content normalization.

Two cross-cutting concerns that every Gemini caller needs:

* **Transient-error handling.** A 429 (`RESOURCE_EXHAUSTED`) is wrapped by
  LangChain as ``GoogleGenerativeAIError``, but a 503 (`ServerError`,
  "model experiencing high demand") bubbles up as a raw
  ``google.genai.errors.ServerError`` that is NOT a subclass of the LangChain
  error — so a narrow ``except GoogleGenerativeAIError`` lets it crash the page.
  ``LLM_TRANSIENT_ERRORS`` catches both; ``is_transient`` classifies them so a
  caller can cascade to the next model on either condition.

* **Content normalization.** Newer Gemini models return content as a list of
  typed blocks (``[{'type': 'text', 'text': '...'}, ...]`` sometimes carrying a
  large ``signature`` field). ``content_to_text`` flattens that to clean text so
  the UI never renders the raw object.
"""

from typing import List, Tuple

from langchain_google_genai._common import GoogleGenerativeAIError

try:  # 503 ServerError / other 5xx bubble up as the genai APIError base
    from google.genai.errors import APIError as _GenAIAPIError
    LLM_TRANSIENT_ERRORS: Tuple[type, ...] = (GoogleGenerativeAIError, _GenAIAPIError)
except ImportError:  # pragma: no cover - SDK layout fallback
    LLM_TRANSIENT_ERRORS = (GoogleGenerativeAIError,)


def is_quota_error(exc: Exception) -> bool:
    """True for a 429 / RESOURCE_EXHAUSTED daily-quota exhaustion."""
    message: str = str(exc)
    return ("429" in message or "RESOURCE_EXHAUSTED" in message
            or "exceeded your current quota" in message.lower())


def is_server_busy(exc: Exception) -> bool:
    """True for a transient 5xx ('high demand' / UNAVAILABLE / overloaded)."""
    message: str = str(exc).lower()
    return ("503" in message or "500" in message or "unavailable" in message
            or "overloaded" in message or "high demand" in message)


def is_transient(exc: Exception) -> bool:
    """True if the error warrants cascading to the next model."""
    return is_quota_error(exc) or is_server_busy(exc)


def content_to_text(content: object) -> str:
    """Flatten an LLM completion's content into clean, UI-safe text."""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: List[str] = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text", "")))
            else:
                parts.append(str(block))
        return " ".join(part for part in parts if part).strip()
    return str(content).strip()
