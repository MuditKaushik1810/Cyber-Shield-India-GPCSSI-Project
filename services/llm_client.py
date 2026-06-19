"""Shared synchronous Gemini cascade client for the Streamlit frontend.

Streamlit renders synchronously, so the interactive frontend features (Victim
Triage, CDR/IPDR forensics, the OSINT sandbox, the Practice Lab notice engine)
call Gemini through this *blocking* cascade rather than the async cascades that
power ``rag_service`` / ``research_extractor``.

Every path shares :mod:`services.llm_errors`, so a 429 (per-model daily quota)
or a 503 ("model experiencing high demand") rotates to the next model instead of
crashing the page. Two entry points are exposed:

* :func:`invoke_text` — free-form generation, returns normalized, UI-safe text.
* :func:`invoke_structured` — Pydantic structured output for deterministic
  rendering of legal/forensic payloads.

Both return an empty value (``""`` / ``None``) only when *every* model in the
cascade is unavailable, leaving the caller free to fall back deterministically.
"""

import logging
from typing import List, Optional, Sequence, Type, TypeVar

from langchain_core.messages import BaseMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from pydantic import BaseModel, ValidationError

from core.config import get_google_api_key
from services.llm_errors import (
    LLM_TRANSIENT_ERRORS, content_to_text, is_quota_error, is_server_busy,
)

LOGGER: logging.Logger = logging.getLogger("cybershield.llm_client")

# Single source of truth for the frontend cascade. Each model owns its own
# free-tier daily bucket, and 503s are transient — both warrant rotation.
MODEL_CASCADE_ORDER: List[str] = [
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
]

_SchemaT = TypeVar("_SchemaT", bound=BaseModel)


def _shift_reason(exc: Exception) -> str:
    """Human-readable cause for a cascade shift (for structured logging)."""
    if is_quota_error(exc):
        return "exhausted its free-tier pool (429)"
    if is_server_busy(exc):
        return "is experiencing high demand (503)"
    return f"is unavailable ({type(exc).__name__})"


def invoke_text(
    messages: Sequence[BaseMessage], *, origin: str, temperature: float = 0.3,
) -> str:
    """Run a free-form completion across the model cascade.

    Returns clean, UI-safe text (the signature/block-list can never leak), or an
    empty string if every model is quota-exhausted or unavailable.
    """
    api_key: str = get_google_api_key()
    for index, model_name in enumerate(MODEL_CASCADE_ORDER):
        try:
            llm = ChatGoogleGenerativeAI(
                model=model_name, temperature=temperature, google_api_key=api_key,
            )
            completion = llm.invoke(list(messages))
            text: str = content_to_text(completion.content)
            if text:
                return text
            LOGGER.warning("%s: model %s returned empty content — shifting",
                           origin, model_name)
        except LLM_TRANSIENT_ERRORS as exc:
            LOGGER.warning("%s: model %s %s — shifting to next fallback",
                           origin, model_name, _shift_reason(exc))
        except (RuntimeError, ValueError) as exc:
            LOGGER.warning("%s: model %s payload fault (%s) — shifting",
                           origin, model_name, type(exc).__name__)
        _ = index  # cascade position retained for log correlation
    LOGGER.error("%s: all %d models unavailable — caller must fall back",
                 origin, len(MODEL_CASCADE_ORDER))
    return ""


def invoke_structured(
    messages: Sequence[BaseMessage], schema: Type[_SchemaT], *, origin: str,
    temperature: float = 0.2,
) -> Optional[_SchemaT]:
    """Run a structured-output completion across the model cascade.

    Returns a validated instance of ``schema`` or ``None`` if every model is
    unavailable / could not produce a schema-valid payload.
    """
    api_key: str = get_google_api_key()
    for model_name in MODEL_CASCADE_ORDER:
        try:
            llm = ChatGoogleGenerativeAI(
                model=model_name, temperature=temperature, google_api_key=api_key,
            ).with_structured_output(schema)
            result = llm.invoke(list(messages))
            if isinstance(result, schema):
                return result
            LOGGER.warning("%s: model %s returned non-schema payload — shifting",
                           origin, model_name)
        except LLM_TRANSIENT_ERRORS as exc:
            LOGGER.warning("%s: model %s %s — shifting to next fallback",
                           origin, model_name, _shift_reason(exc))
        except (ValidationError, ValueError) as exc:
            LOGGER.warning("%s: model %s parse/validation fault (%s) — shifting",
                           origin, model_name, type(exc).__name__)
    LOGGER.error("%s: all %d models unavailable for structured output — caller "
                 "must fall back", origin, len(MODEL_CASCADE_ORDER))
    return None
