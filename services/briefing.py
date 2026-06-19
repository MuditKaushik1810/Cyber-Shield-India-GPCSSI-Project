"""Cyber Shield India — automated Threat Briefing generator.

Turns the aggregated ``briefing_stats`` of the active dashboard filter into a
story-driven, 3-sentence narrative highlighting the dominant region, the
leading scam vector, and any sudden volume shift versus the previous window.

Uses Gemini for a natural narrative, with a deterministic template fallback so
the briefing always renders even when the LLM is unavailable.
"""

import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

from core.config import GEMINI_FLASH_MODEL as _FLASH, get_google_api_key
# Using an explicit relative import clears the IDE linter path resolution error
from .llm_errors import (
    LLM_TRANSIENT_ERRORS, content_to_text, is_quota_error, is_transient,
)

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the briefing logger (midnight-rotating)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.briefing")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "frontend.log", when="midnight",
        backupCount=14, encoding="utf-8",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOGGER: logging.Logger = _build_logger()

GEMINI_MODEL_NAME: str = _FLASH

# Multi-model rotation: the Gemini free-tier daily cap is per-model, and 503
# 'high demand' errors are transient — both warrant shifting to the next model.
MODEL_CASCADE_ORDER: List[str] = [
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
]

INTERVAL_PHRASES: Dict[str, str] = {
    "1d": "the past 24 hours", "1w": "the past week",
    "1m": "the past month", "1y": "the past year",
}

BRIEFING_PROMPT: str = (
    "You are a cyber-crime intelligence analyst writing a public threat "
    "briefing. Given the statistics below for a single time window, write "
    "EXACTLY three sentences: (1) the overall volume and dominant region, "
    "(2) the leading scam vector and its financial toll, (3) any sudden "
    "volume shift versus the previous window or a notable anomaly. Be "
    "specific with the figures provided. Use only these numbers — never "
    "invent data. No preamble, no bullet points."
)


def _inr_compact(value: float) -> str:
    """Format an INR figure into a compact crore/lakh string."""
    if value >= 1e7:
        return f"Rs {value / 1e7:.2f} crore"
    if value >= 1e5:
        return f"Rs {value / 1e5:.2f} lakh"
    return f"Rs {value:,.0f}"


def _template_briefing(stats: Dict[str, object], interval: str) -> str:
    """Deterministic fallback briefing assembled from the raw stats."""
    phrase: str = INTERVAL_PHRASES.get(interval, "the selected window")
    cases: int = int(stats.get("total_cases", 0))            # type: ignore[arg-type]
    loss: float = float(stats.get("total_loss", 0.0))        # type: ignore[arg-type]
    state: str = str(stats.get("top_state") or "no single region")
    vector: str = str(stats.get("top_vector") or "no dominant vector")
    vector_loss: float = float(stats.get("top_vector_loss", 0.0))  # type: ignore[arg-type]
    delta: float = float(stats.get("volume_delta_pct", 0.0))  # type: ignore[arg-type]
    shift: str = (
        f"case volume is up {delta:.0f}% versus the previous window"
        if delta > 0 else
        f"case volume is down {abs(delta):.0f}% versus the previous window"
        if delta < 0 else "case volume is flat versus the previous window"
    )
    return (
        f"Across {phrase}, the repository logged {cases:,} live-captured "
        f"cyber-fraud cases totalling {_inr_compact(loss)}, led by {state}. "
        f"The dominant scam vector was {vector}, accounting for "
        f"{_inr_compact(vector_loss)} in reported losses. "
        f"Notably, {shift}."
    )


def generate_briefing(stats: Dict[str, object], interval: str) -> str:
    """Produce a 3-sentence threat briefing (Gemini, deterministic fallback)."""
    if not stats or (int(stats.get("total_cases", 0)) == 0      # type: ignore[arg-type]
                     and float(stats.get("total_loss", 0.0)) == 0.0):  # type: ignore[arg-type]
        return ("No telemetry is available for this filter window yet. Widen "
                "the chronological range or explore another threat domain.")
    fallback: str = _template_briefing(stats, interval)
    api_key: str = get_google_api_key()
    messages = [
        SystemMessage(content=BRIEFING_PROMPT),
        HumanMessage(content=(
            f"Window: {INTERVAL_PHRASES.get(interval, interval)}\n"
            f"Total cases: {stats.get('total_cases')}\n"
            f"Total loss (INR): {stats.get('total_loss')}\n"
            f"Previous-window cases: {stats.get('prev_cases')}\n"
            f"Volume change vs previous window (%): {stats.get('volume_delta_pct')}\n"
            f"Top state by loss: {stats.get('top_state')} "
            f"({stats.get('top_state_cases')} cases, "
            f"INR {stats.get('top_state_loss')})\n"
            f"Top scam vector by loss: {stats.get('top_vector')} "
            f"(INR {stats.get('top_vector_loss')})"
        )),
    ]
    # Cascade across models on a 429 (quota) OR a 503 ('high demand') — both
    # are transient. Content is normalized so the signature/block list can never
    # leak into the banner. If every model is unavailable, the deterministic
    # template renders, so the briefing never crashes the page.
    for model_name in MODEL_CASCADE_ORDER:
        try:
            llm = ChatGoogleGenerAI(
                model=model_name, temperature=0.3, google_api_key=api_key,
            )
            completion = llm.invoke(messages)
            text: str = content_to_text(completion.content)
            return text or fallback
        except LLM_TRANSIENT_ERRORS as exc:
            reason: str = ("exhausted its free-tier pool (429)"
                           if is_quota_error(exc) else "is experiencing high "
                           "demand (503)") if is_transient(exc) else \
                          f"failed ({type(exc).__name__})"
            LOGGER.warning("briefing: model %s %s — shifting to next fallback",
                           model_name, reason)
            continue
        except (RuntimeError, ValueError):
            LOGGER.warning("briefing: model %s payload fault — shifting", model_name)
            continue
    LOGGER.error("briefing: all models unavailable — deterministic fallback")
    return fallback