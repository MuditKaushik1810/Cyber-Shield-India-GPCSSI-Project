"""Cyber Shield India — Zero-state web-seeding service.

When the local corpus is sparse (e.g. pure-operational mode over a thinly
crawled state), the dashboard's empty components seed themselves with live
intelligence: a SerpAPI sweep feeds Gemini, which returns structured advisory
cards or a concise regional threat insight. Everything degrades gracefully —
no key / quota exhaustion / LLM fault all collapse to an empty result so the
caller falls back to a clean, un-broken zero state.
"""

import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai._common import GoogleGenerativeAIError
from pydantic import BaseModel, Field, ValidationError

from core.config import get_google_api_key
from services.web_search import web_search, web_search_available

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the web-seed logger (midnight-rotating)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.web_seed")
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

from core.config import GEMINI_FLASH_MODEL as _FLASH
GEMINI_MODEL_NAME: str = _FLASH


def web_seed_available() -> bool:
    """True when the live web-seeding pipeline can run (SerpAPI configured)."""
    return web_search_available()


# --------------------------------------------------------------------------- #
# 1. Web-sourced advisory cards.                                              #
# --------------------------------------------------------------------------- #


class WebAdvisory(BaseModel):
    """One structured advisory distilled from web results."""

    title: str = Field(description="Concise advisory headline.")
    description: str = Field(description="One-sentence plain-English summary.")
    url: str = Field(description="Exact deep source URL from the results.")


class WebAdvisoryList(BaseModel):
    """A list of web-sourced advisories."""

    advisories: List[WebAdvisory] = Field(default_factory=list)


_ADVISORY_PROMPT: str = (
    "You extract Indian cyber-fraud advisories from web search results. Return "
    "a list where each item has a concise title, a one-sentence description, "
    "and the exact source URL copied verbatim from the results. Use ONLY the "
    "provided results — never invent advisories or URLs. Skip results that are "
    "not genuine cyber-fraud advisories or warnings."
)


def _results_context(results: List[Dict[str, str]]) -> str:
    """Render web results into a compact context block for the LLM."""
    return "\n".join(
        f"- TITLE: {r.get('title', '')} | SNIPPET: {r.get('snippet', '')} "
        f"| URL: {r.get('link', '')}"
        for r in results
    )


def web_sourced_advisories(
    scam_type: str, max_items: int = 4
) -> List[Dict[str, str]]:
    """Live advisory cards for a scam type: SerpAPI -> Gemini structured JSON.

    Returns [{title, description, url}]. Empty list if web search is
    unavailable; degrades to raw web results if structured extraction fails.
    """
    topic: str = scam_type.strip() or "cyber fraud"
    query: str = f"{topic} latest cyber fraud advisories warnings India 2026"
    results: List[Dict[str, str]] = web_search(query, max_results=6)
    if not results:
        return []
    raw_fallback: List[Dict[str, str]] = [
        {"title": r.get("title", "Web advisory"),
         "description": r.get("snippet", ""),
         "url": r.get("link", "")}
        for r in results[:max_items]
    ]
    try:
        llm = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL_NAME, temperature=0.0,
            google_api_key=get_google_api_key(),
        ).with_structured_output(WebAdvisoryList)
        extracted: Optional[WebAdvisoryList] = llm.invoke([
            SystemMessage(content=_ADVISORY_PROMPT),
            HumanMessage(content=(
                f"SEARCH RESULTS for '{query}':\n{_results_context(results)}")),
        ])
    except (GoogleGenerativeAIError, ValidationError, ValueError):
        LOGGER.exception("advisory extraction failed — using raw web results")
        return raw_fallback
    if extracted is None or not extracted.advisories:
        return raw_fallback
    cards: List[Dict[str, str]] = [
        {"title": a.title, "description": a.description, "url": a.url}
        for a in extracted.advisories if a.title
    ][:max_items]
    LOGGER.info("web_sourced_advisories: %d card(s) for %r", len(cards), topic)
    return cards or raw_fallback


# --------------------------------------------------------------------------- #
# 2. Regional / scam LLM analytical insight.                                  #
# --------------------------------------------------------------------------- #


class RegionalInsight(BaseModel):
    """A concise web-augmented threat insight for a region or scam type."""

    summary: str = Field(description="Exactly three plain-English sentences.")
    estimate: str = Field(
        description="Short estimate — a figure if one appears in the results "
                    "(e.g. 'Rs 4,100 cr, FY24'), else a qualitative descriptor.")
    threat_level: str = Field(
        description="One of: Low, Moderate, Elevated, High.")


_INSIGHT_PROMPT: str = (
    "You are an Indian cyber-crime intelligence analyst. Based ONLY on the web "
    "search results provided, write a 'summary' of EXACTLY three sentences on "
    "the cyber-crime threat level and financial-loss trend for the given "
    "subject, an 'estimate' (a real figure only if it appears in the results, "
    "otherwise a qualitative descriptor), and a 'threat_level' of Low, "
    "Moderate, Elevated, or High. Never fabricate specific numbers absent from "
    "the results."
)


def regional_insight(label: str) -> Dict[str, object]:
    """Live 3-sentence threat insight for a state/scam: SerpAPI -> Gemini.

    Returns {summary, estimate, threat_level, sources}. Empty dict when web
    search is unavailable so the caller can keep a clean zero state.
    """
    subject: str = label.strip() or "India"
    query: str = f"{subject} cyber crime financial losses trends 2026"
    results: List[Dict[str, str]] = web_search(query, max_results=5)
    if not results:
        return {}
    sources: List[Dict[str, str]] = [
        {"title": r.get("title", ""), "url": r.get("link", "")}
        for r in results[:3]
    ]
    try:
        llm = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL_NAME, temperature=0.2,
            google_api_key=get_google_api_key(),
        ).with_structured_output(RegionalInsight)
        insight: Optional[RegionalInsight] = llm.invoke([
            SystemMessage(content=_INSIGHT_PROMPT),
            HumanMessage(content=(
                f"SUBJECT: {subject}\nSEARCH RESULTS:\n"
                f"{_results_context(results)}")),
        ])
    except (GoogleGenerativeAIError, ValidationError, ValueError):
        LOGGER.exception("regional insight failed — using snippet fallback")
        snippet: str = " ".join(r.get("snippet", "") for r in results[:2])[:400]
        return {"summary": snippet, "estimate": "Qualitative",
                "threat_level": "Unknown", "sources": sources}
    if insight is None:
        return {}
    LOGGER.info("regional_insight: %r -> %s", subject, insight.threat_level)
    return {
        "summary": insight.summary,
        "estimate": insight.estimate,
        "threat_level": insight.threat_level,
        "sources": sources,
    }
