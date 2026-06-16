"""Cyber Shield India — Live web-search utility (SerpAPI).

A thin, gracefully-degrading wrapper around SerpAPI's Google engine, reused by
the RAG service for web augmentation when the internal vector corpus is not
saturated for a query. No new credentials are required — it reads the same
``SERPAPI_API_KEY`` already used by the ingestion worker.

When the package or key is absent, ``web_search`` returns an empty list so the
caller transparently falls back to corpus-only retrieval.
"""

import logging
import os
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from core.config import load_environment

try:
    from serpapi import GoogleSearch  # type: ignore
    _SERPAPI_AVAILABLE: bool = True
except ImportError:
    _SERPAPI_AVAILABLE = False

try:
    from requests.exceptions import RequestException
    _NET_ERRORS: Tuple[type, ...] = (RequestException, ValueError, RuntimeError)
except ImportError:
    _NET_ERRORS = (OSError, ValueError, RuntimeError)

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the web-search logger (midnight-rotating)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.web_search")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "rag.log", when="midnight",
        backupCount=14, encoding="utf-8",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOGGER: logging.Logger = _build_logger()

WEB_SEARCH_LOCALE: Dict[str, str] = {"gl": "in", "hl": "en"}
WEB_SEARCH_RESULTS: int = 5


def web_search_available() -> bool:
    """True when SerpAPI is importable and a key is configured."""
    if not _SERPAPI_AVAILABLE:
        return False
    load_environment()
    return bool(os.getenv("SERPAPI_API_KEY"))


def web_search(
    query: str, max_results: int = WEB_SEARCH_RESULTS
) -> List[Dict[str, str]]:
    """Return live Google web results as [{title, snippet, link, source}].

    Synchronous (SerpAPI is blocking); callers in async contexts should wrap
    this in ``asyncio.to_thread``. Returns [] on any missing dependency, missing
    key, API error, or empty query.
    """
    if not query or not query.strip():
        return []
    if not _SERPAPI_AVAILABLE:
        LOGGER.info("SerpAPI unavailable — web search skipped")
        return []
    load_environment()
    api_key: Optional[str] = os.getenv("SERPAPI_API_KEY")
    if not api_key:
        LOGGER.info("SERPAPI_API_KEY absent — web search skipped")
        return []
    try:
        search = GoogleSearch({
            "engine": "google", "q": query.strip(), "api_key": api_key,
            "num": max_results, **WEB_SEARCH_LOCALE,
        })
        data: Dict[str, object] = search.get_dict()
        if data.get("error"):
            LOGGER.warning("SerpAPI web search error: %s", data["error"])
            return []
        organic: List[Dict[str, object]] = data.get("organic_results", [])  # type: ignore[assignment]
    except _NET_ERRORS:
        LOGGER.exception("Web search failed for query=%r", query[:80])
        return []
    results: List[Dict[str, str]] = []
    for hit in organic[:max_results]:
        title: str = str(hit.get("title") or "")
        snippet: str = str(hit.get("snippet") or "")
        link: str = str(hit.get("link") or "")
        if title or snippet:
            results.append({
                "title": title, "snippet": snippet,
                "link": link, "source": "web",
            })
    LOGGER.info("Web search returned %d result(s) for query=%r",
                len(results), query[:80])
    return results
