"""Cyber Shield India — Autonomous Background Ingestion Worker.

A standalone APScheduler-driven process (entirely separate from the Streamlit
frontend) that continuously builds the open-access research corpus from
authentic public sources across two cadences:

* **Static Tier (90-day interval)** — deep regulatory/structural documents
  rendered through a headless **Playwright (Chromium)** browser so that
  JavaScript-heavy government portals and nested PDF advisories
  (``pdfplumber``) are processed cleanly without hanging.
* **Dynamic Tier (48-hour interval)** — volatile real-time alerts via
  **SerpAPI** (real Google results, no GCP-project restriction), routed
  through bundled ``site:`` filters across the exact 45-domain footprint
  (central regulators, state cyber cells, research nodes, and media desks),
  plus NewsAPI media aggregation. The SerpAPI key is read from
  ``SERPAPI_API_KEY`` in ``.env``.

Every fetched document is synthesized by Gemini (``ResearchExtractor``) into
structured ``fraud_records`` rows and chunked into the ``research_corpus``
vector collection (``ResearchRepository``). Sources that block scrapers,
paywall, throttle, or fail simply log-and-skip — nothing is fabricated.

Usage:
  python ingestion_worker.py            # start the persistent scheduler
  python ingestion_worker.py --once     # run both tiers once and exit
  python ingestion_worker.py --seed-demo  # load labelled sample rows and exit
"""

import argparse
import asyncio
import hashlib
import importlib.util
import io
import logging
import os
import random
import sys
from datetime import datetime, timedelta, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiosqlite
import httpx
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from bs4 import BeautifulSoup

from core.config import get_news_api_key, load_environment
from core.database import SQLITE_PATH, init_db
from services.research_extractor import ResearchExtractor
from services.research_repository import ResearchRepository, SourceMeta
from utils.scraper import USER_AGENT_POOL

# --- Optional-dependency guards (worker degrades gracefully if absent) ------ #

try:  # SerpAPI — the `google-search-results` package exposes the `serpapi` module
    from serpapi import GoogleSearch  # type: ignore
    _SERPAPI_AVAILABLE: bool = True
except ImportError:
    _SERPAPI_AVAILABLE = False

try:  # network faults from the SerpAPI client (it rides on `requests`)
    from requests.exceptions import RequestException
    _SERP_NET_ERRORS: Tuple[type, ...] = (RequestException, ValueError, RuntimeError)
except ImportError:
    _SERP_NET_ERRORS = (OSError, ValueError, RuntimeError)

try:
    from playwright.async_api import Error as PlaywrightError  # type: ignore
    _PLAYWRIGHT_AVAILABLE: bool = importlib.util.find_spec("playwright") is not None
except ImportError:
    class PlaywrightError(Exception):  # type: ignore
        """Placeholder when Playwright is not installed."""
    _PLAYWRIGHT_AVAILABLE = False

try:
    from pdfminer.pdfparser import PDFSyntaxError  # type: ignore
    _PDF_ERRORS: Tuple[type, ...] = (PDFSyntaxError, ValueError, OSError)
except ImportError:
    _PDF_ERRORS = (ValueError, OSError)

_PDFPLUMBER_AVAILABLE: bool = importlib.util.find_spec("pdfplumber") is not None

# Cloud-native scanned-PDF fallback: pypdfium2 (pre-compiled PDFium wheels, no
# system binaries) renders pages in-memory; Gemini Vision transcribes them.
_PDFIUM_AVAILABLE: bool = importlib.util.find_spec("pypdfium2") is not None
VISION_MIN_CHARS: int = 100         # below this, treat the PDF as scanned
VISION_RENDER_SCALE: float = 2.5    # ~180 DPI page render for legibility
VISION_MAX_PAGES: int = 5           # cap pages sent to the multimodal model
VISION_MODEL_NAME: str = "gemini-2.5-flash"  # multimodal; project standard
VISION_PROMPT: str = (
    "You are an expert digital forensics document parser. The attached "
    "image(s) represent pages from a scanned Indian state law enforcement "
    "cyber advisory or public circular. Please transcribe all text visible "
    "across these pages with absolute literal accuracy. Retain all names, "
    "bank account numbers, case figures, and specific fraud tactics. Output "
    "only the clean, raw text transcription."
)

PROJECT_ROOT: Path = Path(__file__).resolve().parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the worker logger with a midnight-rotating handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.ingestion_worker")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "ingestion_worker.log",
        when="midnight", backupCount=14, encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    stream_handler: logging.StreamHandler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


LOGGER: logging.Logger = _build_logger()

# Scheduling cadences.
STATIC_INTERVAL_HOURS: int = 24 * 90      # 90-day deep regulatory sweep
DYNAMIC_INTERVAL_HOURS: int = 48          # 48h sweep — stays within SerpAPI free tier
FETCH_TIMEOUT_SECONDS: float = 45.0
MAX_DYNAMIC_DOCS: int = 30                # per-run document cap (cost control)

# SerpAPI: real Google results with no GCP-project restriction. The free tier
# is ~100 searches/month, so we bundle the footprint into a handful of OR'd
# site: queries per sweep rather than one query per domain.
SERP_NUM_RESULTS: int = 10
SERP_PACING_SECONDS: float = 0.5
MAX_SITES_PER_BUNDLE: int = 10  # larger bundles keep the national footprint
                                # within a handful of SerpAPI searches per sweep
SERP_LOCALE: Dict[str, str] = {"gl": "in", "hl": "en"}

# Playwright navigation budget.
STATIC_NAV_TIMEOUT_MS: int = 45_000
STATIC_SETTLE_MS: int = 1_500


def _headers() -> Dict[str, str]:
    """Rotating browser headers for resilient public fetches."""
    return {
        "User-Agent": random.choice(USER_AGENT_POOL),
        "Accept": "text/html,application/xhtml+xml,application/pdf,*/*;q=0.8",
        "Accept-Language": "en-IN,en;q=0.9",
    }


# --------------------------------------------------------------------------- #
# Static tier — regulatory & structural document sources (Playwright/PDF).     #
# --------------------------------------------------------------------------- #

STATIC_SOURCES: Tuple[Tuple[str, str], ...] = (
    ("Cyber Swachhta Kendra", "https://www.csk.gov.in/alerts.html"),
    ("NCRB", "https://www.ncrb.gov.in/crime-in-india-year-wise.html"),
    ("I4C / MHA", "https://i4c.mha.gov.in/"),
    ("UIDAI", "https://uidai.gov.in/en/my-aadhaar/about-your-aadhaar/aadhaar-security.html"),
    ("TRAI", "https://www.trai.gov.in/notifications/press-release"),
    ("RBI", "https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx"),
    ("CERT-In", "https://www.cert-in.org.in/"),
    ("MeitY", "https://www.meity.gov.in/"),
)

# --------------------------------------------------------------------------- #
# Dynamic tier — the exact 45-domain footprint, grouped for SerpAPI site:      #
# bundling. Each group: (topic_terms, (registrable site: domains, ...)).       #
# --------------------------------------------------------------------------- #

SITE_FOOTPRINT: Dict[str, Tuple[str, Tuple[str, ...]]] = {
    # --- Core central government & regulatory portals -----------------------
    "GovPortal": (
        "cyber fraud advisory India",
        (
            "meity.gov.in", "i4c.mha.gov.in", "cybercrime.gov.in",
            "ncrb.gov.in", "uidai.gov.in", "trai.gov.in", "cert-in.org.in",
            "csk.gov.in", "mha.gov.in", "rbi.org.in", "bprd.nic.in",
        ),
    ),
    # --- State & local enforcement cyber cells (national footprint) ---------
    "StateCell": (
        "cyber crime fraud alert advisory",
        (
            # Existing core
            "delhipolice.gov.in", "haryanapolice.gov.in", "mahacyber.gov.in",
            # All states
            "appolice.gov.in", "arunpol.nic.in", "police.assam.gov.in",
            "biharpolice.bihar.gov.in", "cgpolice.gov.in", "goapolice.gov.in",
            "cidcrime.gujarat.gov.in", "gujaratpolice.gov.in", "hppolice.gov.in",
            "jhpolice.gov.in", "cybercrime.cidkarnataka.gov.in",
            "karnatakapolice.gov.in", "cyberdome.kerala.gov.in",
            "keralapolice.gov.in", "mppolice.gov.in", "manipurpolice.gov.in",
            "megpolice.gov.in", "police.mizoram.gov.in", "nagalandpolice.gov.in",
            "odishapolice.gov.in", "punjabpolice.gov.in", "police.rajasthan.gov.in",
            "sikkimpolice.nic.in", "tnpolice.gov.in", "tgccb.telangana.gov.in",
            "tspolice.gov.in", "tripurapolice.gov.in",
            "uttarakhandpolice.uk.gov.in", "wbpolice.gov.in",
            # Union Territories
            "police.andaman.gov.in", "chandigarhpolice.gov.in", "ddshpolice.gov.in",
            "jkpolice.gov.in", "police.ladakh.gov.in", "lakshadweeppolice.gov.in",
            "police.py.gov.in",
        ),
    ),
    # --- Targeted cyber security research nodes -----------------------------
    "ResearchNode": (
        "cyber fraud scam advisory",
        (
            "rakshittandon.com", "amitdubey.me", "instagram.com", "x.com",
            "nipunjaswal.com", "root64foundation.org",
        ),
    ),
    # --- High-volume media aggregation tags & sections ----------------------
    "Media": (
        "cyber crime fraud India",
        (
            "ft.com", "moneycontrol.com", "timesofindia.indiatimes.com",
            "economictimes.indiatimes.com", "indianexpress.com", "news.yahoo.com",
        ),
    ),
}


def build_serpapi_queries() -> List[Tuple[str, str]]:
    """Bundle the footprint into (group, ``topic (site:a OR site:b …)``) queries.

    Domains are chunked at ``MAX_SITES_PER_BUNDLE`` so each Google query stays
    within length limits while covering the entire 45-domain footprint in a
    handful of SerpAPI searches.
    """
    queries: List[Tuple[str, str]] = []
    for group, (topic, domains) in SITE_FOOTPRINT.items():
        for start in range(0, len(domains), MAX_SITES_PER_BUNDLE):
            chunk: Tuple[str, ...] = domains[start:start + MAX_SITES_PER_BUNDLE]
            sites: str = " OR ".join(f"site:{domain}" for domain in chunk)
            queries.append((group, f"{topic} ({sites})"))
    return queries


# --------------------------------------------------------------------------- #
# Fetch + parse helpers.                                                      #
# --------------------------------------------------------------------------- #


async def _fetch(client: httpx.AsyncClient, url: str) -> Optional[httpx.Response]:
    """GET a URL with rotating headers; None on any transport/HTTP fault."""
    try:
        response: httpx.Response = await client.get(url, headers=_headers())
        response.raise_for_status()
        return response
    except httpx.HTTPStatusError as fault:
        LOGGER.warning("fetch %s: HTTP %d", url, fault.response.status_code)
    except httpx.TimeoutException:
        LOGGER.warning("fetch %s: timeout", url)
    except httpx.RequestError:
        LOGGER.warning("fetch %s: transport error", url)
    return None


def _render_pdf_pages(content: bytes) -> List[bytes]:
    """Render PDF pages to in-memory JPEG bytes via pypdfium2 (no system deps).

    pypdfium2 bundles pre-compiled PDFium binaries inside its wheel, so this
    works in sandboxed environments with zero host-level dependencies.
    """
    if not _PDFIUM_AVAILABLE:
        LOGGER.warning("pypdfium2 not installed — cannot render scanned PDF")
        return []
    import pypdfium2 as pdfium
    pages: List[bytes] = []
    try:
        document = pdfium.PdfDocument(content)
    except (pdfium.PdfiumError, ValueError, OSError):
        LOGGER.exception("pypdfium2 failed to load PDF")
        return []
    try:
        page_count: int = min(len(document), VISION_MAX_PAGES)
        for index in range(page_count):
            bitmap = document[index].render(scale=VISION_RENDER_SCALE)
            image = bitmap.to_pil().convert("RGB")
            buffer: io.BytesIO = io.BytesIO()
            image.save(buffer, format="JPEG", quality=85)
            pages.append(buffer.getvalue())
    except (pdfium.PdfiumError, ValueError, OSError):
        LOGGER.exception("pypdfium2 page render failed")
    finally:
        document.close()
    LOGGER.info("Rendered %d page image(s) for vision transcription", len(pages))
    return pages


def _extract_text_via_vision(image_pages: List[bytes]) -> str:
    """Transcribe rendered page images through the Gemini Vision model."""
    if not image_pages:
        return ""
    import base64
    from langchain_core.messages import HumanMessage
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_google_genai._common import GoogleGenerativeAIError
    from core.config import get_google_api_key

    content: List[Dict[str, str]] = [{"type": "text", "text": VISION_PROMPT}]
    for jpeg in image_pages:
        encoded: str = base64.b64encode(jpeg).decode("ascii")
        content.append({
            "type": "image_url",
            "image_url": f"data:image/jpeg;base64,{encoded}",
        })
    try:
        llm = ChatGoogleGenerativeAI(
            model=VISION_MODEL_NAME, temperature=0.0,
            google_api_key=get_google_api_key(),
        )
        response = llm.invoke([HumanMessage(content=content)])
    except (GoogleGenerativeAIError, ValueError, RuntimeError):
        LOGGER.exception("Gemini Vision transcription failed")
        return ""
    transcription: str = str(response.content).strip()
    LOGGER.info("Gemini Vision transcribed %d chars from %d page(s)",
                len(transcription), len(image_pages))
    return transcription


def _parse_pdf(content: bytes) -> str:
    """Extract text from PDF bytes; Gemini Vision fallback for scanned PDFs.

    pdfplumber handles native-text PDFs. When it yields fewer than
    ``VISION_MIN_CHARS`` characters (a scanned image or unreadable embedded
    fonts), pages are rendered with pypdfium2 and transcribed by Gemini Vision
    — a fully cloud-native fallback with no host-level binary dependencies.
    """
    text: str = ""
    if _PDFPLUMBER_AVAILABLE:
        try:
            import pdfplumber
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                text = "\n".join((page.extract_text() or "") for page in pdf.pages)
        except _PDF_ERRORS:
            LOGGER.exception("pdfplumber parse failed")
            text = ""
    else:
        LOGGER.warning("pdfplumber unavailable — relying on vision fallback")

    if len(text.strip()) >= VISION_MIN_CHARS:
        return text

    LOGGER.warning("⚠️ Scanned document detected. Engaging cloud-native "
                   "Gemini Vision Multimodal Fallback...")
    image_pages: List[bytes] = _render_pdf_pages(content)
    vision_text: str = _extract_text_via_vision(image_pages)
    # Hand back the vision transcription when productive, else the minimal text.
    return vision_text if vision_text.strip() else text


def _html_to_text(html: str) -> str:
    """Reduce raw HTML to clean plain text (httpx fallback path)."""
    soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    return " ".join(soup.get_text(" ").split())


# --------------------------------------------------------------------------- #
# SerpAPI collector (real Google results; replaces Google CSE / DuckDuckGo).   #
# --------------------------------------------------------------------------- #


def _search_serpapi_sync(query: str, api_key: str) -> List[Dict[str, object]]:
    """Synchronous SerpAPI Google search (run off the event loop)."""
    search = GoogleSearch({
        "engine": "google", "q": query, "api_key": api_key,
        "num": SERP_NUM_RESULTS, **SERP_LOCALE,
    })
    data: Dict[str, object] = search.get_dict()
    if data.get("error"):
        raise RuntimeError(str(data["error"]))
    organic: List[Dict[str, object]] = data.get("organic_results", [])  # type: ignore[assignment]
    return organic


async def _collect_serpapi() -> List[Tuple[str, str, str]]:
    """Return (platform, url, raw_text) tuples across the bundled footprint."""
    if not _SERPAPI_AVAILABLE:
        LOGGER.info("google-search-results unavailable — skipping SerpAPI tier")
        return []
    load_environment()
    api_key: Optional[str] = os.getenv("SERPAPI_API_KEY")
    if not api_key:
        LOGGER.info("SERPAPI_API_KEY absent in .env — skipping SerpAPI tier")
        return []
    collected: List[Tuple[str, str, str]] = []
    for group, query in build_serpapi_queries():
        try:
            results: List[Dict[str, object]] = await asyncio.to_thread(
                _search_serpapi_sync, query, api_key
            )
        except _SERP_NET_ERRORS:
            LOGGER.warning("SerpAPI query failed for group %s — skipping", group)
            continue
        for hit in results:
            title: str = str(hit.get("title") or "")
            snippet: str = str(hit.get("snippet") or "")
            link: str = str(hit.get("link") or "")
            source: str = str(hit.get("source") or group)
            raw_text: str = " ".join(p for p in (title, snippet) if p)
            if len(raw_text) >= 60:
                collected.append((f"{group}:{source}", link, raw_text))
        await asyncio.sleep(SERP_PACING_SECONDS)
    LOGGER.info("SerpAPI collected %d candidate items across %d bundled queries",
                len(collected), len(build_serpapi_queries()))
    return collected


# --------------------------------------------------------------------------- #
# NewsAPI media collector (retained).                                         #
# --------------------------------------------------------------------------- #

MEDIA_DOMAINS: str = ",".join((
    "timesofindia.indiatimes.com", "economictimes.indiatimes.com",
    "moneycontrol.com", "indianexpress.com", "news.yahoo.com", "ft.com",
))
NEWS_QUERIES: Tuple[str, ...] = (
    "cyber fraud India", "digital arrest scam India",
    "UPI fraud India", "deepfake scam India",
)


async def _collect_newsapi(
    client: httpx.AsyncClient,
) -> List[Tuple[str, str, str]]:
    """Return (platform, url, raw_text) tuples from NewsAPI media desks."""
    from urllib.parse import quote_plus
    api_key: Optional[str] = get_news_api_key()
    if not api_key:
        LOGGER.info("NewsAPI key absent — skipping media tier")
        return []
    collected: List[Tuple[str, str, str]] = []
    cutoff: str = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d")
    for query in NEWS_QUERIES:
        url: str = (
            "https://newsapi.org/v2/everything"
            f"?q={quote_plus(query)}&domains={MEDIA_DOMAINS}"
            f"&from={cutoff}&language=en&sortBy=publishedAt&pageSize=10"
            f"&apiKey={api_key}"
        )
        response: Optional[httpx.Response] = await _fetch(client, url)
        if response is None:
            continue
        try:
            articles: List[Dict[str, object]] = response.json().get("articles", [])
        except ValueError:
            LOGGER.warning("NewsAPI: unparseable response for %r", query)
            continue
        for article in articles:
            title: str = str(article.get("title") or "")
            description: str = str(article.get("description") or "")
            body: str = str(article.get("content") or "")
            source: Dict[str, object] = article.get("source") or {}  # type: ignore[assignment]
            platform: str = str(source.get("name") or "NewsAPI")
            article_url: str = str(article.get("url") or "")
            raw_text: str = " ".join(p for p in (title, description, body) if p)
            if len(raw_text) >= 80:
                collected.append((platform, article_url, raw_text))
    LOGGER.info("NewsAPI collected %d candidate articles", len(collected))
    return collected


# --------------------------------------------------------------------------- #
# Tier runner.                                                                #
# --------------------------------------------------------------------------- #


class IngestionWorker:
    """Owns the extractor/repository and runs the two harvest tiers."""

    def __init__(self) -> None:
        self._extractor: Optional[ResearchExtractor] = None
        self._repository: ResearchRepository = ResearchRepository()

    @property
    def extractor(self) -> ResearchExtractor:
        """Lazily construct the Gemini extractor on first harvest."""
        if self._extractor is None:
            self._extractor = ResearchExtractor()
        return self._extractor

    async def _ingest_documents(
        self, documents: List[Tuple[str, str, str]], tier: str
    ) -> int:
        """Extract + persist a list of (platform, url, raw_text) docs."""
        total_written: int = 0
        for platform, url, raw_text in documents[:MAX_DYNAMIC_DOCS]:
            batch = await self.extractor.extract(raw_text, origin=platform)
            if not batch.records:
                continue
            meta: SourceMeta = SourceMeta(
                source_platform=platform, source_tier=tier, source_url=url or None
            )
            written: int = await self._repository.persist_batch(batch, meta, raw_text)
            total_written += written
        LOGGER.info("[%s tier] persisted %d new datapoints from %d documents",
                    tier, total_written, len(documents))
        return total_written

    async def _fetch_static_text(
        self, client: httpx.AsyncClient, browser: Optional[object], url: str
    ) -> str:
        """Render one static source: PDF -> pdfplumber, page -> Playwright."""
        if url.lower().endswith(".pdf"):
            response: Optional[httpx.Response] = await _fetch(client, url)
            return _parse_pdf(response.content) if response is not None else ""
        if browser is not None:
            try:
                page = await browser.new_page(  # type: ignore[attr-defined]
                    user_agent=random.choice(USER_AGENT_POOL)
                )
                await page.goto(url, wait_until="domcontentloaded",
                                timeout=STATIC_NAV_TIMEOUT_MS)
                await page.wait_for_timeout(STATIC_SETTLE_MS)
                text: str = await page.inner_text("body")
                await page.close()
                return " ".join(text.split())
            except PlaywrightError:
                LOGGER.warning("Playwright render failed for %s — httpx fallback", url)
        response = await _fetch(client, url)
        if response is None:
            return ""
        content_type: str = response.headers.get("content-type", "").lower()
        if "application/pdf" in content_type:
            return _parse_pdf(response.content)
        return _html_to_text(response.text)

    async def run_static_tier(self) -> int:
        """Harvest the deep regulatory set via headless Chromium."""
        LOGGER.info("STATIC TIER sweep starting (%d sources, playwright=%s)",
                    len(STATIC_SOURCES), _PLAYWRIGHT_AVAILABLE)
        documents: List[Tuple[str, str, str]] = []
        browser: Optional[object] = None
        playwright_ctx: Optional[object] = None
        if _PLAYWRIGHT_AVAILABLE:
            try:
                from playwright.async_api import async_playwright
                playwright_ctx = await async_playwright().start()
                browser = await playwright_ctx.chromium.launch(headless=True)  # type: ignore[attr-defined]
            except (PlaywrightError, OSError):
                LOGGER.warning("Chromium launch failed (run 'playwright install "
                               "chromium') — falling back to httpx for static tier")
                if playwright_ctx is not None:
                    await playwright_ctx.stop()  # type: ignore[attr-defined]
                    playwright_ctx = None
                browser = None
        try:
            async with httpx.AsyncClient(
                timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=True
            ) as client:
                for platform, url in STATIC_SOURCES:
                    text: str = await self._fetch_static_text(client, browser, url)
                    if len(text) >= 200:
                        documents.append((platform, url, text))
        finally:
            if browser is not None:
                await browser.close()  # type: ignore[attr-defined]
            if playwright_ctx is not None:
                await playwright_ctx.stop()  # type: ignore[attr-defined]
        return await self._ingest_documents(documents, tier="static")

    async def run_dynamic_tier(self) -> int:
        """Harvest volatile media + OSINT alerts via SerpAPI + NewsAPI."""
        LOGGER.info("DYNAMIC TIER sweep starting")
        serp: List[Tuple[str, str, str]] = await _collect_serpapi()
        async with httpx.AsyncClient(
            timeout=FETCH_TIMEOUT_SECONDS, follow_redirects=True
        ) as client:
            media: List[Tuple[str, str, str]] = await _collect_newsapi(client)
        return await self._ingest_documents(serp + media, tier="dynamic")


# --------------------------------------------------------------------------- #
# Demo seeding — clearly-labelled sample rows for dashboard bring-up.         #
# --------------------------------------------------------------------------- #

_DEMO_ROWS: Tuple[Dict[str, object], ...] = (
    {"state": "Haryana", "city": "Faridabad", "scam_vector_type": "Digital Arrest",
     "extracted_case_count": 142, "financial_loss_inr": 38_500_000.0,
     "demographic_age_bracket": "60+", "demographic_gender_ratio": "majority male",
     "demographic_profession_target": "retirees", "age_days": 0,
     "advisory": "No agency conducts arrests over video calls; dial 1930 immediately."},
    {"state": "Jharkhand", "city": "Jamtara", "scam_vector_type": "UPI Payment Fraud",
     "extracted_case_count": 318, "financial_loss_inr": 22_100_000.0,
     "demographic_age_bracket": "26-40", "demographic_gender_ratio": "mixed",
     "demographic_profession_target": "small merchants", "age_days": 2,
     "advisory": "Never approve UPI collect requests to receive money."},
    {"state": "Delhi", "city": "New Delhi", "scam_vector_type": "AI Deepfake Identity Theft",
     "extracted_case_count": 76, "financial_loss_inr": 15_900_000.0,
     "demographic_age_bracket": "26-40", "demographic_gender_ratio": "mixed",
     "demographic_profession_target": "corporate employees", "age_days": 4,
     "advisory": "Verify video/voice identity via a known callback number."},
    {"state": "Maharashtra", "city": "Mumbai", "scam_vector_type": "Investment Scam",
     "extracted_case_count": 204, "financial_loss_inr": 61_200_000.0,
     "demographic_age_bracket": "26-40", "demographic_gender_ratio": "60% male",
     "demographic_profession_target": "IT professionals", "age_days": 9,
     "advisory": "Check platforms against SEBI/RBI registries before investing."},
    {"state": "Telangana", "city": "Hyderabad", "scam_vector_type": "Loan App Extortion",
     "extracted_case_count": 158, "financial_loss_inr": 9_400_000.0,
     "demographic_age_bracket": "18-25", "demographic_gender_ratio": "mixed",
     "demographic_profession_target": "students", "age_days": 20,
     "advisory": "Use only RBI-regulated lenders; never grant gallery/contacts access."},
    {"state": "Karnataka", "city": "Bengaluru", "scam_vector_type": "Phishing",
     "extracted_case_count": 261, "financial_loss_inr": 18_700_000.0,
     "demographic_age_bracket": "26-40", "demographic_gender_ratio": "mixed",
     "demographic_profession_target": "corporate employees", "age_days": 45,
     "advisory": "Never enter banking credentials via links in SMS or email."},
    {"state": "Haryana", "city": "Gurugram", "scam_vector_type": "Digital Arrest",
     "extracted_case_count": 97, "financial_loss_inr": 27_300_000.0,
     "demographic_age_bracket": "60+", "demographic_gender_ratio": "majority female",
     "demographic_profession_target": "homemakers", "age_days": 120,
     "advisory": "Disconnect coercive video calls and inform family at once."},
    {"state": "Tamil Nadu", "city": "Chennai", "scam_vector_type": "SIM Swap",
     "extracted_case_count": 64, "financial_loss_inr": 7_800_000.0,
     "demographic_age_bracket": "41-60", "demographic_gender_ratio": "mixed",
     "demographic_profession_target": "business owners", "age_days": 250,
     "advisory": "Set a SIM PIN and act on sudden loss of mobile signal."},
)


async def seed_demo() -> int:
    """Insert clearly-labelled sample rows (source_tier='demo')."""
    await init_db()
    now: datetime = datetime.now(timezone.utc)
    inserted: int = 0
    async with aiosqlite.connect(SQLITE_PATH) as connection:
        try:
            await connection.execute("PRAGMA journal_mode=WAL")
            for row in _DEMO_ROWS:
                published: str = (
                    now - timedelta(days=int(row["age_days"]))  # type: ignore[arg-type]
                ).strftime("%Y-%m-%d %H:%M:%S")
                digest: str = hashlib.sha256(
                    f"demo|{row['state']}|{row['city']}|{row['scam_vector_type']}"
                    .encode("utf-8")
                ).hexdigest()
                loss: float = float(row["financial_loss_inr"])  # type: ignore[arg-type]
                cursor: aiosqlite.Cursor = await connection.execute(
                    "INSERT OR IGNORE INTO fraud_records ("
                    " source_platform, source_tier, publish_timestamp, state, city, "
                    " scam_vector_type, extracted_case_count, financial_loss_inr, "
                    " is_isolated_incident, incident_loss_inr, "
                    " is_macro_historical_summary, macro_summary_loss_inr, "
                    " demographic_age_bracket, demographic_gender_ratio, "
                    " demographic_profession_target, official_safety_advisory, "
                    " source_url, content_hash) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        "demo_sample", "demo", published, row["state"], row["city"],
                        row["scam_vector_type"], row["extracted_case_count"],
                        loss, 1, loss, 0, 0.0,
                        row["demographic_age_bracket"],
                        row["demographic_gender_ratio"],
                        row["demographic_profession_target"], row["advisory"],
                        None, digest,
                    ),
                )
                inserted += cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
            await connection.commit()
        except aiosqlite.Error:
            await connection.rollback()
            LOGGER.exception("demo seeding failed — rolled back")
            raise
    LOGGER.info("Demo seeding complete: %d sample rows inserted", inserted)
    return inserted


# --------------------------------------------------------------------------- #
# Entrypoints.                                                                #
# --------------------------------------------------------------------------- #


async def run_once() -> None:
    """Run both tiers a single time (used for manual/CI verification)."""
    await init_db()
    worker: IngestionWorker = IngestionWorker()
    dynamic: int = await worker.run_dynamic_tier()
    static: int = await worker.run_static_tier()
    LOGGER.info("Single sweep complete: dynamic=%d static=%d new datapoints",
                dynamic, static)


async def run_scheduler() -> None:
    """Start the persistent APScheduler loop with both tiers."""
    await init_db()
    worker: IngestionWorker = IngestionWorker()
    scheduler: AsyncIOScheduler = AsyncIOScheduler(timezone="UTC")
    scheduler.add_job(
        worker.run_dynamic_tier, "interval",
        hours=DYNAMIC_INTERVAL_HOURS, id="dynamic_tier",
        next_run_time=datetime.now(timezone.utc),  # fire immediately on boot
        max_instances=1, coalesce=True,
    )
    scheduler.add_job(
        worker.run_static_tier, "interval",
        hours=STATIC_INTERVAL_HOURS, id="static_tier",
        next_run_time=datetime.now(timezone.utc) + timedelta(minutes=2),
        max_instances=1, coalesce=True,
    )
    scheduler.start()
    LOGGER.info("Scheduler online: dynamic every %dh, static every %dh. "
                "Ctrl+C to stop.", DYNAMIC_INTERVAL_HOURS, STATIC_INTERVAL_HOURS)
    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        LOGGER.info("Scheduler shutdown requested")
        scheduler.shutdown(wait=False)


def main() -> None:
    """CLI dispatch for the autonomous ingestion worker."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Cyber Shield India autonomous ingestion worker"
    )
    parser.add_argument("--once", action="store_true",
                        help="run both tiers once and exit")
    parser.add_argument("--seed-demo", action="store_true",
                        help="insert labelled sample rows and exit")
    args: argparse.Namespace = parser.parse_args()
    if args.seed_demo:
        count: int = asyncio.run(seed_demo())
        print(f"Seeded {count} labelled demo rows into fraud_records.")
        return
    if args.once:
        asyncio.run(run_once())
        return
    try:
        asyncio.run(run_scheduler())
    except KeyboardInterrupt:
        print("\nWorker stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
