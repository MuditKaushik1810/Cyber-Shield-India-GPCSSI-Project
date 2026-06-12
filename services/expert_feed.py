"""Cyber Shield India — Expert Intelligence Stream Parser & News Triage Engine
(STATUS.md Steps 1.5 & 1.6).

Two asynchronous ingestion pipelines compiled into one unified stream buffer:

* **Expert Intelligence Stream Parser** — ingests public tactical advisories,
  case logs, and investigative commentary from verified digital policing
  strategists. Each expert is registered as an ``ExpertProfile`` whose public
  commentary is harvested through targeted Google News RSS query channels and
  enriched with tactic detection (Digital Arrest mechanics over virtual
  gateways, malicious sideloaded APK vectors, accessibility API exploits,
  SIM impersonation, and VoIP spoof arrays).

* **Structured News Triage Engine** — polls the RSS streams of the primary
  trade publications (ET Telecom, MediaNama, Inc42, Gadgets360), triages each
  article against a cybersecurity keyword lattice, and emits only
  threat-relevant items into continuous raw text queues.

Both pipelines drain into ``UnifiedIntelligenceStream``: a single
``asyncio.Queue``-backed buffer exposed as an ``AsyncGenerator`` for
downstream extraction (Phase 2.3) and persisted to JSON via ``aiofiles``.
"""

import asyncio
import json
import logging
import random
import re
import xml.etree.ElementTree as ElementTree
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Tuple
from urllib.parse import quote_plus

import aiofiles
import httpx
from bs4 import BeautifulSoup

from utils.scraper import (
    MAX_RETRIES,
    RAW_DATA_DIR,
    REQUEST_TIMEOUT_SECONDS,
    RETRY_BACKOFF_SECONDS,
    USER_AGENT_POOL,
    clean_text,
    extract_first_date,
)

# --------------------------------------------------------------------------- #
# Forensic logging — dedicated daily-rotating channel for feed ingestion.     #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the feed logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.expert_feed")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "expert_feed.log",
        when="midnight",
        backupCount=14,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    stream_handler: logging.StreamHandler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


LOGGER: logging.Logger = _build_logger()

# --------------------------------------------------------------------------- #
# Tactic detection lattice — maps expert/news language onto threat vectors.   #
# --------------------------------------------------------------------------- #

TACTIC_PATTERNS: Dict[str, re.Pattern] = {
    "digital_arrest": re.compile(
        r"digital\s+arrest|fake\s+(?:cbi|police|customs|narcotics|court)|"
        r"video[\s-]+call\s+(?:interrogation|custody)|skype\s+(?:court|police)|"
        r"impersonat\w+\s+(?:officer|official|police)",
        re.IGNORECASE,
    ),
    "apk_sideloading": re.compile(
        r"\bapk\b|side[\s-]?load|fake\s+wedding\s+invit|malicious\s+(?:app|apk)|"
        r"whatsapp\s+(?:apk|file)\s",
        re.IGNORECASE,
    ),
    "accessibility_exploit": re.compile(
        r"accessibility\s+(?:service|api|permission|abuse)|screen[\s-]?read\w*\s+abuse|"
        r"overlay\s+attack",
        re.IGNORECASE,
    ),
    "voip_spoofing": re.compile(
        r"voip|virtual\s+gateway|spoof\w*\s+call|international\s+call\s+spoof|"
        r"whatsapp\s+call\s+(?:scam|fraud)|caller\s+id\s+spoof",
        re.IGNORECASE,
    ),
    "sim_impersonation": re.compile(
        r"sim\s+(?:swap|clon\w+|card\s+fraud)|e[\s-]?sim\s+fraud|"
        r"sim\s+impersonat\w+|otp\s+(?:theft|interception)",
        re.IGNORECASE,
    ),
    "payment_fraud": re.compile(
        r"\bupi\b|aeps|payment\s+fraud|money\s+mule|mule\s+account|"
        r"qr\s+code\s+scam|collect\s+request",
        re.IGNORECASE,
    ),
    "investment_scam": re.compile(
        r"investment\s+(?:scam|fraud)|trading\s+(?:scam|app\s+fraud)|"
        r"crypto\s+(?:scam|fraud)|ponzi|task\s+(?:scam|fraud)|pig\s+butchering",
        re.IGNORECASE,
    ),
}


def detect_tactics(text: str) -> Tuple[str, ...]:
    """Return every tactic tag whose signature pattern fires on ``text``."""
    return tuple(
        tactic for tactic, pattern in TACTIC_PATTERNS.items()
        if pattern.search(text)
    )


# --------------------------------------------------------------------------- #
# Unified intelligence artifact.                                              #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class IntelligenceItem:
    """One normalized artifact from either ingestion stream."""

    stream_type: str            # "expert_advisory" | "news_article"
    source: str                 # expert name or publication
    url: str
    title: str
    content: str
    author: str
    date_published: Optional[str]
    threat_category: str
    tactic_tags: Tuple[str, ...]

    def to_record(self) -> Dict[str, object]:
        """Serialize into a flat, JSON-safe dictionary."""
        record: Dict[str, object] = asdict(self)
        record["tactic_tags"] = list(self.tactic_tags)
        return record


# --------------------------------------------------------------------------- #
# Shared async fetch + RSS parsing primitives.                                #
# --------------------------------------------------------------------------- #


def _rotate_headers() -> Dict[str, str]:
    """Return request headers carrying a freshly rotated user agent."""
    return {
        "User-Agent": random.choice(USER_AGENT_POOL),
        "Accept": "application/rss+xml,application/xml,text/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-IN,en;q=0.9,hi;q=0.8",
    }


async def fetch_feed_text(
    client: httpx.AsyncClient, url: str, channel: str
) -> Optional[str]:
    """GET a feed URL with rotating user agents and bounded retry."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response: httpx.Response = await client.get(url, headers=_rotate_headers())
            response.raise_for_status()
            return response.text
        except httpx.TimeoutException:
            LOGGER.warning(
                "%s: timeout on %s (attempt %d/%d)", channel, url, attempt, MAX_RETRIES
            )
        except httpx.HTTPStatusError as status_error:
            LOGGER.warning(
                "%s: HTTP %d on %s (attempt %d/%d)",
                channel, status_error.response.status_code, url, attempt, MAX_RETRIES,
            )
        except httpx.RequestError:
            LOGGER.exception(
                "%s: transport failure on %s (attempt %d/%d)",
                channel, url, attempt, MAX_RETRIES,
            )
        await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
    LOGGER.error("%s: exhausted retries for %s", channel, url)
    return None


def _rfc822_to_iso(raw: str) -> Optional[str]:
    """Convert an RFC-822 RSS pubDate into an ISO-8601 date string."""
    try:
        return parsedate_to_datetime(raw).date().isoformat()
    except (TypeError, ValueError):
        return extract_first_date(raw)


def _strip_html(fragment: str) -> str:
    """Reduce an HTML description fragment to clean plain text."""
    return clean_text(BeautifulSoup(fragment, "html.parser").get_text(" "))


def parse_rss_items(xml_text: str, channel: str) -> List[Dict[str, str]]:
    """Parse an RSS payload into raw item dictionaries.

    Returns dictionaries with ``title``, ``link``, ``description``, and
    ``pub_date`` keys. Malformed XML is logged and yields an empty list.
    """
    try:
        root: ElementTree.Element = ElementTree.fromstring(xml_text)
    except ElementTree.ParseError:
        LOGGER.exception("%s: malformed RSS payload, skipping channel", channel)
        return []
    items: List[Dict[str, str]] = []
    for node in root.iter("item"):
        items.append({
            "title": clean_text(node.findtext("title", default="")),
            "link": clean_text(node.findtext("link", default="")),
            "description": _strip_html(node.findtext("description", default="")),
            "pub_date": clean_text(node.findtext("pubDate", default="")),
        })
    return items


# --------------------------------------------------------------------------- #
# Step 1.5 — Expert Intelligence Stream Parser.                               #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExpertProfile:
    """A verified digital policing strategist tracked by the parser."""

    name: str
    designation: str
    focus_summary: str
    query: str                  # news search query targeting public commentary
    default_category: str


EXPERT_REGISTRY: Tuple[ExpertProfile, ...] = (
    ExpertProfile(
        name="Dr. Rakshit Tandon",
        designation="Cyber Security Consultant & Digital Policing Strategist",
        focus_summary=(
            "Remote 'Digital Arrest' scam mechanics over virtual gateways: "
            "fake CBI/police video-call custody, Skype court impersonation, "
            "and coerced victim fund transfers."
        ),
        query='"Rakshit Tandon" cyber fraud OR "digital arrest" OR scam',
        default_category="digital_arrest",
    ),
    ExpertProfile(
        name="Amit Dubey",
        designation="National Cyber Crime Investigator & Author",
        focus_summary=(
            "Malicious sideloaded Android APK delivery vectors (fake wedding "
            "invites, courier notices), accessibility API exploits, and "
            "device-level OTP interception."
        ),
        query='"Amit Dubey" cyber crime OR APK OR malware OR scam',
        default_category="apk_sideloading",
    ),
)

GOOGLE_NEWS_RSS_TEMPLATE: str = (
    "https://news.google.com/rss/search?q={query}&hl=en-IN&gl=IN&ceid=IN:en"
)


class ExpertFeedParser:
    """Ingests public tactical advisories from registered expert channels."""

    def __init__(self, registry: Tuple[ExpertProfile, ...] = EXPERT_REGISTRY) -> None:
        self.registry: Tuple[ExpertProfile, ...] = registry

    @staticmethod
    def channel_url(profile: ExpertProfile) -> str:
        """Build the targeted RSS query channel for one expert profile."""
        return GOOGLE_NEWS_RSS_TEMPLATE.format(query=quote_plus(profile.query))

    def build_item(
        self, profile: ExpertProfile, raw: Dict[str, str]
    ) -> IntelligenceItem:
        """Normalize one raw RSS item into an expert advisory artifact."""
        combined_text: str = f"{raw['title']} {raw['description']}"
        tactics: Tuple[str, ...] = detect_tactics(combined_text)
        return IntelligenceItem(
            stream_type="expert_advisory",
            source=profile.name,
            url=raw["link"],
            title=raw["title"],
            content=raw["description"] or raw["title"],
            author=profile.name,
            date_published=_rfc822_to_iso(raw["pub_date"]),
            threat_category=tactics[0] if tactics else profile.default_category,
            tactic_tags=tactics or (profile.default_category,),
        )

    async def parse_expert(
        self, client: httpx.AsyncClient, profile: ExpertProfile
    ) -> List[IntelligenceItem]:
        """Fetch and normalize the advisory channel for a single expert."""
        url: str = self.channel_url(profile)
        xml_text: Optional[str] = await fetch_feed_text(client, url, profile.name)
        if xml_text is None:
            return []
        raw_items: List[Dict[str, str]] = parse_rss_items(xml_text, profile.name)
        items: List[IntelligenceItem] = [
            self.build_item(profile, raw) for raw in raw_items if raw["title"]
        ]
        LOGGER.info("%s: normalized %d advisory items", profile.name, len(items))
        return items

    async def collect(self, client: httpx.AsyncClient) -> List[IntelligenceItem]:
        """Run every registered expert channel concurrently."""
        batches: List[List[IntelligenceItem]] = await asyncio.gather(
            *(self.parse_expert(client, profile) for profile in self.registry)
        )
        return [item for batch in batches for item in batch]


# --------------------------------------------------------------------------- #
# Step 1.6 — Structured News Triage Engine.                                   #
# --------------------------------------------------------------------------- #

NEWS_FEED_REGISTRY: Dict[str, Tuple[str, ...]] = {
    "ET Telecom": (
        "https://telecom.economictimes.indiatimes.com/rss/topstories",
        "https://telecom.economictimes.indiatimes.com/rss/internet",
    ),
    "MediaNama": (
        "https://www.medianama.com/feed/",
    ),
    "Inc42": (
        "https://inc42.com/feed/",
    ),
    "Gadgets360": (
        "https://www.gadgets360.com/rss/news",
    ),
}

TRIAGE_KEYWORDS: Tuple[str, ...] = (
    "cyber", "fraud", "scam", "phishing", "breach", "hack", "malware",
    "ransomware", "digital arrest", "upi", "aeps", "otp", "sim", "apk",
    "spyware", "dark web", "data leak", "vishing", "smishing", "mule",
    "identity theft", "deepfake", "extortion", "cert-in", "i4c",
)


class NewsTriageEngine:
    """Aggregates trade publication streams into triaged raw text queues."""

    def __init__(
        self, registry: Dict[str, Tuple[str, ...]] = NEWS_FEED_REGISTRY
    ) -> None:
        self.registry: Dict[str, Tuple[str, ...]] = registry

    @staticmethod
    def is_threat_relevant(text: str) -> bool:
        """Triage gate: keep only articles matching the cyber keyword lattice."""
        lowered: str = text.lower()
        return any(keyword in lowered for keyword in TRIAGE_KEYWORDS)

    def build_item(self, publication: str, raw: Dict[str, str]) -> IntelligenceItem:
        """Normalize one triaged article into a news artifact."""
        combined_text: str = f"{raw['title']} {raw['description']}"
        tactics: Tuple[str, ...] = detect_tactics(combined_text)
        return IntelligenceItem(
            stream_type="news_article",
            source=publication,
            url=raw["link"],
            title=raw["title"],
            content=raw["description"] or raw["title"],
            author=publication,
            date_published=_rfc822_to_iso(raw["pub_date"]),
            threat_category=tactics[0] if tactics else "general_cyber",
            tactic_tags=tactics,
        )

    async def parse_publication(
        self, client: httpx.AsyncClient, publication: str, feeds: Tuple[str, ...]
    ) -> List[IntelligenceItem]:
        """Fetch, parse, and triage every feed for a single publication."""
        items: List[IntelligenceItem] = []
        for feed_url in feeds:
            xml_text: Optional[str] = await fetch_feed_text(
                client, feed_url, publication
            )
            if xml_text is None:
                continue
            raw_items: List[Dict[str, str]] = parse_rss_items(xml_text, publication)
            triaged: List[IntelligenceItem] = [
                self.build_item(publication, raw)
                for raw in raw_items
                if raw["title"] and self.is_threat_relevant(
                    f"{raw['title']} {raw['description']}"
                )
            ]
            LOGGER.info(
                "%s: %d/%d articles passed triage from %s",
                publication, len(triaged), len(raw_items), feed_url,
            )
            items.extend(triaged)
        return items

    async def collect(self, client: httpx.AsyncClient) -> List[IntelligenceItem]:
        """Run every publication stream concurrently."""
        batches: List[List[IntelligenceItem]] = await asyncio.gather(
            *(
                self.parse_publication(client, publication, feeds)
                for publication, feeds in self.registry.items()
            )
        )
        return [item for batch in batches for item in batch]


# --------------------------------------------------------------------------- #
# Unified asynchronous stream buffer.                                         #
# --------------------------------------------------------------------------- #


class UnifiedIntelligenceStream:
    """Compiles both ingestion pipelines into one async stream buffer."""

    def __init__(self) -> None:
        self.expert_parser: ExpertFeedParser = ExpertFeedParser()
        self.news_engine: NewsTriageEngine = NewsTriageEngine()

    async def stream(self) -> AsyncGenerator[IntelligenceItem, None]:
        """Yield items from both pipelines through a single queue buffer."""
        buffer: asyncio.Queue = asyncio.Queue()

        async def _pump_pipeline(collector_name: str, client: httpx.AsyncClient) -> None:
            """Drain one pipeline into the shared buffer as items arrive."""
            items: List[IntelligenceItem]
            if collector_name == "expert":
                items = await self.expert_parser.collect(client)
            else:
                items = await self.news_engine.collect(client)
            for item in items:
                await buffer.put(item)

        timeout: httpx.Timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            pumps: List[asyncio.Task] = [
                asyncio.create_task(_pump_pipeline("expert", client)),
                asyncio.create_task(_pump_pipeline("news", client)),
            ]

            async def _finalize() -> None:
                """Signal end-of-stream once every pump has drained."""
                await asyncio.gather(*pumps)
                await buffer.put(None)

            finalizer: asyncio.Task = asyncio.create_task(_finalize())
            while True:
                item: Optional[IntelligenceItem] = await buffer.get()
                if item is None:
                    break
                yield item
            await finalizer

    async def run(self) -> List[IntelligenceItem]:
        """Materialize the full unified stream into an ordered list."""
        collected: List[IntelligenceItem] = [item async for item in self.stream()]
        LOGGER.info("Unified stream complete: %d intelligence items", len(collected))
        return collected

    @staticmethod
    async def persist_raw(items: List[IntelligenceItem]) -> Path:
        """Persist a unified stream run to timestamped JSON via aiofiles."""
        RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
        stamp: str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target: Path = RAW_DATA_DIR / f"intel_{stamp}.json"
        payload: str = json.dumps(
            [item.to_record() for item in items], ensure_ascii=False, indent=2
        )
        async with aiofiles.open(target, mode="w", encoding="utf-8") as handle:
            await handle.write(payload)
        LOGGER.info("Persisted %d intelligence items to %s", len(items), target)
        return target


async def run_unified_stream_and_persist() -> Path:
    """Convenience entrypoint: drain both pipelines and persist the buffer."""
    stream: UnifiedIntelligenceStream = UnifiedIntelligenceStream()
    items: List[IntelligenceItem] = await stream.run()
    return await UnifiedIntelligenceStream.persist_raw(items)


if __name__ == "__main__":
    asyncio.run(run_unified_stream_and_persist())
