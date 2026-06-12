"""Cyber Shield India — Government Web Scraper Matrix (STATUS.md Step 1.4).

Fully asynchronous, user-agent rotating extraction modules covering the
eleven intelligence targets defined in the project ledger:

 1. MHA Cyberdost / NCRP        — trending alert feeds & public threat advisories
 2. DoT Sanchar Saathi (TAFCOP) — bulk connections disconnected for fraud
 3. DoT Sanchar Saathi (CEIR)   — device/IMEI blacklists
 4. TRAI                        — SMS spoofing registry & UCC header monitoring
 5. NPCI                        — payment rail circulars & UPI/AePS vulnerability reports
 6. RBI Cyber Cell              — circulars & digital lending app blocklists
 7. NCIIPC                      — cross-sector infrastructure protection sheets
 8. UIDAI                       — Aadhaar biometric locking parameters
 9. IT Act (IndiaCode)          — Sections 66A/C/D statutory text
10. DPDP Act (MeitY)            — Digital Personal Data Protection statutory text
11. State Cyber Bureaus         — TCSB, Maharashtra Cyber, Karnataka CEN,
                                  Haryana & Delhi Police bulletins

All network traffic flows through a shared ``httpx.AsyncClient``; raw payload
persistence uses ``aiofiles``. Government portals periodically restructure —
every endpoint URL lives in the ``*_ENDPOINTS`` constants below so retargeting
is a one-line change, and every parser degrades to a resilient anchor/paragraph
harvest when its primary selectors stop matching.
"""

import asyncio
import json
import logging
import random
import re
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import ClassVar, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiofiles
import httpx
from bs4 import BeautifulSoup
from bs4.element import Tag

# --------------------------------------------------------------------------- #
# Forensic logging — structured daily-rotating logs per CLAUDE.md mandate.    #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"
RAW_DATA_DIR: Path = PROJECT_ROOT / "data" / "raw"


def _build_logger() -> logging.Logger:
    """Construct the scraper logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.scraper")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "scraper.log",
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
# Network configuration.                                                      #
# --------------------------------------------------------------------------- #

USER_AGENT_POOL: Tuple[str, ...] = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) "
    "Gecko/20100101 Firefox/138.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) "
    "Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0",
)

REQUEST_TIMEOUT_SECONDS: float = 30.0
MAX_RETRIES: int = 3
RETRY_BACKOFF_SECONDS: float = 2.0
CONCURRENCY_LIMIT: int = 6

# --------------------------------------------------------------------------- #
# Date extraction helpers.                                                    #
# --------------------------------------------------------------------------- #

_MONTHS: str = (
    "January|February|March|April|May|June|July|August|"
    "September|October|November|December"
)

_DATE_PATTERNS: Tuple[Tuple[re.Pattern, str], ...] = (
    (re.compile(r"\b(\d{2}/\d{2}/\d{4})\b"), "%d/%m/%Y"),
    (re.compile(r"\b(\d{2}-\d{2}-\d{4})\b"), "%d-%m-%Y"),
    (re.compile(r"\b(\d{4}-\d{2}-\d{2})\b"), "%Y-%m-%d"),
    (re.compile(rf"\b(\d{{1,2}}\s+(?:{_MONTHS})\s+\d{{4}})\b", re.IGNORECASE), "%d %B %Y"),
    (re.compile(rf"\b((?:{_MONTHS})\s+\d{{1,2}},\s+\d{{4}})\b", re.IGNORECASE), "%B %d, %Y"),
)


def extract_first_date(text: str) -> Optional[str]:
    """Return the first recognizable date in ``text`` as ISO-8601, else None."""
    for pattern, fmt in _DATE_PATTERNS:
        match: Optional[re.Match] = pattern.search(text)
        if match is None:
            continue
        try:
            parsed: datetime = datetime.strptime(match.group(1).title(), fmt)
        except ValueError:
            continue
        return parsed.date().isoformat()
    return None


def clean_text(raw: str) -> str:
    """Collapse all whitespace runs into single spaces and strip the result."""
    return re.sub(r"\s+", " ", raw).strip()


# --------------------------------------------------------------------------- #
# Canonical scraped-document container (metadata mirrors the Phase 2.1        #
# ChromaDB indexing parameters: source, url, date_published, jurisdiction,    #
# threat_category).                                                           #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ScrapedDocument:
    """One normalized intelligence artifact emitted by a scraper module."""

    source: str
    url: str
    title: str
    content: str
    date_published: Optional[str]
    jurisdiction: str
    threat_category: str

    def to_record(self) -> Dict[str, Optional[str]]:
        """Serialize into a flat, JSON-safe dictionary."""
        return asdict(self)


# --------------------------------------------------------------------------- #
# Abstract scraper base.                                                      #
# --------------------------------------------------------------------------- #


class BaseScraper(ABC):
    """Shared async fetch loop with UA rotation, retries, and fallbacks."""

    source: ClassVar[str]
    jurisdiction: ClassVar[str]
    threat_category: ClassVar[str]
    endpoints: ClassVar[Tuple[str, ...]]

    @staticmethod
    def rotate_user_agent() -> Dict[str, str]:
        """Return request headers carrying a freshly rotated user agent."""
        return {
            "User-Agent": random.choice(USER_AGENT_POOL),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-IN,en;q=0.9,hi;q=0.8",
        }

    async def fetch(self, client: httpx.AsyncClient, url: str) -> Optional[str]:
        """GET ``url`` with rotating user agents and bounded exponential retry."""
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response: httpx.Response = await client.get(
                    url, headers=self.rotate_user_agent()
                )
                response.raise_for_status()
                return response.text
            except httpx.TimeoutException:
                LOGGER.warning(
                    "%s: timeout on %s (attempt %d/%d)",
                    self.source, url, attempt, MAX_RETRIES,
                )
            except httpx.HTTPStatusError as status_error:
                LOGGER.warning(
                    "%s: HTTP %d on %s (attempt %d/%d)",
                    self.source,
                    status_error.response.status_code,
                    url, attempt, MAX_RETRIES,
                )
            except httpx.RequestError:
                LOGGER.exception(
                    "%s: transport failure on %s (attempt %d/%d)",
                    self.source, url, attempt, MAX_RETRIES,
                )
            await asyncio.sleep(RETRY_BACKOFF_SECONDS * attempt)
        LOGGER.error("%s: exhausted retries for %s", self.source, url)
        return None

    @abstractmethod
    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        """Transform one raw HTML payload into normalized documents."""

    async def scrape(self, client: httpx.AsyncClient) -> List[ScrapedDocument]:
        """Fetch and parse every configured endpoint for this module."""
        documents: List[ScrapedDocument] = []
        for endpoint in self.endpoints:
            html: Optional[str] = await self.fetch(client, endpoint)
            if html is None:
                continue
            parsed: List[ScrapedDocument] = self.parse(html, endpoint)
            LOGGER.info("%s: extracted %d documents from %s",
                        self.source, len(parsed), endpoint)
            documents.extend(parsed)
        return documents

    # -- shared parsing utilities ------------------------------------------ #

    def make_document(
        self,
        url: str,
        title: str,
        content: str,
        date_published: Optional[str] = None,
        jurisdiction: Optional[str] = None,
    ) -> ScrapedDocument:
        """Build a ``ScrapedDocument`` stamped with this module's identity."""
        return ScrapedDocument(
            source=self.source,
            url=url,
            title=clean_text(title)[:300],
            content=clean_text(content),
            date_published=date_published or extract_first_date(content),
            jurisdiction=jurisdiction or self.jurisdiction,
            threat_category=self.threat_category,
        )

    def harvest_fallback(self, soup: BeautifulSoup, base_url: str) -> List[ScrapedDocument]:
        """Resilient harvest of substantive anchors when selectors go stale."""
        documents: List[ScrapedDocument] = []
        seen: set = set()
        for anchor in soup.select("a[href]"):
            text: str = clean_text(anchor.get_text())
            href: str = urljoin(base_url, str(anchor.get("href", "")))
            if len(text) < 30 or href in seen or href.startswith("javascript"):
                continue
            seen.add(href)
            documents.append(self.make_document(url=href, title=text, content=text))
        return documents


# --------------------------------------------------------------------------- #
# 1. MHA Cyberdost / National Cybercrime Reporting Portal.                    #
# --------------------------------------------------------------------------- #


class CyberdostScraper(BaseScraper):
    """Polls MHA Cyberdost / NCRP trending alerts and public advisories."""

    source: ClassVar[str] = "MHA Cyberdost"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "national_advisory"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://cybercrime.gov.in/Webform/CrimeCatDes.aspx",
        "https://cybercrime.gov.in/Webform/cyber_suraksha.aspx",
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        # Live alert tickers and advisory cards used on the NCRP portal.
        for node in soup.select("marquee, .news-ticker li, .alert, .card-body, .panel-body"):
            text: str = clean_text(node.get_text())
            if len(text) < 40:
                continue
            documents.append(self.make_document(
                url=url, title=text[:120], content=text,
            ))
        for heading in soup.select("h2, h3, h4"):
            sibling_text: str = clean_text(
                " ".join(p.get_text() for p in heading.find_all_next("p", limit=3))
            )
            if len(sibling_text) < 60:
                continue
            documents.append(self.make_document(
                url=url, title=heading.get_text(), content=sibling_text,
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 2. DoT Sanchar Saathi — TAFCOP (fraud disconnections).                      #
# --------------------------------------------------------------------------- #


class TafcopScraper(BaseScraper):
    """Captures bulk fraud-disconnection metrics from the TAFCOP module."""

    source: ClassVar[str] = "DoT Sanchar Saathi (TAFCOP)"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "telecom_fraud"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://sancharsaathi.gov.in/sfc/",
        "https://tafcop.sancharsaathi.gov.in/telecomUser/",
    )

    _METRIC_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"([\d,]{4,})\s+(?:mobile\s+)?(connections?|subscribers?|SIMs?)\s+"
        r"(disconnected|flagged|reported|blocked)",
        re.IGNORECASE,
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        page_text: str = clean_text(soup.get_text(" "))
        for match in self._METRIC_PATTERN.finditer(page_text):
            statement: str = clean_text(match.group(0))
            documents.append(self.make_document(
                url=url,
                title=f"TAFCOP metric: {statement}",
                content=statement,
            ))
        # Dashboard counter widgets and statistics tables.
        for node in soup.select(".counter, .count-box, .stat-card, table tr"):
            text: str = clean_text(node.get_text(" "))
            if len(text) < 25 or not re.search(r"\d", text):
                continue
            documents.append(self.make_document(
                url=url, title=text[:120], content=text,
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 3. DoT Sanchar Saathi — CEIR (IMEI blacklists).                             #
# --------------------------------------------------------------------------- #


class CeirScraper(BaseScraper):
    """Tracks stolen/blocked device and IMEI blacklist statistics via CEIR."""

    source: ClassVar[str] = "DoT Sanchar Saathi (CEIR)"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "device_blacklist"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://www.ceir.gov.in/Home/index.jsp",
        "https://sancharsaathi.gov.in/Home/index.jsp",
    )

    _DEVICE_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"([\d,]{4,})\s+(?:devices?|mobiles?|handsets?|IMEIs?)\s+"
        r"(blocked|traced|recovered|blacklisted)",
        re.IGNORECASE,
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        page_text: str = clean_text(soup.get_text(" "))
        for match in self._DEVICE_PATTERN.finditer(page_text):
            statement: str = clean_text(match.group(0))
            documents.append(self.make_document(
                url=url,
                title=f"CEIR blacklist metric: {statement}",
                content=statement,
            ))
        for node in soup.select(".counter, .count, .figure, .stats, table tr"):
            text: str = clean_text(node.get_text(" "))
            if len(text) < 20 or not re.search(r"\d", text):
                continue
            documents.append(self.make_document(
                url=url, title=text[:120], content=text,
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 4. TRAI — UCC headers & SMS spoofing registry.                              #
# --------------------------------------------------------------------------- #


class TraiScraper(BaseScraper):
    """Monitors TRAI releases on UCC headers and SMS spoofing definitions."""

    source: ClassVar[str] = "TRAI"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "sms_spoofing"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://www.trai.gov.in/release-publication/press-release",
        "https://www.trai.gov.in/notifications",
    )

    _UCC_KEYWORDS: ClassVar[Tuple[str, ...]] = (
        "ucc", "unsolicited", "spam", "header", "spoof", "tcccpr",
        "telemarketer", "sms", "fraud",
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        # TRAI runs Drupal: releases appear as view rows / table listings.
        for row in soup.select(".view-content .views-row, table tbody tr"):
            anchor: Optional[Tag] = row.find("a", href=True)
            if anchor is None:
                continue
            title: str = clean_text(anchor.get_text())
            row_text: str = clean_text(row.get_text(" "))
            if not any(keyword in row_text.lower() for keyword in self._UCC_KEYWORDS):
                continue
            documents.append(self.make_document(
                url=urljoin(url, str(anchor["href"])),
                title=title,
                content=row_text,
                date_published=extract_first_date(row_text),
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 5. NPCI — payment rail circulars & UPI/AePS vulnerability reports.          #
# --------------------------------------------------------------------------- #


class NpciScraper(BaseScraper):
    """Targets NPCI circulars covering UPI/AePS rails and fraud controls."""

    source: ClassVar[str] = "NPCI"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "payment_fraud"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://www.npci.org.in/what-we-do/upi/circular",
        "https://www.npci.org.in/what-we-do/aeps/circulars",
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        # NPCI circulars surface as PDF anchors inside listing tables/cards.
        for anchor in soup.select("a[href$='.pdf'], a[href*='circular' i]"):
            title: str = clean_text(anchor.get_text())
            if len(title) < 15:
                continue
            container: Optional[Tag] = anchor.find_parent(("tr", "li", "div"))
            context: str = clean_text(container.get_text(" ")) if container else title
            documents.append(self.make_document(
                url=urljoin(url, str(anchor["href"])),
                title=title,
                content=context,
                date_published=extract_first_date(context),
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 6. RBI Cyber Cell — circulars & digital lending blocklists.                 #
# --------------------------------------------------------------------------- #


class RbiScraper(BaseScraper):
    """Pulls RBI notifications, fraud circulars, and lending-app advisories."""

    source: ClassVar[str] = "RBI Cyber Cell"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "payment_fraud"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://www.rbi.org.in/Scripts/NotificationUser.aspx",
        "https://www.rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx",
    )

    _CYBER_KEYWORDS: ClassVar[Tuple[str, ...]] = (
        "fraud", "cyber", "digital lending", "phishing", "upi", "card",
        "mule", "kyc", "security", "unauthorised", "unauthorized",
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        # RBI listing pages use dense link tables (.link2 anchors / tablebg).
        for anchor in soup.select("a.link2[href], table a[href]"):
            title: str = clean_text(anchor.get_text())
            if len(title) < 20:
                continue
            if not any(keyword in title.lower() for keyword in self._CYBER_KEYWORDS):
                continue
            container: Optional[Tag] = anchor.find_parent("tr")
            context: str = clean_text(container.get_text(" ")) if container else title
            documents.append(self.make_document(
                url=urljoin(url, str(anchor["href"])),
                title=title,
                content=context,
                date_published=extract_first_date(context),
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 7. NCIIPC — critical infrastructure protection sheets.                      #
# --------------------------------------------------------------------------- #


class NciipcScraper(BaseScraper):
    """Parses NCIIPC advisories, newsletters, and CII protection sheets."""

    source: ClassVar[str] = "NCIIPC"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "critical_infrastructure"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://nciipc.gov.in/index.html",
        "https://nciipc.gov.in/NCIIPC_Newsletter.html",
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        for anchor in soup.select(
            "a[href$='.pdf'], a[href*='advisor' i], a[href*='newsletter' i]"
        ):
            title: str = clean_text(anchor.get_text()) or str(anchor.get("href", ""))
            if len(title) < 10:
                continue
            container: Optional[Tag] = anchor.find_parent(("li", "tr", "div"))
            context: str = clean_text(container.get_text(" ")) if container else title
            documents.append(self.make_document(
                url=urljoin(url, str(anchor["href"])),
                title=title,
                content=context,
                date_published=extract_first_date(context),
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 8. UIDAI — Aadhaar biometric locking parameters.                            #
# --------------------------------------------------------------------------- #


class UidaiScraper(BaseScraper):
    """Extracts Aadhaar biometric locking guidance and security parameters."""

    source: ClassVar[str] = "UIDAI"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "identity_security"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://uidai.gov.in/en/my-aadhaar/aadhaar-services.html",
        "https://uidai.gov.in/en/contact-support/have-any-question/308-faqs/aadhaar-online-services/biometric-lock-unlock.html",
    )

    _BIOMETRIC_KEYWORDS: ClassVar[Tuple[str, ...]] = (
        "biometric", "lock", "unlock", "vid", "virtual id", "authentication",
        "fingerprint", "iris", "aadhaar number",
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        for node in soup.select("p, li, .accordion-body, .faq-answer"):
            text: str = clean_text(node.get_text(" "))
            if len(text) < 60:
                continue
            if not any(keyword in text.lower() for keyword in self._BIOMETRIC_KEYWORDS):
                continue
            documents.append(self.make_document(
                url=url, title=text[:120], content=text,
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 9. IT Act statutory text (IndiaCode) — Sections 66A/C/D focus.              #
# --------------------------------------------------------------------------- #


class ItActScraper(BaseScraper):
    """Loads IT Act, 2000 text with focus on Sections 66A/66C/66D."""

    source: ClassVar[str] = "IT Act 2000 (IndiaCode)"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "legal_statute"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://www.indiacode.nic.in/handle/123456789/1999",
        "https://www.meity.gov.in/content/information-technology-act-2000",
    )

    _SECTION_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"\b(?:section\s+)?66\s*[ACD]?\b", re.IGNORECASE
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        for node in soup.select("p, li, td, .artifact-description, .item-page"):
            text: str = clean_text(node.get_text(" "))
            if len(text) < 50:
                continue
            if not self._SECTION_PATTERN.search(text) and "information technology" not in text.lower():
                continue
            documents.append(self.make_document(
                url=url, title=f"IT Act provision: {text[:100]}", content=text,
            ))
        # Statute PDFs hosted alongside the handle pages.
        for anchor in soup.select("a[href$='.pdf']"):
            title: str = clean_text(anchor.get_text()) or "IT Act statutory PDF"
            documents.append(self.make_document(
                url=urljoin(url, str(anchor["href"])), title=title, content=title,
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 10. DPDP Act statutory text (MeitY).                                        #
# --------------------------------------------------------------------------- #


class DpdpActScraper(BaseScraper):
    """Loads Digital Personal Data Protection Act text and framework pages."""

    source: ClassVar[str] = "DPDP Act 2023 (MeitY)"
    jurisdiction: ClassVar[str] = "National"
    threat_category: ClassVar[str] = "legal_statute"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://www.meity.gov.in/data-protection-framework",
        "https://www.meity.gov.in/content/digital-personal-data-protection-act-2023",
    )

    _DPDP_KEYWORDS: ClassVar[Tuple[str, ...]] = (
        "personal data", "data fiduciary", "data principal", "consent",
        "dpdp", "data protection", "breach", "penalty",
    )

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        documents: List[ScrapedDocument] = []
        for node in soup.select("p, li, .view-content .views-row, .field-content"):
            text: str = clean_text(node.get_text(" "))
            if len(text) < 60:
                continue
            if not any(keyword in text.lower() for keyword in self._DPDP_KEYWORDS):
                continue
            documents.append(self.make_document(
                url=url, title=f"DPDP provision: {text[:100]}", content=text,
            ))
        for anchor in soup.select("a[href$='.pdf']"):
            title: str = clean_text(anchor.get_text()) or "DPDP Act statutory PDF"
            documents.append(self.make_document(
                url=urljoin(url, str(anchor["href"])), title=title, content=title,
            ))
        return documents or self.harvest_fallback(soup, url)


# --------------------------------------------------------------------------- #
# 11. State Cyber Bureaus — TCSB, Maharashtra, Karnataka, Haryana, Delhi.     #
# --------------------------------------------------------------------------- #


class StateCyberBureauScraper(BaseScraper):
    """Ingests bulletins from the priority state cybercrime bureaus."""

    source: ClassVar[str] = "State Cyber Bureaus"
    jurisdiction: ClassVar[str] = "State"
    threat_category: ClassVar[str] = "regional_bulletin"
    endpoints: ClassVar[Tuple[str, ...]] = (
        "https://www.cyberabadpolice.gov.in/cyber-crimes.html",   # Telangana CSB
        "https://www.mahacyber1930.in/",                          # Maharashtra Cyber
        "https://ksp.karnataka.gov.in/page/Cyber+Crime/en",       # Karnataka CEN
        "https://haryanapolice.gov.in/login/cyber-crime",         # Haryana Police
        "https://www.delhipolice.gov.in/cybercrime",              # Delhi Police
    )

    _DOMAIN_JURISDICTION: ClassVar[Dict[str, str]] = {
        "cyberabadpolice.gov.in": "Telangana",
        "mahacyber1930.in": "Maharashtra",
        "ksp.karnataka.gov.in": "Karnataka",
        "haryanapolice.gov.in": "Haryana",
        "delhipolice.gov.in": "Delhi",
    }

    def _jurisdiction_for(self, url: str) -> str:
        """Map an endpoint URL onto its issuing state jurisdiction."""
        host: str = urlparse(url).netloc.lower()
        for domain, state in self._DOMAIN_JURISDICTION.items():
            if domain in host:
                return state
        return self.jurisdiction

    def parse(self, html: str, url: str) -> List[ScrapedDocument]:
        soup: BeautifulSoup = BeautifulSoup(html, "html.parser")
        state: str = self._jurisdiction_for(url)
        documents: List[ScrapedDocument] = []
        # Bulletin/news widgets common across state police portals.
        for node in soup.select(
            ".news li, .latest-news li, .notice li, .marquee, marquee, "
            ".press-release, .bulletin, .card-body, article"
        ):
            text: str = clean_text(node.get_text(" "))
            if len(text) < 40:
                continue
            anchor: Optional[Tag] = node.find("a", href=True) if isinstance(node, Tag) else None
            link: str = urljoin(url, str(anchor["href"])) if anchor else url
            documents.append(self.make_document(
                url=link,
                title=text[:120],
                content=text,
                jurisdiction=state,
            ))
        if documents:
            return documents
        fallback: List[ScrapedDocument] = self.harvest_fallback(soup, url)
        return [
            ScrapedDocument(
                source=doc.source,
                url=doc.url,
                title=doc.title,
                content=doc.content,
                date_published=doc.date_published,
                jurisdiction=state,
                threat_category=doc.threat_category,
            )
            for doc in fallback
        ]


# --------------------------------------------------------------------------- #
# Matrix orchestrator.                                                        #
# --------------------------------------------------------------------------- #


class ScraperMatrix:
    """Runs every registered scraper concurrently over one shared client."""

    def __init__(self) -> None:
        self.scrapers: List[BaseScraper] = [
            CyberdostScraper(),
            TafcopScraper(),
            CeirScraper(),
            TraiScraper(),
            NpciScraper(),
            RbiScraper(),
            NciipcScraper(),
            UidaiScraper(),
            ItActScraper(),
            DpdpActScraper(),
            StateCyberBureauScraper(),
        ]
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def _run_one(
        self, client: httpx.AsyncClient, scraper: BaseScraper
    ) -> List[ScrapedDocument]:
        """Execute a single scraper under the global concurrency gate."""
        async with self._semaphore:
            return await scraper.scrape(client)

    async def run_full_matrix(self) -> List[ScrapedDocument]:
        """Execute all eleven modules concurrently and merge their output."""
        timeout: httpx.Timeout = httpx.Timeout(REQUEST_TIMEOUT_SECONDS)
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True, http2=False
        ) as client:
            batches: List[List[ScrapedDocument]] = await asyncio.gather(
                *(self._run_one(client, scraper) for scraper in self.scrapers)
            )
        merged: List[ScrapedDocument] = [doc for batch in batches for doc in batch]
        LOGGER.info("Matrix run complete: %d documents across %d modules",
                    len(merged), len(self.scrapers))
        return merged

    @staticmethod
    async def persist_raw(documents: List[ScrapedDocument]) -> Path:
        """Persist a matrix run to timestamped JSON via aiofiles."""
        RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
        stamp: str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target: Path = RAW_DATA_DIR / f"scrape_{stamp}.json"
        payload: str = json.dumps(
            [doc.to_record() for doc in documents], ensure_ascii=False, indent=2
        )
        async with aiofiles.open(target, mode="w", encoding="utf-8") as handle:
            await handle.write(payload)
        LOGGER.info("Persisted %d raw documents to %s", len(documents), target)
        return target


async def run_matrix_and_persist() -> Path:
    """Convenience entrypoint: run the full matrix and persist the output."""
    matrix: ScraperMatrix = ScraperMatrix()
    documents: List[ScrapedDocument] = await matrix.run_full_matrix()
    return await ScraperMatrix.persist_raw(documents)


if __name__ == "__main__":
    asyncio.run(run_matrix_and_persist())
