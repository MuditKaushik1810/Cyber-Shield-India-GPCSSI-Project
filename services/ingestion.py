"""Cyber Shield India — Document Extraction Pipeline (STATUS.md Step 1.7).

Continuous data-streaming parsers that segment dense government handbooks,
agency advisories, and scraped intelligence into clean, vector-ready chunk
arrays using LangChain's ``RecursiveCharacterTextSplitter`` locked to an
exact **800-token chunk size with a 100-token overlap matrix**, splitting
along smart boundaries (paragraphs → lines → spaces → characters).

Includes a dedicated **CERT-In normalization layer** purpose-built for
Indian Computer Emergency Response Team Vulnerability Notes (CIVN) and
Security Advisories (CIAD): it strips administrative headers and footers,
extracts CVE identifiers and severity ratings, detects targeted platforms
(e.g., Android OS flaws weaponized in sideloaded APK campaigns), and emits
clean text payloads before chunking.

Every emitted chunk carries an explicit metadata dictionary matching the
Phase 2.1 ChromaDB indexing parameters: ``source``, ``url``,
``date_published``, ``jurisdiction``, ``threat_category``.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import aiofiles
from langchain_text_splitters import RecursiveCharacterTextSplitter

from utils.scraper import RAW_DATA_DIR, ScrapedDocument, clean_text, extract_first_date

# --------------------------------------------------------------------------- #
# Forensic logging — dedicated daily-rotating channel: logs/ingestion.log.    #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"
PROCESSED_DATA_DIR: Path = PROJECT_ROOT / "data" / "processed"


def _build_logger() -> logging.Logger:
    """Construct the ingestion logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.ingestion")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "ingestion.log",
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
# Splitter configuration — exact 800-token size / 100-token overlap matrix.   #
# --------------------------------------------------------------------------- #

CHUNK_SIZE_TOKENS: int = 800
CHUNK_OVERLAP_TOKENS: int = 100

# Smart boundary cascade: paragraphs first, then lines, then spaces, then
# raw characters as the unconditional last resort.
SPLIT_SEPARATORS: List[str] = ["\n\n", "\n", " ", ""]

_TOKEN_PATTERN: re.Pattern = re.compile(r"\S+")


def count_tokens(text: str) -> int:
    """Whitespace-delimited token counter driving the splitter's sizing."""
    return len(_TOKEN_PATTERN.findall(text))


# --------------------------------------------------------------------------- #
# Chunk container.                                                            #
# --------------------------------------------------------------------------- #

MetadataValue = Union[str, int, None]


@dataclass(frozen=True)
class DocumentChunk:
    """One vector-ready text segment plus its Phase 2.1 metadata payload."""

    chunk_id: str
    text: str
    metadata: Dict[str, MetadataValue]

    def to_record(self) -> Dict[str, object]:
        """Serialize into a flat, JSON-safe dictionary."""
        return {"chunk_id": self.chunk_id, "text": self.text, "metadata": self.metadata}


# --------------------------------------------------------------------------- #
# CERT-In normalization layer.                                                #
# --------------------------------------------------------------------------- #

CVE_PATTERN: re.Pattern = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

ADVISORY_ID_PATTERN: re.Pattern = re.compile(
    r"\b(CI(?:VN|AD)-\d{4}-\d{2,5})\b", re.IGNORECASE
)

SEVERITY_PATTERN: re.Pattern = re.compile(
    r"severity\s+rating\s*:?\s*(critical|high|medium|low)", re.IGNORECASE
)

# Administrative boilerplate lines stripped before chunking. Matched per-line.
ADMIN_LINE_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"^\s*indian\s+computer\s+emergency\s+response\s+team\b.*$", re.IGNORECASE),
    re.compile(r"^\s*cert-in\s+(?:vulnerability\s+note|security\s+advisory)\b.*$", re.IGNORECASE),
    re.compile(r"^\s*(?:note|advisory)\s+no\.?\s*[:.]?\s*\S*\s*$", re.IGNORECASE),
    re.compile(r"^\s*original\s+issue\s+date\s*:.*$", re.IGNORECASE),
    re.compile(r"^\s*updated\s+on\s*:.*$", re.IGNORECASE),
    re.compile(r"^\s*severity\s+rating\s*:.*$", re.IGNORECASE),
    re.compile(r"^\s*ministry\s+of\s+electronics.*$", re.IGNORECASE),
    re.compile(r"^\s*government\s+of\s+india\s*$", re.IGNORECASE),
    re.compile(r"^\s*page\s+\d+\s+of\s+\d+\s*$", re.IGNORECASE),
    re.compile(r"^\s*disclaimer\s*:?.*$", re.IGNORECASE),
    re.compile(r"^\s*(?:e-?mail|phone|fax|postal\s+address)\s*:.*$", re.IGNORECASE),
    re.compile(r"^\s*www\.cert-in\.org\.in\s*$", re.IGNORECASE),
    re.compile(r"^\s*[-=_*]{4,}\s*$"),
)

# Target-platform detection lattice for vulnerability classification.
PLATFORM_PATTERNS: Dict[str, re.Pattern] = {
    "android": re.compile(r"\bandroid\b|\bapk\b|google\s+play", re.IGNORECASE),
    "ios": re.compile(r"\bios\b|\biphone\b|\bipad\b", re.IGNORECASE),
    "windows": re.compile(r"\bwindows\b|\bmicrosoft\s+(?:office|exchange|edge)\b", re.IGNORECASE),
    "linux": re.compile(r"\blinux\b|\bubuntu\b|\bred\s+hat\b|\bkernel\b", re.IGNORECASE),
    "browser": re.compile(r"\bchrome\b|\bfirefox\b|\bsafari\b|\bbrowser\b", re.IGNORECASE),
    "network_device": re.compile(r"\brouter\b|\bfirewall\b|\bcisco\b|\bvpn\b|\bswitch\b", re.IGNORECASE),
}


@dataclass(frozen=True)
class CertInAdvisory:
    """A normalized CERT-In Vulnerability Note / Security Advisory."""

    advisory_id: Optional[str]
    title: str
    severity: Optional[str]
    cve_ids: Tuple[str, ...]
    affected_platforms: Tuple[str, ...]
    clean_body: str
    date_published: Optional[str]


class CertInNormalizer:
    """Cleans and structures raw CERT-In advisory text before chunking."""

    @staticmethod
    def strip_admin_lines(raw: str) -> str:
        """Remove administrative headers, footers, and boilerplate lines."""
        kept: List[str] = []
        for line in raw.splitlines():
            if any(pattern.match(line) for pattern in ADMIN_LINE_PATTERNS):
                continue
            kept.append(line)
        return "\n".join(kept)

    @staticmethod
    def extract_cve_ids(raw: str) -> Tuple[str, ...]:
        """Return all distinct CVE identifiers, upper-cased, in first-seen order."""
        seen: List[str] = []
        for match in CVE_PATTERN.finditer(raw):
            cve: str = match.group(0).upper()
            if cve not in seen:
                seen.append(cve)
        return tuple(seen)

    @staticmethod
    def detect_platforms(raw: str) -> Tuple[str, ...]:
        """Return every targeted platform whose signature pattern fires."""
        return tuple(
            platform for platform, pattern in PLATFORM_PATTERNS.items()
            if pattern.search(raw)
        )

    @staticmethod
    def extract_title(raw: str) -> str:
        """Derive the advisory title from the first substantive body line."""
        for line in raw.splitlines():
            candidate: str = clean_text(line)
            if len(candidate) >= 20:
                return candidate[:200]
        return "Untitled CERT-In Advisory"

    def normalize(self, raw_text: str) -> CertInAdvisory:
        """Run the full normalization pass over one raw advisory payload."""
        advisory_match: Optional[re.Match] = ADVISORY_ID_PATTERN.search(raw_text)
        severity_match: Optional[re.Match] = SEVERITY_PATTERN.search(raw_text)
        body: str = self.strip_admin_lines(raw_text)
        # Collapse intra-line whitespace but preserve paragraph boundaries
        # so the splitter's smart-boundary cascade stays effective.
        paragraphs: List[str] = [
            clean_text(block) for block in re.split(r"\n\s*\n", body)
        ]
        clean_body: str = "\n\n".join(p for p in paragraphs if p)
        advisory: CertInAdvisory = CertInAdvisory(
            advisory_id=advisory_match.group(1).upper() if advisory_match else None,
            title=self.extract_title(body),
            severity=severity_match.group(1).upper() if severity_match else None,
            cve_ids=self.extract_cve_ids(raw_text),
            affected_platforms=self.detect_platforms(raw_text),
            clean_body=clean_body,
            date_published=extract_first_date(raw_text),
        )
        LOGGER.info(
            "CERT-In normalization: id=%s severity=%s cves=%d platforms=%s",
            advisory.advisory_id, advisory.severity,
            len(advisory.cve_ids), ",".join(advisory.affected_platforms) or "-",
        )
        return advisory

    @staticmethod
    def threat_category(advisory: CertInAdvisory) -> str:
        """Map detected platforms onto the grid's threat-category taxonomy."""
        if "android" in advisory.affected_platforms:
            return "mobile_os_vulnerability"
        if "network_device" in advisory.affected_platforms:
            return "critical_infrastructure"
        if advisory.affected_platforms:
            return "software_vulnerability"
        return "national_advisory"


# --------------------------------------------------------------------------- #
# Document extraction pipeline.                                               #
# --------------------------------------------------------------------------- #


class DocumentExtractionPipeline:
    """Segments normalized documents into 800/100 vector-ready chunk arrays."""

    def __init__(self) -> None:
        self.splitter: RecursiveCharacterTextSplitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE_TOKENS,
            chunk_overlap=CHUNK_OVERLAP_TOKENS,
            separators=SPLIT_SEPARATORS,
            length_function=count_tokens,
            keep_separator=True,
        )
        self.normalizer: CertInNormalizer = CertInNormalizer()

    def chunk_text(
        self,
        text: str,
        base_metadata: Dict[str, MetadataValue],
        parent_key: str,
    ) -> List[DocumentChunk]:
        """Split one clean text payload and stamp Phase 2.1 metadata."""
        segments: List[str] = self.splitter.split_text(text)
        chunks: List[DocumentChunk] = []
        for index, segment in enumerate(segments):
            metadata: Dict[str, MetadataValue] = dict(base_metadata)
            metadata["chunk_index"] = index
            metadata["chunk_total"] = len(segments)
            chunks.append(DocumentChunk(
                chunk_id=f"{parent_key}::chunk-{index:04d}",
                text=segment.strip(),
                metadata=metadata,
            ))
        LOGGER.info("Chunked '%s' into %d segments", parent_key, len(chunks))
        return chunks

    # -- CERT-In specialized path ------------------------------------------ #

    def process_cert_in_advisory(
        self, raw_text: str, url: str
    ) -> List[DocumentChunk]:
        """Normalize a raw CERT-In advisory and emit metadata-rich chunks."""
        advisory: CertInAdvisory = self.normalizer.normalize(raw_text)
        base_metadata: Dict[str, MetadataValue] = {
            "source": "cert-in",
            "url": url,
            "date_published": advisory.date_published,
            "jurisdiction": "National",
            "threat_category": self.normalizer.threat_category(advisory),
            "title": advisory.title,
            "advisory_id": advisory.advisory_id,
            "severity": advisory.severity,
            "cve_ids": ",".join(advisory.cve_ids),
            "affected_platforms": ",".join(advisory.affected_platforms),
        }
        parent_key: str = advisory.advisory_id or f"cert-in-{abs(hash(url))}"
        return self.chunk_text(advisory.clean_body, base_metadata, parent_key)

    # -- Generic agency path ------------------------------------------------ #

    def process_scraped_document(self, document: ScrapedDocument) -> List[DocumentChunk]:
        """Chunk a generic scraped agency document, preserving its metadata."""
        base_metadata: Dict[str, MetadataValue] = {
            "source": document.source,
            "url": document.url,
            "date_published": document.date_published,
            "jurisdiction": document.jurisdiction,
            "threat_category": document.threat_category,
            "title": document.title,
        }
        parent_key: str = f"{document.source}-{abs(hash(document.url))}"
        return self.chunk_text(document.content, base_metadata, parent_key)

    # -- Asynchronous file ingestion ---------------------------------------- #

    async def ingest_text_file(
        self,
        path: Path,
        url: str,
        cert_in: bool = False,
        fallback_metadata: Optional[Dict[str, MetadataValue]] = None,
    ) -> List[DocumentChunk]:
        """Stream one handbook/advisory file from disk and chunk it."""
        try:
            async with aiofiles.open(path, mode="r", encoding="utf-8") as handle:
                raw_text: str = await handle.read()
        except FileNotFoundError:
            LOGGER.error("Ingestion target missing: %s", path)
            return []
        except (OSError, UnicodeDecodeError):
            LOGGER.exception("Unreadable ingestion target: %s", path)
            return []
        if cert_in:
            return self.process_cert_in_advisory(raw_text, url)
        metadata: Dict[str, MetadataValue] = {
            "source": "government_handbook",
            "url": url,
            "date_published": extract_first_date(raw_text),
            "jurisdiction": "National",
            "threat_category": "national_advisory",
            "title": path.stem,
        }
        if fallback_metadata:
            metadata.update(fallback_metadata)
        return self.chunk_text(raw_text, metadata, path.stem)

    async def ingest_raw_scrape_files(self) -> List[DocumentChunk]:
        """Re-chunk every persisted scraper/feed JSON drop in data/raw."""
        chunks: List[DocumentChunk] = []
        if not RAW_DATA_DIR.exists():
            LOGGER.warning("Raw data directory absent: %s", RAW_DATA_DIR)
            return chunks
        for json_path in sorted(RAW_DATA_DIR.glob("*.json")):
            try:
                async with aiofiles.open(json_path, mode="r", encoding="utf-8") as handle:
                    payload: str = await handle.read()
                records: List[Dict[str, object]] = json.loads(payload)
            except (OSError, UnicodeDecodeError):
                LOGGER.exception("Unreadable raw drop: %s", json_path)
                continue
            except json.JSONDecodeError:
                LOGGER.exception("Corrupt JSON in raw drop: %s", json_path)
                continue
            for record in records:
                document: ScrapedDocument = ScrapedDocument(
                    source=str(record.get("source", "unknown")),
                    url=str(record.get("url", "")),
                    title=str(record.get("title", "")),
                    content=str(record.get("content", "")),
                    date_published=(
                        str(record["date_published"])
                        if record.get("date_published") else None
                    ),
                    jurisdiction=str(record.get("jurisdiction", "National")),
                    threat_category=str(record.get("threat_category", "national_advisory")),
                )
                chunks.extend(self.process_scraped_document(document))
        return chunks

    @staticmethod
    async def persist_chunks(chunks: List[DocumentChunk]) -> Path:
        """Persist a chunk batch to timestamped JSON via aiofiles."""
        PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)
        stamp: str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target: Path = PROCESSED_DATA_DIR / f"chunks_{stamp}.json"
        payload: str = json.dumps(
            [chunk.to_record() for chunk in chunks], ensure_ascii=False, indent=2
        )
        async with aiofiles.open(target, mode="w", encoding="utf-8") as handle:
            await handle.write(payload)
        LOGGER.info("Persisted %d chunks to %s", len(chunks), target)
        return target


# --------------------------------------------------------------------------- #
# Standalone verification harness (temporary — run: python -m services.ingestion)
# Validates the 800/100 split discipline and the metadata generation loop
# against a synthetic CERT-In advisory.                                       #
# --------------------------------------------------------------------------- #

_SYNTHETIC_CERT_IN_ADVISORY: str = (
    "Indian Computer Emergency Response Team\n"
    "CERT-In Vulnerability Note\n"
    "Note No. : CIVN-2026-0142\n"
    "Original Issue Date: 10 June 2026\n"
    "Severity Rating: HIGH\n"
    "----------------------------------------\n"
    "Multiple Vulnerabilities in Android OS Enabling Sideloaded APK Exploits\n"
    "\n"
    "Overview\n"
    "Multiple vulnerabilities have been reported in Android OS versions prior "
    "to the June 2026 security patch level which could allow a remote attacker "
    "to execute arbitrary code, escalate privileges via the accessibility "
    "service, and exfiltrate OTP messages through sideloaded APK packages "
    "distributed over messaging platforms as fake wedding invitations. "
    "These vulnerabilities are tracked as CVE-2026-21443, CVE-2026-21509 and "
    "CVE-2026-21788.\n"
    "\n"
    "Description\n"
    + ("An attacker can craft a malicious APK that abuses the accessibility "
       "API to capture screen contents, intercept one-time passwords, and "
       "initiate unauthorized UPI collect requests without user awareness. "
       "Successful exploitation grants persistence across reboots and evades "
       "uninstallation by masquerading as a system service. ") * 60
    + "\n\n"
    "Solution\n"
    "Apply the June 2026 Android security patch. Disable installation from "
    "unknown sources. Audit accessibility permissions granted to non-system "
    "applications.\n"
    "\n"
    "Disclaimer: The information provided herein is on 'as is' basis.\n"
    "www.cert-in.org.in\n"
    "Page 1 of 1\n"
)


def _run_standalone_verification() -> None:
    """Temporary self-test: 800/100 split discipline + metadata loop."""
    pipeline: DocumentExtractionPipeline = DocumentExtractionPipeline()
    chunks: List[DocumentChunk] = pipeline.process_cert_in_advisory(
        _SYNTHETIC_CERT_IN_ADVISORY,
        url="https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-2026-0142",
    )

    assert len(chunks) >= 2, "synthetic advisory must split into multiple chunks"
    for chunk in chunks:
        token_count: int = count_tokens(chunk.text)
        assert token_count <= CHUNK_SIZE_TOKENS, (
            f"chunk {chunk.chunk_id} exceeds 800 tokens ({token_count})"
        )

    # Overlap matrix: when the splitter subdivides an oversized block, each
    # successor chunk must reopen inside its predecessor's trailing 100-token
    # window. (Overlap is not injected across natural paragraph boundaries,
    # so we assert that subdivided-block pairs exhibit it.)
    def _pair_overlaps(previous_text: str, next_text: str) -> bool:
        previous_window: str = " ".join(
            _TOKEN_PATTERN.findall(previous_text)[-CHUNK_OVERLAP_TOKENS:]
        )
        next_opening: str = " ".join(_TOKEN_PATTERN.findall(next_text)[:10])
        return next_opening in previous_window

    overlapping_pairs: int = sum(
        1 for previous, successor in zip(chunks, chunks[1:])
        if _pair_overlaps(previous.text, successor.text)
    )
    assert overlapping_pairs >= 1, (
        "100-token overlap matrix not detected in any subdivided chunk pair"
    )

    # Metadata generation loop: Phase 2.1 keys plus CERT-In enrichment.
    for index, chunk in enumerate(chunks):
        for key in ("source", "url", "date_published", "jurisdiction", "threat_category"):
            assert key in chunk.metadata, f"missing Phase 2.1 key: {key}"
        assert chunk.metadata["source"] == "cert-in"
        assert chunk.metadata["jurisdiction"] == "National"
        assert chunk.metadata["chunk_index"] == index

    head: DocumentChunk = chunks[0]
    assert head.metadata["advisory_id"] == "CIVN-2026-0142"
    assert head.metadata["severity"] == "HIGH"
    assert head.metadata["date_published"] == "2026-06-10"
    assert head.metadata["cve_ids"] == "CVE-2026-21443,CVE-2026-21509,CVE-2026-21788"
    assert "android" in str(head.metadata["affected_platforms"])
    assert head.metadata["threat_category"] == "mobile_os_vulnerability"

    # Administrative boilerplate must not survive normalization.
    assert "Note No." not in head.text
    assert "Disclaimer" not in chunks[-1].text
    assert "www.cert-in.org.in" not in chunks[-1].text

    print(f"Chunks emitted        : {len(chunks)}")
    print(f"Overlapping pairs     : {overlapping_pairs}")
    print(f"Max chunk tokens      : {max(count_tokens(c.text) for c in chunks)}")
    print(f"Advisory ID           : {head.metadata['advisory_id']}")
    print(f"CVEs extracted        : {head.metadata['cve_ids']}")
    print(f"Threat category       : {head.metadata['threat_category']}")
    print("STANDALONE VERIFICATION: PASS")


if __name__ == "__main__":
    _run_standalone_verification()
