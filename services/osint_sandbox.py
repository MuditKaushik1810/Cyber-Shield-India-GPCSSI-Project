"""Cyber Shield India — Integrated OSINT Sandbox engine (Feature 3).

A single investigator workbench of *deterministic*, native-Python forensic
processors. None of the core parsing touches an LLM — every structure (email
routing hops, EXIF/GPS tags, WHOIS records, URL reputation, media container
integrity) is reconstructed programmatically so the output is reproducible and
court-defensible.

The only optional AI hop is :func:`summarize_for_officer`, which routes a
*summarized* metadata block through the shared 503/429-safe cascade
(:mod:`services.llm_client`) to add a three-bullet operational-risk read on top
of the deterministic facts. If every model is unavailable, the deterministic
report stands on its own.

Processors
----------
* :func:`parse_email_headers`   — ``email.parser.HeaderParser`` routing + auth.
* :func:`extract_exif`          — ``PIL`` camera/software/GPS metadata.
* :func:`whois_lookup`          — ``python-whois`` with a socket (port 43) fallback.
* :func:`analyze_url` / :func:`analyze_text` — regex URL/QR reputation scoring.
* :func:`inspect_media`         — magic-byte + EOF container integrity checker.
* :func:`hibp_check`            — HIBP v3 interface with an offline mock tier.
* :func:`hash_artifact`         — SHA-256 chain-of-custody record per upload.
"""

import base64
import binascii
import hashlib
import io
import logging
import os
import re
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.parser import HeaderParser
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
from langchain_core.messages import HumanMessage, SystemMessage

from core.config import get_hf_api_token, get_hibp_api_key
from services.llm_client import invoke_text

LOGGER: logging.Logger = logging.getLogger("cybershield.osint_sandbox")

# Network knobs kept tight so a slow third-party never wedges a Streamlit frame.
_WHOIS_TIMEOUT: float = 8.0
_HIBP_TIMEOUT: float = 10.0
_HF_TIMEOUT: float = 30.0
_IANA_WHOIS_HOST: str = "whois.iana.org"
# Current HF serverless inference router (the legacy api-inference.huggingface.co
# host was deprecated). Env-overridable so a future endpoint change needs no code
# edit. Format: <base>/<model-id>.
_HF_INFERENCE_BASE: str = (
    os.environ.get("HF_INFERENCE_BASE", "").strip()
    or "https://router.huggingface.co/hf-inference/models")
_DEFAULT_HF_DEEPFAKE_MODEL: str = "prithivirajdamodaran/deepfake-image-detector"

# Shared regexes (compiled once).
_IPV4_RE: re.Pattern = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_IPV6_RE: re.Pattern = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE)
_URL_RE: re.Pattern = re.compile(r"\b(?:https?://|www\.)[^\s<>\"')\]]+", re.IGNORECASE)
_PRIVATE_IP_RE: re.Pattern = re.compile(
    r"^(?:10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[0-1])\.)"
)


# --------------------------------------------------------------------------- #
# Chain-of-custody (SHA-256 logged on every upload).                          #
# --------------------------------------------------------------------------- #


def sha256_of_bytes(payload: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of an uploaded artifact."""
    return hashlib.sha256(payload).hexdigest()


def hash_artifact(filename: str, payload: bytes) -> Dict[str, object]:
    """Build a chain-of-custody record for one uploaded OSINT artifact."""
    record: Dict[str, object] = {
        "filename": filename,
        "size_bytes": len(payload),
        "sha256": sha256_of_bytes(payload),
        "logged_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }
    LOGGER.info("osint artifact hashed: %s sha256=%s size=%d",
                filename, record["sha256"], record["size_bytes"])
    return record


# --------------------------------------------------------------------------- #
# 1. Email header forensics — native email.parser.HeaderParser.               #
# --------------------------------------------------------------------------- #


@dataclass
class EmailHop:
    """One ``Received`` routing hop, parsed chronologically (oldest first)."""

    index: int
    from_host: str
    by_host: str
    ip: str
    is_public: bool
    timestamp: str
    protocol: str


@dataclass
class EmailHeaderReport:
    """Deterministic forensic summary of a raw email header block."""

    from_addr: str
    from_display: str
    return_path: str
    reply_to: str
    subject: str
    message_id: str
    originating_ip: str
    hops: List[EmailHop] = field(default_factory=list)
    spf: str = "not found"
    dkim: str = "not found"
    dmarc: str = "not found"
    flags: List[str] = field(default_factory=list)
    decoded_from_base64: bool = False

    @property
    def hop_count(self) -> int:
        return len(self.hops)


_HEADER_TOKEN_RE: re.Pattern = re.compile(
    r"^(Received|From|To|Subject|Date|Message-ID|Return-Path|"
    r"Authentication-Results|DKIM-Signature|Content-Type|MIME-Version)\b",
    re.IGNORECASE | re.MULTILINE,
)
_B64_CHARSET_RE: re.Pattern = re.compile(r"^[A-Za-z0-9+/=\s]+$")


def maybe_b64_decode(raw: str) -> Tuple[str, bool]:
    """Detect a Base64-encoded header/EML payload and decode it to UTF-8 text.

    Returns ``(text, was_base64)``. The input is treated as Base64 only when it
    is pure Base64 charset, length-aligned, and — once decoded — actually looks
    like an email header block. Anything else is returned verbatim so raw header
    pastes are never corrupted.
    """
    candidate: str = raw.strip()
    if len(candidate) < 16 or _HEADER_TOKEN_RE.search(raw):
        return raw, False  # already looks like real headers — don't touch it.
    compact: str = re.sub(r"\s+", "", candidate)
    if len(compact) % 4 != 0 or not _B64_CHARSET_RE.match(candidate):
        return raw, False
    try:
        decoded_bytes: bytes = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return raw, False
    try:
        decoded: str = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        decoded = decoded_bytes.decode("latin-1", "ignore")
    if _HEADER_TOKEN_RE.search(decoded):
        LOGGER.info("email input auto-decoded from Base64 (%d→%d bytes)",
                    len(compact), len(decoded))
        return decoded, True
    return raw, False


def decode_mime_words(value: str) -> str:
    """Decode RFC 2047 encoded-words (``=?utf-8?B?...?=``) to a clean string."""
    if not value or "=?" not in value:
        return value.strip()
    try:
        return str(make_header(decode_header(value))).strip()
    except (UnicodeDecodeError, LookupError, ValueError):
        return value.strip()


def _verdict_word(value: str) -> str:
    """Normalize an auth verdict token to a lowercase status word."""
    return value.strip().lower().split()[0] if value.strip() else "not found"


def _extract_auth_results(message: Message) -> Tuple[str, str, str]:
    """Pull SPF / DKIM / DMARC verdicts from Authentication-Results + SPF lines."""
    blob: str = " ".join(message.get_all("Authentication-Results", []))
    blob += " " + " ".join(message.get_all("ARC-Authentication-Results", []))
    spf: str = "not found"
    dkim: str = "not found"
    dmarc: str = "not found"
    for mech, verdict in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*(\w+)", blob, re.IGNORECASE):
        word: str = verdict.lower()
        if mech.lower() == "spf" and spf == "not found":
            spf = word
        elif mech.lower() == "dkim" and dkim == "not found":
            dkim = word
        elif mech.lower() == "dmarc" and dmarc == "not found":
            dmarc = word
    # Standalone Received-SPF header (e.g. "Pass (google.com: domain of …)").
    received_spf: List[str] = message.get_all("Received-SPF", [])
    if spf == "not found" and received_spf:
        spf = _verdict_word(received_spf[0])
    return spf, dkim, dmarc


def _parse_received(raw: str, index: int) -> EmailHop:
    """Parse a single ``Received`` header value into a routing hop."""
    collapsed: str = " ".join(raw.split())
    from_match = re.search(r"\bfrom\s+(.+?)\s+by\s+", collapsed, re.IGNORECASE)
    by_match = re.search(r"\bby\s+(.+?)(?:\s+with\b|\s+id\b|;|$)", collapsed, re.IGNORECASE)
    proto_match = re.search(r"\bwith\s+([A-Za-z0-9.\-/]+)", collapsed, re.IGNORECASE)

    ipv4: List[str] = _IPV4_RE.findall(collapsed)
    ip: str = next((cand for cand in ipv4 if not _PRIVATE_IP_RE.match(cand)),
                   ipv4[0] if ipv4 else "")
    if not ip:
        ipv6: List[str] = _IPV6_RE.findall(collapsed)
        ip = ipv6[0] if ipv6 else ""

    timestamp: str = ""
    if ";" in collapsed:
        tail: str = collapsed.rsplit(";", 1)[-1].strip()
        try:
            parsed = parsedate_to_datetime(tail)
            timestamp = (parsed.astimezone(timezone.utc)
                         .strftime("%Y-%m-%d %H:%M:%S UTC") if parsed else tail)
        except (TypeError, ValueError, OverflowError):
            timestamp = tail

    return EmailHop(
        index=index,
        from_host=(from_match.group(1).strip() if from_match else "—"),
        by_host=(by_match.group(1).strip() if by_match else "—"),
        ip=ip,
        is_public=bool(ip) and not _PRIVATE_IP_RE.match(ip),
        timestamp=timestamp or "—",
        protocol=(proto_match.group(1).strip() if proto_match else "—"),
    )


def parse_email_headers(raw_headers: str) -> EmailHeaderReport:
    """Parse raw OR Base64-encoded email headers into a routing report.

    Accepts either a raw header/EML block or a pure Base64 string of one; the
    Base64 case is auto-detected and decoded before parsing. RFC 2047 inline
    encoded-words in display-name / Subject fields are decoded natively.
    """
    raw_headers, decoded_from_base64 = maybe_b64_decode(raw_headers)
    message: Message = HeaderParser().parsestr(raw_headers)

    raw_display, from_addr = parseaddr(message.get("From", ""))
    from_display: str = decode_mime_words(raw_display)
    _, return_path = parseaddr(message.get("Return-Path", ""))
    _, reply_to = parseaddr(message.get("Reply-To", ""))

    # Received headers are stored newest-first; reverse for chronological order.
    received: List[str] = list(reversed(message.get_all("Received", [])))
    hops: List[EmailHop] = [_parse_received(value, i + 1)
                            for i, value in enumerate(received)]

    public_hops: List[EmailHop] = [h for h in hops if h.is_public]
    originating_ip: str = public_hops[0].ip if public_hops else ""

    spf, dkim, dmarc = _extract_auth_results(message)

    flags: List[str] = []
    if spf in {"fail", "softfail"}:
        flags.append(f"SPF {spf} — sender IP not authorized by the From-domain.")
    if dkim == "fail":
        flags.append("DKIM signature failed — body/headers may be tampered.")
    if dmarc == "fail":
        flags.append("DMARC fail — message would be quarantined/rejected by policy.")
    if return_path and from_addr and _domain_of(return_path) != _domain_of(from_addr):
        flags.append(f"Return-Path domain ({_domain_of(return_path)}) differs from "
                     f"From domain ({_domain_of(from_addr)}) — common in spoofing.")
    if reply_to and from_addr and _domain_of(reply_to) != _domain_of(from_addr):
        flags.append(f"Reply-To redirects to a different domain "
                     f"({_domain_of(reply_to)}) — verify before replying.")
    if not hops:
        flags.append("No Received headers found — paste the FULL raw header block.")

    if decoded_from_base64:
        flags.insert(0, "Input was Base64-encoded — auto-decoded before parsing.")

    LOGGER.info("email headers parsed: %d hops, spf=%s dkim=%s dmarc=%s b64=%s",
                len(hops), spf, dkim, dmarc, decoded_from_base64)
    return EmailHeaderReport(
        from_addr=from_addr or "—",
        from_display=from_display or "",
        return_path=return_path or "—",
        reply_to=reply_to or "—",
        subject=decode_mime_words(message.get("Subject", "")) or "—",
        message_id=message.get("Message-ID", "—"),
        originating_ip=originating_ip or "—",
        hops=hops, spf=spf, dkim=dkim, dmarc=dmarc, flags=flags,
        decoded_from_base64=decoded_from_base64,
    )


def _domain_of(addr: str) -> str:
    """Return the lowercase domain part of an email address, or ''."""
    return addr.rsplit("@", 1)[-1].lower() if "@" in addr else ""


# --------------------------------------------------------------------------- #
# 2. EXIF metadata extraction — PIL.Image / PIL.ExifTags.                      #
# --------------------------------------------------------------------------- #


@dataclass
class ExifReport:
    """Human-readable EXIF summary, including decoded GPS coordinates."""

    available: bool
    make: str = "—"
    model: str = "—"
    software: str = "—"
    datetime_original: str = "—"
    orientation: str = "—"
    dimensions: str = "—"
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    maps_url: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    note: str = ""

    @property
    def has_gps(self) -> bool:
        return self.gps_lat is not None and self.gps_lon is not None


def _rational_to_float(value: object) -> float:
    """Coerce a PIL rational / tuple into a float degree component."""
    try:
        if isinstance(value, tuple) and len(value) == 2:
            num, den = value
            return float(num) / float(den) if den else 0.0
        return float(value)
    except (TypeError, ValueError, ZeroDivisionError):
        return 0.0


def gps_dms_to_decimal(dms: object, ref: object) -> Optional[float]:
    """Convert a (degrees, minutes, seconds) EXIF tuple + N/S/E/W ref to decimal."""
    if not isinstance(dms, (tuple, list)) or len(dms) != 3:
        return None
    degrees: float = _rational_to_float(dms[0])
    minutes: float = _rational_to_float(dms[1])
    seconds: float = _rational_to_float(dms[2])
    decimal: float = degrees + minutes / 60.0 + seconds / 3600.0
    if isinstance(ref, bytes):
        ref = ref.decode("ascii", "ignore")
    if str(ref).strip().upper() in {"S", "W"}:
        decimal = -decimal
    return round(decimal, 6)


def extract_exif(image_bytes: bytes) -> ExifReport:
    """Parse uploaded image bytes into a human-readable EXIF report."""
    try:
        from PIL import Image, ExifTags
    except ImportError:
        return ExifReport(available=False,
                          note="Pillow is not installed (pip install Pillow).")

    import io

    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()
    except (OSError, ValueError) as exc:
        LOGGER.warning("exif: unreadable image (%s)", type(exc).__name__)
        return ExifReport(available=False,
                          note=f"Could not decode image bytes ({type(exc).__name__}).")

    dimensions: str = f"{image.width} × {image.height}px ({image.format})"
    raw_exif = image.getexif()
    if not raw_exif:
        return ExifReport(
            available=False, dimensions=dimensions,
            note="No EXIF block present — common for screenshots, social-media "
                 "re-encodes and metadata-stripped images.",
            flags=["No embedded metadata — image was likely re-encoded or stripped."],
        )

    label: Dict[int, str] = ExifTags.TAGS
    gps_label: Dict[int, str] = ExifTags.GPSTAGS
    tags: Dict[str, str] = {}
    for tag_id, value in raw_exif.items():
        name: str = label.get(tag_id, f"0x{tag_id:04X}")
        if name == "GPSInfo":
            continue
        if isinstance(value, bytes):
            value = value.decode("utf-8", "ignore").strip("\x00").strip()
        text: str = str(value).strip()
        if text and len(text) <= 240:
            tags[name] = text

    gps_lat = gps_lon = None
    maps_url: str = ""
    gps_block = raw_exif.get_ifd(0x8825) if hasattr(raw_exif, "get_ifd") else {}
    if gps_block:
        named: Dict[str, object] = {gps_label.get(k, str(k)): v
                                    for k, v in gps_block.items()}
        gps_lat = gps_dms_to_decimal(named.get("GPSLatitude"), named.get("GPSLatitudeRef"))
        gps_lon = gps_dms_to_decimal(named.get("GPSLongitude"), named.get("GPSLongitudeRef"))
        if gps_lat is not None and gps_lon is not None:
            maps_url = f"https://www.google.com/maps?q={gps_lat},{gps_lon}"

    flags: List[str] = []
    if gps_lat is not None:
        flags.append("Embedded GPS coordinates present — image discloses a "
                     "physical capture location.")
    if "Software" in tags:
        flags.append(f"Processed by '{tags['Software']}' — may indicate editing "
                     f"or re-encoding after capture.")

    LOGGER.info("exif parsed: %d tags, gps=%s", len(tags), gps_lat is not None)
    return ExifReport(
        available=True,
        make=tags.get("Make", "—"),
        model=tags.get("Model", "—"),
        software=tags.get("Software", "—"),
        datetime_original=tags.get("DateTimeOriginal", tags.get("DateTime", "—")),
        orientation=tags.get("Orientation", "—"),
        dimensions=dimensions,
        gps_lat=gps_lat, gps_lon=gps_lon, maps_url=maps_url,
        tags=tags, flags=flags,
    )


# --------------------------------------------------------------------------- #
# 3. Domain WHOIS — python-whois with a socket (port 43) fallback.            #
# --------------------------------------------------------------------------- #


@dataclass
class WhoisReport:
    """Deterministic WHOIS summary with a clear source/error interface."""

    domain: str
    available: bool
    source: str  # "python-whois" | "socket" | "error"
    registrar: str = "—"
    creation_date: str = "—"
    expiration_date: str = "—"
    updated_date: str = "—"
    name_servers: List[str] = field(default_factory=list)
    statuses: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    registrant_country: str = "—"
    age_days: Optional[int] = None
    raw: str = ""
    flags: List[str] = field(default_factory=list)
    error: str = ""


_DOMAIN_CLEAN_RE: re.Pattern = re.compile(r"^[a-z0-9.\-]+$")
# Strict FQDN validation: labels of 1-63 chars (no leading/trailing hyphen) and a
# 2-24 char alphabetic TLD, total <= 253 chars — rejects junk like 'asdf' or
# 'http://nonsense' so the WHOIS tool never renders an empty profile table.
_VALID_DOMAIN_RE: re.Pattern = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*"
    r"\.[a-z]{2,24}$")


def normalize_domain(value: str) -> str:
    """Strip scheme/path/port and lowercase a user-entered domain or URL."""
    value = value.strip().lower()
    value = re.sub(r"^[a-z]+://", "", value)
    value = value.split("/", 1)[0].split("?", 1)[0]
    value = value.split(":", 1)[0]
    if value.startswith("www."):
        value = value[4:]
    return value.strip(".")


def is_valid_domain(value: str) -> bool:
    """True only for a structurally valid, registrable domain (post-normalization)."""
    clean: str = normalize_domain(value)
    return bool(clean) and _VALID_DOMAIN_RE.match(clean) is not None


def _first(value: object) -> Optional[object]:
    """Return the first element if a list/tuple, else the value itself."""
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _fmt_date(value: object) -> str:
    """Format a WHOIS date (datetime or str) into an ISO date string."""
    item = _first(value)
    if isinstance(item, datetime):
        return item.strftime("%Y-%m-%d")
    return str(item).strip() if item else "—"


def _age_days(created: object) -> Optional[int]:
    """Compute domain age in days from a creation datetime, if available."""
    item = _first(created)
    if isinstance(item, datetime):
        ref = item if item.tzinfo else item.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - ref).days)
    return None


def _whois_socket(domain: str) -> str:
    """Raw WHOIS over TCP/43: resolve the TLD's server via IANA, then query it."""

    def _query(host: str, query: str) -> str:
        with socket.create_connection((host, 43), timeout=_WHOIS_TIMEOUT) as sock:
            sock.sendall((query + "\r\n").encode("utf-8", "ignore"))
            chunks: List[bytes] = []
            while True:
                data: bytes = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        return b"".join(chunks).decode("utf-8", "ignore")

    tld: str = domain.rsplit(".", 1)[-1]
    referral: str = _query(_IANA_WHOIS_HOST, tld)
    server_match = re.search(r"whois:\s*(\S+)", referral, re.IGNORECASE)
    if not server_match:
        return referral
    return _query(server_match.group(1).strip(), domain)


def _parse_socket_whois(domain: str, raw: str) -> WhoisReport:
    """Best-effort field extraction from a raw socket WHOIS response."""
    def grab(*keys: str) -> str:
        for key in keys:
            match = re.search(rf"^\s*{re.escape(key)}\s*:\s*(.+)$", raw,
                              re.IGNORECASE | re.MULTILINE)
            if match:
                return match.group(1).strip()
        return "—"

    name_servers: List[str] = sorted({m.strip().lower() for m in re.findall(
        r"^\s*(?:Name Server|nserver)\s*:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)})
    statuses: List[str] = sorted({m.strip() for m in re.findall(
        r"^\s*(?:Domain Status|status)\s*:\s*(.+)$", raw, re.IGNORECASE | re.MULTILINE)})
    emails: List[str] = sorted({m.lower() for m in re.findall(
        r"[\w.\-]+@[\w.\-]+\.[A-Za-z]{2,}", raw)})

    created: str = grab("Creation Date", "created", "Registered on")
    report = WhoisReport(
        domain=domain, available=True, source="socket",
        registrar=grab("Registrar", "Sponsoring Registrar"),
        creation_date=created,
        expiration_date=grab("Registry Expiry Date", "Expiry Date", "paid-till",
                             "Expiration Date"),
        updated_date=grab("Updated Date", "last-update", "changed"),
        name_servers=name_servers, statuses=statuses, emails=emails,
        registrant_country=grab("Registrant Country", "country"),
        raw=raw,
    )
    _apply_whois_flags(report)
    return report


def _apply_whois_flags(report: WhoisReport) -> None:
    """Append risk flags derived from the parsed WHOIS record."""
    if report.age_days is not None and report.age_days < 90:
        report.flags.append(f"Domain registered only {report.age_days} days ago — "
                            "newly-registered domains are a strong phishing signal.")
    if not report.name_servers:
        report.flags.append("No name servers listed — domain may be unconfigured/parked.")
    if any("clienthold" in s.lower() or "serverhold" in s.lower()
           for s in report.statuses):
        report.flags.append("Registry HOLD status present — domain may be suspended.")


def whois_lookup(domain: str) -> WhoisReport:
    """Look up WHOIS for a domain via python-whois, falling back to a socket."""
    clean: str = normalize_domain(domain)
    if not clean or "." not in clean or not _DOMAIN_CLEAN_RE.match(clean):
        return WhoisReport(domain=domain, available=False, source="error",
                           error="Enter a valid domain, e.g. 'example.com'.")

    try:
        import whois as _whois  # python-whois
    except ImportError:
        _whois = None

    if _whois is not None:
        try:
            data = _whois.whois(clean)
            if data and (data.get("domain_name") or data.get("registrar")):
                report = WhoisReport(
                    domain=clean, available=True, source="python-whois",
                    registrar=str(_first(data.get("registrar")) or "—"),
                    creation_date=_fmt_date(data.get("creation_date")),
                    expiration_date=_fmt_date(data.get("expiration_date")),
                    updated_date=_fmt_date(data.get("updated_date")),
                    name_servers=sorted({str(n).lower()
                                         for n in (data.get("name_servers") or [])}),
                    statuses=sorted({str(s) for s in (
                        data.get("status") if isinstance(data.get("status"), list)
                        else [data.get("status")]) if s}),
                    emails=sorted({str(e).lower() for e in (
                        data.get("emails") if isinstance(data.get("emails"), list)
                        else [data.get("emails")]) if e}),
                    registrant_country=str(_first(data.get("country")) or "—"),
                    age_days=_age_days(data.get("creation_date")),
                    raw=str(data.text) if hasattr(data, "text") else "",
                )
                _apply_whois_flags(report)
                LOGGER.info("whois %s ok via python-whois", clean)
                return report
            LOGGER.info("whois %s: python-whois empty — trying socket", clean)
        except (socket.error, ConnectionError, UnicodeError, ValueError,
                AttributeError, KeyError) as exc:
            LOGGER.warning("whois %s: python-whois failed (%s) — socket fallback",
                           clean, type(exc).__name__)

    # Socket fallback (no system `whois` binary required).
    try:
        raw: str = _whois_socket(clean)
        if raw.strip():
            report = _parse_socket_whois(clean, raw)
            report.age_days = _age_days(_coerce_date(report.creation_date))
            _apply_whois_flags(report)
            LOGGER.info("whois %s ok via socket fallback", clean)
            return report
        return WhoisReport(domain=clean, available=False, source="error",
                           error="WHOIS server returned no data for this domain.")
    except (socket.timeout, socket.gaierror, OSError) as exc:
        LOGGER.warning("whois %s socket failed (%s)", clean, type(exc).__name__)
        return WhoisReport(
            domain=clean, available=False, source="error",
            error=f"WHOIS network lookup failed ({type(exc).__name__}). The host "
                  "may be offline or the TLD's WHOIS server unreachable. Install "
                  "'python-whois' (pip install python-whois) for richer parsing.")


def _coerce_date(value: str) -> Optional[datetime]:
    """Parse a 'YYYY-MM-DD…' WHOIS date string back to a datetime, if possible."""
    if not value or value == "—":
        return None
    match = re.search(r"(\d{4})-(\d{2})-(\d{2})", value)
    if not match:
        return None
    try:
        return datetime(int(match.group(1)), int(match.group(2)),
                        int(match.group(3)), tzinfo=timezone.utc)
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# 4. URL / QR reputation — regex-driven heuristic scorer.                      #
# --------------------------------------------------------------------------- #


@dataclass
class UrlVerdict:
    """Risk scoring for a single URL or QR-decoded string."""

    url: str
    host: str
    scheme: str
    risk_score: int
    level: str  # "Low" | "Suspicious" | "High"
    flags: List[str] = field(default_factory=list)


# Known URL-shortening / redirect vectors that mask the true destination.
_SHORTENERS: frozenset = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "bit.do", "t.ly",
    "tiny.cc", "lnkd.in", "soo.gd", "clck.ru", "qr.io",
})
# Cheap TLDs heavily abused for throwaway phishing infrastructure.
_RISKY_TLDS: frozenset = frozenset({
    "zip", "mov", "xyz", "top", "click", "country", "kim", "work", "gq",
    "ml", "cf", "ga", "tk", "rest", "fit", "support", "live", "icu", "cyou",
})
# Brand/keyword bait commonly used in Indian financial-fraud lures.
_BRAND_KEYWORDS: Tuple[str, ...] = (
    "bank-secure-login", "secure-login", "kyc-update", "paytm-kyc",
    "phonepe-kyc", "sbi-update", "hdfc-secure", "icici-verify", "account-verify",
    "verify-account", "update-kyc", "netbanking", "rbi-alert", "income-tax-refund",
    "refund-portal", "wallet-update", "card-block", "reward-claim", "lucky-draw",
)
_TRACKING_PARAMS: Tuple[str, ...] = (
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "mc_eid", "ref", "igshid",
)


def analyze_url(url: str) -> UrlVerdict:
    """Score a single URL/QR string for phishing & obfuscation indicators."""
    original: str = url.strip()
    working: str = original if re.match(r"^[a-z]+://", original, re.IGNORECASE) \
        else f"http://{original}"
    scheme_match = re.match(r"^([a-z]+)://", working, re.IGNORECASE)
    scheme: str = scheme_match.group(1).lower() if scheme_match else "http"
    host: str = re.sub(r"^[a-z]+://", "", working, flags=re.IGNORECASE)
    host = host.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":")[0].lower()

    score: int = 0
    flags: List[str] = []
    lowered: str = original.lower()

    if scheme != "https":
        score += 10
        flags.append("Not served over HTTPS — credentials would travel in clear.")
    if host in _SHORTENERS:
        score += 30
        flags.append(f"URL shortener ({host}) hides the true destination — expand "
                     "before trusting.")
    if _IPV4_RE.fullmatch(host):
        score += 25
        flags.append("Raw IP address used as host — legitimate brands use named domains.")
    if "xn--" in host:
        score += 30
        flags.append("Punycode (xn--) host — possible homograph/look-alike domain.")
    if "@" in re.sub(r"^[a-z]+://", "", working, flags=re.IGNORECASE).split("/", 1)[0]:
        score += 25
        flags.append("'@' in the authority — everything before it is decoration; the "
                     "real host is after the @.")
    subdomain_depth: int = host.count(".")
    if subdomain_depth >= 4:
        score += 15
        flags.append(f"Deep subdomain nesting ({subdomain_depth} labels) — a trusted "
                     "brand name is often buried as a fake subdomain.")
    tld: str = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _RISKY_TLDS:
        score += 20
        flags.append(f"High-abuse TLD (.{tld}) frequently used for throwaway phishing.")
    hits: List[str] = [kw for kw in _BRAND_KEYWORDS if kw in lowered]
    if hits:
        score += 25
        flags.append(f"Typosquatting/brand-bait keywords: {', '.join(hits[:4])}.")
    if re.search(r"\d{1,3}-\d{1,3}-\d{1,3}", lowered) or lowered.count("-") >= 4:
        score += 10
        flags.append("Excessive hyphenation — a hallmark of look-alike fraud domains.")
    tracking: List[str] = [p for p in _TRACKING_PARAMS if re.search(rf"[?&]{p}=", lowered)]
    if tracking:
        score += 5
        flags.append(f"Tracking parameters present: {', '.join(tracking[:4])}.")
    if len(original) > 100:
        score += 5
        flags.append("Very long URL — padding is used to push the real domain "
                     "out of view on mobile.")

    score = min(score, 100)
    level: str = "High" if score >= 50 else "Suspicious" if score >= 20 else "Low"
    if not flags:
        flags.append("No high-risk indicators detected by the heuristic engine.")
    return UrlVerdict(url=original, host=host or "—", scheme=scheme,
                      risk_score=score, level=level, flags=flags)


def analyze_text(text: str) -> List[UrlVerdict]:
    """Extract every URL from free text / QR payload and score each one."""
    found: List[str] = []
    seen: set = set()
    for match in _URL_RE.finditer(text):
        candidate: str = match.group(0).rstrip(".,);]")
        if candidate.lower() not in seen:
            seen.add(candidate.lower())
            found.append(candidate)
    # A bare 'host.tld/...' with no scheme still deserves scoring.
    if not found:
        stripped: str = text.strip()
        if re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}", stripped, re.IGNORECASE):
            found.append(stripped.split()[0])
    verdicts: List[UrlVerdict] = [analyze_url(u) for u in found]
    LOGGER.info("url scan: %d urls, max risk=%s", len(verdicts),
                max((v.risk_score for v in verdicts), default=0))
    return verdicts


@dataclass
class QRDecodeResult:
    """Outcome of decoding QR matrices from an uploaded image."""

    available: bool
    payloads: List[str] = field(default_factory=list)
    error: str = ""

    @property
    def primary(self) -> str:
        return self.payloads[0] if self.payloads else ""


def decode_qr_image(image_bytes: bytes) -> QRDecodeResult:
    """Decode QR matrices from image bytes with OpenCV's ``QRCodeDetector``.

    Real computer-vision decoding — no mocks. Handles single- and multi-QR
    images and degrades to an honest diagnostic if OpenCV is unavailable or no
    matrix is found.
    """
    try:
        import cv2
        import numpy as np
    except ImportError:
        return QRDecodeResult(
            available=False,
            error="OpenCV is not installed — run "
                  "`pip install opencv-python-headless` to enable QR decoding.")

    try:
        buffer = np.frombuffer(image_bytes, dtype=np.uint8)
        image = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
        if image is None:
            return QRDecodeResult(available=True,
                                  error="Could not decode the uploaded image bytes.")
        detector = cv2.QRCodeDetector()
        payloads: List[str] = []
        ok, decoded, _points, _ = detector.detectAndDecodeMulti(image)
        if ok and decoded:
            payloads = [d for d in decoded if d]
        if not payloads:
            single, _pts, _qr = detector.detectAndDecode(image)
            if single:
                payloads = [single]
        if not payloads:
            return QRDecodeResult(
                available=True,
                error="No QR code matrix was found in the image. Re-crop tightly "
                      "around the code and re-upload at higher resolution.")
        LOGGER.info("qr decode: %d matrix payload(s) recovered", len(payloads))
        return QRDecodeResult(available=True, payloads=payloads)
    except cv2.error as exc:
        LOGGER.warning("qr decode: OpenCV error (%s)", type(exc).__name__)
        return QRDecodeResult(available=True,
                              error=f"OpenCV failed to process the image ({exc}).")


# --------------------------------------------------------------------------- #
# 5. Media codec & container integrity — magic bytes + EOF anomalies.         #
# --------------------------------------------------------------------------- #


@dataclass
class MediaReport:
    """Structural integrity verdict for an uploaded media container."""

    filename: str
    declared_ext: str
    detected_type: str
    mime: str
    extension_match: bool
    eof_intact: bool
    trailing_bytes: int
    size_bytes: int
    structural_flags: List[str] = field(default_factory=list)
    severity: str = "Clean"  # "Clean" | "Review" | "Anomalous"


# (label, mime, signature-at-offset-0). Container formats checked separately.
_MAGIC_SIGNATURES: Tuple[Tuple[str, str, bytes], ...] = (
    ("JPEG image", "image/jpeg", b"\xFF\xD8\xFF"),
    ("PNG image", "image/png", b"\x89PNG\r\n\x1a\n"),
    ("GIF image", "image/gif", b"GIF87a"),
    ("GIF image", "image/gif", b"GIF89a"),
    ("BMP image", "image/bmp", b"BM"),
    ("PDF document", "application/pdf", b"%PDF-"),
    ("ZIP/Office container", "application/zip", b"PK\x03\x04"),
)


def _detect_type(data: bytes) -> Tuple[str, str]:
    """Identify a media container from its leading magic bytes."""
    for label, mime, sig in _MAGIC_SIGNATURES:
        if data.startswith(sig):
            return label, mime
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "WEBP image", "image/webp"
    if data[4:8] == b"ftyp":
        brand: str = data[8:12].decode("ascii", "ignore")
        if brand.startswith(("qt", "moov")):
            return "QuickTime video", "video/quicktime"
        return f"MP4/ISO media ({brand or 'ftyp'})", "video/mp4"
    if data[:4] == b"RIFF" and data[8:12] == b"AVI ":
        return "AVI video", "video/x-msvideo"
    if data[:2] == b"\xFF\xFB" or data[:3] == b"ID3":
        return "MP3 audio", "audio/mpeg"
    return "Unknown / unrecognized", "application/octet-stream"


def _check_eof(data: bytes, mime: str) -> Tuple[bool, int]:
    """Return (eof_intact, trailing_byte_count) for known container formats."""
    if mime == "image/jpeg":
        marker: int = data.rfind(b"\xFF\xD9")
        if marker == -1:
            return False, 0
        return True, len(data) - (marker + 2)
    if mime == "image/png":
        marker = data.rfind(b"IEND\xaeB`\x82")
        if marker == -1:
            return False, 0
        return True, len(data) - (marker + 8)
    if mime == "image/gif":
        return data.endswith(b"\x3B"), 0
    # Containers without a strict trailer convention: treat as intact.
    return True, 0


def inspect_media(data: bytes, filename: str) -> MediaReport:
    """Run a structural sanity check on an uploaded media container."""
    declared_ext: str = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    label, mime = _detect_type(data)
    detected_ext_map: Dict[str, str] = {
        "image/jpeg": "jpg/jpeg", "image/png": "png", "image/gif": "gif",
        "image/webp": "webp", "image/bmp": "bmp", "video/mp4": "mp4",
        "video/quicktime": "mov", "audio/mpeg": "mp3", "application/pdf": "pdf",
    }
    expected: str = detected_ext_map.get(mime, "")
    norm_decl: str = "jpg/jpeg" if declared_ext in {"jpg", "jpeg"} else declared_ext
    extension_match: bool = (not declared_ext) or (norm_decl == expected) or expected == ""

    eof_intact, trailing = _check_eof(data, mime)

    flags: List[str] = []
    severity: str = "Clean"
    if mime == "application/octet-stream":
        flags.append("Magic bytes do not match any known media container — the "
                     "file may be corrupt, encrypted, or a disguised payload.")
        severity = "Review"
    if declared_ext and not extension_match and expected:
        flags.append(f"Extension/content mismatch: file is named '.{declared_ext}' "
                     f"but its bytes are a {label}. Classic disguise tactic.")
        severity = "Anomalous"
    if not eof_intact:
        flags.append(f"Missing/!truncated {label} end-of-file marker — the container "
                     "is incomplete or was re-muxed (a re-encode/deepfake tell).")
        severity = "Anomalous"
    elif trailing > 16:
        flags.append(f"{trailing:,} bytes appended AFTER the {label} EOF marker — "
                     "possible steganography, polyglot file, or hidden payload.")
        severity = "Anomalous" if trailing > 256 else "Review"
    if len(data) < 64:
        flags.append("File is implausibly small for a real media capture.")
        severity = "Anomalous"
    if not flags:
        flags.append("Container header and EOF marker are structurally consistent. "
                     "Note: this checks integrity, not pixel-level deepfake synthesis.")

    LOGGER.info("media inspect: %s detected=%s match=%s eof=%s trailing=%d sev=%s",
                filename, mime, extension_match, eof_intact, trailing, severity)
    return MediaReport(
        filename=filename, declared_ext=declared_ext or "—", detected_type=label,
        mime=mime, extension_match=extension_match, eof_intact=eof_intact,
        trailing_bytes=trailing, size_bytes=len(data),
        structural_flags=flags, severity=severity,
    )


# --------------------------------------------------------------------------- #
# 6. HaveIBeenPwned v3 interface — live API or offline mock dataset.           #
# --------------------------------------------------------------------------- #


@dataclass
class BreachReport:
    """Breach-exposure summary for one account identifier."""

    account: str
    breached: bool
    source: str  # "hibp-live" | "offline-mock" | "error"
    breaches: List[Dict[str, str]] = field(default_factory=list)
    note: str = ""
    warning: str = ""


# Clearly-labelled offline sample data so the tool is demonstrable without a key.
_MOCK_BREACHES: Dict[str, List[Dict[str, str]]] = {
    "test@example.com": [
        {"Name": "Adobe", "BreachDate": "2013-10-04",
         "DataClasses": "Email addresses, Password hints, Passwords, Usernames"},
        {"Name": "LinkedIn", "BreachDate": "2012-05-05",
         "DataClasses": "Email addresses, Passwords"},
    ],
    "victim@gmail.com": [
        {"Name": "Collection1", "BreachDate": "2019-01-07",
         "DataClasses": "Email addresses, Passwords"},
    ],
}


def hibp_check(account: str) -> BreachReport:
    """Query HIBP v3 for breach exposure, or serve a labelled offline mock."""
    target: str = account.strip().lower()
    if not target or "@" not in target:
        return BreachReport(account=account, breached=False, source="error",
                            note="Enter a valid email address to check.")

    api_key: Optional[str] = get_hibp_api_key()
    if not api_key:
        hits: List[Dict[str, str]] = _MOCK_BREACHES.get(target, [])
        LOGGER.info("hibp: no key — offline mock for %s (%d hits)", target, len(hits))
        return BreachReport(
            account=target, breached=bool(hits), source="offline-mock",
            breaches=hits,
            warning="OFFLINE MOCK MODE — no HIBP_API_KEY configured. Results below "
                    "are sample data, NOT a live breach check. Set HIBP_API_KEY in "
                    ".env for authoritative results.",
            note=("Sample account matched the offline dataset." if hits else
                  "Not present in the offline sample set (this is not authoritative)."),
        )

    url: str = (f"https://haveibeenpwned.com/api/v3/breachedaccount/"
                f"{quote(target, safe='')}?truncateResponse=false")
    headers: Dict[str, str] = {
        "hibp-api-key": api_key,
        "user-agent": "CyberShieldIndia-OSINT-Sandbox",
    }
    try:
        with httpx.Client(timeout=_HIBP_TIMEOUT) as client:
            response = client.get(url, headers=headers)
        if response.status_code == 404:
            LOGGER.info("hibp: %s clean (404)", target)
            return BreachReport(account=target, breached=False, source="hibp-live",
                                note="✅ No breaches found for this account on HIBP.")
        if response.status_code == 401:
            return BreachReport(account=target, breached=False, source="error",
                                note="HIBP rejected the API key (401). Verify HIBP_API_KEY.")
        if response.status_code == 429:
            return BreachReport(account=target, breached=False, source="error",
                                note="HIBP rate limit hit (429). Wait and retry.")
        response.raise_for_status()
        payload = response.json()
        breaches: List[Dict[str, str]] = [{
            "Name": str(b.get("Title", b.get("Name", "Unknown"))),
            "BreachDate": str(b.get("BreachDate", "—")),
            "DataClasses": ", ".join(b.get("DataClasses", []) or []),
        } for b in payload]
        LOGGER.info("hibp: %s breached in %d datasets", target, len(breaches))
        return BreachReport(account=target, breached=True, source="hibp-live",
                            breaches=breaches,
                            note=f"⚠️ Found in {len(breaches)} known breach(es).")
    except (httpx.HTTPError, ValueError) as exc:
        LOGGER.warning("hibp: live lookup failed (%s)", type(exc).__name__)
        return BreachReport(account=target, breached=False, source="error",
                            note=f"HIBP network/parse error ({type(exc).__name__}).")


# --------------------------------------------------------------------------- #
# 6b. Identity-exposure aggregator — live, unauthenticated breach ingestion.   #
# --------------------------------------------------------------------------- #
#
# Pulls and PARSES real breach telemetry (never hands the user raw links):
#   * Email  -> XposedOrNot breach-analytics API (free, unauthenticated).
#   * Domain -> HaveIBeenPwned public /breaches?domain= (no API key required).
# Each breach is reduced to {source, date, data_classes, records}, and a
# deterministic 0-100 risk score is computed from the sensitivity of the exposed
# PII data classes plus breach breadth.

_XPOSEDORNOT_ANALYTICS: str = "https://api.xposedornot.com/v1/breach-analytics"
_HIBP_BREACHES_URL: str = "https://haveibeenpwned.com/api/v3/breaches"
_EXPOSURE_TIMEOUT: float = 12.0
_EXPOSURE_UA: str = "CyberShieldIndia-OSINT-Sandbox"

# Sensitivity weights (per distinct data class) used for the risk score. Keys are
# matched as case-insensitive substrings against each breach's data classes.
_DATA_CLASS_WEIGHTS: Tuple[Tuple[str, int], ...] = (
    ("password", 25), ("bank account", 25), ("credit card", 25),
    ("financial", 22), ("cvv", 25), ("government issued id", 20),
    ("passport", 20), ("social security", 20), ("aadhaar", 20), ("pan ", 18),
    ("tax", 16), ("security question", 14), ("biometric", 22),
    ("date of birth", 12), ("phone", 12), ("physical address", 10),
    ("geographic location", 9), ("ip address", 8), ("device", 6),
    ("username", 5), ("name", 3), ("email", 4),
)


@dataclass
class BreachExposure:
    """One parsed breach record naming the searched identifier."""

    source: str
    date: str
    data_classes: List[str] = field(default_factory=list)
    records: Optional[int] = None
    password_risk: str = ""


@dataclass
class ExposureReport:
    """Aggregated, parsed identity-exposure intelligence for one identifier."""

    identifier: str
    kind: str            # "email" | "domain"
    found: bool
    source: str          # "xposedornot" | "hibp-breaches" | "clean" | "error"
    breaches: List[BreachExposure] = field(default_factory=list)
    risk_score: int = 0          # 0-100
    risk_label: str = "None"     # None|Low|Moderate|Elevated|High|Critical
    data_class_tally: Dict[str, int] = field(default_factory=dict)
    note: str = ""


_EMAIL_RE: re.Pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _class_weight(data_class: str) -> int:
    """Sensitivity weight for a single data-class label (substring match)."""
    low: str = data_class.lower()
    for needle, weight in _DATA_CLASS_WEIGHTS:
        if needle in low:
            return weight
    return 5


def _score_exposure(breaches: List[BreachExposure]) -> Tuple[int, str, Dict[str, int]]:
    """Deterministic 0-100 risk score from exposed PII sensitivity + breadth."""
    tally: Dict[str, int] = {}
    distinct: Dict[str, int] = {}
    for breach in breaches:
        for data_class in breach.data_classes:
            label: str = data_class.strip()
            if not label:
                continue
            tally[label] = tally.get(label, 0) + 1
            distinct[label.lower()] = _class_weight(label)
    score: int = sum(distinct.values()) + min(len(breaches) * 3, 20)
    score = max(0, min(score, 100))
    if not breaches:
        label = "None"
    elif score >= 80:
        label = "Critical"
    elif score >= 60:
        label = "High"
    elif score >= 40:
        label = "Elevated"
    elif score >= 20:
        label = "Moderate"
    else:
        label = "Low"
    ordered: Dict[str, int] = dict(
        sorted(tally.items(), key=lambda kv: kv[1], reverse=True))
    return score, label, ordered


def _xposedornot_email(email: str) -> ExposureReport:
    """Email path: ingest & parse XposedOrNot breach-analytics (unauthenticated)."""
    try:
        with httpx.Client(timeout=_EXPOSURE_TIMEOUT,
                          headers={"user-agent": _EXPOSURE_UA}) as client:
            response = client.get(_XPOSEDORNOT_ANALYTICS,
                                  params={"email": email})
        if response.status_code == 404:
            return ExposureReport(identifier=email, kind="email", found=False,
                                  source="clean",
                                  note="No public breach records found for this email.")
        response.raise_for_status()
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        LOGGER.warning("exposure(email): lookup failed (%s)", type(exc).__name__)
        return ExposureReport(identifier=email, kind="email", found=False,
                              source="error",
                              note=f"Live exposure lookup failed ({type(exc).__name__}).")

    if isinstance(data, dict) and data.get("Error"):
        return ExposureReport(identifier=email, kind="email", found=False,
                              source="clean",
                              note="No public breach records found for this email.")

    exposed = (data.get("ExposedBreaches") or {}) if isinstance(data, dict) else {}
    details = exposed.get("breaches_details") or []
    breaches: List[BreachExposure] = []
    for item in details:
        if not isinstance(item, dict):
            continue
        classes: List[str] = [c.strip() for c in
                              str(item.get("xposed_data", "")).split(";") if c.strip()]
        records_raw = item.get("xposed_records")
        breaches.append(BreachExposure(
            source=str(item.get("breach", "Unknown")),
            date=str(item.get("xposed_date", "—")),
            data_classes=classes,
            records=int(records_raw) if isinstance(records_raw, int) else None,
            password_risk=str(item.get("password_risk", "")),
        ))
    if not breaches:
        return ExposureReport(identifier=email, kind="email", found=False,
                              source="clean",
                              note="No public breach records found for this email.")
    score, label, tally = _score_exposure(breaches)
    LOGGER.info("exposure(email): %s -> %d breach(es), risk=%s",
                email, len(breaches), label)
    return ExposureReport(
        identifier=email, kind="email", found=True, source="xposedornot",
        breaches=breaches, risk_score=score, risk_label=label,
        data_class_tally=tally,
        note=f"Aggregated {len(breaches)} public breach record(s).")


def _hibp_domain(domain: str) -> ExposureReport:
    """Domain path: ingest & parse HIBP public /breaches?domain= (no API key)."""
    try:
        with httpx.Client(timeout=_EXPOSURE_TIMEOUT,
                          headers={"user-agent": _EXPOSURE_UA}) as client:
            response = client.get(_HIBP_BREACHES_URL, params={"domain": domain})
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        LOGGER.warning("exposure(domain): lookup failed (%s)", type(exc).__name__)
        return ExposureReport(identifier=domain, kind="domain", found=False,
                              source="error",
                              note=f"Live exposure lookup failed ({type(exc).__name__}).")

    rows = payload if isinstance(payload, list) else []
    breaches: List[BreachExposure] = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        classes: List[str] = [str(c).strip() for c in
                              (item.get("DataClasses") or []) if str(c).strip()]
        records_raw = item.get("PwnCount")
        breaches.append(BreachExposure(
            source=str(item.get("Title", item.get("Name", "Unknown"))),
            date=str(item.get("BreachDate", "—")),
            data_classes=classes,
            records=int(records_raw) if isinstance(records_raw, int) else None,
        ))
    if not breaches:
        return ExposureReport(identifier=domain, kind="domain", found=False,
                              source="clean",
                              note="No public breaches registered for this domain.")
    score, label, tally = _score_exposure(breaches)
    LOGGER.info("exposure(domain): %s -> %d breach(es), risk=%s",
                domain, len(breaches), label)
    return ExposureReport(
        identifier=domain, kind="domain", found=True, source="hibp-breaches",
        breaches=breaches, risk_score=score, risk_label=label,
        data_class_tally=tally,
        note=f"Aggregated {len(breaches)} breach(es) registered against this domain.")


def breach_exposure_lookup(identifier: str) -> ExposureReport:
    """Live, parsed identity-exposure aggregation for an email or domain.

    Routes emails to XposedOrNot and domains to HIBP's public breaches endpoint —
    both unauthenticated — and returns fully-parsed breach telemetry (source,
    date, PII data classes, record counts) plus a deterministic risk score. No
    external links are surfaced; the investigator gets the compiled answer.
    """
    target: str = (identifier or "").strip()
    if not target:
        return ExposureReport(identifier=target, kind="email", found=False,
                              source="error",
                              note="Enter a target email address or domain.")
    if _EMAIL_RE.match(target):
        return _xposedornot_email(target.lower())
    domain: str = normalize_domain(target)
    if is_valid_domain(domain):
        return _hibp_domain(domain)
    return ExposureReport(identifier=target, kind="email", found=False,
                          source="error",
                          note="Enter a valid email address (name@domain) or a "
                               "registrable domain (example.com).")


# --------------------------------------------------------------------------- #
# 7. Deepfake verification — deterministic ELA + Hugging Face inference layer. #
# --------------------------------------------------------------------------- #


@dataclass
class ELAReport:
    """Error-Level-Analysis forensic result for one image."""

    available: bool
    ela_png: bytes = b""           # autoscaled ELA visualization (PNG bytes)
    max_diff: int = 0
    mean_diff: float = 0.0
    suspicion: str = "Inconclusive"  # "Low" | "Elevated" | "High"
    note: str = ""
    flags: List[str] = field(default_factory=list)


def error_level_analysis(image_bytes: bytes, quality: int = 95) -> ELAReport:
    """Run Error Level Analysis: resave at fixed quality and diff against origin.

    Splices/face-swaps re-compress at a different error level than the
    surrounding pixels; ELA surfaces those high-frequency edge inconsistencies.
    Returns an autoscaled PNG visualization plus diff statistics. Deterministic,
    fully local — no model weights required.
    """
    try:
        from PIL import Image, ImageChops, ImageEnhance
        import numpy as np
    except ImportError:
        return ELAReport(available=False,
                         note="Pillow/numpy unavailable — cannot run ELA.")

    try:
        original = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except (OSError, ValueError) as exc:
        return ELAReport(available=False,
                         note=f"Could not decode image for ELA ({type(exc).__name__}).")

    resaved_buffer = io.BytesIO()
    original.save(resaved_buffer, "JPEG", quality=quality)
    resaved_buffer.seek(0)
    resaved = Image.open(resaved_buffer).convert("RGB")

    diff = ImageChops.difference(original, resaved)
    extrema = diff.getextrema()
    max_diff: int = max(band[1] for band in extrema) or 1
    scale: float = 255.0 / max_diff
    ela_image = ImageEnhance.Brightness(diff).enhance(scale)

    mean_diff: float = float(np.asarray(diff, dtype=np.float32).mean())

    out_buffer = io.BytesIO()
    ela_image.save(out_buffer, "PNG")

    # Heuristic banding: bright, *localized* residue (high max vs. modest mean)
    # is the classic splice tell; uniform low residue reads as a clean re-encode.
    if max_diff >= 60 and mean_diff >= 8:
        suspicion = "High"
    elif max_diff >= 35 or mean_diff >= 4:
        suspicion = "Elevated"
    else:
        suspicion = "Low"

    flags: List[str] = []
    if suspicion == "High":
        flags.append("Strong, localized ELA residue — bright edges concentrated in "
                     "a region are a classic splice / face-swap indicator. Inspect "
                     "the highlighted zones.")
    elif suspicion == "Elevated":
        flags.append("Moderate ELA residue — possible localized editing or a "
                     "multi-generation re-encode. Corroborate before concluding.")
    else:
        flags.append("Uniform low ELA residue — consistent with a single clean "
                     "compression pass (no strong manipulation signal).")
    flags.append("ELA is an indicator, not proof. PNG/screenshot re-encodes and "
                 "heavy social-media recompression can mask or mimic these tells.")

    LOGGER.info("ela: max=%d mean=%.2f suspicion=%s", max_diff, mean_diff, suspicion)
    return ELAReport(
        available=True, ela_png=out_buffer.getvalue(), max_diff=max_diff,
        mean_diff=round(mean_diff, 2), suspicion=suspicion, flags=flags,
    )


@dataclass
class DeepfakeVerdict:
    """Remote deepfake-classifier result (Hugging Face Inference API)."""

    source: str  # "hf-live" | "no-token" | "loading" | "error"
    available: bool
    model: str = ""
    top_label: str = ""
    top_score: float = 0.0
    scores: List[Dict[str, object]] = field(default_factory=list)
    note: str = ""


def _hf_deepfake_model() -> str:
    """Return the configured HF deepfake model id (env-overridable)."""
    return os.environ.get("HF_DEEPFAKE_MODEL", "").strip() or _DEFAULT_HF_DEEPFAKE_MODEL


def huggingface_deepfake_detect(image_bytes: bytes) -> DeepfakeVerdict:
    """Classify an image via a Hugging Face deepfake model, failing gracefully.

    Honest diagnostic states (never a fabricated verdict) for: no token, model
    cold-start (503), auth/rate errors, and network/timeout failures.
    """
    model: str = _hf_deepfake_model()
    token: Optional[str] = get_hf_api_token()
    if not token:
        return DeepfakeVerdict(
            source="no-token", available=False, model=model,
            note="No HF_API_TOKEN configured — remote deepfake model skipped. The "
                 "deterministic ELA layer above still applies. Add a free token "
                 "from huggingface.co/settings/tokens to enable this layer.")

    url: str = f"{_HF_INFERENCE_BASE}/{model}"
    headers: Dict[str, str] = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/octet-stream",
    }
    try:
        with httpx.Client(timeout=_HF_TIMEOUT) as client:
            response = client.post(url, headers=headers, content=image_bytes)
        if response.status_code == 503:
            payload = _safe_json(response)
            wait = payload.get("estimated_time", "a few") if payload else "a few"
            return DeepfakeVerdict(
                source="loading", available=False, model=model,
                note=f"Model is cold-starting on Hugging Face (~{wait}s). Retry "
                     "shortly — this is normal for the first request.")
        if response.status_code in (401, 403):
            return DeepfakeVerdict(source="error", available=False, model=model,
                                   note="HF rejected the token (401/403). Verify HF_API_TOKEN.")
        if response.status_code == 429:
            return DeepfakeVerdict(source="error", available=False, model=model,
                                   note="HF rate limit reached (429). Wait and retry.")
        if response.status_code == 404:
            return DeepfakeVerdict(source="error", available=False, model=model,
                                   note=f"Model '{model}' not found on HF (404). "
                                        "Set HF_DEEPFAKE_MODEL to a valid image-classification model.")
        response.raise_for_status()
        data = response.json()
        scores: List[Dict[str, object]] = _normalize_hf_scores(data)
        if not scores:
            return DeepfakeVerdict(source="error", available=False, model=model,
                                   note="HF returned an unrecognized payload shape.")
        top = scores[0]
        LOGGER.info("hf deepfake: model=%s top=%s score=%.3f",
                    model, top["label"], top["score"])
        return DeepfakeVerdict(
            source="hf-live", available=True, model=model,
            top_label=str(top["label"]), top_score=float(top["score"]),
            scores=scores,
            note=f"Top class '{top['label']}' at {float(top['score']):.1%} confidence.")
    except (httpx.HTTPError, ValueError) as exc:
        LOGGER.warning("hf deepfake: request failed (%s)", type(exc).__name__)
        return DeepfakeVerdict(source="error", available=False, model=model,
                               note=f"HF network/parse error ({type(exc).__name__}).")


def _safe_json(response: httpx.Response) -> Optional[Dict[str, object]]:
    """Return parsed JSON dict from a response, or None on any parse failure."""
    try:
        parsed = response.json()
        return parsed if isinstance(parsed, dict) else None
    except ValueError:
        return None


def _normalize_hf_scores(data: object) -> List[Dict[str, object]]:
    """Flatten HF image-classification output into sorted [{label, score}]."""
    # HF returns either [{label,score},…] or [[{label,score},…]] (batched).
    rows = data[0] if (isinstance(data, list) and data
                       and isinstance(data[0], list)) else data
    if not isinstance(rows, list):
        return []
    out: List[Dict[str, object]] = []
    for item in rows:
        if isinstance(item, dict) and "label" in item and "score" in item:
            out.append({"label": item["label"], "score": float(item["score"])})
    return sorted(out, key=lambda r: r["score"], reverse=True)


# --------------------------------------------------------------------------- #
# Contextual AI interpretation — OSINT Intelligence Officer (cascade-safe).    #
# --------------------------------------------------------------------------- #


_OFFICER_PROMPT: str = (
    "You are an OSINT Intelligence Officer supporting an AUTHORIZED cyber "
    "investigation for Indian law enforcement (NCRP / I4C context). You are "
    "given the DETERMINISTIC output of an automated OSINT tool — never raw "
    "private data. Read the metadata and deliver EXACTLY three concise bullet "
    "points headed '**Operational risk read:**'. Each bullet states one "
    "actionable intelligence inference (attribution lead, infrastructure "
    "tell, or recommended next pivot). Be specific, do not invent fields that "
    "are not present, and never output disclaimers or preamble."
)


def summarize_for_officer(tool: str, metadata_summary: str) -> str:
    """Pass a summarized metadata block through the cascade for a 3-bullet read.

    Returns clean UI-safe text, or '' if every cascade model is unavailable
    (the caller then simply shows the deterministic report alone).
    """
    if not metadata_summary.strip():
        return ""
    messages = [
        SystemMessage(content=_OFFICER_PROMPT),
        HumanMessage(content=f"OSINT tool: {tool}\n\nDeterministic findings:\n"
                             f"{metadata_summary.strip()}"),
    ]
    summary: str = invoke_text(messages, origin="osint_sandbox", temperature=0.2)
    if summary.strip():
        return summary
    LOGGER.warning("osint officer summary: cascade exhausted for %s", tool)
    return ""
