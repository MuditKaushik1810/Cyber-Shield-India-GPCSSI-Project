"""Cyber Shield India — Downstream Extraction Controller (STATUS.md Step 2.3).

Zero-shot structured extraction matrix: raw, unstructured news articles and
expert commentary flow in; clean, database-insertable Pydantic structures
flow out. The controller pairs strict **Pydantic v2** schemas (mirroring the
``incidents``, ``entities``, and ``expert_advisories`` relational blueprints
in ``core/database.py``) with **Gemini 2.5 Flash** through LangChain's
``.with_structured_output()`` enforcement channel.

Integrity guarantee: when a text block carries no viable threat
intelligence, the controller returns a clean, empty ``ExtractionResult`` —
it never invents incidents, entities, or CVEs. All anomalies (Gemini API
faults, Pydantic validation failures, timeouts) are intercepted explicitly
and degrade to the empty fallback with full forensic traces routed to
``logs/extractor.log``.
"""

import asyncio
import logging
import re
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import List, Literal, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai._common import GoogleGenerativeAIError
from pydantic import BaseModel, Field, ValidationError, field_validator

from core.config import get_google_api_key
from utils.scraper import extract_first_date

# --------------------------------------------------------------------------- #
# Forensic logging — dedicated daily-rotating channel: logs/extractor.log.    #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the extractor logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.extractor")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "extractor.log",
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
# Controlled vocabularies — aligned with core/database.py CHECK constraints   #
# and the services/expert_feed.py tactic lattice.                             #
# --------------------------------------------------------------------------- #

ThreatCategory = Literal[
    "digital_arrest",
    "apk_sideloading",
    "accessibility_exploit",
    "voip_spoofing",
    "sim_impersonation",
    "payment_fraud",
    "investment_scam",
    "general_cyber",
]

TacticVector = Literal[
    "digital_arrest",
    "apk_sideloading",
    "accessibility_exploit",
    "voip_spoofing",
    "sim_impersonation",
    "payment_fraud",
    "investment_scam",
]

EntityType = Literal[
    "phone",
    "upi_id",
    "bank_account",
    "imei",
    "url",
    "email",
    "app_package",
    "ip_address",
    "crypto_wallet",
    "aadhaar_masked",
]

SeverityLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

_CVE_PATTERN: re.Pattern = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

# --------------------------------------------------------------------------- #
# Strict Pydantic extraction schemas (relational blueprint mirrors).          #
# --------------------------------------------------------------------------- #


class IncidentExtraction(BaseModel):
    """One structured fraud incident, insertable into ``incidents``."""

    title: str = Field(
        min_length=10, max_length=300,
        description="Concise factual headline of the incident as stated in the text.",
    )
    threat_category: ThreatCategory = Field(
        description="The single best-fit threat vector from the controlled taxonomy.",
    )
    jurisdiction: str = Field(
        default="National",
        description="Indian state/UT explicitly named, else 'National'.",
    )
    severity: Optional[SeverityLevel] = Field(
        default=None,
        description="Severity only when the text supports it; otherwise null.",
    )
    date: Optional[str] = Field(
        default=None,
        description="Incident/publication date in ISO YYYY-MM-DD, only if stated.",
    )

    @field_validator("date")
    @classmethod
    def normalize_date(cls, value: Optional[str]) -> Optional[str]:
        """Coerce loosely formatted dates to ISO; drop unparseable values."""
        if value is None or not value.strip():
            return None
        candidate: str = value.strip()
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", candidate):
            return candidate
        return extract_first_date(candidate)


class EntityExtraction(BaseModel):
    """One digital identity indicator, insertable into ``entities``."""

    entity_type: EntityType = Field(
        description="Indicator class: phone, upi_id, bank_account, imei, url, "
                    "email, app_package, ip_address, crypto_wallet, aadhaar_masked.",
    )
    value: str = Field(
        min_length=3, max_length=500,
        description="The exact indicator value verbatim from the text.",
    )
    risk_score: float = Field(
        ge=0.0, le=100.0,
        description="Baseline risk 0-100: 90+ confirmed fraud instrument, "
                    "60-89 strongly implicated, 30-59 suspicious context, "
                    "<30 incidental mention.",
    )

    @field_validator("value")
    @classmethod
    def strip_value(cls, value: str) -> str:
        """Normalize surrounding whitespace on the raw indicator."""
        return value.strip()


class AdvisoryExtraction(BaseModel):
    """One expert tactical advisory, insertable into ``expert_advisories``."""

    expert_name: str = Field(
        min_length=3, max_length=120,
        description="The named expert or strategist issuing the commentary.",
    )
    advisory_text: str = Field(
        min_length=20,
        description="Faithful summary of the tactical advice or case analysis.",
    )
    target_vector: TacticVector = Field(
        description="The tactic lattice vector this advisory addresses.",
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="CVE identifier only if explicitly cited, e.g. CVE-2026-21443.",
    )

    @field_validator("cve_id")
    @classmethod
    def normalize_cve(cls, value: Optional[str]) -> Optional[str]:
        """Upper-case well-formed CVE ids; reject malformed ones to null."""
        if value is None or not value.strip():
            return None
        candidate: str = value.strip().upper()
        return candidate if _CVE_PATTERN.match(candidate) else None


class ExtractionResult(BaseModel):
    """The full zero-shot extraction matrix for one raw text block."""

    incidents: List[IncidentExtraction] = Field(
        default_factory=list,
        description="Structured fraud incidents present in the text; empty if none.",
    )
    entities: List[EntityExtraction] = Field(
        default_factory=list,
        description="Digital identity indicators present in the text; empty if none.",
    )
    advisories: List[AdvisoryExtraction] = Field(
        default_factory=list,
        description="Expert tactical advisories present in the text; empty if none.",
    )

    def is_empty(self) -> bool:
        """True when the text yielded no viable threat intelligence."""
        return not (self.incidents or self.entities or self.advisories)

    @classmethod
    def empty(cls) -> "ExtractionResult":
        """Clean fallback result carrying zero fabricated intelligence."""
        return cls()


# --------------------------------------------------------------------------- #
# Zero-shot system directive.                                                 #
# --------------------------------------------------------------------------- #

SYSTEM_DIRECTIVE: str = (
    "You are the Downstream Extraction Controller of Cyber Shield India, a "
    "government-grade threat intelligence grid. You receive one raw text "
    "block (news article, advisory, or expert commentary) and must populate "
    "the structured extraction matrix.\n"
    "\n"
    "STRICT RULES:\n"
    "1. Extract ONLY facts explicitly present in the text. Never infer, "
    "embellish, or invent incidents, indicators, experts, or CVE numbers.\n"
    "2. If the text contains no cybercrime or threat intelligence content, "
    "return the matrix with ALL THREE lists empty. An empty result is the "
    "correct answer for benign text.\n"
    "3. Indicators (phone numbers, UPI IDs, bank accounts, IMEIs, URLs, "
    "emails, app packages, IP addresses, crypto wallets) must be copied "
    "verbatim. Skip placeholders such as 'XXXXX'.\n"
    "4. Attribute advisories only to experts actually named in the text.\n"
    "5. Choose threat categories strictly from the provided taxonomy; use "
    "'general_cyber' when no specific vector fits.\n"
    "6. Dates must be ISO YYYY-MM-DD and only when stated in the text."
)

GEMINI_MODEL_NAME: str = "gemini-2.5-flash"
EXTRACTION_TIMEOUT_SECONDS: float = 90.0
BATCH_CONCURRENCY: int = 4

# --------------------------------------------------------------------------- #
# Controller.                                                                  #
# --------------------------------------------------------------------------- #


class DownstreamExtractionController:
    """Asynchronous zero-shot extraction pipeline over Gemini 2.5 Flash."""

    def __init__(self, temperature: float = 0.0) -> None:
        self._llm: ChatGoogleGenerativeAI = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL_NAME,
            temperature=temperature,
            google_api_key=get_google_api_key(),
        )
        self._structured_llm = self._llm.with_structured_output(ExtractionResult)
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(BATCH_CONCURRENCY)
        LOGGER.info(
            "Extraction controller online: model=%s temperature=%.1f",
            GEMINI_MODEL_NAME, temperature,
        )

    async def extract(self, raw_text: str, origin: str = "unknown") -> ExtractionResult:
        """Run one raw text block through the zero-shot extraction matrix.

        Degrades to ``ExtractionResult.empty()`` on any intercepted anomaly —
        the pipeline never emits fabricated or partially validated payloads.
        """
        if not raw_text or not raw_text.strip():
            LOGGER.info("origin=%s: blank payload, returning empty matrix", origin)
            return ExtractionResult.empty()
        messages: List[object] = [
            SystemMessage(content=SYSTEM_DIRECTIVE),
            HumanMessage(content=f"RAW TEXT BLOCK:\n\n{raw_text.strip()}"),
        ]
        try:
            result: Optional[ExtractionResult] = await asyncio.wait_for(
                self._structured_llm.ainvoke(messages),
                timeout=EXTRACTION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            LOGGER.error(
                "origin=%s: extraction timed out after %.0fs — empty fallback",
                origin, EXTRACTION_TIMEOUT_SECONDS,
            )
            return ExtractionResult.empty()
        except GoogleGenerativeAIError:
            LOGGER.exception(
                "origin=%s: Gemini API fault — empty fallback", origin
            )
            return ExtractionResult.empty()
        except ValidationError:
            LOGGER.exception(
                "origin=%s: Pydantic validation anomaly — empty fallback", origin
            )
            return ExtractionResult.empty()
        except ValueError:
            LOGGER.exception(
                "origin=%s: structured output parsing fault — empty fallback", origin
            )
            return ExtractionResult.empty()
        if result is None:
            LOGGER.warning(
                "origin=%s: model returned no structure — empty fallback", origin
            )
            return ExtractionResult.empty()
        LOGGER.info(
            "origin=%s: extracted %d incidents, %d entities, %d advisories",
            origin, len(result.incidents), len(result.entities), len(result.advisories),
        )
        return result

    async def extract_batch(
        self, payloads: List[str], origin: str = "batch"
    ) -> List[ExtractionResult]:
        """Run a payload batch concurrently under the controller's gate."""

        async def _gated(index: int, payload: str) -> ExtractionResult:
            async with self._semaphore:
                return await self.extract(payload, origin=f"{origin}[{index}]")

        return list(await asyncio.gather(
            *(_gated(index, payload) for index, payload in enumerate(payloads))
        ))


# --------------------------------------------------------------------------- #
# In-module verification harness — passes the synthetic 'Digital Arrest'      #
# expert text (Step 1.5 lineage) through the live LLM pipeline.               #
# --------------------------------------------------------------------------- #

_SYNTHETIC_DIGITAL_ARREST_TEXT: str = (
    "Cyber security consultant Dr. Rakshit Tandon on 11 June 2026 warned of a "
    "sharp escalation in 'digital arrest' operations targeting senior citizens "
    "across Telangana. Victims receive Skype video calls from men impersonating "
    "CBI and customs officers, are told a money-laundering case is registered "
    "against their Aadhaar, and are held under continuous camera surveillance "
    "for hours. In one Hyderabad case a retired bank manager was coerced into "
    "transferring Rs 18 lakh to the UPI ID verify.cbi@okaxis after callbacks "
    "from the number 9876012345. Dr. Tandon advised that no Indian agency "
    "conducts arrests over video calls and that victims should disconnect "
    "immediately and dial the 1930 cyber helpline."
)

_BENIGN_CONTROL_TEXT: str = (
    "The annual Lalbagh flower show opened in Bengaluru this weekend, drawing "
    "record crowds. Organisers expect over two lakh visitors before the "
    "exhibition closes, with the rose garden and bonsai pavilion proving the "
    "most popular attractions among families."
)


async def _run_verification_harness() -> None:
    """Verify live structured extraction plus the clean-empty fallback."""
    controller: DownstreamExtractionController = DownstreamExtractionController()

    rich: ExtractionResult = await controller.extract(
        _SYNTHETIC_DIGITAL_ARREST_TEXT, origin="harness-digital-arrest"
    )
    assert isinstance(rich, ExtractionResult)
    assert not rich.is_empty(), "digital arrest text must yield intelligence"
    assert rich.incidents, "expected at least one structured incident"
    assert any(
        incident.threat_category == "digital_arrest" for incident in rich.incidents
    ), "expected digital_arrest categorization"
    assert any(
        advisory.target_vector == "digital_arrest" and "Tandon" in advisory.expert_name
        for advisory in rich.advisories
    ), "expected a Tandon advisory targeting digital_arrest"
    extracted_values: List[str] = [entity.value for entity in rich.entities]
    assert any("verify.cbi@okaxis" in value for value in extracted_values), (
        "expected the UPI indicator to be captured verbatim"
    )

    print("--- Rich extraction ---")
    for incident in rich.incidents:
        print(f"incident : [{incident.threat_category}] {incident.title} "
              f"(jurisdiction={incident.jurisdiction}, date={incident.date})")
    for entity in rich.entities:
        print(f"entity   : {entity.entity_type}={entity.value} "
              f"(risk={entity.risk_score:.0f})")
    for advisory in rich.advisories:
        print(f"advisory : {advisory.expert_name} -> {advisory.target_vector}")

    empty: ExtractionResult = await controller.extract(
        _BENIGN_CONTROL_TEXT, origin="harness-benign-control"
    )
    assert isinstance(empty, ExtractionResult)
    assert empty.is_empty(), "benign text must yield a clean empty matrix"
    print("--- Benign control ---")
    print("empty matrix returned: no fabricated intelligence")
    print("EXTRACTION HARNESS: PASS")


if __name__ == "__main__":
    asyncio.run(_run_verification_harness())
