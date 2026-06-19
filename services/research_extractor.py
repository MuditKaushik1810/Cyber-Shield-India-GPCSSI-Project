"""Cyber Shield India — Research Corpus AI Extraction Component.

Passes raw ingested text (articles, advisories, regulatory PDFs) through
Gemini 2.5 Flash under a strict JSON system directive that synthesizes
descriptive prose into the structured ``fraud_records`` schema variables:
region, scam vector, case counts, financial loss, and demographic targeting.

Integrity guarantee: when the text carries no extractable fraud-landscape
content, the extractor returns an empty batch — it never invents states,
loss figures, or demographics. Every anomaly (Gemini fault, validation
error, timeout) degrades to the empty batch with a forensic trace.
"""

import asyncio
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import List, Literal, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from services.llm_errors import LLM_TRANSIENT_ERRORS, is_server_busy
from pydantic import BaseModel, Field, ValidationError, field_validator

from core.config import get_google_api_key

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the research-extractor logger (midnight-rotating)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.research_extractor")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "ingestion_worker.log",
        when="midnight", backupCount=14, encoding="utf-8",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOGGER: logging.Logger = _build_logger()

from core.config import GEMINI_FLASH_MODEL as _FLASH
GEMINI_MODEL_NAME: str = _FLASH
EXTRACTION_TIMEOUT_SECONDS: float = 120.0
# Gemini context is large but we cap input defensively to control cost/latency.
MAX_INPUT_CHARS: int = 24_000

# Multi-model rotation: the Gemini free-tier daily cap is PER MODEL, so when one
# model exhausts its pool we cascade to the next — each has its own daily quota.
MODEL_CASCADE_ORDER: List[str] = [
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
]


def _is_quota_error(exc: Exception) -> bool:
    """True if the error is a 429 / RESOURCE_EXHAUSTED quota exhaustion."""
    message: str = str(exc)
    return ("429" in message or "RESOURCE_EXHAUSTED" in message
            or "exceeded your current quota" in message.lower())


class FraudRecordExtraction(BaseModel):
    """One structured fraud-landscape datapoint synthesized from text."""

    state: Optional[str] = Field(
        default=None,
        description="Indian state/UT the datapoint concerns, else null.")
    city: Optional[str] = Field(
        default=None,
        description="Specific city/district hotspot named, else null.")
    scam_vector_type: str = Field(
        description="Specific scam/threat label, e.g. 'Digital Arrest', "
                    "'AI Deepfake Identity Theft', 'UPI Payment Fraud', "
                    "'Investment Scam', 'Data Breach', 'Phishing', 'SIM Swap', "
                    "'Ransomware', 'Sextortion'.")
    threat_domain: Literal[
        "Financial Fraud", "Data & Privacy Breaches",
        "Social & Behavioral Exploitation", "Deceptive & Malicious Campaigns",
        "Network & Infrastructure Attacks", "Emerging & Other Cybercrimes",
    ] = Field(
        default="Financial Fraud",
        description="The broad threat domain. Money/UPI/loan/investment scams -> "
                    "'Financial Fraud'; data breaches/leaks/PII exposure -> "
                    "'Data & Privacy Breaches'; phishing/romance/sextortion/"
                    "impersonation/social engineering -> 'Social & Behavioral "
                    "Exploitation'; malware/ransomware/deepfake/fake-app "
                    "campaigns -> 'Deceptive & Malicious Campaigns'; "
                    "MITM/DDoS/router/DNS/server/infrastructure compromise -> "
                    "'Network & Infrastructure Attacks'; anything else -> "
                    "'Emerging & Other Cybercrimes'.")
    extracted_case_count: int = Field(
        default=0, ge=0,
        description="Number of cases/victims explicitly cited, else 0.")
    records_exposed: Optional[int] = Field(
        default=None, ge=0,
        description="Records/accounts exposed in a data leak, if stated.")
    incident_count: Optional[int] = Field(
        default=None, ge=0,
        description="Distinct incidents reported (non-financial), if stated.")
    compromised_assets: Optional[str] = Field(
        default=None,
        description="Free-text assets compromised, e.g. '12 IP addresses', "
                    "'3 phishing domains', 'Corporate PII', if stated.")
    target_sector: Optional[str] = Field(
        default=None,
        description="Targeted sector, e.g. 'Critical Infrastructure', "
                    "'Healthcare', 'Banking', 'Public Sector', 'Individuals'.")
    severity_level: Optional[str] = Field(
        default=None,
        description="Severity if stated: Low, Medium, High, or Critical.")
    is_isolated_incident: bool = Field(
        default=False,
        description="True ONLY if the figure describes a single specific "
                    "case/event (e.g. 'a resident lost Rs 5 lakh yesterday').")
    incident_loss_inr: float = Field(
        default=0.0, ge=0.0,
        description="INR lost in THIS isolated incident; 0 if not isolated. "
                    "Convert lakh/crore to a plain rupee figure.")
    is_macro_historical_summary: bool = Field(
        default=False,
        description="True if the figure is a cumulative/aggregate total over "
                    "a long period (e.g. 'victims lost Rs 300 cr since 2023').")
    macro_summary_loss_inr: float = Field(
        default=0.0, ge=0.0,
        description="INR cumulative total for a macro summary; 0 if isolated. "
                    "Convert lakh/crore to a plain rupee figure.")
    demographic_age_bracket: Optional[str] = Field(
        default=None,
        description="Targeted age band, e.g. '18-25', '60+', 'senior citizens'.")
    demographic_gender_ratio: Optional[str] = Field(
        default=None,
        description="Gender skew if stated, e.g. 'majority male', '60% female'.")
    demographic_profession_target: Optional[str] = Field(
        default=None,
        description="Targeted occupation, e.g. 'students', 'retirees', "
                    "'corporate employees', 'homemakers'.")
    official_safety_advisory: Optional[str] = Field(
        default=None,
        description="Concise official safety guidance present in the text.")
    publish_timestamp: Optional[str] = Field(
        default=None,
        description="Publication/report date in ISO YYYY-MM-DD if stated.")

    @field_validator("incident_loss_inr", "macro_summary_loss_inr")
    @classmethod
    def clamp_loss(cls, value: float) -> float:
        """Guard against absurd overflow figures from hallucination."""
        # Cap at INR 100,000 crore — beyond any single credible report.
        return min(max(value, 0.0), 1_000_000_000_000.0)


class FraudExtractionBatch(BaseModel):
    """The full set of datapoints extracted from one raw document."""

    records: List[FraudRecordExtraction] = Field(
        default_factory=list,
        description="Every distinct fraud-landscape datapoint; empty if none.")

    @classmethod
    def empty(cls) -> "FraudExtractionBatch":
        """Clean fallback carrying zero fabricated datapoints."""
        return cls()


SYSTEM_DIRECTIVE: str = (
    "You are the data-synthesis engine of Cyber Shield India, an open-access "
    "public research repository covering the FULL Indian cyber-threat ecosystem "
    "— financial fraud, data leaks, deepfakes/extortion, phishing/spam, and "
    "MITM/infrastructure compromise. You receive one raw document and must "
    "convert ONLY its explicit, factual content into structured datapoints.\n\n"
    "STRICT RULES:\n"
    "0. Set threat_domain to the correct broad domain. For non-financial "
    "incidents, populate records_exposed / incident_count / severity_level "
    "when stated and leave the financial fields at 0 — never force a money "
    "figure onto a data leak or deepfake report.\n"
    "1. Extract only facts present in the text. Never invent states, cities, "
    "loss figures, case counts, record counts, or demographics. Unknown "
    "fields stay null/0.\n"
    "2. Convert Indian currency phrasing precisely: 'Rs 5 lakh' -> 500000, "
    "'2.5 crore' -> 25000000.\n"
    "3. TEMPORAL CLASSIFICATION — this is critical. For every monetary figure, "
    "decide whether it is an ISOLATED INCIDENT or a MACRO HISTORICAL SUMMARY:\n"
    "   - ISOLATED INCIDENT: a single specific event tied to one victim/case "
    "or a short recent window (e.g. 'A Bengaluru resident was swindled out of "
    "Rs 5,00,000 yesterday'). Set is_isolated_incident=true, put the amount in "
    "incident_loss_inr, and leave is_macro_historical_summary=false, "
    "macro_summary_loss_inr=0.\n"
    "   - MACRO HISTORICAL SUMMARY: a cumulative/aggregate total spanning "
    "months or years or many cases (e.g. 'Victims have lost Rs 300 crore to "
    "digital arrests since last year', 'India lost Rs 22,845 crore in 2024'). "
    "Set is_macro_historical_summary=true, put the amount in "
    "macro_summary_loss_inr, and leave is_isolated_incident=false, "
    "incident_loss_inr=0.\n"
    "   - If genuinely ambiguous, treat it as a macro summary (never inflate a "
    "weekly window with cumulative history).\n"
    "4. Emit one record per distinct (state, scam vector) combination the "
    "text actually describes. If the document is not about Indian cyber "
    "fraud, return an empty records list — that is the correct answer.\n"
    "5. Summarize any official safety guidance faithfully and concisely.\n"
    "6. Prefer specific scam vector names (Digital Arrest, AI Deepfake "
    "Identity Theft, UPI Payment Fraud, Investment Scam, Loan App Extortion, "
    "Phishing, SIM Swap) over vague labels."
)


class ResearchExtractor:
    """Gemini-backed structured extractor with multi-model rotation fallback."""

    def __init__(self, temperature: float = 0.0) -> None:
        self._temperature: float = temperature
        self._api_key: str = get_google_api_key()
        # Per-model structured LLMs are built lazily and cached so we never
        # reconstruct the same client across documents.
        self._structured: dict = {}
        LOGGER.info("Research extractor online: model cascade=%s",
                    MODEL_CASCADE_ORDER)

    def _structured_llm(self, model_name: str):
        """Return (and cache) a structured-output LLM for one model id."""
        if model_name not in self._structured:
            self._structured[model_name] = ChatGoogleGenerativeAI(
                model=model_name,
                temperature=self._temperature,
                google_api_key=self._api_key,
            ).with_structured_output(FraudExtractionBatch)
        return self._structured[model_name]

    async def extract(
        self, raw_text: str, origin: str = "unknown"
    ) -> FraudExtractionBatch:
        """Synthesize one raw document, cascading models on 429 exhaustion."""
        if not raw_text or not raw_text.strip():
            return FraudExtractionBatch.empty()
        payload: str = raw_text.strip()[:MAX_INPUT_CHARS]
        messages: List[object] = [
            SystemMessage(content=SYSTEM_DIRECTIVE),
            HumanMessage(content=f"RAW DOCUMENT:\n\n{payload}"),
        ]
        last: int = len(MODEL_CASCADE_ORDER) - 1
        for index, model_name in enumerate(MODEL_CASCADE_ORDER):
            next_model: str = (
                MODEL_CASCADE_ORDER[index + 1] if index < last
                else "(none — cascade exhausted)"
            )
            try:
                result: Optional[FraudExtractionBatch] = await asyncio.wait_for(
                    self._structured_llm(model_name).ainvoke(messages),
                    timeout=EXTRACTION_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                LOGGER.warning("origin=%s: model %s timed out — shifting to %s",
                               origin, model_name, next_model)
                continue
            except LLM_TRANSIENT_ERRORS as exc:
                if _is_quota_error(exc):
                    LOGGER.warning(
                        "origin=%s: model %s exhausted its free-tier pool (429) "
                        "— shifting to %s", origin, model_name, next_model)
                elif is_server_busy(exc):
                    LOGGER.warning(
                        "origin=%s: model %s experiencing high demand (503) "
                        "— shifting to %s", origin, model_name, next_model)
                else:
                    LOGGER.warning(
                        "origin=%s: model %s unavailable (%s) — shifting to %s",
                        origin, model_name, type(exc).__name__, next_model)
                continue
            except (ValidationError, ValueError):
                LOGGER.warning("origin=%s: model %s parse/validation fault — "
                               "shifting to %s", origin, model_name, next_model)
                continue
            if result is None:
                continue
            LOGGER.info("origin=%s: extracted %d datapoints via %s",
                        origin, len(result.records), model_name)
            return result
        LOGGER.error("origin=%s: entire model cascade exhausted — empty batch",
                     origin)
        return FraudExtractionBatch.empty()
