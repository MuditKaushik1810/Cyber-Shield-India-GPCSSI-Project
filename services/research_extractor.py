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
from typing import List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai._common import GoogleGenerativeAIError
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

GEMINI_MODEL_NAME: str = "gemini-2.5-flash"
EXTRACTION_TIMEOUT_SECONDS: float = 120.0
# Gemini context is large but we cap input defensively to control cost/latency.
MAX_INPUT_CHARS: int = 24_000


class FraudRecordExtraction(BaseModel):
    """One structured fraud-landscape datapoint synthesized from text."""

    state: Optional[str] = Field(
        default=None,
        description="Indian state/UT the datapoint concerns, else null.")
    city: Optional[str] = Field(
        default=None,
        description="Specific city/district hotspot named, else null.")
    scam_vector_type: str = Field(
        description="Scam category, e.g. 'Digital Arrest', 'AI Deepfake "
                    "Identity Theft', 'UPI Payment Fraud', 'Investment Scam', "
                    "'Loan App Extortion', 'Phishing', 'SIM Swap'.")
    extracted_case_count: int = Field(
        default=0, ge=0,
        description="Number of cases/victims explicitly cited, else 0.")
    financial_loss_inr: float = Field(
        default=0.0, ge=0.0,
        description="Total financial loss in INR (convert lakh/crore to a "
                    "plain rupee figure), else 0.0.")
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

    @field_validator("financial_loss_inr")
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
    "public research repository on Indian cybercrime trends. You receive one "
    "raw document (news article, regulatory advisory, or handbook excerpt) "
    "and must convert ONLY its explicit, factual cyber-fraud content into "
    "structured datapoints.\n\n"
    "STRICT RULES:\n"
    "1. Extract only facts present in the text. Never invent states, cities, "
    "loss figures, case counts, or demographics. Unknown fields stay null/0.\n"
    "2. Convert Indian currency phrasing precisely: 'Rs 5 lakh' -> 500000, "
    "'2.5 crore' -> 25000000.\n"
    "3. Emit one record per distinct (state, scam vector) combination the "
    "text actually describes. If the document is not about Indian cyber "
    "fraud, return an empty records list — that is the correct answer.\n"
    "4. Summarize any official safety guidance faithfully and concisely.\n"
    "5. Prefer specific scam vector names (Digital Arrest, AI Deepfake "
    "Identity Theft, UPI Payment Fraud, Investment Scam, Loan App Extortion, "
    "Phishing, SIM Swap) over vague labels."
)


class ResearchExtractor:
    """Gemini-backed structured extractor for the research repository."""

    def __init__(self, temperature: float = 0.0) -> None:
        self._llm = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL_NAME,
            temperature=temperature,
            google_api_key=get_google_api_key(),
        ).with_structured_output(FraudExtractionBatch)
        LOGGER.info("Research extractor online: model=%s", GEMINI_MODEL_NAME)

    async def extract(
        self, raw_text: str, origin: str = "unknown"
    ) -> FraudExtractionBatch:
        """Synthesize one raw document into structured fraud datapoints."""
        if not raw_text or not raw_text.strip():
            return FraudExtractionBatch.empty()
        payload: str = raw_text.strip()[:MAX_INPUT_CHARS]
        messages: List[object] = [
            SystemMessage(content=SYSTEM_DIRECTIVE),
            HumanMessage(content=f"RAW DOCUMENT:\n\n{payload}"),
        ]
        try:
            result: Optional[FraudExtractionBatch] = await asyncio.wait_for(
                self._llm.ainvoke(messages),
                timeout=EXTRACTION_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            LOGGER.error("origin=%s: extraction timed out", origin)
            return FraudExtractionBatch.empty()
        except GoogleGenerativeAIError:
            LOGGER.exception("origin=%s: Gemini API fault", origin)
            return FraudExtractionBatch.empty()
        except ValidationError:
            LOGGER.exception("origin=%s: Pydantic validation anomaly", origin)
            return FraudExtractionBatch.empty()
        except ValueError:
            LOGGER.exception("origin=%s: structured-output parse fault", origin)
            return FraudExtractionBatch.empty()
        if result is None:
            return FraudExtractionBatch.empty()
        LOGGER.info("origin=%s: extracted %d datapoints",
                    origin, len(result.records))
        return result
