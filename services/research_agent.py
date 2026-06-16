"""Cyber Shield India — Agentic Analytics Planner (safe NL → SQL → chart).

Turns a researcher's natural-language analytical question into a deterministic,
auditable plan: Gemini emits a strictly-validated ``SELECT``-only SQL query
plus a structured chart specification. The SQL runs against a SQLite
**read-only** connection; the chart is built deterministically from the spec
by the caller (no LLM-authored Python is ever executed — that would be remote
code execution). When a question is not chartable, the planner defers to the
semantic RAG path.

Defense in depth around the SQL:
1. Gemini is told to produce one read-only SELECT over ``fraud_records``.
2. ``validate_select`` rejects multi-statement, DDL/DML, or pragma payloads.
3. Execution uses ``mode=ro`` so the engine itself forbids any mutation.
"""

import logging
import re
import sqlite3
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai._common import GoogleGenerativeAIError
from pydantic import BaseModel, Field, ValidationError

from core.config import get_google_api_key
from core.database import SQLITE_PATH
from services.research_repository import readonly_connection

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the research-agent logger (midnight-rotating)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.research_agent")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "frontend.log",
        when="midnight", backupCount=14, encoding="utf-8",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOGGER: logging.Logger = _build_logger()

from core.config import GEMINI_FLASH_MODEL as _FLASH
GEMINI_MODEL_NAME: str = _FLASH
MAX_ROWS: int = 500

ChartType = Literal["bar", "line", "pie", "scatter", "none"]

# The single table the agent may query, plus its columns, for the prompt.
SCHEMA_BRIEF: str = (
    "Table fraud_records(\n"
    "  id INTEGER, source_platform TEXT, source_tier TEXT,\n"
    "  publish_timestamp TEXT, state TEXT, city TEXT, scam_vector_type TEXT,\n"
    "  threat_domain TEXT, extracted_case_count INTEGER, financial_loss_inr REAL,\n"
    "  records_exposed INTEGER, incident_count INTEGER, severity_level TEXT,\n"
    "  demographic_age_bracket TEXT, demographic_gender_ratio TEXT,\n"
    "  demographic_profession_target TEXT, official_safety_advisory TEXT,\n"
    "  ingested_at TEXT)\n"
    "threat_domain is one of 'Financial Fraud','Data Leak','Deepfake/Extortion',"
    "'Phishing/Spam','MITM/Infrastructure'. records_exposed/incident_count are "
    "non-financial impact metrics (may be NULL). "
    "Use COALESCE(publish_timestamp, ingested_at) for date filtering. "
    "Money is in INR. Aggregate with SUM/COUNT/AVG and GROUP BY."
)

_FORBIDDEN: Tuple[str, ...] = (
    "insert", "update", "delete", "drop", "alter", "create", "attach",
    "detach", "pragma", "replace", "vacuum", "reindex", "trigger",
)


class AnalyticalPlan(BaseModel):
    """A validated plan for answering one analytical question."""

    intent: Literal["chart", "semantic"] = Field(
        description="'chart' if the question maps to a SQL aggregation over "
                    "fraud_records; 'semantic' if it needs document context.")
    sql: Optional[str] = Field(
        default=None,
        description="A single read-only SELECT over fraud_records. Required "
                    "when intent='chart'. No other statement type is allowed.")
    chart_type: ChartType = Field(
        default="bar",
        description="How to plot the SQL result: bar, line, pie, scatter.")
    x: Optional[str] = Field(
        default=None, description="Result column for the x-axis / labels.")
    y: Optional[str] = Field(
        default=None, description="Result column for the y-axis / values.")
    color: Optional[str] = Field(
        default=None, description="Optional result column for series colour.")
    title: str = Field(default="Analytical result",
                       description="Concise human-readable chart title.")


SYSTEM_DIRECTIVE: str = (
    "You are the analytics planner for Cyber Shield India, an open-access "
    "research repository on Indian cybercrime trends. Convert the user's "
    "question into a plan over this read-only schema:\n\n"
    f"{SCHEMA_BRIEF}\n\n"
    "RULES:\n"
    "1. If the question can be answered by aggregating fraud_records, set "
    "intent='chart' and write ONE SQL SELECT statement (no semicolons, no "
    "writes, no PRAGMA). Alias aggregates clearly (e.g. SUM(...) AS loss).\n"
    "2. Pick x, y (and optional color) from your SELECT's output column "
    "aliases, and the best chart_type.\n"
    "3. If the question needs descriptive document context rather than "
    "numbers, set intent='semantic' and leave sql null.\n"
    "4. Never reference any table other than fraud_records."
)


def validate_select(sql: str) -> Optional[str]:
    """Return a sanitized single SELECT, or None if the SQL is unsafe."""
    if not sql or not sql.strip():
        return None
    cleaned: str = sql.strip().rstrip(";").strip()
    # Reject stacked statements (anything after the first ; was already cut;
    # a remaining ; means an embedded second statement).
    if ";" in cleaned:
        LOGGER.warning("SQL rejected: multiple statements")
        return None
    lowered: str = cleaned.lower()
    if not re.match(r"^\s*select\b", lowered):
        LOGGER.warning("SQL rejected: not a SELECT")
        return None
    for token in _FORBIDDEN:
        if re.search(rf"\b{token}\b", lowered):
            LOGGER.warning("SQL rejected: forbidden token %r", token)
            return None
    if "fraud_records" not in lowered:
        LOGGER.warning("SQL rejected: does not reference fraud_records")
        return None
    # Enforce a row cap defensively.
    if not re.search(r"\blimit\b", lowered):
        cleaned = f"{cleaned} LIMIT {MAX_ROWS}"
    return cleaned


def run_select(
    sql: str, database_path: Path = SQLITE_PATH
) -> Tuple[List[Dict[str, object]], Optional[str]]:
    """Execute a validated SELECT read-only; returns (rows, error)."""
    safe_sql: Optional[str] = validate_select(sql)
    if safe_sql is None:
        return [], "The generated query was not a safe read-only SELECT."
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(safe_sql).fetchall()
    except sqlite3.Error as fault:
        LOGGER.exception("read-only SELECT failed")
        return [], f"Query execution failed: {fault}"
    finally:
        connection.close()
    return [dict(row) for row in rows], None


class ResearchAgent:
    """Gemini-backed planner that maps questions onto safe SQL + chart specs."""

    def __init__(self, temperature: float = 0.0) -> None:
        self._llm = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL_NAME,
            temperature=temperature,
            google_api_key=get_google_api_key(),
        ).with_structured_output(AnalyticalPlan)
        LOGGER.info("Research agent online: model=%s", GEMINI_MODEL_NAME)

    def plan(self, question: str) -> Optional[AnalyticalPlan]:
        """Produce an analytical plan for one question (None on fault)."""
        messages: List[object] = [
            SystemMessage(content=SYSTEM_DIRECTIVE),
            HumanMessage(content=f"QUESTION: {question.strip()}"),
        ]
        try:
            return self._llm.invoke(messages)
        except GoogleGenerativeAIError:
            LOGGER.exception("planner Gemini fault for question=%r", question[:80])
            return None
        except ValidationError:
            LOGGER.exception("planner validation fault for question=%r", question[:80])
            return None
        except ValueError:
            LOGGER.exception("planner parse fault for question=%r", question[:80])
            return None
