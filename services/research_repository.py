"""Cyber Shield India — Research Repository persistence & analytics layer.

Two faces over the ``fraud_records`` table and the ``research_corpus``
vector collection:

* **Write side (async, ``aiosqlite``)** — used by the autonomous ingestion
  worker. ``persist_batch`` inserts each AI-synthesized datapoint (idempotent
  via a content hash), chunks the raw document, and commits those chunks to
  ChromaDB keyed by the new ``fraud_records.id`` for clean attribution.

* **Read side (sync, read-only ``sqlite3``)** — used by the Streamlit
  frontend. Interval-filtered aggregations for the geospatial, demographic,
  and localized-state dashboard modules. Connections are opened in SQLite
  read-only URI mode so the frontend can never mutate the curated corpus.

Interval windows: 1d / 1w / 1m / 1y, filtered on
``COALESCE(publish_timestamp, ingested_at)``.
"""

import hashlib
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiosqlite

from core.database import SQLITE_PATH, VectorStoreManager
from services.ingestion import DocumentChunk, DocumentExtractionPipeline, MetadataValue
from services.research_extractor import FraudExtractionBatch, FraudRecordExtraction

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the research-repository logger (midnight-rotating)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.research_repo")
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

RESEARCH_COLLECTION: str = "research_corpus"

# Interval label -> rolling window length for chronological filtering.
INTERVAL_WINDOWS: Dict[str, timedelta] = {
    "1d": timedelta(days=1),
    "1w": timedelta(days=7),
    "1m": timedelta(days=30),
    "1y": timedelta(days=365),
}
INTERVAL_LABELS: Dict[str, str] = {
    "1d": "Past 1 Day",
    "1w": "Past 1 Week",
    "1m": "Past 1 Month",
    "1y": "Past 1 Year",
}


# --------------------------------------------------------------------------- #
# Document metadata container passed from the worker.                         #
# --------------------------------------------------------------------------- #


class SourceMeta:
    """Provenance metadata for one harvested document."""

    def __init__(
        self,
        source_platform: str,
        source_tier: str,
        source_url: Optional[str] = None,
    ) -> None:
        self.source_platform: str = source_platform
        self.source_tier: str = source_tier
        self.source_url: Optional[str] = source_url


def _content_hash(meta: SourceMeta, record: FraudRecordExtraction) -> str:
    """Stable dedup hash over provenance + the record's identifying fields."""
    basis: str = "|".join([
        meta.source_platform,
        meta.source_url or "",
        record.scam_vector_type,
        record.state or "",
        record.city or "",
        str(record.extracted_case_count),
        # Phase 2 schema: financial_loss_inr was split into temporal variants.
        str(record.incident_loss_inr),
        str(record.macro_summary_loss_inr),
        record.publish_timestamp or "",
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Write side — async, used by the ingestion worker.                          #
# --------------------------------------------------------------------------- #


class ResearchRepository:
    """Async writer for the curated research corpus (relational + vector)."""

    def __init__(self, database_path: Path = SQLITE_PATH) -> None:
        self.database_path: Path = database_path
        self._chunker: DocumentExtractionPipeline = DocumentExtractionPipeline()
        self._vector_store: VectorStoreManager = VectorStoreManager()

    async def persist_batch(
        self, batch: FraudExtractionBatch, meta: SourceMeta, raw_text: str
    ) -> int:
        """Insert each datapoint and commit its chunks; returns rows written."""
        if not batch.records:
            return 0
        written: int = 0
        async with aiosqlite.connect(self.database_path) as connection:
            try:
                await connection.execute("PRAGMA journal_mode=WAL")
                for record in batch.records:
                    digest: str = _content_hash(meta, record)
                    # Compat column: only isolated-incident losses populate the
                    # window-aggregated financial_loss_inr; macro summaries are
                    # retained separately so they never inflate short windows.
                    isolated: int = 1 if record.is_isolated_incident else 0
                    macro: int = 1 if record.is_macro_historical_summary else 0
                    financial_loss: float = (
                        record.incident_loss_inr if record.is_isolated_incident else 0.0
                    )
                    cursor: aiosqlite.Cursor = await connection.execute(
                        "INSERT OR IGNORE INTO fraud_records ("
                        " source_platform, source_tier, publish_timestamp, "
                        " state, city, scam_vector_type, extracted_case_count, "
                        " financial_loss_inr, is_isolated_incident, incident_loss_inr, "
                        " is_macro_historical_summary, macro_summary_loss_inr, "
                        " demographic_age_bracket, demographic_gender_ratio, "
                        " demographic_profession_target, official_safety_advisory, "
                        " source_url, content_hash) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            meta.source_platform, meta.source_tier,
                            record.publish_timestamp, record.state, record.city,
                            record.scam_vector_type, record.extracted_case_count,
                            financial_loss, isolated, record.incident_loss_inr,
                            macro, record.macro_summary_loss_inr,
                            record.demographic_age_bracket,
                            record.demographic_gender_ratio,
                            record.demographic_profession_target,
                            record.official_safety_advisory, meta.source_url, digest,
                        ),
                    )
                    if cursor.rowcount and cursor.lastrowid:
                        written += 1
                        await self._commit_chunks(
                            cursor.lastrowid, meta, record, raw_text
                        )
                await connection.commit()
            except aiosqlite.Error:
                await connection.rollback()
                LOGGER.exception("persist_batch failed — rolled back")
                raise
        LOGGER.info("Persisted %d/%d datapoints from %s",
                    written, len(batch.records), meta.source_platform)
        return written

    async def _commit_chunks(
        self, record_id: int, meta: SourceMeta,
        record: FraudRecordExtraction, raw_text: str,
    ) -> None:
        """Chunk the raw document and add it to the research corpus."""
        metadata: Dict[str, MetadataValue] = {
            "fraud_record_id": record_id,
            "source_platform": meta.source_platform,
            "source_tier": meta.source_tier,
            "scam_vector_type": record.scam_vector_type,
            "state": record.state or "",
            "url": meta.source_url or "",
            "date_published": record.publish_timestamp or "",
        }
        chunks: List[DocumentChunk] = self._chunker.chunk_text(
            raw_text, metadata, parent_key=f"fraud-{record_id}"
        )
        if not chunks:
            return
        collection = self._vector_store.get_collection(RESEARCH_COLLECTION)
        collection.add(
            ids=[chunk.chunk_id for chunk in chunks],
            documents=[chunk.text for chunk in chunks],
            metadatas=[
                {k: ("" if v is None else v) for k, v in chunk.metadata.items()}
                for chunk in chunks
            ],
        )


# --------------------------------------------------------------------------- #
# Read side — synchronous read-only, used by the Streamlit frontend.         #
# --------------------------------------------------------------------------- #


def _interval_cutoff(interval: str) -> str:
    """Return the ISO cutoff timestamp for an interval label."""
    window: timedelta = INTERVAL_WINDOWS.get(interval, INTERVAL_WINDOWS["1y"])
    cutoff: datetime = datetime.now(timezone.utc) - window
    return cutoff.strftime("%Y-%m-%d %H:%M:%S")


def readonly_connection(database_path: Path = SQLITE_PATH) -> sqlite3.Connection:
    """Open the curated corpus in SQLite read-only URI mode.

    The frontend physically cannot mutate the worker-curated data: any
    write attempt raises ``sqlite3.OperationalError``.
    """
    uri: str = f"file:{database_path}?mode=ro"
    connection: sqlite3.Connection = sqlite3.connect(
        uri, uri=True, check_same_thread=False
    )
    connection.row_factory = sqlite3.Row
    return connection


_DATE_EXPR: str = "COALESCE(publish_timestamp, ingested_at)"
# Phase 2: timeline modules count ONLY verified isolated incidents so that
# cumulative macro-historical figures never inflate a short window.
_ISOLATED_ONLY: str = "is_isolated_incident = 1"


def _demo_clause(exclude_demo: bool) -> str:
    """SQL fragment stripping demo-tier rows when pure-operational mode is on."""
    return "AND source_tier != 'demo' " if exclude_demo else ""


def geospatial_hotspots(
    interval: str, exclude_demo: bool = False, database_path: Path = SQLITE_PATH
) -> List[Dict[str, object]]:
    """State/city scam density and financial impact within the interval."""
    cutoff: str = _interval_cutoff(interval)
    demo: str = _demo_clause(exclude_demo)
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(
            f"SELECT state, city, "
            f"  SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss, "
            f"  COUNT(*)                  AS reports "
            f"FROM fraud_records "
            f"WHERE state IS NOT NULL AND {_ISOLATED_ONLY} {demo}"
            f"  AND {_DATE_EXPR} >= ? "
            f"GROUP BY state, city "
            f"ORDER BY loss DESC",
            (cutoff,),
        ).fetchall()
    except sqlite3.Error:
        LOGGER.exception("geospatial_hotspots query failed")
        return []
    finally:
        connection.close()
    return [dict(row) for row in rows]


def demographic_matrix(
    interval: str, dimension: str, exclude_demo: bool = False,
    database_path: Path = SQLITE_PATH,
) -> List[Dict[str, object]]:
    """Targeted-demographic breakdown for one dimension within the interval.

    ``dimension`` is one of: age, gender, profession.
    """
    column_map: Dict[str, str] = {
        "age": "demographic_age_bracket",
        "gender": "demographic_gender_ratio",
        "profession": "demographic_profession_target",
    }
    column: str = column_map.get(dimension, "demographic_age_bracket")
    cutoff: str = _interval_cutoff(interval)
    demo: str = _demo_clause(exclude_demo)
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(
            f"SELECT {column} AS bucket, "
            f"  SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss "
            f"FROM fraud_records "
            f"WHERE {column} IS NOT NULL AND {column} != '' "
            f"  AND {_ISOLATED_ONLY} {demo}AND {_DATE_EXPR} >= ? "
            f"GROUP BY {column} "
            f"ORDER BY cases DESC",
            (cutoff,),
        ).fetchall()
    except sqlite3.Error:
        LOGGER.exception("demographic_matrix query failed")
        return []
    finally:
        connection.close()
    return [dict(row) for row in rows]


def latest_advisories(
    interval: str, scam_vector: Optional[str] = None,
    limit: int = 6, database_path: Path = SQLITE_PATH,
) -> List[Dict[str, object]]:
    """Most recent official safety advisories, optionally vector-filtered."""
    cutoff: str = _interval_cutoff(interval)
    connection: sqlite3.Connection = readonly_connection(database_path)
    params: List[object] = [cutoff]
    vector_clause: str = ""
    if scam_vector:
        vector_clause = "AND scam_vector_type = ? "
        params.append(scam_vector)
    params.append(limit)
    try:
        # Exclude demo-tier rows: advisory cards must reflect only genuine
        # crawled telemetry, never the 'demo_sample' bring-up seed.
        rows: List[sqlite3.Row] = connection.execute(
            f"SELECT scam_vector_type, state, official_safety_advisory, "
            f"  {_DATE_EXPR} AS dated, source_platform, source_url "
            f"FROM fraud_records "
            f"WHERE official_safety_advisory IS NOT NULL "
            f"  AND official_safety_advisory != '' "
            f"  AND source_tier != 'demo' "
            f"  AND source_platform NOT LIKE '%cron%' "
            f"  AND (source_url IS NULL OR "
            f"       (source_url NOT LIKE '%.local%' AND source_url NOT LIKE '%cron%')) "
            f"  AND {_DATE_EXPR} >= ? {vector_clause}"
            f"ORDER BY {_DATE_EXPR} DESC LIMIT ?",
            tuple(params),
        ).fetchall()
    except sqlite3.Error:
        LOGGER.exception("latest_advisories query failed")
        return []
    finally:
        connection.close()
    return [dict(row) for row in rows]


def _window_fraction(interval: str) -> float:
    """Fraction of a year covered by the interval (for NCRB proration)."""
    window: timedelta = INTERVAL_WINDOWS.get(interval, INTERVAL_WINDOWS["1y"])
    return window.days / 365.0


# Ingestion-deficit detection: a "high baseline" state that yields effectively
# zero live telemetry over a fixed trailing window signals a crawler gap.
HIGH_BASELINE_ANNUAL_CASES: int = 3_000
DEFICIT_LIVE_SHARE_THRESHOLD: float = 0.05
DEFICIT_WINDOW_DAYS: int = 30


def state_versus_national(
    interval: str, state: str, exclude_demo: bool = False,
    database_path: Path = SQLITE_PATH,
) -> Dict[str, object]:
    """Raw live state telemetry alongside an explicit NCRB control benchmark.

    NO substitution: ``live_*`` fields are the unadulterated crawler counters
    (isolated incidents only), reported even when exactly 0. The prorated NCRB
    figures are returned separately as ``benchmark_*`` for an honest overlay,
    never blended into the live numbers. ``ingestion_deficit`` flags a
    high-baseline state producing near-zero telemetry over a 30-day window.
    """
    cutoff: str = _interval_cutoff(interval)
    fraction: float = _window_fraction(interval)
    demo: str = _demo_clause(exclude_demo)
    deficit_cutoff: str = (
        datetime.now(timezone.utc) - timedelta(days=DEFICIT_WINDOW_DAYS)
    ).strftime("%Y-%m-%d %H:%M:%S")
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        local: sqlite3.Row = connection.execute(
            f"SELECT SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss, "
            f"  COUNT(*)                  AS reports "
            f"FROM fraud_records "
            f"WHERE state = ? AND {_ISOLATED_ONLY} {demo}AND {_DATE_EXPR} >= ?",
            (state, cutoff),
        ).fetchone()
        deficit_row: sqlite3.Row = connection.execute(
            f"SELECT SUM(extracted_case_count) AS cases "
            f"FROM fraud_records "
            f"WHERE state = ? AND {_ISOLATED_ONLY} {demo}AND {_DATE_EXPR} >= ?",
            (state, deficit_cutoff),
        ).fetchone()
        baseline: Optional[sqlite3.Row] = connection.execute(
            "SELECT annual_cases, annual_loss_inr, primary_vector "
            "FROM state_baselines WHERE state_name = ?",
            (state,),
        ).fetchone()
        national: sqlite3.Row = connection.execute(
            "SELECT AVG(annual_cases) AS avg_cases, "
            "  AVG(annual_loss_inr) AS avg_loss FROM state_baselines"
        ).fetchone()
    except sqlite3.Error:
        LOGGER.exception("state_versus_national query failed")
        return {}
    finally:
        connection.close()

    # Raw live telemetry — never substituted, may legitimately be 0.
    live_cases: int = int(local["cases"] or 0)
    live_loss: float = float(local["loss"] or 0.0)
    reports: int = int(local["reports"] or 0)

    # Explicit NCRB control benchmark, prorated to the same window.
    annual_cases: int = int(baseline["annual_cases"]) if baseline else 0
    annual_loss: float = float(baseline["annual_loss_inr"]) if baseline else 0.0
    benchmark_cases: float = round(annual_cases * fraction, 1)
    benchmark_loss: float = round(annual_loss * fraction, 2)
    nat_avg_cases: float = round(float(national["avg_cases"] or 0.0) * fraction, 1)
    nat_avg_loss: float = round(float(national["avg_loss"] or 0.0) * fraction, 2)

    # Ingestion-deficit health check over a fixed 30-day trailing window.
    live_30d: int = int(deficit_row["cases"] or 0)
    expected_30d: float = annual_cases * (DEFICIT_WINDOW_DAYS / 365.0)
    ingestion_deficit: bool = (
        annual_cases >= HIGH_BASELINE_ANNUAL_CASES
        and expected_30d > 0
        and live_30d < DEFICIT_LIVE_SHARE_THRESHOLD * expected_30d
    )

    return {
        "state": state,
        "live_cases": live_cases,
        "live_loss": live_loss,
        "live_reports": reports,
        "benchmark_cases": benchmark_cases,
        "benchmark_loss": benchmark_loss,
        "national_avg_cases": nat_avg_cases,
        "national_avg_loss": nat_avg_loss,
        "annual_cases": annual_cases,
        "primary_vector": str(baseline["primary_vector"]) if baseline else "—",
        "ingestion_deficit": ingestion_deficit,
    }


def scam_vector_landscape(
    interval: str, exclude_demo: bool = False, database_path: Path = SQLITE_PATH
) -> List[Dict[str, object]]:
    """Scam-vector distribution (cases + financial toll) within the interval."""
    cutoff: str = _interval_cutoff(interval)
    demo: str = _demo_clause(exclude_demo)
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(
            f"SELECT scam_vector_type AS vector, "
            f"  SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss, "
            f"  COUNT(*)                  AS reports "
            f"FROM fraud_records "
            f"WHERE scam_vector_type IS NOT NULL AND scam_vector_type != '' "
            f"  AND {_ISOLATED_ONLY} {demo}AND {_DATE_EXPR} >= ? "
            f"GROUP BY scam_vector_type "
            f"ORDER BY loss DESC",
            (cutoff,),
        ).fetchall()
    except sqlite3.Error:
        LOGGER.exception("scam_vector_landscape query failed")
        return []
    finally:
        connection.close()
    return [dict(row) for row in rows]


def distinct_states(database_path: Path = SQLITE_PATH) -> List[str]:
    """Full national state/UT list for the tracker selector.

    Drawn from the NCRB baseline registry (all 28 states + 8 UTs) unioned with
    any live-crawled states, so every jurisdiction is selectable even before it
    has been crawled — the tracker then renders the prorated NCRB fallback.
    """
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(
            "SELECT state_name AS state FROM state_baselines "
            "UNION "
            "SELECT state FROM fraud_records "
            "WHERE state IS NOT NULL AND state != '' "
            "ORDER BY state"
        ).fetchall()
    except sqlite3.Error:
        LOGGER.exception("distinct_states query failed")
        return []
    finally:
        connection.close()
    return [str(row["state"]) for row in rows]


def corpus_size(database_path: Path = SQLITE_PATH) -> int:
    """Total datapoints in the curated corpus (0 if table absent/empty)."""
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        row: sqlite3.Row = connection.execute(
            "SELECT COUNT(*) AS n FROM fraud_records"
        ).fetchone()
        return int(row["n"])
    except sqlite3.Error:
        return 0
    finally:
        connection.close()
