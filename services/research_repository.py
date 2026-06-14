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
        str(record.financial_loss_inr),
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
                    cursor: aiosqlite.Cursor = await connection.execute(
                        "INSERT OR IGNORE INTO fraud_records ("
                        " source_platform, source_tier, publish_timestamp, "
                        " state, city, scam_vector_type, extracted_case_count, "
                        " financial_loss_inr, demographic_age_bracket, "
                        " demographic_gender_ratio, demographic_profession_target, "
                        " official_safety_advisory, source_url, content_hash) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            meta.source_platform, meta.source_tier,
                            record.publish_timestamp, record.state, record.city,
                            record.scam_vector_type, record.extracted_case_count,
                            record.financial_loss_inr, record.demographic_age_bracket,
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


def geospatial_hotspots(
    interval: str, database_path: Path = SQLITE_PATH
) -> List[Dict[str, object]]:
    """State/city scam density and financial impact within the interval."""
    cutoff: str = _interval_cutoff(interval)
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(
            f"SELECT state, city, "
            f"  SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss, "
            f"  COUNT(*)                  AS reports "
            f"FROM fraud_records "
            f"WHERE state IS NOT NULL AND {_DATE_EXPR} >= ? "
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
    interval: str, dimension: str, database_path: Path = SQLITE_PATH
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
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(
            f"SELECT {column} AS bucket, "
            f"  SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss "
            f"FROM fraud_records "
            f"WHERE {column} IS NOT NULL AND {column} != '' "
            f"  AND {_DATE_EXPR} >= ? "
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
        rows: List[sqlite3.Row] = connection.execute(
            f"SELECT scam_vector_type, state, official_safety_advisory, "
            f"  {_DATE_EXPR} AS dated, source_platform "
            f"FROM fraud_records "
            f"WHERE official_safety_advisory IS NOT NULL "
            f"  AND official_safety_advisory != '' "
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


def state_versus_national(
    interval: str, state: str, database_path: Path = SQLITE_PATH
) -> Dict[str, object]:
    """Localized state metrics against macro national averages."""
    cutoff: str = _interval_cutoff(interval)
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        national: sqlite3.Row = connection.execute(
            f"SELECT COUNT(DISTINCT state) AS states, "
            f"  SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss "
            f"FROM fraud_records "
            f"WHERE state IS NOT NULL AND {_DATE_EXPR} >= ?",
            (cutoff,),
        ).fetchone()
        local: sqlite3.Row = connection.execute(
            f"SELECT SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss, "
            f"  COUNT(*)                  AS reports "
            f"FROM fraud_records "
            f"WHERE state = ? AND {_DATE_EXPR} >= ?",
            (state, cutoff),
        ).fetchone()
    except sqlite3.Error:
        LOGGER.exception("state_versus_national query failed")
        return {}
    finally:
        connection.close()
    state_count: int = int(national["states"] or 0)
    nat_cases: int = int(national["cases"] or 0)
    nat_loss: float = float(national["loss"] or 0.0)
    avg_cases: float = nat_cases / state_count if state_count else 0.0
    avg_loss: float = nat_loss / state_count if state_count else 0.0
    return {
        "state": state,
        "state_cases": int(local["cases"] or 0),
        "state_loss": float(local["loss"] or 0.0),
        "state_reports": int(local["reports"] or 0),
        "national_avg_cases": round(avg_cases, 2),
        "national_avg_loss": round(avg_loss, 2),
        "national_total_cases": nat_cases,
        "national_total_loss": nat_loss,
    }


def scam_vector_landscape(
    interval: str, database_path: Path = SQLITE_PATH
) -> List[Dict[str, object]]:
    """Scam-vector distribution (cases + financial toll) within the interval."""
    cutoff: str = _interval_cutoff(interval)
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(
            f"SELECT scam_vector_type AS vector, "
            f"  SUM(extracted_case_count) AS cases, "
            f"  SUM(financial_loss_inr)   AS loss, "
            f"  COUNT(*)                  AS reports "
            f"FROM fraud_records "
            f"WHERE scam_vector_type IS NOT NULL AND scam_vector_type != '' "
            f"  AND {_DATE_EXPR} >= ? "
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
    """All states present in the corpus, for the state-tracker selector."""
    connection: sqlite3.Connection = readonly_connection(database_path)
    try:
        rows: List[sqlite3.Row] = connection.execute(
            "SELECT DISTINCT state FROM fraud_records "
            "WHERE state IS NOT NULL AND state != '' ORDER BY state"
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
