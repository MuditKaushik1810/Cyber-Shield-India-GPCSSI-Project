"""Cyber Shield India — FastAPI Gateway (STATUS.md Step 4.1).

ASGI-compliant operational gateway exposing the analytical engines and the
ingestion pipeline through a versioned ``/api/v1`` router framework:

* ``GET  /api/v1/analytics/mavi``     — composite MAVI risk matrix + anomaly profile.
* ``GET  /api/v1/analytics/kcvi``     — delivery vector shares + kill chain failure point.
* ``GET  /api/v1/analytics/horizons`` — rolling 24h/7d/30d/1y snapshot matrices.
* ``POST /api/v1/ingest/text``        — raw threat text → Gemini 2.5 Flash extraction
  → concurrent relational inserts + ChromaDB chunk commits → extraction manifest.
* ``POST /api/v1/rag/query``          — guarded RAG inference: dual-collection
  retrieval → guardrail prompt → grounded, cited answer (or integrity fallback).

A lifespan handler drives ``core.database.init_db()`` so both persistence
tiers are physically validated before the gateway accepts traffic.
``CORSMiddleware`` clears cross-origin parameters for the Phase 5 Streamlit
dashboard. Global exception handlers map database anomalies, validation
failures, and timeouts onto clean structural JSON responses, with unified
telemetry rotating daily into ``logs/gateway.log``.
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import AsyncGenerator, Dict, List, Optional, Tuple

import aiosqlite
from fastapi import FastAPI, APIRouter, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from core.database import SQLITE_PATH, VectorStoreManager, init_db
from services.analytics import (
    AnalyticsResult,
    KcviResult,
    MaviAnalyticsProcessor,
    TimeHorizonMatrix,
    calculate_kcvi,
    compute_time_horizons,
)
from services.extractor import DownstreamExtractionController, ExtractionResult
from services.ingestion import DocumentChunk, DocumentExtractionPipeline, MetadataValue
from services.rag_service import get_rag_service

# --------------------------------------------------------------------------- #
# Unified gateway telemetry — daily-rotating channel: logs/gateway.log.       #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the gateway logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.gateway")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "gateway.log",
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
# Request/response contracts.                                                 #
# --------------------------------------------------------------------------- #


class IngestTextRequest(BaseModel):
    """Raw unstructured threat text payload entering the grid."""

    text: str = Field(min_length=40, max_length=100_000,
                      description="Raw article, advisory, or commentary text.")
    origin: str = Field(default="api", max_length=120,
                        description="Caller-supplied provenance label.")
    source: str = Field(default="api_ingest", max_length=200,
                        description="Publishing source for chunk metadata.")
    url: Optional[str] = Field(default=None, max_length=1000,
                               description="Canonical URL of the payload, if any.")


class IngestManifest(BaseModel):
    """Finalized manifest returned after one ingestion pass."""

    incidents_inserted: int = Field(ge=0)
    entities_upserted: int = Field(ge=0)
    advisories_inserted: int = Field(ge=0)
    chunks_committed: int = Field(ge=0)
    vector_ids: List[str] = Field(default_factory=list)
    extraction: ExtractionResult
    ingested_at: str


class RagQueryRequest(BaseModel):
    """Natural-language query entering the guarded RAG engine."""

    query: str = Field(min_length=3, max_length=2000,
                       description="The user's natural-language question.")
    filters: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional ChromaDB metadata filters "
                    "(e.g. {'threat_category': 'apk_sideloading'}).")


class RagQueryResponse(BaseModel):
    """Structured guarded-inference envelope returned by the RAG service."""

    answer: str
    citations: List[Dict[str, object]] = Field(default_factory=list)
    grounded: bool
    fallback_reason: Optional[str] = None
    chunks_retrieved: int = Field(ge=0)
    query: str
    generated_at: str


# --------------------------------------------------------------------------- #
# Lazy service singletons (constructed on first use, never at import).        #
# --------------------------------------------------------------------------- #

_extractor: Optional[DownstreamExtractionController] = None
_chunk_pipeline: Optional[DocumentExtractionPipeline] = None
_vector_store: Optional[VectorStoreManager] = None


def get_extractor() -> DownstreamExtractionController:
    """Return the shared Gemini extraction controller."""
    global _extractor
    if _extractor is None:
        _extractor = DownstreamExtractionController()
    return _extractor


def get_chunk_pipeline() -> DocumentExtractionPipeline:
    """Return the shared 800/100 chunking pipeline."""
    global _chunk_pipeline
    if _chunk_pipeline is None:
        _chunk_pipeline = DocumentExtractionPipeline()
    return _chunk_pipeline


def get_vector_store() -> VectorStoreManager:
    """Return the shared ChromaDB persistence manager."""
    global _vector_store
    if _vector_store is None:
        _vector_store = VectorStoreManager()
    return _vector_store


# --------------------------------------------------------------------------- #
# Ingestion orchestration (relational + vector tiers, concurrent).            #
# --------------------------------------------------------------------------- #


async def _persist_extraction(
    extraction: ExtractionResult, payload: IngestTextRequest
) -> Tuple[int, int, int]:
    """Insert the extraction matrix into the relational tier.

    Returns (incidents_inserted, entities_upserted, advisories_inserted).
    Rolls back the whole transaction on any aiosqlite fault.
    """
    incidents_inserted: int = 0
    entities_upserted: int = 0
    advisories_inserted: int = 0
    async with aiosqlite.connect(SQLITE_PATH) as connection:
        try:
            await connection.execute("PRAGMA foreign_keys = ON")
            for incident in extraction.incidents:
                cursor: aiosqlite.Cursor = await connection.execute(
                    "INSERT OR IGNORE INTO incidents "
                    "(title, source, url, date_published, threat_category, "
                    " jurisdiction, severity) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (incident.title, payload.source, payload.url,
                     incident.date, incident.threat_category,
                     incident.jurisdiction, incident.severity),
                )
                incidents_inserted += cursor.rowcount if cursor.rowcount > 0 else 0
            for entity in extraction.entities:
                await connection.execute(
                    "INSERT INTO entities (entity_type, value, risk_score) "
                    "VALUES (?, ?, ?) "
                    "ON CONFLICT (entity_type, value) DO UPDATE SET "
                    "last_seen = datetime('now'), "
                    "risk_score = MAX(risk_score, excluded.risk_score)",
                    (entity.entity_type, entity.value, entity.risk_score),
                )
                entities_upserted += 1
            for advisory in extraction.advisories:
                await connection.execute(
                    "INSERT INTO expert_advisories "
                    "(expert_name, advisory_text, target_vector, cve_id) "
                    "VALUES (?, ?, ?, ?)",
                    (advisory.expert_name, advisory.advisory_text,
                     advisory.target_vector, advisory.cve_id),
                )
                advisories_inserted += 1
            await connection.commit()
        except aiosqlite.Error:
            await connection.rollback()
            LOGGER.exception(
                "origin=%s: relational persistence failed — rolled back",
                payload.origin,
            )
            raise
    return incidents_inserted, entities_upserted, advisories_inserted


def _commit_chunks_to_vector_store(
    payload: IngestTextRequest, extraction: ExtractionResult
) -> List[str]:
    """Chunk the raw payload and commit it into ChromaDB (sync, off-loop)."""
    threat_category: str = (
        extraction.incidents[0].threat_category
        if extraction.incidents else "general_cyber"
    )
    date_published: str = next(
        (incident.date for incident in extraction.incidents if incident.date), ""
    ) or ""
    metadata: Dict[str, MetadataValue] = {
        "source": payload.source,
        "url": payload.url or "",
        "date_published": date_published,
        "jurisdiction": "National",
        "threat_category": threat_category,
        "title": payload.text.strip()[:120],
    }
    parent_key: str = f"ingest-{abs(hash((payload.text, payload.url)))}"
    chunks: List[DocumentChunk] = get_chunk_pipeline().chunk_text(
        payload.text, metadata, parent_key
    )
    if not chunks:
        return []
    collection = get_vector_store().get_collection("threat_intel_chunks")
    collection.add(
        ids=[chunk.chunk_id for chunk in chunks],
        documents=[chunk.text for chunk in chunks],
        metadatas=[
            {key: ("" if value is None else value)
             for key, value in chunk.metadata.items()}
            for chunk in chunks
        ],
    )
    return [chunk.chunk_id for chunk in chunks]


# --------------------------------------------------------------------------- #
# Application lifespan — both tiers validated before traffic is accepted.     #
# --------------------------------------------------------------------------- #


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """Validate the dual-tier stores, then open the gateway for traffic."""
    summary: Dict[str, List[str]] = await init_db()
    LOGGER.info(
        "Gateway lifespan: stores validated (%d tables, %d collections) — "
        "accepting traffic",
        len(summary["sqlite_tables"]), len(summary["vector_collections"]),
    )
    yield
    LOGGER.info("Gateway lifespan: shutdown complete")


app: FastAPI = FastAPI(
    title="Cyber Shield India — Threat Intelligence Gateway",
    version="1.0.0",
    lifespan=lifespan,
)

# Cross-origin clearance for the Phase 5 Streamlit command center.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "http://127.0.0.1:8501",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# --------------------------------------------------------------------------- #
# Global exception handlers — clean structural JSON, full forensic traces.    #
# --------------------------------------------------------------------------- #


async def _database_fault_handler(
    request: Request, exc: aiosqlite.Error
) -> JSONResponse:
    """Map relational store anomalies onto a structural 500."""
    LOGGER.exception("path=%s: relational store anomaly", request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "relational_store_anomaly",
                 "detail": "The relational tier rejected the operation.",
                 "path": request.url.path},
    )


async def _validation_fault_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Map malformed request payloads onto a structural 400."""
    LOGGER.warning("path=%s: request validation failed: %s",
                   request.url.path, exc.errors())
    return JSONResponse(
        status_code=400,
        content={"error": "request_validation_failed",
                 "detail": exc.errors(),
                 "path": request.url.path},
    )


async def _model_fault_handler(
    request: Request, exc: ValidationError
) -> JSONResponse:
    """Map internal Pydantic anomalies onto a structural 500."""
    LOGGER.exception("path=%s: internal model validation anomaly",
                     request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error": "internal_model_anomaly",
                 "detail": "An internal data structure failed validation.",
                 "path": request.url.path},
    )


async def _timeout_fault_handler(
    request: Request, exc: asyncio.TimeoutError
) -> JSONResponse:
    """Map upstream timeouts onto a structural 504."""
    LOGGER.error("path=%s: upstream operation timed out", request.url.path)
    return JSONResponse(
        status_code=504,
        content={"error": "upstream_timeout",
                 "detail": "An upstream engine did not respond in time.",
                 "path": request.url.path},
    )


app.add_exception_handler(aiosqlite.Error, _database_fault_handler)
app.add_exception_handler(RequestValidationError, _validation_fault_handler)
app.add_exception_handler(ValidationError, _model_fault_handler)
app.add_exception_handler(asyncio.TimeoutError, _timeout_fault_handler)

# --------------------------------------------------------------------------- #
# Versioned operational router.                                               #
# --------------------------------------------------------------------------- #

api_v1: APIRouter = APIRouter(prefix="/api/v1")


@api_v1.get("/analytics/mavi", response_model=AnalyticsResult,
            summary="Composite MAVI risk matrix over the live stores")
async def get_mavi_analytics() -> AnalyticsResult:
    """Execute the MAVI engine against the live dual-tier stores."""
    LOGGER.info("GET /analytics/mavi")
    return await MaviAnalyticsProcessor().compute_from_stores()


@api_v1.get("/analytics/kcvi", response_model=KcviResult,
            summary="Kill chain delivery vector shares and failure point")
async def get_kcvi_analytics() -> KcviResult:
    """Aggregate real-time delivery vector distributions."""
    LOGGER.info("GET /analytics/kcvi")
    return await calculate_kcvi()


@api_v1.get("/analytics/horizons", response_model=TimeHorizonMatrix,
            summary="Rolling 24h/7d/30d/1y snapshot matrices")
async def get_time_horizons() -> TimeHorizonMatrix:
    """Generate the four-interval temporal snapshot matrix."""
    LOGGER.info("GET /analytics/horizons")
    return await compute_time_horizons()


@api_v1.post("/ingest/text", response_model=IngestManifest, status_code=201,
             summary="Extract, persist, and vectorize one raw threat text")
async def ingest_text(payload: IngestTextRequest) -> IngestManifest:
    """Full ingestion pass: extraction → concurrent dual-tier persistence."""
    LOGGER.info("POST /ingest/text origin=%s chars=%d",
                payload.origin, len(payload.text))
    extraction: ExtractionResult = await get_extractor().extract(
        payload.text, origin=payload.origin
    )
    relational_counts: Tuple[int, int, int]
    vector_ids: List[str]
    relational_counts, vector_ids = await asyncio.gather(
        _persist_extraction(extraction, payload),
        asyncio.to_thread(_commit_chunks_to_vector_store, payload, extraction),
    )
    manifest: IngestManifest = IngestManifest(
        incidents_inserted=relational_counts[0],
        entities_upserted=relational_counts[1],
        advisories_inserted=relational_counts[2],
        chunks_committed=len(vector_ids),
        vector_ids=vector_ids,
        extraction=extraction,
        ingested_at=datetime.now(timezone.utc).isoformat(),
    )
    LOGGER.info(
        "Ingest manifest: incidents=%d entities=%d advisories=%d chunks=%d",
        manifest.incidents_inserted, manifest.entities_upserted,
        manifest.advisories_inserted, manifest.chunks_committed,
    )
    return manifest


@api_v1.post("/rag/query", response_model=RagQueryResponse,
             summary="Guarded RAG inference over the official vector corpus")
async def rag_query(payload: RagQueryRequest) -> RagQueryResponse:
    """Dual-collection retrieval → guardrail prompt → grounded, cited answer.

    The RAG service degrades internally to the mandated integrity fallback
    on any retrieval, timeout, or LLM anomaly, so this route always returns
    a structurally valid envelope; the global gateway handlers remain the
    final safety net for unexpected runtime faults.
    """
    LOGGER.info("POST /rag/query chars=%d filters=%s",
                len(payload.query), payload.filters or {})
    envelope: Dict[str, object] = await get_rag_service().generate_response(
        payload.query, payload.filters
    )
    response: RagQueryResponse = RagQueryResponse(**envelope)  # type: ignore[arg-type]
    LOGGER.info("RAG envelope: grounded=%s citations=%d fallback=%s",
                response.grounded, len(response.citations),
                response.fallback_reason or "-")
    return response


app.include_router(api_v1)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
