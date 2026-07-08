"""Cyber Shield India — RAG Inference Service & Guardrail Prompt Architecture
(STATUS.md Steps 4.2 & 4.3).

**Inference (Step 4.2).** The asynchronous controller semantically searches
BOTH ChromaDB collections (``threat_intel_chunks`` and ``expert_feed_chunks``)
through ``core/database.py``, merges the candidates by cosine distance,
retains the global top-K (K=4), and bundles their text payloads into an
isolated, metadata-annotated context window.

**Guardrails (Step 4.3).** The context window rides a structured system
prompt into Gemini 2.5 Flash enforcing four hard boundaries:

1. *Role* — exclusively an expert Indian digital policing intelligence
   assistant.
2. *Grounding* — answers draw ONLY on the retrieved context; insufficient
   context triggers the mandated integrity fallback instead of fabrication.
3. *Citations* — every technical finding carries inline structural
   attribution (source agency, date, CVE where present).
4. *Scope* — non-cybersecurity prompts receive the standardized refusal.

Defense in depth: a deterministic retrieval-relevance gate fires the
fallback *before* the LLM is ever invoked when the vector space itself
reports no sufficiently close official content — so out-of-scope prompts
are refused even if the model were to misbehave. Forensic traces rotate
daily into ``logs/rag.log``.
"""

import asyncio
import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

from services.llm_errors import LLM_TRANSIENT_ERRORS, is_server_busy

from core.config import get_google_api_key
from core.database import VectorStoreManager

# --------------------------------------------------------------------------- #
# Forensic logging — dedicated daily-rotating channel: logs/rag.log.          #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the RAG logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.rag")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "rag.log",
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
# Guardrail constants.                                                        #
# --------------------------------------------------------------------------- #

# RAG Integrity Guardrail — the unyielding fallback, verbatim.
RAG_FALLBACK_MESSAGE: str = (
    "I am sorry, but I can only provide cyber safety protocols verified by "
    "official government sources."
)

TOP_K: int = 4
# Cosine distance ceiling: retrieval hits farther than this are not
# considered official grounding and trigger the deterministic fallback.
MAX_GROUNDING_DISTANCE: float = 0.70
from core.config import GEMINI_FLASH_MODEL as _FLASH
GEMINI_MODEL_NAME: str = _FLASH
INFERENCE_TIMEOUT_SECONDS: float = 90.0

# Multi-model rotation: the Gemini free-tier daily cap is PER MODEL, so when one
# model exhausts its pool the synthesis cascades to the next endpoint.
MODEL_CASCADE_ORDER: List[str] = [
    "gemini-3.5-flash",
    "gemini-3.1-flash-lite",
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-2.5-flash-lite",
]

# User-facing markdown shown when EVERY model in the cascade is quota-exhausted.
QUOTA_EXHAUSTED_MESSAGE: str = (
    "⚠️ **Daily research capacity reached.** All available community AI models "
    "have hit their free-tier query limit for today. Your search retrieved the "
    "sources below, but the AI summary is paused — please try again shortly, as "
    "capacity resets daily."
)


def _is_quota_error(exc: Exception) -> bool:
    """True if the error is a 429 / RESOURCE_EXHAUSTED quota exhaustion."""
    message: str = str(exc)
    return ("429" in message or "RESOURCE_EXHAUSTED" in message
            or "exceeded your current quota" in message.lower())


def _content_to_text(content: object) -> str:
    """Normalize an LLM completion's content into clean text.

    Newer Gemini models return content as a list of typed blocks
    (``[{'type': 'text', 'text': '...'}]``); older ones return a plain string.
    This flattens both into readable text so the UI never shows raw blocks.
    """
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts: List[str] = []
        for block in content:
            if isinstance(block, dict):
                parts.append(str(block.get("text", "")))
            else:
                parts.append(str(block))
        return " ".join(part for part in parts if part).strip()
    return str(content).strip()

RAG_COLLECTIONS: tuple = (
    "threat_intel_chunks", "expert_feed_chunks", "research_corpus",
)

# Internal system artifacts that must never surface in the public view
# (e.g. cron.local test bulletins). Matched against source + url, case-folded.
INTERNAL_ARTIFACT_MARKERS: tuple = (".local", "cron")


def is_internal_artifact(source: str, url: str) -> bool:
    """True if a chunk's provenance is an internal system artifact."""
    blob: str = f"{source} {url}".lower()
    return any(marker in blob for marker in INTERNAL_ARTIFACT_MARKERS)

GUARDRAIL_SYSTEM_PROMPT: str = (
    "You are the intelligence assistant of Cyber Shield India — an expert "
    "Indian digital policing analyst serving investigators and citizens. "
    "You operate under four ABSOLUTE guardrails:\n"
    "\n"
    "1. ROLE — You act exclusively as an Indian cybercrime and digital "
    "safety intelligence assistant. You hold no other persona.\n"
    "2. GROUNDING — You answer using ONLY the official context chunks "
    "provided below. You must not draw on outside knowledge, speculate, or "
    "fabricate. If the context does not contain the answer to the user's "
    f"question, reply with exactly: \"{RAG_FALLBACK_MESSAGE}\"\n"
    "3. CITATIONS — Every technical finding you present must carry inline "
    "attribution to its context chunk in the form [source, date] or "
    "[source, CVE-ID] when a CVE is present. Never present an uncited "
    "technical claim.\n"
    "4. SCOPE — If the user's request is not about cybersecurity, "
    "cybercrime, digital fraud, or digital safety in India (for example "
    "cooking, creative writing, entertainment, or general trivia), refuse "
    f"politely by replying with exactly: \"{RAG_FALLBACK_MESSAGE}\"\n"
    "\n"
    "Answer clearly and concisely. Hinglish queries may be answered in "
    "simple English with key safety terms restated in Hindi where helpful."
)

# --------------------------------------------------------------------------- #
# Retrieval containers.                                                       #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RetrievedChunk:
    """One semantic hit pulled from a vector collection."""

    text: str
    source: str
    url: str
    date_published: str
    threat_category: str
    collection: str
    distance: float

    def citation(self) -> Dict[str, object]:
        """Structural citation payload for downstream UI cards."""
        return {
            "source": self.source,
            "url": self.url,
            "date_published": self.date_published,
            "threat_category": self.threat_category,
            "collection": self.collection,
            "distance": round(self.distance, 4),
        }


# --------------------------------------------------------------------------- #
# RAG inference service.                                                      #
# --------------------------------------------------------------------------- #


class RagService:
    """Asynchronous dual-collection RAG controller with hard guardrails."""

    def __init__(
        self,
        top_k: int = TOP_K,
        max_grounding_distance: float = MAX_GROUNDING_DISTANCE,
        temperature: float = 0.2,
    ) -> None:
        self.top_k: int = top_k
        self.max_grounding_distance: float = max_grounding_distance
        self._vector_store: VectorStoreManager = VectorStoreManager()
        self._temperature: float = temperature
        self._api_key: str = get_google_api_key()
        # Per-model LLM clients are built lazily and cached for the cascade.
        self._model_clients: dict = {}
        self._llm: ChatGoogleGenerativeAI = self._cascade_llm(GEMINI_MODEL_NAME)
        LOGGER.info(
            "RAG service online: cascade=%s top_k=%d grounding_gate=%.2f",
            MODEL_CASCADE_ORDER, self.top_k, self.max_grounding_distance,
        )

    def _cascade_llm(self, model_name: str) -> ChatGoogleGenerativeAI:
        """Return (and cache) a chat LLM client for one model id."""
        if model_name not in self._model_clients:
            self._model_clients[model_name] = ChatGoogleGenerativeAI(
                model=model_name,
                temperature=self._temperature,
                google_api_key=self._api_key,
            )
        return self._model_clients[model_name]

    async def cascade_invoke(
        self, messages: List[object], origin: str = "synthesis"
    ) -> str:
        """Invoke the LLM, rotating models on 429 exhaustion.

        Returns the model's answer on success; ``QUOTA_EXHAUSTED_MESSAGE`` when
        every model is quota-exhausted (a user-facing markdown string, never a
        traceback); or "" on a non-quota failure. Respects the per-call
        asyncio timeout for every attempt.
        """
        last: int = len(MODEL_CASCADE_ORDER) - 1
        quota_hits: int = 0
        for index, model_name in enumerate(MODEL_CASCADE_ORDER):
            next_model: str = (
                MODEL_CASCADE_ORDER[index + 1] if index < last
                else "(none — cascade exhausted)"
            )
            try:
                completion = await asyncio.wait_for(
                    self._cascade_llm(model_name).ainvoke(messages),
                    timeout=INFERENCE_TIMEOUT_SECONDS,
                )
                return _content_to_text(completion.content)
            except asyncio.TimeoutError:
                LOGGER.warning("%s: model %s timed out — shifting to %s",
                               origin, model_name, next_model)
                continue
            except LLM_TRANSIENT_ERRORS as exc:
                if _is_quota_error(exc):
                    quota_hits += 1
                    LOGGER.warning(
                        "Model %s exhausted its free-tier pool (429) - shifting "
                        "to next fallback endpoint...", model_name)
                elif is_server_busy(exc):
                    LOGGER.warning("%s: model %s experiencing high demand (503) "
                                   "— shifting to %s", origin, model_name, next_model)
                else:
                    LOGGER.warning("%s: model %s unavailable (%s) — shifting to %s",
                                   origin, model_name, type(exc).__name__, next_model)
                continue
            except ValueError:
                LOGGER.warning("%s: model %s payload fault — shifting to %s",
                               origin, model_name, next_model)
                continue
        if quota_hits > 0:
            LOGGER.error("%s: all %d models quota-exhausted — returning "
                         "user-facing notice", origin, len(MODEL_CASCADE_ORDER))
            return QUOTA_EXHAUSTED_MESSAGE
        return ""

    # -- Step 4.2: semantic retrieval --------------------------------------- #

    def _query_collection(
        self, name: str, query: str, filters: Optional[Dict[str, str]]
    ) -> List[RetrievedChunk]:
        """Synchronous Chroma query for one collection (run off-loop)."""
        collection = self._vector_store.get_collection(name)
        if collection.count() == 0:
            return []
        response: Dict[str, object] = collection.query(
            query_texts=[query],
            n_results=min(self.top_k, collection.count()),
            where=filters if filters else None,
            include=["documents", "metadatas", "distances"],
        )
        documents: List[str] = response["documents"][0]          # type: ignore[index]
        metadatas: List[Dict[str, object]] = response["metadatas"][0]  # type: ignore[index]
        distances: List[float] = response["distances"][0]        # type: ignore[index]
        chunks: List[RetrievedChunk] = []
        for text, metadata, distance in zip(documents, metadatas, distances):
            # research_corpus chunks carry 'source_platform'; older collections
            # carry 'source'. Fall back across both so chunks never display as
            # an "unknown" ghost when real provenance exists.
            source: str = str(
                metadata.get("source")
                or metadata.get("source_platform")
                or "unknown"
            )
            category: str = str(
                metadata.get("threat_category")
                or metadata.get("scam_vector_type")
                or ""
            )
            chunks.append(RetrievedChunk(
                text=str(text),
                source=source,
                url=str(metadata.get("url", "")),
                date_published=str(metadata.get("date_published", "")),
                threat_category=category,
                collection=name,
                distance=float(distance),
            ))
        return chunks

    async def retrieve(
        self, query: str, filters: Optional[Dict[str, str]] = None
    ) -> List[RetrievedChunk]:
        """Search every collection and keep the global top-K.

        Queried in-thread: ChromaDB's local persistent client is not reliably
        usable across the asyncio thread pool (it raises a tenant-connection
        error), and local cosine lookups are fast enough to run inline.
        """
        try:
            batches: List[List[RetrievedChunk]] = [
                self._query_collection(name, query, filters)
                for name in RAG_COLLECTIONS
            ]
        except (ValueError, KeyError):
            LOGGER.exception("Vector retrieval anomaly for query=%r", query[:80])
            return []
        # Strip internal system artifacts (.local / cron) before ranking so
        # they can never leak into the public semantic view.
        merged: List[RetrievedChunk] = sorted(
            (
                chunk for batch in batches for chunk in batch
                if not is_internal_artifact(chunk.source, chunk.url)
            ),
            key=lambda chunk: chunk.distance,
        )[: self.top_k]
        LOGGER.info(
            "Retrieved %d chunks (best=%.4f worst=%.4f) for query=%r",
            len(merged),
            merged[0].distance if merged else -1.0,
            merged[-1].distance if merged else -1.0,
            query[:80],
        )
        return merged

    @staticmethod
    def _build_context_window(chunks: List[RetrievedChunk]) -> str:
        """Bundle retrieved payloads into an isolated, annotated window."""
        blocks: List[str] = []
        for index, chunk in enumerate(chunks, start=1):
            header: str = (
                f"[CHUNK {index} | source: {chunk.source} | "
                f"date: {chunk.date_published or 'undated'} | "
                f"category: {chunk.threat_category or 'unclassified'}]"
            )
            blocks.append(f"{header}\n{chunk.text}")
        return "\n\n---\n\n".join(blocks)

    # -- Step 4.3: guarded generation ---------------------------------------- #

    @staticmethod
    def _fallback_payload(
        query: str, chunks: List[RetrievedChunk], reason: str
    ) -> Dict[str, object]:
        """The unyielding integrity fallback response envelope."""
        LOGGER.info("Fallback triggered (%s) for query=%r", reason, query[:80])
        return {
            "answer": RAG_FALLBACK_MESSAGE,
            "citations": [],
            "grounded": False,
            "fallback_reason": reason,
            "chunks_retrieved": len(chunks),
            "query": query,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    async def generate_response(
        self, query: str, filters: Optional[Dict[str, str]] = None
    ) -> Dict[str, object]:
        """Full guarded inference pass: retrieve → gate → generate → cite."""
        if not query or not query.strip():
            return self._fallback_payload(query or "", [], "blank_query")

        chunks: List[RetrievedChunk] = await self.retrieve(query.strip(), filters)

        # Deterministic relevance gate: if the vector space holds nothing
        # close enough to count as official grounding, refuse before the
        # LLM is ever consulted.
        if not chunks or chunks[0].distance > self.max_grounding_distance:
            return self._fallback_payload(query, chunks, "no_official_grounding")

        context_window: str = self._build_context_window(chunks)
        messages: List[object] = [
            SystemMessage(content=GUARDRAIL_SYSTEM_PROMPT),
            HumanMessage(content=(
                f"OFFICIAL CONTEXT CHUNKS:\n\n{context_window}\n\n"
                f"USER QUERY: {query.strip()}"
            )),
        ]
        # Guarded generation through the multi-model cascade: 429-resilient and
        # content-normalized. The 0.70 grounding gate above already ran, so the
        # safety boundary is intact regardless of which model answers.
        answer: str = await self.cascade_invoke(messages, origin="guarded")
        if answer == QUOTA_EXHAUSTED_MESSAGE:
            LOGGER.error("Guarded inference: every model quota-exhausted for "
                         "query=%r", query[:80])
            return {
                "answer": QUOTA_EXHAUSTED_MESSAGE,
                "citations": [],
                "grounded": False,
                "fallback_reason": "quota_exhausted",
                "chunks_retrieved": len(chunks),
                "query": query,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }
        if not answer:
            return self._fallback_payload(query, chunks, "llm_api_fault")
        refused: bool = RAG_FALLBACK_MESSAGE in answer
        response: Dict[str, object] = {
            "answer": RAG_FALLBACK_MESSAGE if refused else answer,
            "citations": [] if refused else [chunk.citation() for chunk in chunks],
            "grounded": not refused,
            "fallback_reason": "llm_guardrail_refusal" if refused else None,
            "chunks_retrieved": len(chunks),
            "query": query,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        LOGGER.info(
            "Inference complete: grounded=%s citations=%d query=%r",
            response["grounded"], len(response["citations"]), query[:80],  # type: ignore[arg-type]
        )
        return response


# --------------------------------------------------------------------------- #
# Module-level convenience controller.                                        #
# --------------------------------------------------------------------------- #

_service: Optional[RagService] = None


def get_rag_service() -> RagService:
    """Return the shared RAG service singleton (constructed on first use)."""
    global _service
    if _service is None:
        _service = RagService()
    return _service


async def generate_response(
    query: str, filters: Optional[Dict[str, str]] = None
) -> Dict[str, object]:
    """Asynchronous inference controller entrypoint (Step 4.2 contract)."""
    return await get_rag_service().generate_response(query, filters)


async def relaxed_search(query: str, k: int = 5) -> List[Dict[str, object]]:
    """Ungated cosine-similarity fallback over the global corpus.

    Strips all strict metadata/time filters and the grounding-distance gate,
    returning the top conceptual matches regardless of distance. Used by the
    Semantic Explorer when a strict query yields zero database rows.
    """
    service: RagService = get_rag_service()
    chunks: List[RetrievedChunk] = await service.retrieve(query)
    return [
        {
            "text": chunk.text,
            "source": chunk.source,
            "url": chunk.url,
            "date_published": chunk.date_published,
            "threat_category": chunk.threat_category,
            "collection": chunk.collection,
            "distance": round(chunk.distance, 4),
        }
        for chunk in chunks[:k]
    ]


SYNTHESIS_PROMPT: str = (
    "You are the research assistant of Cyber Shield India, an open-access "
    "cybercrime trend repository. Using ONLY the retrieved context snippets "
    "below, write a concise, factual answer to the user's question in plain "
    "English. Ground every claim in the snippets — cite the specific states, "
    "figures, scam types, or agencies that actually appear. If the snippets "
    "are only loosely related to the question, say so honestly and summarise "
    "what IS available instead of inventing facts. Never fabricate numbers, "
    "states, or sources not present in the context. Keep the answer under "
    "160 words."
)

WEB_AUGMENTED_PROMPT: str = (
    "You are the research assistant of Cyber Shield India, an open-access "
    "cybercrime trend repository. You are given two kinds of context: curated "
    "internal corpus snippets ([CORPUS]) and live web search results ([WEB]). "
    "Answer the user's question in plain English using ONLY these snippets. "
    "Prefer [CORPUS] for grounded facts and use [WEB] to add current or broad "
    "context, clearly attributing web-derived claims. Cite specific states, "
    "figures, scam types, or agencies that actually appear. Do not fabricate "
    "anything absent from the context. Keep the answer under 180 words."
)

# Web-augmentation triggers: a query is under-saturated internally when the
# corpus returns too few chunks or the best match is weak, OR the query asks
# for real-time / broad context the static corpus cannot satisfy.
MIN_INTERNAL_CHUNKS: int = 2
WEB_AUGMENTATION_DISTANCE: float = 0.55
REALTIME_MARKERS: Tuple[str, ...] = (
    "latest", "recent", "today", "yesterday", "current", "currently", "now",
    "this week", "this month", "this year", "2026", "2025", "trend",
    "trending", "real-time", "real time", "up to date", "news", "breaking",
)


def needs_web_augmentation(
    query: str, chunks: List[RetrievedChunk]
) -> bool:
    """Decide whether a query warrants a live web sweep."""
    if len(chunks) < MIN_INTERNAL_CHUNKS:
        return True
    if chunks and chunks[0].distance > WEB_AUGMENTATION_DISTANCE:
        return True
    lowered: str = query.lower()
    return any(marker in lowered for marker in REALTIME_MARKERS)


def _build_combined_context(
    chunks: List[RetrievedChunk], web_results: List[Dict[str, str]]
) -> str:
    """Merge internal corpus chunks and web results into one labelled window."""
    blocks: List[str] = []
    for index, chunk in enumerate(chunks, start=1):
        blocks.append(
            f"[CORPUS {index} | source: {chunk.source} | "
            f"date: {chunk.date_published or 'undated'}]\n{chunk.text}"
        )
    for index, result in enumerate(web_results, start=1):
        body: str = " ".join(p for p in (
            result.get("title", ""), result.get("snippet", "")) if p)
        blocks.append(
            f"[WEB {index} | {result.get('link', '')}]\n{body}"
        )
    return "\n\n---\n\n".join(blocks)


WEB_SEED_COLLECTION: str = "research_corpus"
WEB_SEED_DATE: str = "2026-06-16"

# Keyword domain classifier for write-through tags (deterministic, no LLM cost;
# the synthesis already consumes a Flash call). Specific domains checked first.
_DOMAIN_KEYWORDS: Dict[str, tuple] = {
    "Data Leak": ("data leak", "data breach", "records exposed", "leaked",
                  "breach", "database exposed"),
    "Deepfake/Extortion": ("deepfake", "extortion", "sextortion", "blackmail",
                           "morphed", "ai-generated"),
    "MITM/Infrastructure": ("man-in-the-middle", "mitm", "router", "dns",
                            "interception", "rogue wifi", "infrastructure"),
    "Phishing/Spam": ("phishing", "smishing", "vishing", "spam", "fake link"),
    "Financial Fraud": ("upi", "fraud", "scam", "loan", "investment",
                        "digital arrest", "otp", "bank", "money"),
}


def detect_threat_domain(text: str) -> str:
    """Lightweight keyword classifier for a web snippet's threat domain."""
    lowered: str = text.lower()
    for domain in ("Data Leak", "Deepfake/Extortion", "MITM/Infrastructure",
                   "Phishing/Spam", "Financial Fraud"):
        if any(keyword in lowered for keyword in _DOMAIN_KEYWORDS[domain]):
            return domain
    return "Financial Fraud"


def _web_chunk_id(url: str, title: str) -> str:
    """Deterministic chunk id from the URL (or title) for dedup."""
    basis: str = (url or title).strip().lower()
    return f"web-seed-{hashlib.sha256(basis.encode('utf-8')).hexdigest()[:20]}"


def writethrough_web_chunks(web_results: List[Dict[str, str]]) -> int:
    """Write-through: ingest web snippets into ChromaDB, deduped by URL hash.

    Tags each chunk with source_platform='Web-Seeded: Explorer', the detected
    threat_category, and date_ingested. Returns the count newly written.
    Idempotent across reruns — existing URL-hash ids are skipped.
    """
    if not web_results:
        return 0
    candidates: Dict[str, Dict[str, str]] = {}
    for result in web_results:
        title: str = str(result.get("title") or "")
        snippet: str = str(result.get("snippet") or "")
        url: str = str(result.get("link") or result.get("url") or "")
        body: str = " ".join(p for p in (title, snippet) if p).strip()
        if len(body) < 20:
            continue
        candidates[_web_chunk_id(url, title)] = {
            "id": _web_chunk_id(url, title), "text": body, "url": url,
            "domain": detect_threat_domain(body),
        }
    if not candidates:
        return 0
    try:
        collection = get_rag_service()._vector_store.get_collection(
            WEB_SEED_COLLECTION)
        existing: Dict[str, object] = collection.get(ids=list(candidates))
        existing_ids: set = set(existing.get("ids", []))  # type: ignore[arg-type]
        fresh: List[Dict[str, str]] = [
            c for cid, c in candidates.items() if cid not in existing_ids
        ]
        if not fresh:
            LOGGER.info("write-through: all %d web chunks already present",
                        len(candidates))
            return 0
        collection.add(
            ids=[c["id"] for c in fresh],
            documents=[c["text"] for c in fresh],
            metadatas=[{
                "source": "Web-Seeded: Explorer",
                "source_platform": "Web-Seeded: Explorer",
                "threat_category": c["domain"],
                "url": c["url"],
                "date_published": WEB_SEED_DATE,
                "date_ingested": WEB_SEED_DATE,
                "state": "",
            } for c in fresh],
        )
    except (ValueError, KeyError, RuntimeError):
        LOGGER.exception("write-through web ingest failed")
        return 0
    LOGGER.info("write-through: ingested %d new web chunk(s) into %s",
                len(fresh), WEB_SEED_COLLECTION)
    return len(fresh)


def seed_relational_from_web(web_results: List[Dict[str, str]]) -> int:
    """Parse web results into structured non-financial fraud_records rows.

    Pre-dedup by URL/title hash (so reruns skip the LLM parse entirely), then
    gemini-3.5-flash classifies each new result into the threat taxonomy and the
    rows are INSERTed with financial fields zeroed — driving the technical
    charts without ever touching the financial dashboard.
    """
    from services.research_repository import (
        existing_web_hashes, insert_web_threat_rows, web_row_hash,
    )
    from services.web_seed import parse_web_threats

    if not web_results:
        return 0
    keyed: List[tuple] = [
        (web_row_hash(str(r.get("link") or r.get("url") or ""),
                      str(r.get("title") or "")), r)
        for r in web_results
    ]
    seen: set = existing_web_hashes([h for h, _ in keyed])
    fresh: List[Dict[str, str]] = [r for h, r in keyed if h not in seen]
    if not fresh:
        LOGGER.info("relational web-seed: all results already present")
        return 0
    parsed = parse_web_threats(fresh)
    rows: List[Dict[str, object]] = []
    for record, source in zip(parsed, fresh):
        if record.threat_domain == "Financial Fraud":
            continue  # financial flows via the worker, never web-seed
        rows.append({
            "url": str(source.get("link") or source.get("url") or ""),
            "title": str(source.get("title") or ""),
            "threat_domain": record.threat_domain,
            "scam_vector_type": record.scam_vector_type,
            "state": record.state,
            "target_sector": record.target_sector,
            "compromised_assets": record.compromised_assets,
            "records_exposed": record.records_exposed,
            "incident_count": record.incident_count,
            "severity_level": record.severity_level,
        })
    return insert_web_threat_rows(rows)


async def synthesize_answer(
    query: str, k: int = 5, allow_web: bool = True
) -> Dict[str, object]:
    """Dual-path synthesis: corpus retrieval + automatic web augmentation.

    Retrieves internal chunks and, when the corpus is under-saturated for the
    query (too few/weak matches or a real-time/broad ask), triggers a live web
    sweep, merges both into one context window, and synthesizes a single
    human-readable answer. Internal safety guardrails (generate_response) are
    unaffected — this path serves the open research Explorer.
    """
    from services.web_search import web_search

    service: RagService = get_rag_service()
    chunks: List[RetrievedChunk] = await service.retrieve(query)
    top: List[RetrievedChunk] = chunks[:k]

    web_results: List[Dict[str, str]] = []
    if allow_web and needs_web_augmentation(query, top):
        web_results = await asyncio.to_thread(web_search, query)
        if web_results:
            # Write-through: ingest fresh web snippets into ChromaDB (deduped)
            # AND seed structured non-financial rows into the relational store
            # so the technical infrastructure charts update on the fly.
            await asyncio.to_thread(writethrough_web_chunks, web_results)
            await asyncio.to_thread(seed_relational_from_web, web_results)

    if not top and not web_results:
        return {"answer": None, "citations": [], "matches": [],
                "web_sources": [], "web_augmented": False}

    web_augmented: bool = bool(web_results)
    context: str = _build_combined_context(top, web_results)
    prompt: str = WEB_AUGMENTED_PROMPT if web_augmented else SYNTHESIS_PROMPT
    messages: List[object] = [
        SystemMessage(content=prompt),
        HumanMessage(content=f"CONTEXT SNIPPETS:\n\n{context}\n\nQUESTION: {query}"),
    ]
    # Multi-model cascade: rotates through MODEL_CASCADE_ORDER on 429, and
    # returns a user-facing notice (not a traceback) if all are exhausted.
    answer: str = await service.cascade_invoke(messages, origin="synthesis")
    LOGGER.info("synthesis complete: web_augmented=%s corpus=%d web=%d query=%r",
                web_augmented, len(top), len(web_results), query[:80])
    return {
        "answer": answer or None,
        "citations": [chunk.citation() for chunk in top],
        "matches": [
            {"text": c.text, "source": c.source, "url": c.url,
             "date_published": c.date_published,
             "threat_category": c.threat_category,
             "distance": round(c.distance, 4)}
            for c in top
        ],
        "web_sources": web_results,
        "web_augmented": web_augmented,
    }


# --------------------------------------------------------------------------- #
# In-module verification harness.                                             #
# --------------------------------------------------------------------------- #

_HARNESS_THREAT_DOCS: List[Dict[str, str]] = [
    {
        "id": "rag-harness-threat-0001",
        "text": (
            "CERT-In advisory CIVN-2026-0142 (10 June 2026): multiple Android "
            "OS vulnerabilities tracked as CVE-2026-21443 allow sideloaded APK "
            "packages, distributed on messaging platforms as fake wedding "
            "invitations, to abuse the accessibility service, capture screen "
            "contents, intercept OTP messages, and trigger unauthorized UPI "
            "collect requests. Users must apply the June 2026 security patch "
            "and disable installation from unknown sources."
        ),
        "source": "cert-in", "date_published": "2026-06-10",
        "threat_category": "apk_sideloading",
    },
    {
        "id": "rag-harness-threat-0002",
        "text": (
            "Sanchar Saathi (DoT) bulletin: over 12 lakh mobile connections "
            "obtained on forged documents were disconnected this quarter. "
            "Citizens should verify connections issued in their name on the "
            "TAFCOP portal and report unknown SIMs immediately."
        ),
        "source": "DoT Sanchar Saathi (TAFCOP)", "date_published": "2026-05-28",
        "threat_category": "telecom_fraud",
    },
]

_HARNESS_EXPERT_DOCS: List[Dict[str, str]] = [
    {
        "id": "rag-harness-expert-0001",
        "text": (
            "Investigator Amit Dubey notes that recent malicious APK campaigns "
            "request accessibility permissions within seconds of installation; "
            "granting them lets the trojan auto-approve UPI collect requests "
            "invisibly. He advises auditing accessibility access for every "
            "non-system app and revoking anything unrecognized."
        ),
        "source": "Amit Dubey", "date_published": "2026-06-08",
        "threat_category": "accessibility_exploit",
    },
]


def _seed_harness_documents(store: VectorStoreManager) -> None:
    """Load synthetic official chunks into both collections."""
    threat = store.get_collection("threat_intel_chunks")
    threat.add(
        ids=[doc["id"] for doc in _HARNESS_THREAT_DOCS],
        documents=[doc["text"] for doc in _HARNESS_THREAT_DOCS],
        metadatas=[
            {"source": doc["source"], "url": "https://harness.local/doc",
             "date_published": doc["date_published"],
             "jurisdiction": "National",
             "threat_category": doc["threat_category"]}
            for doc in _HARNESS_THREAT_DOCS
        ],
    )
    expert = store.get_collection("expert_feed_chunks")
    expert.add(
        ids=[doc["id"] for doc in _HARNESS_EXPERT_DOCS],
        documents=[doc["text"] for doc in _HARNESS_EXPERT_DOCS],
        metadatas=[
            {"source": doc["source"], "url": "https://harness.local/expert",
             "date_published": doc["date_published"],
             "jurisdiction": "National",
             "threat_category": doc["threat_category"]}
            for doc in _HARNESS_EXPERT_DOCS
        ],
    )


def _remove_harness_documents(store: VectorStoreManager) -> None:
    """Remove every synthetic harness chunk from both collections."""
    store.get_collection("threat_intel_chunks").delete(
        ids=[doc["id"] for doc in _HARNESS_THREAT_DOCS]
    )
    store.get_collection("expert_feed_chunks").delete(
        ids=[doc["id"] for doc in _HARNESS_EXPERT_DOCS]
    )


async def _run_verification_harness() -> None:
    """Prove grounded inference and the out-of-scope refusal gate."""
    store: VectorStoreManager = VectorStoreManager()
    await asyncio.to_thread(_seed_harness_documents, store)
    try:
        # 1. Valid threat query — must ground, answer, and cite.
        threat_query: str = (
            "How are fake wedding invite APKs abusing Android accessibility "
            "services to steal money, and what should users do?"
        )
        grounded_response: Dict[str, object] = await generate_response(threat_query)
        assert grounded_response["grounded"] is True, (
            f"expected grounded response, got fallback: "
            f"{grounded_response['fallback_reason']}"
        )
        answer_text: str = str(grounded_response["answer"])
        assert answer_text != RAG_FALLBACK_MESSAGE
        assert len(answer_text) > 100, "grounded answer suspiciously short"
        citations: List[Dict[str, object]] = grounded_response["citations"]  # type: ignore[assignment]
        assert len(citations) >= 1, "grounded answer must carry citations"
        cited_sources: List[str] = [str(c["source"]) for c in citations]
        assert "cert-in" in cited_sources, "CERT-In chunk must be retrieved"

        # 2. Out-of-scope prompt — the refusal must trigger.
        refusal_response: Dict[str, object] = await generate_response(
            "Please give me a detailed recipe for a chocolate truffle cake."
        )
        assert refusal_response["answer"] == RAG_FALLBACK_MESSAGE
        assert refusal_response["grounded"] is False
        assert refusal_response["citations"] == []

        print("--- Grounded threat query ---")
        print(f"retrieved : {grounded_response['chunks_retrieved']} chunks")
        print(f"citations : {cited_sources}")
        print(f"answer    : {answer_text[:300]}...")
        print("--- Out-of-scope control ---")
        print(f"fallback  : {refusal_response['fallback_reason']}")
        print(f"answer    : {refusal_response['answer']}")
        print("RAG GUARDRAIL HARNESS: PASS")
    finally:
        await asyncio.to_thread(_remove_harness_documents, store)


if __name__ == "__main__":
    asyncio.run(_run_verification_harness())
