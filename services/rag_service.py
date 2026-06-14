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
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai._common import GoogleGenerativeAIError

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

# CLAUDE.md RAG Integrity Guardrail — the unyielding fallback, verbatim.
RAG_FALLBACK_MESSAGE: str = (
    "I am sorry, but I can only provide cyber safety protocols verified by "
    "official government sources."
)

TOP_K: int = 4
# Cosine distance ceiling: retrieval hits farther than this are not
# considered official grounding and trigger the deterministic fallback.
MAX_GROUNDING_DISTANCE: float = 0.70
GEMINI_MODEL_NAME: str = "gemini-2.5-flash"
INFERENCE_TIMEOUT_SECONDS: float = 90.0

RAG_COLLECTIONS: tuple = (
    "threat_intel_chunks", "expert_feed_chunks", "research_corpus",
)

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
        self._llm: ChatGoogleGenerativeAI = ChatGoogleGenerativeAI(
            model=GEMINI_MODEL_NAME,
            temperature=temperature,
            google_api_key=get_google_api_key(),
        )
        LOGGER.info(
            "RAG service online: model=%s top_k=%d grounding_gate=%.2f",
            GEMINI_MODEL_NAME, self.top_k, self.max_grounding_distance,
        )

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
            chunks.append(RetrievedChunk(
                text=str(text),
                source=str(metadata.get("source", "unknown")),
                url=str(metadata.get("url", "")),
                date_published=str(metadata.get("date_published", "")),
                threat_category=str(metadata.get("threat_category", "")),
                collection=name,
                distance=float(distance),
            ))
        return chunks

    async def retrieve(
        self, query: str, filters: Optional[Dict[str, str]] = None
    ) -> List[RetrievedChunk]:
        """Search both collections concurrently; keep the global top-K."""
        try:
            batches: List[List[RetrievedChunk]] = list(await asyncio.gather(
                *(
                    asyncio.to_thread(self._query_collection, name, query, filters)
                    for name in RAG_COLLECTIONS
                )
            ))
        except (ValueError, KeyError):
            LOGGER.exception("Vector retrieval anomaly for query=%r", query[:80])
            return []
        merged: List[RetrievedChunk] = sorted(
            (chunk for batch in batches for chunk in batch),
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
        try:
            completion = await asyncio.wait_for(
                self._llm.ainvoke(messages),
                timeout=INFERENCE_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            LOGGER.error("Inference timed out for query=%r", query[:80])
            return self._fallback_payload(query, chunks, "inference_timeout")
        except GoogleGenerativeAIError:
            LOGGER.exception("Gemini API fault for query=%r", query[:80])
            return self._fallback_payload(query, chunks, "llm_api_fault")
        except ValueError:
            LOGGER.exception("Inference payload anomaly for query=%r", query[:80])
            return self._fallback_payload(query, chunks, "payload_anomaly")

        answer: str = str(completion.content).strip()
        if not answer:
            return self._fallback_payload(query, chunks, "empty_completion")
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
