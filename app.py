"""Cyber Shield India — Production Streamlit Command Center (Phase 5).

Wide-layout operational terminal consuming the live FastAPI gateway at
``http://localhost:8000/api/v1`` across three dedicated tabs:

* **Tab 1 — Incident Triage & Live Ingest**: raw crime-string intake →
  ``POST /api/v1/ingest/text`` → metric tiles + extraction data tables.
* **Tab 2 — Advanced Math Analytics**: concurrent MAVI / KCVI / horizon
  calls → color-coded KPI blocks, delivery-vector charts, SPOF callout,
  and the rolling Interval Matrix — with a cross-tab hook piping vector
  telemetry into the RAG interrogation buffer (ledger Step 5.4).
* **Tab 3 — Grounded Intelligence RAG Chat**: plain-language queries →
  ``POST /api/v1/rag/query`` → cited answers, with the mandated official
  safety fallback rendered verbatim when a query is intercepted.

Backend unavailability degrades to a clean offline banner — never a raw
connection trace. Runtime telemetry rotates daily into ``logs/frontend.log``.

Run:  streamlit run app.py   (gateway: python main.py)
"""

import asyncio
import logging
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# --------------------------------------------------------------------------- #
# Frontend telemetry — daily-rotating channel: logs/frontend.log.             #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the frontend logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.frontend")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "frontend.log",
        when="midnight",
        backupCount=14,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


LOGGER: logging.Logger = _build_logger()

# --------------------------------------------------------------------------- #
# Gateway communication utilities.                                            #
# --------------------------------------------------------------------------- #

API_BASE: str = "http://localhost:8000/api/v1"
OFFLINE_BANNER: str = "System Offline: Awaiting Connection to Core Analytics Core"
RAG_FALLBACK_MESSAGE: str = (
    "I am sorry, but I can only provide cyber safety protocols verified by "
    "official government sources."
)

THREAT_LEVEL_COLORS: Dict[str, str] = {
    "CRITICAL": "#DC2626",
    "ELEVATED": "#EA580C",
    "GUARDED": "#D97706",
    "LOW": "#059669",
}


def api_get(path: str, timeout: float = 15.0) -> Optional[Dict[str, object]]:
    """GET one gateway route; connection faults degrade to None."""
    try:
        response: httpx.Response = httpx.get(f"{API_BASE}{path}", timeout=timeout)
        response.raise_for_status()
        return response.json()
    except httpx.ConnectError:
        LOGGER.warning("GET %s: gateway unreachable", path)
        return None
    except httpx.TimeoutException:
        LOGGER.warning("GET %s: gateway timeout", path)
        return None
    except httpx.HTTPStatusError as fault:
        LOGGER.error("GET %s: HTTP %d", path, fault.response.status_code)
        return None


def api_post(
    path: str, payload: Dict[str, object], timeout: float = 240.0
) -> Tuple[Optional[Dict[str, object]], Optional[str]]:
    """POST one gateway route; returns (body, clean_error_message)."""
    try:
        response: httpx.Response = httpx.post(
            f"{API_BASE}{path}", json=payload, timeout=timeout
        )
        if response.status_code >= 400:
            LOGGER.error("POST %s: HTTP %d — %s",
                         path, response.status_code, response.text[:200])
            return None, f"Gateway rejected the request (HTTP {response.status_code})."
        return response.json(), None
    except httpx.ConnectError:
        LOGGER.warning("POST %s: gateway unreachable", path)
        return None, OFFLINE_BANNER
    except httpx.TimeoutException:
        LOGGER.warning("POST %s: gateway timeout", path)
        return None, "The analytics core timed out processing this payload."


async def _gather_analytics() -> Tuple[
    Optional[Dict[str, object]],
    Optional[Dict[str, object]],
    Optional[Dict[str, object]],
]:
    """Fetch MAVI, KCVI, and horizon matrices concurrently."""

    async def _one(client: httpx.AsyncClient, path: str) -> Optional[Dict[str, object]]:
        try:
            response: httpx.Response = await client.get(f"{API_BASE}{path}")
            response.raise_for_status()
            return response.json()
        except httpx.ConnectError:
            LOGGER.warning("async GET %s: gateway unreachable", path)
            return None
        except httpx.TimeoutException:
            LOGGER.warning("async GET %s: gateway timeout", path)
            return None
        except httpx.HTTPStatusError as fault:
            LOGGER.error("async GET %s: HTTP %d", path, fault.response.status_code)
            return None

    async with httpx.AsyncClient(timeout=30.0) as client:
        results: Tuple[
            Optional[Dict[str, object]],
            Optional[Dict[str, object]],
            Optional[Dict[str, object]],
        ] = tuple(await asyncio.gather(  # type: ignore[assignment]
            _one(client, "/analytics/mavi"),
            _one(client, "/analytics/kcvi"),
            _one(client, "/analytics/horizons"),
        ))
    return results


@st.cache_data(ttl=30, show_spinner=False)
def fetch_analytics_snapshot() -> Tuple[
    Optional[Dict[str, object]],
    Optional[Dict[str, object]],
    Optional[Dict[str, object]],
]:
    """Cached concurrent snapshot of all three analytical matrices."""
    return asyncio.run(_gather_analytics())


# --------------------------------------------------------------------------- #
# Layout chrome.                                                              #
# --------------------------------------------------------------------------- #

TERMINAL_CSS: str = """
<style>
.cs-header {
    border: 1px solid #1E3A5F; border-left: 6px solid #0A74B9;
    border-radius: 6px; padding: 14px 22px; margin-bottom: 14px;
    background: linear-gradient(90deg, #0F2537 0%, #133150 100%);
}
.cs-header h1 {
    color: #F8F9FA; font-size: 1.35rem; letter-spacing: 0.12em;
    margin: 0; font-weight: 700; text-transform: uppercase;
}
.cs-header p {
    color: #7FA8C9; font-size: 0.72rem; letter-spacing: 0.22em;
    margin: 4px 0 0 0; text-transform: uppercase;
}
.cs-kpi {
    border: 1px solid #E5E7EB; border-radius: 8px; padding: 16px 20px;
    background: #FFFFFF; text-align: center;
}
.cs-kpi .label { font-size: 0.68rem; letter-spacing: 0.18em;
    color: #6B7280; text-transform: uppercase; }
.cs-kpi .value { font-size: 2.1rem; font-weight: 800; line-height: 1.2; }
.cs-flag {
    display: inline-block; border-radius: 999px; padding: 3px 12px;
    font-size: 0.7rem; font-weight: 700; letter-spacing: 0.1em;
    color: #FFFFFF; margin: 2px;
}
.cs-citation {
    border: 1px solid #D1E3F0; border-left: 4px solid #0A74B9;
    border-radius: 6px; padding: 8px 14px; margin: 6px 0;
    background: #FFFFFF; font-size: 0.8rem; color: #1F2937;
}
.cs-offline {
    border: 1px solid #FCA5A5; border-left: 6px solid #DC2626;
    border-radius: 6px; padding: 14px 20px; background: #FEF2F2;
    color: #991B1B; font-weight: 600; letter-spacing: 0.04em;
}
</style>
"""


def render_header(online: bool) -> None:
    """Crisp operational-terminal header bar with live status pill."""
    status_color: str = "#059669" if online else "#DC2626"
    status_text: str = "CORE LINK ESTABLISHED" if online else "CORE LINK DOWN"
    st.markdown(
        f"""
        <div class="cs-header">
          <h1>🛡️ Cyber Shield India — Threat Intelligence Grid</h1>
          <p>National Cybercrime Operational Terminal &nbsp;·&nbsp;
             <span style="color:{status_color};">●</span> {status_text}
             &nbsp;·&nbsp; {datetime.now(timezone.utc).strftime('%d %b %Y %H:%M UTC')}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_offline_banner() -> None:
    """Clean professional banner shown when the gateway is unreachable."""
    st.markdown(
        f'<div class="cs-offline">⚠️ {OFFLINE_BANNER}</div>',
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------------- #
# Tab 1 — Incident Triage & Live Ingest.                                      #
# --------------------------------------------------------------------------- #


def render_ingest_tab(online: bool) -> None:
    """Raw crime-string intake with forensic extraction and result grids."""
    st.subheader("Incident Triage & Live Ingest")
    if not online:
        render_offline_banner()
        return
    raw_text: str = st.text_area(
        "Raw intelligence payload",
        height=220,
        placeholder=("Paste the raw crime narrative, advisory text, or "
                     "investigator notes here (minimum 40 characters)…"),
    )
    source: str = st.text_input("Source label", value="manual_triage")
    if st.button("⚡ Execute Forensic Extraction", type="primary"):
        if len(raw_text.strip()) < 40:
            st.warning("Payload must carry at least 40 characters of narrative.")
            return
        with st.spinner("Running Gemini extraction and dual-tier persistence…"):
            manifest, error = api_post("/ingest/text", {
                "text": raw_text.strip(),
                "origin": "command-center",
                "source": source.strip() or "manual_triage",
            })
        if manifest is None:
            st.error(error or "Extraction failed — see logs/frontend.log.")
            return
        try:
            tiles: List[Tuple[str, int]] = [
                ("Incidents", int(manifest["incidents_inserted"])),     # type: ignore[arg-type]
                ("Indicators", int(manifest["entities_upserted"])),     # type: ignore[arg-type]
                ("Advisories", int(manifest["advisories_inserted"])),   # type: ignore[arg-type]
                ("Vector Chunks", int(manifest["chunks_committed"])),   # type: ignore[arg-type]
            ]
            columns: List[object] = st.columns(len(tiles))
            for column, (label, value) in zip(columns, tiles):
                with column:  # type: ignore[union-attr]
                    st.metric(label, value)
            extraction: Dict[str, object] = manifest["extraction"]  # type: ignore[assignment]
            incidents: List[Dict[str, object]] = extraction.get("incidents", [])  # type: ignore[assignment]
            entities: List[Dict[str, object]] = extraction.get("entities", [])    # type: ignore[assignment]
            advisories: List[Dict[str, object]] = extraction.get("advisories", [])  # type: ignore[assignment]
            if incidents:
                st.markdown("**Extracted incidents**")
                st.dataframe(pd.DataFrame(incidents), use_container_width=True)
            if entities:
                st.markdown("**Extracted indicators**")
                st.dataframe(pd.DataFrame(entities), use_container_width=True)
            if advisories:
                st.markdown("**Extracted advisories**")
                st.dataframe(pd.DataFrame(advisories), use_container_width=True)
            if not (incidents or entities or advisories):
                st.info("Zero-fabrication guarantee held: no viable threat "
                        "intelligence found in this payload.")
            LOGGER.info("Ingest rendered: %s", tiles)
        except (KeyError, TypeError, ValueError):
            LOGGER.exception("Malformed ingest manifest payload")
            st.error("The extraction manifest arrived malformed — "
                     "see logs/frontend.log.")


# --------------------------------------------------------------------------- #
# Tab 2 — Advanced Math Analytics.                                            #
# --------------------------------------------------------------------------- #


def _render_mavi_block(mavi: Dict[str, object]) -> None:
    """Color-coded composite MAVI KPI block with anomaly flags."""
    try:
        score: float = float(mavi["mavi_score"])        # type: ignore[arg-type]
        level: str = str(mavi["threat_level"])
        variance: float = float(mavi["variance"])       # type: ignore[arg-type]
        flags: List[str] = [str(f) for f in mavi.get("anomaly_flags", [])]  # type: ignore[union-attr]
    except (KeyError, TypeError, ValueError):
        LOGGER.exception("Malformed MAVI payload")
        st.error("MAVI payload malformed — see logs/frontend.log.")
        return
    color: str = THREAT_LEVEL_COLORS.get(level, "#6B7280")
    left, right = st.columns([1, 2])
    with left:
        st.markdown(
            f"""
            <div class="cs-kpi">
              <div class="label">Composite MAVI Score</div>
              <div class="value" style="color:{color};">{score:.2f}</div>
              <span class="cs-flag" style="background:{color};">{level}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with right:
        st.metric("Population variance", f"{variance:.2f}")
        if flags:
            chips: str = "".join(
                f'<span class="cs-flag" style="background:#0F2537;">{flag}</span>'
                for flag in flags
            )
            st.markdown(f"**Anomaly flags** {chips}", unsafe_allow_html=True)
        else:
            st.caption("No anomaly flags raised.")


def _render_kcvi_block(kcvi: Dict[str, object]) -> None:
    """KCVI delivery-vector distribution chart and SPOF callout."""
    try:
        distribution: Dict[str, float] = {
            str(k): float(v)
            for k, v in dict(kcvi["vector_distribution"]).items()  # type: ignore[arg-type]
        }
        spof: str = str(kcvi["single_point_of_failure"])
        index: float = float(kcvi["vulnerability_index"])  # type: ignore[arg-type]
        stages: Dict[str, float] = {
            str(k): float(v)
            for k, v in dict(kcvi.get("stage_distribution", {})).items()  # type: ignore[arg-type]
        }
    except (KeyError, TypeError, ValueError):
        LOGGER.exception("Malformed KCVI payload")
        st.error("KCVI payload malformed — see logs/frontend.log.")
        return
    st.markdown(f"**Single Point of Failure:** "
                f"<span class='cs-flag' style='background:#DC2626;'>{spof}</span> "
                f"&nbsp; Vulnerability index **{index:.2f}**",
                unsafe_allow_html=True)
    if not distribution:
        st.info("No delivery-vector telemetry recorded yet.")
        return
    chart_left, chart_right = st.columns(2)
    with chart_left:
        vector_figure: go.Figure = go.Figure(go.Bar(
            x=[round(v * 100.0, 2) for v in distribution.values()],
            y=list(distribution.keys()),
            orientation="h",
            marker={"color": "#0A74B9"},
        ))
        vector_figure.update_layout(
            title="Delivery vector share (%)", height=320,
            margin={"l": 10, "r": 10, "t": 40, "b": 10},
        )
        st.plotly_chart(vector_figure, use_container_width=True)
    with chart_right:
        stage_figure: go.Figure = go.Figure(go.Bar(
            x=[round(v * 100.0, 2) for v in stages.values()],
            y=list(stages.keys()),
            orientation="h",
            marker={"color": "#0F2537"},
        ))
        stage_figure.update_layout(
            title="Kill chain stage concentration (%)", height=320,
            margin={"l": 10, "r": 10, "t": 40, "b": 10},
        )
        st.plotly_chart(stage_figure, use_container_width=True)

    # Cross-tab RAG injection hook (ledger Step 5.4): pipe the selected
    # vector's telemetry into the Tab 3 interrogation buffer.
    hook_vector: str = st.selectbox(
        "Interrogate a delivery vector", sorted(distribution),
    )
    if st.button("🔁 Pipe telemetry into RAG interrogation"):
        share: float = distribution.get(hook_vector, 0.0)
        st.session_state["rag_prefill"] = (
            f"Telemetry context: vector={hook_vector}, "
            f"share={share:.1%}, spof={spof}. "
            f"What official protocols address {hook_vector.replace('_', ' ')} "
            f"campaigns and how should investigators respond?"
        )
        LOGGER.info("Cross-tab hook armed for vector=%s", hook_vector)
        st.success("Telemetry piped — open the RAG Chat tab to interrogate.")


def _render_horizon_block(horizons: Dict[str, object]) -> None:
    """Rolling Interval Matrix with volume deltas and accelerating trends."""
    try:
        snapshots: Dict[str, Dict[str, object]] = dict(horizons["snapshots"])  # type: ignore[arg-type]
    except (KeyError, TypeError):
        LOGGER.exception("Malformed horizon payload")
        st.error("Horizon payload malformed — see logs/frontend.log.")
        return
    order: List[str] = ["24h", "7d", "30d", "1y"]
    columns: List[object] = st.columns(len(order))
    for column, horizon in zip(columns, order):
        snapshot: Dict[str, object] = dict(snapshots.get(horizon, {}))
        with column:  # type: ignore[union-attr]
            st.metric(
                f"{horizon} incident volume",
                int(snapshot.get("incident_volume", 0)),       # type: ignore[arg-type]
                delta=int(snapshot.get("volume_delta", 0)),    # type: ignore[arg-type]
            )
            st.caption(
                f"new indicators: {snapshot.get('new_entity_count', 0)} · "
                f"volatility {snapshot.get('entity_volatility_index', 0.0)}"
            )
            gaining: List[str] = [str(v) for v in snapshot.get("gaining_vectors", [])]  # type: ignore[union-attr]
            if gaining:
                st.markdown("\n".join(f"▲ `{vector}`" for vector in gaining[:4]))
            else:
                st.caption("no accelerating vectors")


def render_analytics_tab(online: bool) -> None:
    """Concurrent triple-endpoint analytics dashboard."""
    st.subheader("Advanced Math Analytics")
    if not online:
        render_offline_banner()
        return
    if st.button("🔄 Refresh analytical matrices"):
        fetch_analytics_snapshot.clear()
    mavi, kcvi, horizons = fetch_analytics_snapshot()
    if mavi is None or kcvi is None or horizons is None:
        render_offline_banner()
        return
    _render_mavi_block(mavi)
    st.divider()
    _render_kcvi_block(kcvi)
    st.divider()
    st.markdown("**Time-Horizon Interval Matrix**")
    _render_horizon_block(horizons)


# --------------------------------------------------------------------------- #
# Tab 3 — Grounded Intelligence RAG Chat.                                     #
# --------------------------------------------------------------------------- #


def _render_citations(citations: List[Dict[str, object]]) -> None:
    """Highlight inline structural citations as styled cards."""
    for citation in citations:
        st.markdown(
            f"""
            <div class="cs-citation">
              📌 <b>{citation.get('source', 'unknown')}</b>
              &nbsp;·&nbsp; {citation.get('date_published') or 'undated'}
              &nbsp;·&nbsp; {citation.get('threat_category') or 'unclassified'}
              &nbsp;·&nbsp; distance {citation.get('distance', '—')}
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_rag_tab(online: bool) -> None:
    """Interactive grounded search against the official vector corpus."""
    st.subheader("Grounded Intelligence RAG Chat")
    if not online:
        render_offline_banner()
        return
    if "chat_history" not in st.session_state:
        st.session_state["chat_history"] = []
    prefill: str = str(st.session_state.pop("rag_prefill", ""))
    query: str = st.text_input(
        "Ask the intelligence grid",
        value=prefill,
        placeholder="e.g. How do fake wedding invite APK scams operate?",
    )
    if st.button("🔍 Interrogate", type="primary") and query.strip():
        with st.spinner("Retrieving official grounding and generating…"):
            envelope, error = api_post(
                "/rag/query", {"query": query.strip()}, timeout=120.0
            )
        if envelope is None:
            st.error(error or "Inference failed — see logs/frontend.log.")
        else:
            st.session_state["chat_history"].append(envelope)
    history: List[Dict[str, object]] = st.session_state["chat_history"]
    for envelope in reversed(history):
        try:
            st.markdown(f"**🧑‍✈️ Query:** {envelope.get('query', '')}")
            answer: str = str(envelope.get("answer", ""))
            grounded: bool = bool(envelope.get("grounded", False))
            if grounded:
                st.markdown(answer)
                citations: List[Dict[str, object]] = envelope.get("citations", [])  # type: ignore[assignment]
                if citations:
                    _render_citations(citations)
            else:
                # The mandated official safety protocol fallback, verbatim.
                st.warning(f"🛡️ {RAG_FALLBACK_MESSAGE}")
                st.caption(f"gate: {envelope.get('fallback_reason', 'unknown')}")
            st.divider()
        except (KeyError, TypeError, ValueError):
            LOGGER.exception("Malformed RAG envelope in history")
            st.error("A response envelope arrived malformed — "
                     "see logs/frontend.log.")


# --------------------------------------------------------------------------- #
# Application assembly.                                                       #
# --------------------------------------------------------------------------- #


@st.cache_data(ttl=15, show_spinner=False)
def backend_online() -> bool:
    """Lightweight cached gateway liveness probe."""
    return api_get("/analytics/kcvi", timeout=5.0) is not None


def main() -> None:
    """Assemble the wide-layout three-tab command center."""
    st.set_page_config(
        page_title="Cyber Shield India — Command Center",
        page_icon="🛡️",
        layout="wide",
    )
    st.markdown(TERMINAL_CSS, unsafe_allow_html=True)
    online: bool = backend_online()
    render_header(online)
    if not online:
        render_offline_banner()
    triage_tab, analytics_tab, rag_tab = st.tabs([
        "🛡️ Incident Triage & Live Ingest",
        "📊 Advanced Math Analytics",
        "🔎 Grounded Intelligence RAG Chat",
    ])
    with triage_tab:
        render_ingest_tab(online)
    with analytics_tab:
        render_analytics_tab(online)
    with rag_tab:
        render_rag_tab(online)
    LOGGER.info("Frame rendered (online=%s)", online)


if __name__ == "__main__":
    main()
