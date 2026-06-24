"""Cyber Shield India — Public Cybercrime Research & Trend Analytics Hub.

An open-access Streamlit frontend over the autonomously-curated research
corpus. The frontend reads the relational tier in SQLite **read-only** mode
(it can never mutate the worker-curated data) and calls Gemini in-process for
the semantic explorer and the analytics agent.

Two top-level tabs:

* **Macro Trends** — four Plotly modules (geospatial hot-spots, scam-vector
  landscape, demographic vulnerability matrix, localized state tracker) under
  a shared chronological filter (Past 1 Day / 1 Week / 1 Month / 1 Year).
* **Semantic Knowledge Explorer** — an agentic chat that answers analytical
  questions with custom charts (safe NL → read-only SQL → deterministic
  Plotly) or grounded semantic answers, plus an isolated sidebar sandbox for
  querying a researcher's own uploaded document (never merged into the corpus).

Run:  streamlit run app.py     (worker: python ingestion_worker.py)
"""

import asyncio
import io
import logging
import re
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from services import research_repository as rr
from services import cdr_analyzer
from services import osint_sandbox
from services import practice_lab
from services import threat_registry
from services import victim_triage
from services.research_agent import AnalyticalPlan, ResearchAgent, run_select

# Navigation registry — single source of truth for the home grid + top nav.
# (key, icon, title, one-line blurb, "ready" flag for this build phase).
NAV_FEATURES: List[Tuple[str, str, str, str, bool]] = [
    ("macro", "📊", "Strategic Threat Analytics",
     "Asset-centric threat registry: a cross-referencing tag matrix, regulatory "
     "advisories, a 36-jurisdiction State/UT directory and an expert signal "
     "monitor.", True),
    ("explorer", "🔎", "Semantic Explorer",
     "Ask deep research questions across the curated advisory corpus or render "
     "custom analytical charts from natural language.", True),
    ("triage", "🚨", "Victim Triage & First-Action",
     "Narrate an incident, hash your proofs for chain-of-custody, and get the "
     "BNS/IT-Act mapping plus a ready-to-send complaint.", True),
    ("cdr", "📞", "CDR & IPDR Analyzer",
     "Upload call/IP detail records for Pandas-driven B-party, odd-hour and "
     "IMEI/IMSI link analysis with a forensic AI breakdown.", True),
    ("osint", "🕵️", "OSINT Sandbox",
     "Deterministic email-header forensics, WHOIS, EXIF/GPS, breach checks and "
     "URL reputation in one investigator workspace.", True),
    ("lab", "🎓", "Case-Building Practice Lab",
     "Level-based mock investigations with a Section-94 BNSS legal-notice "
     "drafting engine.", True),
]

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
    handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "frontend.log",
        when="midnight", backupCount=14, encoding="utf-8",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOGGER: logging.Logger = _build_logger()

INTERVAL_ORDER: List[str] = ["1d", "1w", "1m", "1y"]
INTERVAL_LABELS: Dict[str, str] = {
    "1d": "Past 1 Day", "1w": "Past 1 Week",
    "1m": "Past 1 Month", "1y": "Past 1 Year",
}

# City coordinates for the geospatial hot-spot map (offline, no geojson).
CITY_COORDS: Dict[str, Tuple[float, float]] = {
    "Faridabad": (28.4089, 77.3178), "Gurugram": (28.4595, 77.0266),
    "New Delhi": (28.6139, 77.2090), "Delhi": (28.6139, 77.2090),
    "Mumbai": (19.0760, 72.8777), "Hyderabad": (17.3850, 78.4867),
    "Bengaluru": (12.9716, 77.5946), "Chennai": (13.0827, 80.2707),
    "Jamtara": (23.9620, 86.8030), "Kolkata": (22.5726, 88.3639),
    "Pune": (18.5204, 73.8567), "Ahmedabad": (23.0225, 72.5714),
    "Jaipur": (26.9124, 75.7873), "Lucknow": (26.8467, 80.9462),
}

TERMINAL_CSS: str = """
<style>
.cs-header {
    border: 1px solid #1E3A5F; border-left: 6px solid #0A74B9;
    border-radius: 6px; padding: 14px 22px; margin-bottom: 14px;
    background: linear-gradient(90deg, #0F2537 0%, #133150 100%);
}
.cs-header h1 { color: #F8F9FA; font-size: 1.4rem; letter-spacing: 0.06em;
    margin: 0; font-weight: 800; }
.cs-header p { color: #7FA8C9; font-size: 0.74rem; letter-spacing: 0.16em;
    margin: 4px 0 0 0; text-transform: uppercase; }
.cs-header .desc { color: #B9CFE0; font-size: 0.82rem; letter-spacing: 0.02em;
    margin: 10px 0 0 0; text-transform: none; font-style: italic; }
.cs-advisory {
    border: 1px solid #D1E3F0; border-left: 4px solid #0A74B9;
    border-radius: 6px; padding: 10px 14px; margin: 8px 0;
    background: #FFFFFF; font-size: 0.84rem; color: #1F2937;
}
.cs-citation {
    border: 1px solid #D1E3F0; border-left: 4px solid #0A74B9;
    border-radius: 6px; padding: 8px 14px; margin: 6px 0;
    background: #FFFFFF; font-size: 0.8rem; color: #1F2937;
}
.cs-empty {
    border: 1px dashed #CBD5E1; border-radius: 6px; padding: 18px 20px;
    background: #FFFFFF; color: #475569; text-align: center;
}
.cs-briefing {
    border: 1px solid #C7DCEC; border-left: 6px solid #0A74B9;
    border-radius: 8px; padding: 14px 20px; margin: 6px 0 4px 0;
    background: #F0F7FC; color: #1F2937; font-size: 0.92rem; line-height: 1.5;
}
.cs-briefing b { color: #0A74B9; letter-spacing: 0.08em; }
.cs-webbadge {
    display: inline-block; background: #0A74B9; color: #FFFFFF;
    font-size: 0.64rem; font-weight: 700; letter-spacing: 0.08em;
    border-radius: 999px; padding: 2px 9px; margin-bottom: 4px;
}
.cs-domainchip {
    display: inline-block; background: #E8F1F8; color: #0F2537;
    border: 1px solid #C7DCEC; font-size: 0.72rem; font-weight: 600;
    border-radius: 999px; padding: 2px 10px; margin: 2px 3px;
}
/* Contrast patch: navy theme darkens inputs; force readable field text. */
.stTextInput input, .stTextArea textarea {
    background-color: #FFFFFF !important; color: #1F2937 !important;
    caret-color: #0A74B9 !important; border: 1px solid #CBD5E1 !important;
}
.stTextInput input::placeholder, .stTextArea textarea::placeholder {
    color: #9CA3AF !important;
}
div[data-baseweb="select"] > div {
    background-color: #FFFFFF !important; color: #1F2937 !important;
}
/* === Sidebar high-contrast: navy background, light text everywhere ===
   Broad element + legacy/emotion-class selectors force legibility regardless
   of Streamlit's exact DOM or system light/dark mode. Light-background
   controls (inputs, dropdowns, file uploader, alerts, default buttons) are
   re-darkened afterwards so their own text stays readable. */
section[data-testid="stSidebar"],
section[data-testid="stSidebar"] > div,
div[data-testid="stSidebarContent"] {
    background-color: #0F2537 !important;
}
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3,
section[data-testid="stSidebar"] h4,
section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] span,
section[data-testid="stSidebar"] li,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] small,
section[data-testid="stSidebar"] strong,
section[data-testid="stSidebar"] .stMarkdown,
section[data-testid="stSidebar"] .stMarkdown *,
section[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] *,
section[data-testid="stSidebar"] [data-testid="stWidgetLabel"] *,
section[data-testid="stSidebar"] [data-testid="stMetricLabel"] *,
section[data-testid="stSidebar"] [data-testid="stMetricValue"],
section[data-testid="stSidebar"] [class*="css-"],
section[data-testid="stSidebar"] [class*="st-emotion-cache-"] {
    color: #F1F5F9 !important;
}
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"],
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] * {
    color: #B9CFE0 !important;
}
/* Keep text dark on the light-background interactive controls. */
section[data-testid="stSidebar"] input,
section[data-testid="stSidebar"] textarea,
section[data-testid="stSidebar"] div[data-baseweb="select"] *,
section[data-testid="stSidebar"] div[data-baseweb="popover"] *,
section[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] *,
section[data-testid="stSidebar"] [data-testid="stAlert"] *,
section[data-testid="stSidebar"] button p {
    color: #1F2937 !important;
}
/* === Sidebar file-uploader: high-contrast, visible without hover ===
   The dropzone + Browse button must read clearly on the navy sidebar. */
section[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {
    background-color: #14304A !important;
    border: 1.5px dashed #FFFFFF !important;
    border-radius: 8px !important;
}
section[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"],
section[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] *,
section[data-testid="stSidebar"] [data-testid="stFileUploaderDropzoneInstructions"] * {
    color: #FFFFFF !important;
}
section[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] button,
section[data-testid="stSidebar"] [data-testid="stFileUploader"] button {
    background-color: #0A74B9 !important;
    color: #FFFFFF !important;
    border: 1.5px solid #FFFFFF !important;
    font-weight: 700 !important;
    opacity: 1 !important;
}
section[data-testid="stSidebar"] [data-testid="stFileUploader"] button:hover {
    background-color: #0C8AE0 !important;
}
/* === Home feature-card grid =========================================== */
.cs-card {
    border: 1px solid #1E3A5F; border-top: 4px solid #0A74B9;
    border-radius: 10px; padding: 16px 18px 10px 18px; margin: 4px 0 2px 0;
    background: linear-gradient(160deg, #0F2537 0%, #15324D 100%);
    min-height: 188px; box-shadow: 0 2px 8px rgba(8,20,33,0.35);
}
.cs-card .cs-card-ico { font-size: 1.7rem; line-height: 1; }
.cs-card h4 { color: #F8F9FA; font-size: 1.0rem; margin: 8px 0 4px 0;
    letter-spacing: 0.03em; font-weight: 700; }
.cs-card p { color: #B9CFE0; font-size: 0.8rem; line-height: 1.45;
    margin: 0 0 8px 0; }
.cs-card .cs-card-tag {
    display: inline-block; background: #0A74B9; color: #FFFFFF;
    font-size: 0.62rem; font-weight: 700; letter-spacing: 0.08em;
    border-radius: 999px; padding: 2px 9px; text-transform: uppercase;
}
.cs-card .cs-card-tag.soon { background: #4B5C6B; }
/* === Triage / forensic output panels ================================== */
.cs-legal {
    border: 1px solid #D1E3F0; border-left: 4px solid #0A74B9;
    border-radius: 6px; padding: 8px 14px; margin: 6px 0; background: #FFFFFF;
    font-size: 0.82rem; color: #1F2937;
}
.cs-legal b { color: #0A74B9; }
.cs-hash {
    border: 1px solid #1E3A5F; border-radius: 6px; padding: 6px 12px;
    margin: 4px 0; background: #0F2537; color: #9FE2B0;
    font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 0.72rem;
    word-break: break-all;
}
.cs-golden {
    border: 1px solid #E0A800; border-left: 5px solid #E0A800;
    border-radius: 8px; padding: 12px 16px; margin: 8px 0;
    background: #FFF8E6; color: #7A5C00; font-size: 0.84rem; line-height: 1.5;
}
.cs-sev {
    display: inline-block; border-radius: 999px; padding: 2px 12px;
    font-size: 0.72rem; font-weight: 800; letter-spacing: 0.08em; color: #FFFFFF;
}
.cs-sev.critical { background: #B91C1C; }
.cs-sev.high { background: #D9730D; }
.cs-sev.medium { background: #0A74B9; }
.cs-sev.low { background: #15803D; }
</style>
"""


# --------------------------------------------------------------------------- #
# Cached resources & data access.                                            #
# --------------------------------------------------------------------------- #


@st.cache_resource(show_spinner=False)
def get_agent() -> Optional[ResearchAgent]:
    """Construct the analytics agent once; None if Gemini is unconfigured."""
    try:
        return ResearchAgent()
    except (RuntimeError, ValueError):
        LOGGER.exception("Research agent unavailable")
        return None


def _cache_day() -> str:
    """Today's UTC date — folded into cache keys for date-relative freshness."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# Each cache is keyed on (interval, exclude_demo, day): toggling the
# chronological filter OR the data-integrity toggle instantly invalidates the
# entry, forcing a fresh windowed SQLite read; a date rollover invalidates via
# ``day``.
@st.cache_data(ttl=60, show_spinner=False)
def cached_hotspots(
    interval: str, exclude_demo: bool, day: str
) -> List[Dict[str, object]]:
    """Interval-filtered geospatial hot-spot rows (cache-keyed on all inputs)."""
    return rr.geospatial_hotspots(interval, exclude_demo)


@st.cache_data(ttl=60, show_spinner=False)
def cached_vectors(
    interval: str, exclude_demo: bool, day: str
) -> List[Dict[str, object]]:
    """Interval-filtered scam-vector landscape rows (cache-keyed on all inputs)."""
    return rr.scam_vector_landscape(interval, exclude_demo)


@st.cache_data(ttl=60, show_spinner=False)
def cached_demographic(
    interval: str, dimension: str, exclude_demo: bool, day: str
) -> List[Dict[str, object]]:
    """Interval-filtered demographic breakdown rows (cache-keyed on all inputs)."""
    return rr.demographic_matrix(interval, dimension, exclude_demo)


@st.cache_data(ttl=300, show_spinner=False)
def cached_briefing(interval: str, exclude_demo: bool, day: str) -> str:
    """Story-driven Threat Briefing for the active filter (cached 5 min)."""
    from services.briefing import generate_briefing
    stats: Dict[str, object] = rr.briefing_stats(interval, exclude_demo)
    return generate_briefing(stats, interval)


# Zero-state web-seeding (cached 1 hour to avoid re-billing SerpAPI/Gemini).
@st.cache_data(ttl=3600, show_spinner=False)
def cached_web_advisories(scam_type: str, day: str) -> List[Dict[str, str]]:
    """Live web-sourced advisory cards for an empty advisory panel."""
    from services.web_seed import web_sourced_advisories
    return web_sourced_advisories(scam_type)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_regional_insight(label: str, day: str) -> Dict[str, object]:
    """Live web-augmented threat insight for an empty chart/state."""
    from services.web_seed import regional_insight
    return regional_insight(label)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_playbook(
    threat_domain: str, target_sector: str, day: str
) -> List[Dict[str, str]]:
    """Cached 4-point forensic triage playbook (one LLM call per combo/day)."""
    from services.playbook import generate_triage_playbook
    return generate_triage_playbook(threat_domain, target_sector)


# --- Cached read-side wrappers: every dashboard query is cache-keyed so a    --
# --- filter rerun never re-opens the SQLite file on the main thread. The     --
# --- minute-bucket key keeps RAG-seeded / worker-written rows fresh.         --
def _minute_bucket() -> str:
    """Cache key that rolls every 30s so newly-written rows surface quickly."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y%m%d%H") + str(now.minute // 1)


@st.cache_data(ttl=60, show_spinner=False)
def cached_advisories(interval: str, scam_vector: Optional[str], bucket: str
                      ) -> List[Dict[str, object]]:
    """Cached official-safety advisories for the active filter."""
    return rr.latest_advisories(interval, scam_vector=scam_vector, limit=6)


@st.cache_data(ttl=300, show_spinner=False)
def cached_states(bucket: str) -> List[str]:
    """Cached state/UT list for the tracker selector."""
    return rr.distinct_states()


@st.cache_data(ttl=60, show_spinner=False)
def cached_state_snapshot(interval: str, state: str, exclude_demo: bool,
                          bucket: str) -> Dict[str, object]:
    """Cached live-vs-benchmark snapshot for one state."""
    return rr.state_versus_national(interval, state, exclude_demo)


@st.cache_data(ttl=30, show_spinner=False)
def cached_domain_kpis(interval: str, exclude_demo: bool, bucket: str
                       ) -> Dict[str, object]:
    """Cached non-financial KPI aggregate (30s so seeded rows surface fast)."""
    return rr.domain_kpis(interval, exclude_demo)


@st.cache_data(ttl=30, show_spinner=False)
def cached_records_by_sector(interval: str, exclude_demo: bool, bucket: str
                             ) -> List[Dict[str, object]]:
    """Cached records-exposed-by-sector aggregate."""
    return rr.records_by_sector(interval, exclude_demo)


@st.cache_data(ttl=30, show_spinner=False)
def cached_incidents_by_domain(interval: str, exclude_demo: bool, bucket: str
                               ) -> List[Dict[str, object]]:
    """Cached incidents-by-domain aggregate."""
    return rr.incidents_by_domain(interval, exclude_demo)


@st.cache_data(ttl=30, show_spinner=False)
def cached_asset_log(interval: str, exclude_demo: bool, bucket: str
                     ) -> List[Dict[str, object]]:
    """Cached non-financial asset intelligence log."""
    return rr.asset_log(interval, exclude_demo)


@st.cache_data(ttl=30, show_spinner=False)
def cached_corpus_size(bucket: str) -> int:
    """Cached corpus row count."""
    return rr.corpus_size()


@st.cache_resource(show_spinner=False)
def warm_resources() -> bool:
    """Load heavy ML resources (embedding model) once per session — keeps the
    embedding model out of the per-rerun hot path and off stdout."""
    try:
        from core.database import VectorStoreManager
        VectorStoreManager().get_collection("research_corpus")
    except (RuntimeError, ValueError, KeyError):
        LOGGER.exception("resource warmup skipped")
    return True


ZERO_STATE_MESSAGE: str = "No active telemetry records captured for this filter window."


def render_web_advisories(scam_type: str) -> bool:
    """Render live web-sourced advisory cards; True if any were rendered."""
    from services.web_seed import web_seed_available
    if not web_seed_available():
        return False
    with st.spinner("Seeding live advisories from the web…"):
        cards: List[Dict[str, str]] = cached_web_advisories(
            scam_type or "cyber fraud", _cache_day())
    if not cards:
        return False
    for card in cards:
        url: str = str(card.get("url") or "")
        link: str = (f"<br>🔗 <a href='{url}' target='_blank'>Source</a>"
                     if url else "")
        st.markdown(
            f"""<div class="cs-advisory">
            <span class="cs-webbadge">🌐 Live Web Sourced</span>
            <b>{card.get('title', '')}</b><br>
            {card.get('description', '')}{link}</div>""",
            unsafe_allow_html=True,
        )
    return True


def render_insight_panel(label: str) -> None:
    """Swap a broken empty chart for a live LLM Analytical Insight Panel."""
    from services.web_seed import web_seed_available
    if not web_seed_available():
        st.info(ZERO_STATE_MESSAGE)
        return
    with st.spinner(f"Synthesizing live web intelligence for {label}…"):
        insight: Dict[str, object] = cached_regional_insight(label, _cache_day())
    if not insight or not insight.get("summary"):
        st.info(ZERO_STATE_MESSAGE)
        return
    st.markdown(
        f"""<div class="cs-briefing">🌐 <b>LLM ANALYTICAL INSIGHT</b>
        &nbsp;·&nbsp; {label} &nbsp;·&nbsp; Live Web-Augmented</div>""",
        unsafe_allow_html=True,
    )
    body_col, metric_col = st.columns([3, 1])
    with body_col:
        st.markdown(str(insight.get("summary", "")))
    with metric_col:
        st.metric("Live Web-Augmented Estimate", str(insight.get("estimate", "—")))
        st.caption(f"Threat level: {insight.get('threat_level', '—')}")
    sources: List[Dict[str, str]] = insight.get("sources", [])  # type: ignore[assignment]
    if sources:
        with st.expander("🔗 Web sources"):
            for src in sources:
                src_url: str = str(src.get("url") or "")
                title: str = str(src.get("title") or src_url or "source")
                if src_url:
                    st.markdown(f"- [{title}]({src_url})")


def _inr(value: float) -> str:
    """Format an INR amount into a compact crore/lakh string."""
    if value >= 1e7:
        return f"₹{value / 1e7:.2f} Cr"
    if value >= 1e5:
        return f"₹{value / 1e5:.2f} L"
    return f"₹{value:,.0f}"


# --------------------------------------------------------------------------- #
# Layout chrome.                                                              #
# --------------------------------------------------------------------------- #


def render_header() -> None:
    """Academic identity header with the repository mission statement."""
    st.markdown(
        """
        <div class="cs-header">
          <h1>🛡️ Cyber Shield India</h1>
          <p>Unified Cybercrime Research Conspectus &amp; Trend Repository</p>
          <p class="desc">A centralized repository aggregating distributed
             public cyber advisories, safety matrices, and threat data into a
             single open-access hub for scholars, students, and trend
             researchers.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state(message: str) -> None:
    """Clean placeholder when the corpus has no data for the filter."""
    st.markdown(f'<div class="cs-empty">{message}</div>', unsafe_allow_html=True)


# --------------------------------------------------------------------------- #
# Module 1 — Geospatial Crime Hot-Spots.                                      #
# --------------------------------------------------------------------------- #


def render_geospatial(interval: str, exclude_demo: bool) -> None:
    """India hot-spot map (cities) + state-level financial-impact bars.

    Every layer is rebuilt from the interval-filtered frame on each rerun:
    bubble size binds to live ``cases`` and colour intensity to live
    ``loss``. A state/window with no live telemetry renders a clean
    zero-state instead of a stale placeholder layer.
    """
    st.markdown("#### 🗺️ Geospatial Crime Hot-Spots")
    rows: List[Dict[str, object]] = cached_hotspots(
        interval, exclude_demo, _cache_day())
    frame: pd.DataFrame = pd.DataFrame(rows)
    # Drop rows that carry no live signal so zero-telemetry states never
    # surface as artifacts on the map or bars.
    if not frame.empty:
        frame["loss"] = frame["loss"].fillna(0.0)
        frame["cases"] = frame["cases"].fillna(0).astype(int)
        frame = frame[(frame["cases"] > 0) | (frame["loss"] > 0)]
    if frame.empty:
        # No live hot-spots — seed a national web-augmented insight panel
        # instead of a broken empty map canvas.
        render_insight_panel("India cyber fraud hot-spots")
        return

    map_col, bar_col = st.columns([3, 2])
    with map_col:
        mapped: pd.DataFrame = frame[frame["city"].isin(CITY_COORDS)].copy()
        if not mapped.empty:
            mapped["lat"] = mapped["city"].map(lambda c: CITY_COORDS[c][0])
            mapped["lon"] = mapped["city"].map(lambda c: CITY_COORDS[c][1])
            max_loss: float = float(mapped["loss"].max()) or 1.0
            figure: go.Figure = px.scatter_geo(
                mapped, lat="lat", lon="lon", size="cases",
                color="loss", hover_name="city",
                hover_data={"state": True, "loss": ":,.0f", "cases": True,
                            "lat": False, "lon": False},
                color_continuous_scale="Reds", range_color=[0, max_loss],
                size_max=42,
                title="Hot-spot cities — bubble size = live cases, colour = ₹ loss",
            )
            figure.update_geos(scope="asia", center={"lat": 22.0, "lon": 80.0},
                               lataxis_range=[6, 37], lonaxis_range=[67, 98],
                               showcountries=True, landcolor="#EAEFF4")
            figure.update_layout(height=360, margin={"l": 0, "r": 0, "t": 40, "b": 0})
            st.plotly_chart(figure, width="stretch")
        else:
            st.info("No mapped hot-spot cities with live telemetry this window.")
    with bar_col:
        by_state: pd.DataFrame = (
            frame.groupby("state", as_index=False)["loss"].sum()
            .sort_values("loss", ascending=True)
        )
        bar: go.Figure = px.bar(
            by_state, x="loss", y="state", orientation="h",
            title="Financial impact by state (₹, live)",
            color_discrete_sequence=["#0A74B9"],
        )
        bar.update_layout(height=360, margin={"l": 0, "r": 0, "t": 40, "b": 0})
        st.plotly_chart(bar, width="stretch")


# --------------------------------------------------------------------------- #
# Module 2 — Scam-Vector Landscape.                                           #
# --------------------------------------------------------------------------- #


def render_vector_landscape(interval: str, exclude_demo: bool) -> None:
    """Distribution of emerging scam types by cases and financial toll."""
    st.markdown("#### 🧬 Scam-Vector Landscape")
    rows: List[Dict[str, object]] = cached_vectors(
        interval, exclude_demo, _cache_day())
    if not rows:
        render_empty_state("No scam-vector datapoints in this window yet.")
        return
    frame: pd.DataFrame = pd.DataFrame(rows)
    left, right = st.columns(2)
    with left:
        pie: go.Figure = px.pie(
            frame, names="vector", values="cases", hole=0.45,
            title="Share of reported cases by scam type",
        )
        pie.update_layout(height=340, margin={"l": 0, "r": 0, "t": 40, "b": 0})
        st.plotly_chart(pie, width="stretch")
    with right:
        bar: go.Figure = px.bar(
            frame.sort_values("loss"), x="loss", y="vector", orientation="h",
            title="Financial toll by scam type (₹)",
            color_discrete_sequence=["#0F2537"],
        )
        bar.update_layout(height=340, margin={"l": 0, "r": 0, "t": 40, "b": 0})
        st.plotly_chart(bar, width="stretch")


# --------------------------------------------------------------------------- #
# Module 3 — Demographic Vulnerability Matrix.                                #
# --------------------------------------------------------------------------- #


def render_demographic(interval: str, exclude_demo: bool) -> None:
    """Side-by-side age/gender/profession charts + live advisory panel."""
    st.markdown("#### 👥 Demographic Vulnerability Matrix")
    charts_col, advisory_col = st.columns([3, 2])
    with charts_col:
        dims: List[Tuple[str, str]] = [
            ("age", "Age bracket"), ("gender", "Gender skew"),
            ("profession", "Occupation"),
        ]
        triple: List[object] = st.columns(3)
        for column, (dimension, label) in zip(triple, dims):
            data: List[Dict[str, object]] = cached_demographic(
                interval, dimension, exclude_demo, _cache_day())
            with column:  # type: ignore[union-attr]
                if not data:
                    render_empty_state(f"No {label.lower()} data.")
                    continue
                frame: pd.DataFrame = pd.DataFrame(data)
                fig: go.Figure = px.bar(
                    frame, x="bucket", y="cases", title=label,
                    color_discrete_sequence=["#0A74B9"],
                )
                fig.update_layout(height=300, xaxis_title=None, yaxis_title=None,
                                  margin={"l": 0, "r": 0, "t": 40, "b": 0})
                st.plotly_chart(fig, width="stretch")
    with advisory_col:
        st.markdown("**Matching official safety advisories**")
        vectors: List[Dict[str, object]] = cached_vectors(
            interval, exclude_demo, _cache_day())
        vector_names: List[str] = [str(v["vector"]) for v in vectors]
        chosen: Optional[str] = None
        if vector_names:
            chosen = st.selectbox("Filter advisories by scam type",
                                  ["All"] + vector_names)
            chosen = None if chosen == "All" else chosen
        advisories: List[Dict[str, object]] = cached_advisories(interval, chosen, _minute_bucket())
        if not advisories:
            # Zero-state: seed live advisory cards from the web for this vector.
            seed_topic: str = chosen or "cyber fraud"
            if not render_web_advisories(seed_topic):
                st.info(ZERO_STATE_MESSAGE)
        for advisory in advisories:
            url: str = str(advisory.get("source_url") or "")
            link_html: str = (
                f'<br>🔗 <a href="{url}" target="_blank">Source</a>' if url else ""
            )
            st.markdown(
                f"""<div class="cs-advisory">🛡️ <b>{advisory['scam_vector_type']}</b>
                &nbsp;·&nbsp; {advisory.get('state') or 'National'}<br>
                {advisory.get('official_safety_advisory') or ''}
                <br><span style="color:#6B7280;font-size:0.72rem;">
                {advisory.get('source_platform') or ''} ·
                {advisory.get('dated') or ''}</span>{link_html}</div>""",
                unsafe_allow_html=True,
            )


# --------------------------------------------------------------------------- #
# Module 4 — Localized State Tracker.                                         #
# --------------------------------------------------------------------------- #


def render_state_tracker(interval: str, exclude_demo: bool) -> None:
    """Raw live state telemetry overlaid against the NCRB control benchmark.

    In pure-operational mode (``exclude_demo``), the NCRB baseline overlay is
    suppressed entirely — the tracker shows only live crawled telemetry.
    """
    st.markdown("#### 📍 Localized State Tracker")
    states: List[str] = cached_states(_minute_bucket())
    if not states:
        render_empty_state("No state-level data in the corpus yet.")
        return
    default_index: int = states.index("Tamil Nadu") if "Tamil Nadu" in states else 0
    state: str = st.selectbox("Select your state context", states, index=default_index)
    snapshot: Dict[str, object] = cached_state_snapshot(
        interval, state, exclude_demo, _minute_bucket())
    if not snapshot:
        render_empty_state("No comparison available for this state/window.")
        return
    live_cases: float = float(snapshot["live_cases"])         # type: ignore[arg-type]
    live_loss: float = float(snapshot["live_loss"])           # type: ignore[arg-type]
    bench_cases: float = float(snapshot["benchmark_cases"])   # type: ignore[arg-type]
    bench_loss: float = float(snapshot["benchmark_loss"])     # type: ignore[arg-type]
    window_label: str = INTERVAL_LABELS.get(interval, interval)

    # Engineering ingestion-deficit alert (shown only when the NCRB control is
    # in play; pure-operational mode has no baseline to compare against).
    if not exclude_demo and bool(snapshot.get("ingestion_deficit")):
        st.warning(
            "⚠️ Potential Ingestion Deficit: High-baseline region yielding zero "
            "telemetry. Verify crawler connectivity for this state's domains."
        )

    live_is_zero: bool = live_cases == 0 and live_loss == 0.0

    if exclude_demo:
        # Pure operational view — live telemetry only, no NCRB baseline.
        st.caption("🟢 Pure operational mode — NCRB baseline overlay hidden.")
        metric_cols: List[object] = st.columns(2)
        with metric_cols[0]:
            st.metric(f"Live cases · {window_label}", f"{live_cases:,.0f}")
        with metric_cols[1]:
            st.metric(f"Live loss · {window_label}", _inr(live_loss))
        if live_is_zero:
            # No live telemetry — swap the empty chart for a web insight panel.
            render_insight_panel(f"{state} cyber crime")
            return
        figure: go.Figure = go.Figure()
        figure.add_bar(x=["Reported cases"], y=[live_cases], name="Live captured",
                       marker={"color": "#0A74B9"})
        figure.update_layout(
            title=f"{state}: live telemetry ({window_label})",
            height=320, margin={"l": 10, "r": 10, "t": 40, "b": 10},
            showlegend=False,
        )
        st.plotly_chart(figure, width="stretch")
        return

    st.caption(f"Dominant historical vector: **{snapshot.get('primary_vector', '—')}** "
               f"· NCRB annual baseline: {int(snapshot.get('annual_cases', 0)):,} cases")

    # Two visually distinct metric groups — live telemetry vs control model.
    live_col, bench_col = st.columns(2)
    with live_col:
        st.markdown("**🟢 Active Cases Captured (Live Crawl)**")
        inner: List[object] = st.columns(2)
        with inner[0]:
            st.metric(f"Cases · {window_label}", f"{live_cases:,.0f}")
        with inner[1]:
            st.metric(f"Loss · {window_label}", _inr(live_loss))
    with bench_col:
        st.markdown("**🔶 NCRB Historical Benchmark (Prorated)**")
        inner_b: List[object] = st.columns(2)
        with inner_b[0]:
            st.metric(f"Expected cases · {window_label}", f"{bench_cases:,.0f}")
        with inner_b[1]:
            st.metric(f"Expected loss · {window_label}", _inr(bench_loss))

    if live_is_zero:
        # No live telemetry for this state/window — swap the empty live-vs-
        # baseline chart for a web-augmented insight panel.
        render_insight_panel(f"{state} cyber crime")
        return

    # Live solid bar with the NCRB baseline as a dashed reference line.
    figure = go.Figure()
    figure.add_bar(x=["Reported cases"], y=[live_cases], name="Live captured",
                   marker={"color": "#0A74B9"})
    figure.add_hline(
        y=bench_cases, line_dash="dash", line_color="#D97706",
        annotation_text="NCRB Statistical Baseline", annotation_position="top left",
    )
    headroom: float = max(live_cases, bench_cases) * 1.25 or 1.0
    figure.update_layout(
        title=f"{state}: live telemetry vs NCRB baseline ({window_label})",
        height=320, yaxis_range=[0, headroom],
        margin={"l": 10, "r": 10, "t": 40, "b": 10}, showlegend=False,
    )
    st.plotly_chart(figure, width="stretch")
    if live_cases < bench_cases:
        st.caption("📉 Live captures are running **below** the historical NCRB "
                   "baseline for this window.")
    else:
        st.caption("📈 Live captures are running **at or above** the historical "
                   "NCRB baseline for this window.")


def render_infrastructure_kpis(interval: str, exclude_demo: bool) -> None:
    """Dedicated non-financial technical KPI block (records, incidents, domains).

    Strictly separate from the financial dashboard above — currency never
    appears here; the financial loss stays in the financial section.
    """
    kpis: Dict[str, object] = cached_domain_kpis(interval, exclude_demo, _minute_bucket())
    if not kpis:
        st.info(ZERO_STATE_MESSAGE)
        return
    cols: List[object] = st.columns(3)
    with cols[0]:
        st.metric("🗄️ Records Exposed", f"{int(kpis.get('records_exposed', 0)):,}")  # type: ignore[arg-type]
    with cols[1]:
        st.metric("🚨 Incidents", f"{int(kpis.get('incidents', 0)):,}")  # type: ignore[arg-type]
    with cols[2]:
        st.metric("🧭 Active Threat Domains", str(kpis.get("active_domains", 0)))
    by_domain: List[Dict[str, object]] = kpis.get("by_domain", [])  # type: ignore[assignment]
    if by_domain:
        chips: str = " ".join(
            f"<span class='cs-domainchip'>{d.get('domain', '?')} · "
            f"{int(d.get('n', 0))}</span>"
            for d in by_domain
        )
        st.markdown(f"<div style='margin:2px 0 6px 0;'>{chips}</div>",
                    unsafe_allow_html=True)
    st.caption("Non-financial threat-domain telemetry (data leaks, deepfakes, "
               "phishing, network attacks) updates continuously as new "
               "intelligence is captured.")


_GATHERING_MSG: str = (
    "⏳ Gathering live threat data… ask the Semantic Explorer about a data "
    "breach, ransomware, or infrastructure attack to seed this section."
)


def render_infrastructure_charts(interval: str, exclude_demo: bool) -> None:
    """Two-column non-financial analytics: records-by-sector + domain matrix."""
    sectors: List[Dict[str, object]] = cached_records_by_sector(
        interval, exclude_demo, _minute_bucket())
    domains: List[Dict[str, object]] = cached_incidents_by_domain(
        interval, exclude_demo, _minute_bucket())
    if not sectors and not domains:
        st.info(_GATHERING_MSG)
        return
    left, right = st.columns(2)
    with left:
        st.markdown("**🗄️ Records Exposed by Targeted Sector**")
        if sectors:
            frame: pd.DataFrame = pd.DataFrame(sectors).sort_values("records")
            fig: go.Figure = px.bar(
                frame, x="records", y="sector", orientation="h",
                color_discrete_sequence=["#0F2537"],
            )
            fig.update_layout(height=320, xaxis_title="Records exposed",
                              yaxis_title=None,
                              margin={"l": 0, "r": 0, "t": 10, "b": 0})
            st.plotly_chart(fig, width="stretch")
        else:
            st.info(_GATHERING_MSG)
    with right:
        st.markdown("**🧬 Incident Volume by Threat Domain**")
        if domains:
            frame_d: pd.DataFrame = pd.DataFrame(domains)
            fig_d: go.Figure = px.pie(
                frame_d, names="domain", values="incidents", hole=0.45,
            )
            fig_d.update_layout(height=320,
                                margin={"l": 0, "r": 0, "t": 10, "b": 0})
            st.plotly_chart(fig_d, width="stretch")
        else:
            st.info(_GATHERING_MSG)


def render_asset_intelligence(interval: str, exclude_demo: bool) -> None:
    """Asset Intelligence Log (table only).

    The forensic-playbook selector and BSA certificate export that previously
    lived here now reside in the Victim Triage tab
    (:func:`render_triage_playbook_console`); this legacy view is purely the
    technical-indicator table.
    """
    st.markdown("#### 🔍 Actionable Technical Indicators & Assets")
    log: List[Dict[str, object]] = cached_asset_log(interval, exclude_demo, _minute_bucket())
    if not log:
        st.info(_GATHERING_MSG)
        return
    frame: pd.DataFrame = pd.DataFrame(log).rename(columns={
        "timestamp": "Timestamp", "threat_domain": "Threat Domain",
        "target_sector": "Target Sector", "compromised_assets": "Compromised Assets",
    })
    st.dataframe(
        frame[["Timestamp", "Threat Domain", "Target Sector", "Compromised Assets"]],
        width="stretch", hide_index=True,
    )


def render_threat_tag_matrix() -> Optional[str]:
    """Global tag selector that bubbles a chosen scam mechanism across the board.

    The selection is mirrored into ``st.session_state['active_threat_tag']`` so it
    carries over to the Victim Triage tab (cross-tab continuity).
    """
    st.markdown("##### 🏷️ Cross-Referencing Threat Tag Matrix")
    st.caption(
        "Select a scam mechanism to instantly filter the regulatory advisories "
        "and expert signals below. Your selection carries into Victim Triage to "
        "pre-select the matching playbook and highlight the relevant provisions.")
    tags: List[str] = threat_registry.list_tags()
    options: List[str] = ["🌐 All vectors"] + tags
    current = st.session_state.get("active_threat_tag")
    index: int = options.index(current) if current in options else 0
    chosen: str = st.radio(
        "Active threat vector", options, horizontal=True, index=index,
        key="threat_tag_radio", label_visibility="collapsed")
    active: Optional[str] = None if chosen == "🌐 All vectors" else chosen
    st.session_state["active_threat_tag"] = active
    if active:
        meta = threat_registry.get_tag(active)
        if meta is not None:
            st.markdown(
                f"<div class='cs-briefing'>🏷️ <b>{meta.tag} — {meta.label}.</b> "
                f"{meta.mechanism}</div>", unsafe_allow_html=True)
            st.markdown(
                f"📡 Matching regulatory body: **[{meta.advisory_body}]"
                f"({meta.advisory_url})** &nbsp;·&nbsp; Indicative provisions: "
                f"{meta.provisions}")
    return active


def render_tag_advisories(active_tag: Optional[str]) -> None:
    """Bubble up official + live web advisories matching the active mechanism."""
    st.markdown("##### 📡 Regulatory & Official Advisories")
    if active_tag:
        meta = threat_registry.get_tag(active_tag)
        scam_query: str = meta.label if meta else "cyber fraud"
        if meta is not None:
            st.markdown(
                f"<div class='cs-advisory'>"
                f"<span class='cs-webbadge'>🏛️ Official Source</span>"
                f"<b>{meta.advisory_body}</b> — authoritative advisory channel for "
                f"{meta.label}.<br>🔗 <a href='{meta.advisory_url}' target='_blank'>"
                f"Open advisory portal</a></div>", unsafe_allow_html=True)
    else:
        scam_query = "cyber fraud"
        st.caption("Select a tag above to bubble up advisories for that specific "
                   "mechanism, or browse the general live feed below.")
    # render_web_advisories returns False when the cascade is fully exhausted (or
    # web seeding is unavailable). Intercept cleanly: banner + static baseline so
    # the tab populates from offline data instead of an unhandled error screen.
    if not render_web_advisories(scam_query):
        st.warning("⚠️ Upstream Threat Intelligence Engine is temporarily "
                   "experiencing high volume. Serving localized offline advisory "
                   "updates.")
        for card in threat_registry.offline_advisories(active_tag):
            st.markdown(
                f"<div class='cs-advisory'>"
                f"<span class='cs-webbadge'>🗂️ Offline Baseline</span>"
                f"<b>{card['title']}</b><br>{card['description']}<br>"
                f"🔗 <a href='{card['url']}' target='_blank'>Official advisory "
                f"portal</a></div>", unsafe_allow_html=True)


# Severity → (badge emoji, accent colour) for the threat matrix display.
_SEVERITY_BADGE: Dict[str, Tuple[str, str]] = {
    "CRITICAL": ("🔴", "#C0392B"),
    "HIGH": ("🟠", "#D97706"),
    "MEDIUM": ("🟡", "#2E7D32"),
}


def _severity_label(severity: str) -> str:
    """Return a scannable '🔴 CRITICAL' style badge label."""
    emoji, _ = _SEVERITY_BADGE.get(severity.upper(), ("⚪", "#4B5C6B"))
    return f"{emoji} {severity.upper()}"


def _render_jurisdiction_header(name: str, intel: Dict[str, object]) -> None:
    """Authoritative directory header card: nodal cell + reporting portal."""
    kind: str = threat_registry.jurisdiction_kind(name)
    cell: str = str(intel.get("cell_name", "—"))
    portal: str = str(intel.get("portal", threat_registry.NCRP_PORTAL))
    st.markdown(
        f"<div class='cs-advisory'>"
        f"<span class='cs-webbadge'>🏛️ National Directory</span>"
        f"<b>{name}</b> &nbsp;·&nbsp; <i>{kind}</i><br>"
        f"<b>Cyber Nodal Cell:</b> {cell}</div>", unsafe_allow_html=True)
    left, right = st.columns([2, 2])
    with left:
        st.metric("📞 NCRP Helpline", threat_registry.NCRP_HELPLINE)
        st.markdown(f"**🔗 Reporting Portal**  \n[{portal}]({portal})")
    with right:
        st.metric("🧭 Jurisdiction Type", kind)
        st.markdown(f"**🛡️ Escalation**  \nFile at "
                    f"[NCRP]({threat_registry.NCRP_PORTAL}) within the golden "
                    "hour · route to the nodal cell above.")


def _render_high_alert_vector(vector_name: str, vec: Dict[str, object]) -> None:
    """Bubble a tag-matched vector as a prominent, colour-coded high alert."""
    severity: str = str(vec.get("severity", "MEDIUM")).upper()
    emoji, color = _SEVERITY_BADGE.get(severity, ("⚪", "#4B5C6B"))
    st.markdown(
        f"<div class='cs-advisory' style='border-left:6px solid {color}'>"
        f"<span class='cs-sev' style='background:{color}'>{emoji} {severity}</span>"
        f"&nbsp;<b>{vector_name}</b> &nbsp;·&nbsp; {vec.get('trend', '')}<br>"
        f"<span style='color:#7FA8C9;font-size:0.8rem'>📋 Governing bulletin: "
        f"{vec.get('bulletin', '')}</span></div>", unsafe_allow_html=True)


def _render_state_matrix_table(intel: Dict[str, object]) -> None:
    """Render a State/UT's full 3-vector threat catalog as a scannable table."""
    matrix: Dict[str, object] = intel.get("threat_matrix", {})  # type: ignore[assignment]
    rows: List[Dict[str, str]] = []
    for vname, vec in matrix.items():
        rows.append({
            "Active Threat Vector": vname,
            "Severity": _severity_label(str(vec.get("severity", ""))),
            "Trend": str(vec.get("trend", "")),
            "Governing Bulletin": str(vec.get("bulletin", "")),
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render_jurisdiction_directory(interval: str, exclude_demo: bool) -> None:
    """36-jurisdiction State/UT directory with a tag-aware dynamic threat matrix."""
    st.markdown("#### 📍 State & Union Territory Threat Directory")
    st.caption("All 28 States and 8 Union Territories mapped to their cyber nodal "
               "cell, reporting portal and a live 3-vector threat matrix. Select a "
               "tag in the matrix above to bubble the matching regional vector to "
               "the top.")
    names: List[str] = threat_registry.all_jurisdictions()
    default_index: int = names.index("Tamil Nadu") if "Tamil Nadu" in names else 0
    chosen: str = st.selectbox("Select your State / Union Territory context",
                               names, index=default_index)
    intel = threat_registry.get_state_intel(chosen)
    if intel is None:
        st.info("No directory profile found for this jurisdiction.")
        return
    _render_jurisdiction_header(chosen, intel)

    active_tag: Optional[str] = st.session_state.get("active_threat_tag")
    matrix: Dict[str, object] = intel.get("threat_matrix", {})  # type: ignore[assignment]

    # Scenario A — a global tag is active: bubble the matching regional vector(s).
    if active_tag:
        matches = [(n, v) for n, v in matrix.items()
                   if isinstance(v, dict) and v.get("tag") == active_tag]
        if matches:
            st.markdown(f"##### 🚨 Tag-matched high-alert vector — {active_tag} "
                        f"in {chosen}")
            for name, vec in matches:
                _render_high_alert_vector(name, vec)
            st.caption("Full regional catalog:")
            _render_state_matrix_table(intel)
            return
        st.info(f"No active **{active_tag}** vector recorded for {chosen} — "
                "showing the full regional threat catalog.")

    # Scenario B — no active tag (or no match): the full scannable catalog.
    st.markdown(f"##### 🗂️ Regional threat catalog — {chosen}")
    _render_state_matrix_table(intel)


def render_signal_monitor(active_tag: Optional[str]) -> None:
    """Phase 3 — curated expert & enforcement awareness signal feed."""
    st.markdown("### 🎙️ Community Awareness & Signal Aggregation Engine")
    caption: str = ("Curated security alerts and tactical case breakdowns from "
                    "prominent cyber-awareness creators and city/state cyber cells.")
    if active_tag:
        caption += f" Filtered to **{active_tag}**."
    st.caption(caption)
    signals = threat_registry.signals_for_tag(active_tag)
    if not signals:
        st.info(f"No curated signals tagged {active_tag} yet — showing the full "
                "awareness feed.")
        signals = threat_registry.signals_for_tag(None)
    for signal in signals:
        meta_col, body_col = st.columns([1, 3])
        with meta_col:
            st.markdown(f"**{signal.author}**")
            st.caption(signal.credentials)
            st.caption(f"{signal.handle} · 🗓️ {signal.published}")
            chips: str = " ".join(
                f"<span class='cs-domainchip'>{tag}</span>" for tag in signal.tags)
            if chips:
                st.markdown(chips, unsafe_allow_html=True)
        with body_col:
            st.markdown(signal.summary)
            if signal.poster_note:
                st.markdown(
                    f"<div class='cs-advisory'>🖼️ <b>Advisory poster:</b> "
                    f"{signal.poster_note}</div>", unsafe_allow_html=True)
        st.divider()


def render_macro_trends_tab(exclude_demo: bool) -> None:
    """Strategic Threat Analytics — asset-centric TIP registry & signal engine."""
    st.caption(
        "Unified threat registry and analytical engine aggregating regional "
        "incident parameters, statutory frameworks, and historical multi-state "
        "cybercrime baselines.")
    if exclude_demo:
        st.caption("🔒 **Pure operational mode** — demo & NCRB-baseline records "
                   "stripped; live crawled telemetry only.")
    interval: str = st.radio(
        "Chronological filter", INTERVAL_ORDER,
        format_func=lambda key: INTERVAL_LABELS[key],
        horizontal=True, index=3,
    )
    with st.spinner("Compiling live threat intelligence…"):
        briefing: str = cached_briefing(interval, exclude_demo, _cache_day())
    st.markdown(
        f"""<div class="cs-briefing">📰 <b>THREAT BRIEFING</b>
        &nbsp;·&nbsp; {INTERVAL_LABELS.get(interval, interval)}<br>{briefing}</div>""",
        unsafe_allow_html=True,
    )

    # ===== Cross-referencing tag matrix (drives the whole board) ============
    st.divider()
    active_tag: Optional[str] = render_threat_tag_matrix()

    # ===== Regulatory advisories scoped to the active mechanism ============
    st.divider()
    render_tag_advisories(active_tag)

    # ===== 36-jurisdiction State/UT directory with admin fallback ==========
    st.divider()
    render_jurisdiction_directory(interval, exclude_demo)

    # ===== Dense non-financial technical KPI strip (qualitative) ===========
    st.divider()
    st.markdown("### 🚨 Digital & Infrastructure Threat Intel")
    render_infrastructure_kpis(interval, exclude_demo)

    # ===== Expert & enforcement awareness signal monitor ===================
    st.divider()
    render_signal_monitor(active_tag)

    # ===== Historical baseline chart layer (graceful bottom section) =======
    st.markdown("---")
    st.markdown("### 📊 Historical Baselines & Volatile Statistical Visualizers")
    with st.expander("📈 View Legacy Spatial & Vector Analytics Charts",
                     expanded=False):
        render_geospatial(interval, exclude_demo)
        st.divider()
        render_vector_landscape(interval, exclude_demo)
        st.divider()
        render_demographic(interval, exclude_demo)
        st.divider()
        render_state_tracker(interval, exclude_demo)
        st.divider()
        render_infrastructure_charts(interval, exclude_demo)
        st.divider()
        render_asset_intelligence(interval, exclude_demo)


# --------------------------------------------------------------------------- #
# Agentic chart rendering (deterministic from the validated plan).            #
# --------------------------------------------------------------------------- #


def _build_chart(plan: AnalyticalPlan, frame: pd.DataFrame) -> Optional[go.Figure]:
    """Deterministically build a Plotly figure from a validated plan."""
    x: Optional[str] = plan.x if plan.x in frame.columns else None
    y: Optional[str] = plan.y if plan.y in frame.columns else None
    color: Optional[str] = plan.color if plan.color in frame.columns else None
    if x is None and frame.columns.size:
        x = str(frame.columns[0])
    if y is None and frame.columns.size > 1:
        y = str(frame.columns[1])
    try:
        if plan.chart_type == "pie" and x and y:
            return px.pie(frame, names=x, values=y, title=plan.title)
        if plan.chart_type == "line" and x and y:
            return px.line(frame, x=x, y=y, color=color, title=plan.title,
                           markers=True)
        if plan.chart_type == "scatter" and x and y:
            return px.scatter(frame, x=x, y=y, color=color, title=plan.title)
        if x and y:
            return px.bar(frame, x=x, y=y, color=color, title=plan.title,
                          color_discrete_sequence=["#0A74B9"])
    except (ValueError, KeyError):
        LOGGER.exception("chart build failed for plan %s", plan.title)
        return None
    return None


STRICT_WINDOW_NOTE: str = (
    "No matching records found for the strict time window. Displaying top "
    "conceptual matches across the global corpus."
)


def _handle_analytical_question(question: str) -> None:
    """Route a chat question through the agent (chart) or RAG (semantic)."""
    agent: Optional[ResearchAgent] = get_agent()
    plan: Optional[AnalyticalPlan] = agent.plan(question) if agent else None
    if plan is not None and plan.intent == "chart" and plan.sql:
        rows: List[Dict[str, object]]
        error: Optional[str]
        rows, error = run_select(plan.sql)
        if error:
            st.warning(f"Could not run that as a chart query ({error}). "
                       "Falling back to conceptual matches.")
            _render_relaxed_fallback(question)
            return
        if not rows:
            # Strict time/metadata filter returned zero rows — relax to
            # ungated cosine similarity over the global corpus.
            _render_relaxed_fallback(question)
            return
        frame: pd.DataFrame = pd.DataFrame(rows)
        figure: Optional[go.Figure] = _build_chart(plan, frame)
        if figure is not None:
            st.plotly_chart(figure, width="stretch")
        with st.expander("Underlying data & query"):
            st.code(plan.sql, language="sql")
            st.dataframe(frame, width="stretch")
        return
    _render_semantic_answer(question)


def _render_relaxed_fallback(question: str) -> None:
    """Synthesize a readable answer from the global corpus, then show sources."""
    from services.rag_service import RAG_FALLBACK_MESSAGE, synthesize_answer
    try:
        result: Dict[str, object] = asyncio.run(synthesize_answer(question))
    except RuntimeError:
        LOGGER.exception("relaxed synthesis failed")
        st.warning(f"🛡️ {RAG_FALLBACK_MESSAGE}")
        return
    matches: List[Dict[str, object]] = result.get("matches", [])  # type: ignore[assignment]
    web_sources: List[Dict[str, object]] = result.get("web_sources", [])  # type: ignore[assignment]
    if not matches and not web_sources:
        st.warning(f"🛡️ {RAG_FALLBACK_MESSAGE}")
        return
    if bool(result.get("web_augmented")):
        st.info("🌐 **Web-augmented** — the corpus was sparse for this query, so "
                "live web results were merged into the answer.")
    else:
        st.info(f"🧭 {STRICT_WINDOW_NOTE}")
    answer: Optional[str] = result.get("answer")  # type: ignore[assignment]
    if answer:
        # Human-readable synthesized answer grounded in the snippets below.
        st.markdown(str(answer))
    if web_sources:
        st.markdown("**🌐 Live web sources**")
        for web in web_sources:
            title: str = str(web.get("title") or "Web result")
            link: str = str(web.get("link") or "")
            snippet: str = str(web.get("snippet") or "")
            with st.expander(f"🌐 {title}"):
                st.markdown(snippet)
                if link:
                    st.markdown(f"🔗 Source Link: [{link}]({link})")
    if not matches:
        return
    st.markdown("**Supporting corpus sources**")
    for match in matches:
        source: str = str(match.get("source", "—"))
        dated: str = str(match.get("date_published") or "undated")
        similarity: float = 1.0 - float(match.get("distance", 1.0))
        with st.expander(f"📌 {source} — {dated} — similarity {similarity:.2f}"):
            st.markdown(str(match.get("text", "")))   # full, untruncated body
            url: str = str(match.get("url") or "")
            if url:
                st.markdown(f"🔗 Source Link: [{url}]({url})")
            else:
                st.caption("🔗 Source link unavailable for this record.")


def _render_semantic_answer(question: str) -> None:
    """Grounded RAG answer over the curated corpus, with citations."""
    from services.rag_service import generate_response
    try:
        envelope: Dict[str, object] = asyncio.run(generate_response(question))
    except RuntimeError:
        LOGGER.exception("RAG inference failed")
        st.error("The semantic engine is unavailable right now.")
        return
    if bool(envelope.get("grounded")):
        st.markdown(str(envelope.get("answer", "")))
        citations: List[Dict[str, object]] = envelope.get("citations", [])  # type: ignore[assignment]
        st.markdown("**Cited sources**")
        for citation in citations:
            url: str = str(citation.get("url") or "")
            link_html: str = (
                f'&nbsp;·&nbsp; 🔗 <a href="{url}" target="_blank">Source</a>'
                if url else ""
            )
            st.markdown(
                f"""<div class="cs-citation">📌 <b>{citation.get('source', '—')}</b>
                &nbsp;·&nbsp; {citation.get('date_published') or 'undated'}
                &nbsp;·&nbsp; {citation.get('threat_category') or 'general'}
                {link_html}</div>""",
                unsafe_allow_html=True,
            )
    else:
        # No strict grounding — relax to conceptual matches rather than a
        # dead-end refusal window.
        _render_relaxed_fallback(question)


# --------------------------------------------------------------------------- #
# Ad-hoc sandbox — isolated, session-only document querying.                  #
# --------------------------------------------------------------------------- #


def _read_upload(uploaded: object) -> str:
    """Extract text from an uploaded PDF or text file."""
    name: str = getattr(uploaded, "name", "upload")
    raw: bytes = uploaded.read()  # type: ignore[attr-defined]
    if name.lower().endswith(".pdf"):
        try:
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(raw))
            return "\n".join((page.extract_text() or "") for page in reader.pages)
        except (ImportError, ValueError, OSError):
            LOGGER.exception("sandbox PDF parse failed")
            return ""
    try:
        return raw.decode("utf-8", errors="ignore")
    except (UnicodeDecodeError, AttributeError):
        return ""


def _ingest_sandbox_document(text: str) -> int:
    """Embed an uploaded document into an isolated in-memory collection.

    Uses a per-session ChromaDB EphemeralClient held in ``st.session_state`` —
    it never touches the persistent store, so a researcher's private document
    can never contaminate the curated corpus.
    """
    import chromadb
    from core.database import VectorStoreManager
    from services.ingestion import DocumentExtractionPipeline

    client = chromadb.EphemeralClient()
    collection = client.create_collection(
        name="sandbox", embedding_function=VectorStoreManager.embedding_function()
    )
    chunks = DocumentExtractionPipeline().chunk_text(
        text, {"source": "sandbox_upload"}, parent_key="sandbox"
    )
    if not chunks:
        return 0
    collection.add(
        ids=[c.chunk_id for c in chunks],
        documents=[c.text for c in chunks],
    )
    st.session_state["sandbox_collection"] = collection
    return len(chunks)


def _query_sandbox(question: str) -> None:
    """Answer a question strictly from the uploaded session document."""
    collection = st.session_state.get("sandbox_collection")
    if collection is None:
        st.info("Upload a document in the sidebar first.")
        return
    result: Dict[str, object] = collection.query(
        query_texts=[question], n_results=4, include=["documents"]
    )
    documents: List[str] = result["documents"][0]  # type: ignore[index]
    if not documents:
        st.warning("No relevant passage found in the uploaded document.")
        return
    context: str = "\n\n".join(documents)
    from langchain_core.messages import HumanMessage, SystemMessage
    from langchain_google_genai import ChatGoogleGenerativeAI
    from core.config import GEMINI_FLASH_MODEL as _SANDBOX_FLASH
    from core.config import get_google_api_key
    from services.llm_errors import LLM_TRANSIENT_ERRORS, content_to_text
    try:
        llm = ChatGoogleGenerativeAI(
            model=_SANDBOX_FLASH, temperature=0.1,
            google_api_key=get_google_api_key(),
        )
        completion = llm.invoke([
            SystemMessage(content=(
                "You are answering ONLY from the researcher's uploaded "
                "document excerpts below. If the answer is not present, say "
                "so plainly. Do not use outside knowledge.")),
            HumanMessage(content=f"EXCERPTS:\n{context}\n\nQUESTION: {question}"),
        ])
        st.markdown(content_to_text(completion.content))
    except LLM_TRANSIENT_ERRORS:
        LOGGER.warning("sandbox query: model busy/quota-limited")
        st.info("The AI is at capacity right now — please retry in a moment.")
    except (RuntimeError, ValueError):
        LOGGER.exception("sandbox query failed")
        st.error("Could not query the uploaded document right now.")


def render_document_ingestion() -> None:
    """Top-of-Explorer file staging buffer (session-only volatile ingestion)."""
    st.markdown("##### 🗂️ Contextual Forensic Document Ingestion Engine")
    st.caption(
        "Stage case files, forensic telemetry logs, or PDF/TXT inputs into "
        "volatile memory for immediate context parsing. Staged files are "
        "embedded for this session only and are **never** merged into the "
        "curated repository.")
    uploaded = st.file_uploader("Stage a PDF / text document", type=["pdf", "txt"],
                                key="explorer_ingest_file")
    if uploaded is not None and st.button("📥 Stage into volatile memory",
                                          key="explorer_ingest_btn"):
        text: str = _read_upload(uploaded)
        if len(text.strip()) < 40:
            st.warning("Could not extract usable text from this file.")
        else:
            count: int = _ingest_sandbox_document(text)
            st.success(f"Embedded {count} passages (session-only). Set the query "
                       "target to 'My uploaded document' below to query it.")
    if "sandbox_collection" in st.session_state:
        st.info("🟢 A staged document is active for this session.")


def render_explorer_tab() -> None:
    """Agentic chat + semantic explorer + document staging buffer."""
    st.markdown("#### 🔎 Semantic Knowledge Explorer")
    render_document_ingestion()
    st.divider()
    st.caption(
        "Ask deep semantic research questions across our centralized "
        "repository of scraped multi-agency advisories (e.g., 'How have "
        "digital arrest fraud methodologies evolved over the past quarter?'), "
        "or request a custom analytical chart (e.g., 'Compare financial loss "
        "by scam type across states this year')."
    )
    mode: str = st.radio(
        "Query target", ["Curated repository", "My uploaded document"],
        horizontal=True,
    )
    question: str = st.text_input(
        "Research query",
        placeholder="e.g. Which states lost the most money to digital arrests?",
    )
    if st.button("🔍 Run Query", type="primary") and question.strip():
        with st.spinner("Analyzing the repository…"):
            if mode == "My uploaded document":
                _query_sandbox(question.strip())
            else:
                _handle_analytical_question(question.strip())


# --------------------------------------------------------------------------- #
# Navigation — session-state driven views (cards & top nav both drive this).  #
# --------------------------------------------------------------------------- #


def _active_view() -> str:
    """Return the currently selected view key (defaults to the home grid)."""
    return st.session_state.get("active_view", "home")


def _go_to(view_key: str) -> None:
    """Switch the active view and rerun so navigation feels seamless."""
    st.session_state["active_view"] = view_key
    st.rerun()


def render_top_nav() -> None:
    """Persistent horizontal nav bar mirroring the home feature grid."""
    keys: List[Tuple[str, str]] = [("home", "🏠 Home")] + [
        (key, f"{icon} {title.split(' & ')[0].split(' (')[0]}")
        for key, icon, title, _blurb, _ready in NAV_FEATURES
    ]
    active: str = _active_view()
    cols: List[object] = st.columns(len(keys))
    for col, (key, label) in zip(cols, keys):
        with col:
            if st.button(label, key=f"nav_{key}", use_container_width=True,
                         type="primary" if key == active else "secondary"):
                if key != active:
                    _go_to(key)


def render_operational_desk() -> None:
    """Three-column statutory status ribbon shown at the top of the workspace."""
    st.markdown("### 🛰️ Operational Intelligence Desk")
    st.markdown("---")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="📞 NCRP National Emergency Helpline", value="1930",
                  delta="24/7 Immediate Response Link")
    with col2:
        st.metric(label="⚖️ Statutory Framework Compliance",
                  value="BNS / BNSS & IT Act",
                  delta="Procedural Standards Guardrail")
    with col3:
        st.metric(label="🔒 Workspace Integrity Status", value="Air-Gapped Volatile",
                  delta="Session Clears on App Close")


def render_home(corpus: int) -> None:
    """Landing grid: operational desk ribbon + one clickable card per feature."""
    render_operational_desk()
    st.markdown("")
    st.markdown("#### 🛰️ Operational Modules")
    per_row: int = 3
    for start in range(0, len(NAV_FEATURES), per_row):
        row: List[Tuple[str, str, str, str, bool]] = NAV_FEATURES[start:start + per_row]
        cols: List[object] = st.columns(per_row)
        for col, (key, icon, title, blurb, ready) in zip(cols, row):
            with col:
                tag: str = ("<span class='cs-card-tag'>LIVE</span>" if ready
                            else "<span class='cs-card-tag soon'>NEXT BUILD</span>")
                st.markdown(
                    f"<div class='cs-card'><div class='cs-card-ico'>{icon}</div>"
                    f"<h4>{title}</h4><p>{blurb}</p>{tag}</div>",
                    unsafe_allow_html=True,
                )
                label: str = "Open ▸" if ready else "Preview ▸"
                if st.button(label, key=f"card_{key}", use_container_width=True):
                    _go_to(key)


# --------------------------------------------------------------------------- #
# Feature 1 — Victim Triage & First-Action Guide.                            #
# --------------------------------------------------------------------------- #


def _split_list(raw: str) -> List[str]:
    """Split a comma / newline / space separated field into clean tokens."""
    if not raw:
        return []
    tokens: List[str] = re.split(r"[,\n;]+", raw)
    flat: List[str] = []
    for token in tokens:
        flat.extend(part for part in token.split() if part.strip())
    seen: Dict[str, None] = {}
    for item in (t.strip() for t in flat if t.strip()):
        seen.setdefault(item, None)
    return list(seen.keys())


def _render_evidence_custody(files: List[object]) -> int:
    """Hash each uploaded proof (SHA-256) and render the chain-of-custody log."""
    if not files:
        return 0
    st.markdown("**🔐 Evidence chain-of-custody (SHA-256 logged on upload):**")
    for uploaded in files:
        payload: bytes = uploaded.getvalue()
        record: Dict[str, object] = victim_triage.hash_evidence(uploaded.name, payload)
        st.markdown(
            f"<div class='cs-hash'>📎 {record['filename']} · "
            f"{record['size_bytes']:,} bytes · {record['logged_utc']}<br>"
            f"SHA-256: {record['sha256']}</div>",
            unsafe_allow_html=True,
        )
        LOGGER.info("triage evidence hashed: %s sha256=%s",
                    record["filename"], record["sha256"])
    return len(files)


def _render_assessment(assessment: victim_triage.TriageAssessment) -> None:
    """Render the full first-action package returned by the triage engine."""
    sev: str = assessment.severity.lower()
    sev_class: str = sev if sev in {"critical", "high", "medium", "low"} else "medium"
    provenance: str = ("AI cascade" if assessment.source == "ai-cascade"
                       else "Deterministic statutory engine (AI at capacity)")
    st.markdown(
        f"<span class='cs-sev {sev_class}'>{assessment.severity.upper()}</span> "
        f"&nbsp;<b>{assessment.vector_label}</b> "
        f"&nbsp;<span style='color:#7FA8C9;font-size:0.74rem'>· {provenance}</span>",
        unsafe_allow_html=True,
    )
    st.markdown(f"<div class='cs-briefing'>{assessment.summary}</div>",
                unsafe_allow_html=True)

    if assessment.golden_hour_applicable:
        st.markdown(
            f"<div class='cs-golden'>⏱️ <b>GOLDEN HOUR — ACT NOW.</b> "
            f"{victim_triage.GOLDEN_HOUR_NOTE}</div>",
            unsafe_allow_html=True,
        )

    left, right = st.columns(2)
    with left:
        st.markdown("##### ⚖️ Applicable legal framework")
        for prov in assessment.legal_provisions:
            st.markdown(
                f"<div class='cs-legal'><b>{prov.statute} — {prov.section}</b><br>"
                f"<i>{prov.title}.</i> {prov.relevance}</div>",
                unsafe_allow_html=True,
            )
    with right:
        st.markdown("##### 🚑 Immediate actions")
        for step in assessment.immediate_actions:
            st.markdown(f"- {step}")
        st.markdown("##### 📢 Advisories")
        for note in assessment.advisories:
            st.markdown(f"- {note}")

    st.markdown(
        f"##### 🆘 Official channels &nbsp;"
        f"<span class='cs-domainchip'>Helpline {victim_triage.NCRP_HELPLINE}</span>"
        f"<span class='cs-domainchip'>{victim_triage.NCRP_PORTAL}</span>",
        unsafe_allow_html=True,
    )

    st.markdown("##### ✉️ Ready-to-send complaint")
    st.text_input("Subject", value=assessment.complaint_subject,
                  key="triage_subject")
    st.caption("Use the copy icon on the block below, or download as a file.")
    st.code(assessment.complaint_body, language="text")
    st.download_button(
        "⬇️ Download complaint (.txt)", data=assessment.complaint_body,
        file_name="cyber_complaint.txt", mime="text/plain",
        use_container_width=True,
    )


# Incident category → (playbook threat domain, target sector) for cached_playbook.
_TRIAGE_PLAYBOOK_MAP: Dict[str, Tuple[str, str]] = {
    "Social & Behavioral Exploitation": (
        "Social & Behavioral Exploitation", "General Public"),
    "Critical Infrastructure": (
        "Network & Infrastructure Attacks", "Critical Infrastructure"),
    "Financial Cyber Fraud": ("Financial Fraud", "Banking & Payment Systems"),
}


def render_triage_playbook_console() -> None:
    """Relocated forensic playbook + BSA certificate, gated on incident category.

    Reads ``st.session_state['active_threat_tag']`` so a tag chosen in Strategic
    Threat Analytics pre-selects the matching category and highlights its
    provisions (cross-tab continuity).
    """
    st.divider()
    st.markdown("#### 🧰 First-Responder Forensic Playbook & BSA Certificate")
    st.caption("Pick the incident category to render a tactical first-responder "
               "checklist and export a Section 63(4) BSA, 2023 certificate draft.")

    active_tag: Optional[str] = st.session_state.get("active_threat_tag")
    categories: List[str] = list(threat_registry.TRIAGE_CATEGORIES)
    preset: Optional[str] = threat_registry.triage_category_for_tag(active_tag)
    index: int = categories.index(preset) if preset in categories else 0
    if active_tag and preset:
        st.info(f"🏷️ Carried over from Strategic Threat Analytics: **{active_tag}** "
                f"→ pre-selected category **{preset}**.")
    category: str = st.selectbox("Incident category", categories, index=index,
                                 key="triage_playbook_category")

    if active_tag:
        meta = threat_registry.get_tag(active_tag)
        if meta is not None and meta.triage_category == category:
            st.markdown(
                f"<div class='cs-legal'><b>Highlighted provisions for {meta.tag}:</b>"
                f"<br>{meta.provisions}</div>", unsafe_allow_html=True)

    domain, sector = _TRIAGE_PLAYBOOK_MAP[category]
    steps: List[Dict[str, str]] = cached_playbook(domain, sector, _cache_day())
    st.markdown("##### 📋 Active tactical checklist")
    for step in steps:
        st.markdown(f"**{step.get('action', '')}**  \n{step.get('detail', '')}")
    st.caption("⚖️ Digital-evidence preservation aligned with Section 63(4), "
               "Bharatiya Sakshya Adhiniyam (BSA), 2023 (Part A & Part B "
               "certificate; SHA-256 hashing; chain of custody).")
    st.caption(
        "⚠️ INVESTIGATIVE TRIAGE NOTE: Automated first-responder guidance and "
        "preservation templates only — not formal legal advice. Cross-verify "
        "certificate formats and chain-of-custody with designated counsel or "
        "cyber-cell prosecutors before judicial submission.")

    from services.playbook import compile_case_brief
    timestamp: str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    brief: str = compile_case_brief(timestamp, domain, sector, "", steps)
    safe_name: str = f"{domain}_{sector}".replace(" ", "_").replace("/", "-")
    st.download_button(
        "📥 Export Investigation Brief & BSA Certificate Draft", data=brief,
        file_name=f"cyber_brief_{safe_name}.md", mime="text/markdown",
        key="triage_bsa_export", use_container_width=True)


def render_triage_tab() -> None:
    """Feature 1 — Victim Triage & First-Action Guide."""
    st.markdown("#### 🚨 Victim Triage & First-Action Guide")
    st.caption(
        "Narrate what happened in plain English or Hinglish. Attach proofs to "
        "lock their cryptographic hashes for chain-of-custody, add any known "
        "identifiers, and get an instant legal classification (BNS 2023 / IT "
        "Act 2000), Golden-Hour banking guidance and a ready-to-file complaint."
    )

    narrative: str = st.text_area(
        "Describe the incident",
        height=150,
        placeholder="e.g. Mujhe ek call aaya CBI officer ka, video call pe "
                    "digital arrest bola, dar ke maine ₹50,000 UPI kiya, "
                    "transaction ID HDFC0098765432…",
    )
    proofs: List[object] = st.file_uploader(
        "Attach proofs (screenshots, receipts, chat logs)",
        type=["png", "jpg", "jpeg", "pdf", "txt", "csv", "eml", "webp"],
        accept_multiple_files=True,
    ) or []
    evidence_count: int = _render_evidence_custody(proofs)

    with st.expander("➕ Add known identifiers (optional, improves accuracy)",
                     expanded=False):
        col_a, col_b = st.columns(2)
        txn_raw: str = col_a.text_area(
            "Transaction / UTR IDs", height=70,
            placeholder="one per line or comma-separated")
        url_raw: str = col_b.text_area(
            "Malicious URLs / handles", height=70,
            placeholder="https://… , scammer@upi")
        phone_raw: str = col_a.text_area(
            "Suspect phone numbers", height=70, placeholder="+91…")
        amount_lost: str = col_b.text_input("Amount lost (₹)", placeholder="50000")
        money_lost: bool = col_b.checkbox("Money was actually transferred",
                                         value=False)
        name_col, contact_col = st.columns(2)
        complainant_name: str = name_col.text_input("Your name (for the complaint)")
        complainant_contact: str = contact_col.text_input(
            "Your contact (phone / email)")

    if st.button("🛡️ Analyze & Build First-Action Plan", type="primary",
                 use_container_width=True):
        if not narrative.strip():
            st.warning("Please describe the incident before analyzing.")
            return
        metadata: Dict[str, object] = {
            "transaction_ids": _split_list(txn_raw),
            "urls": _split_list(url_raw),
            "phones": _split_list(phone_raw),
            "amount_lost": amount_lost.strip(),
            "money_lost": money_lost,
            "evidence_count": evidence_count,
            "complainant_name": complainant_name.strip(),
            "complainant_contact": complainant_contact.strip(),
        }
        with st.spinner("Classifying the incident and drafting your complaint…"):
            assessment = victim_triage.analyze_incident(narrative.strip(), metadata)
        st.session_state["triage_assessment"] = assessment
        LOGGER.info("triage rendered: vector=%s severity=%s evidence=%d source=%s",
                    assessment.threat_vector, assessment.severity,
                    evidence_count, assessment.source)

    cached = st.session_state.get("triage_assessment")
    if isinstance(cached, victim_triage.TriageAssessment):
        st.divider()
        _render_assessment(cached)

    render_triage_playbook_console()


# --------------------------------------------------------------------------- #
# Feature 2 — CDR & IPDR Operational Analyzer.                               #
# --------------------------------------------------------------------------- #


def _cdr_table(title: str, frame: pd.DataFrame, empty: str) -> None:
    """Render one aggregated forensic table (or a clean empty-state note)."""
    st.markdown(f"**{title}**")
    if frame is None or frame.empty:
        st.caption(empty)
    else:
        st.dataframe(frame, use_container_width=True, hide_index=True)


def render_cdr_tab() -> None:
    """Feature 2 — Pandas forensic engine over CDR/IPDR with an AI breakdown."""
    st.markdown("#### 📞 CDR & IPDR Operational Analyzer")
    st.caption(
        "Upload Call Detail Records (CDR) or IP Detail Records (IPDR) as CSV or "
        "Excel. The engine runs real Pandas analytics — B-Party frequency, "
        "odd-hour anomalies, shared IMEI/IMSI links and spatial-temporal tower "
        "footprints — then hands only the aggregated summaries to the AI for a "
        "digital-forensics breakdown. For authorized investigators using their "
        "own lawfully obtained records."
    )

    st.download_button(
        "⬇️ Download sample schema (CSV)", data=cdr_analyzer.sample_schema_csv(),
        file_name="cdr_ipdr_sample_schema.csv", mime="text/csv",
        help="A valid mixed CDR+IPDR dataset you can upload immediately to test.",
    )
    uploaded = st.file_uploader(
        "Upload CDR / IPDR file", type=["csv", "xlsx", "xls"],
        accept_multiple_files=False,
    )
    if uploaded is None:
        st.info("Upload a record set, or grab the sample schema above to test "
                "with valid columns: Caller, Callee, Timestamp, Duration, Cell "
                "Tower ID, IMEI, IMSI, Source IP, Port, Destination IP.")
        return

    try:
        frame = cdr_analyzer.load_dataframe(uploaded.getvalue(), uploaded.name)
        analysis = cdr_analyzer.build_analysis(frame)
    except cdr_analyzer.CDRSchemaError as exc:
        st.error(f"Could not analyze this file: {exc}")
        return

    signature: str = f"{uploaded.name}:{analysis.record_count}"
    kpi: List[object] = st.columns(4)
    kpi[0].metric("Records", f"{analysis.record_count:,}")
    kpi[1].metric("CDR / IPDR", f"{analysis.cdr_count} / {analysis.ipdr_count}")
    kpi[2].metric("Distinct numbers", f"{analysis.distinct_actors:,}")
    kpi[3].metric("Odd-hour events", f"{analysis.odd_hour_events:,}")
    st.caption(f"🕒 Time span: {analysis.time_span} · fields detected: "
               f"{', '.join(analysis.available_fields)}")

    if not analysis.busiest_hours.empty:
        fig = px.bar(
            analysis.busiest_hours, x="hour", y="records",
            title="Activity by hour of day (23:00–04:00 = odd-hour window)",
        )
        fig.update_layout(height=260, margin=dict(l=10, r=10, t=40, b=10),
                          xaxis=dict(dtick=1))
        fig.add_vrect(x0=22.5, x1=23.5, fillcolor="#E0A800", opacity=0.15, line_width=0)
        fig.add_vrect(x0=-0.5, x1=3.5, fillcolor="#E0A800", opacity=0.15, line_width=0)
        st.plotly_chart(fig, use_container_width=True)

    left, right = st.columns(2)
    with left:
        _cdr_table("📇 Top contacts — B-Party analysis", analysis.top_contacts,
                   "No counterpart numbers/destinations found.")
        _cdr_table("🌙 Odd-hour activity by number", analysis.odd_hour_by_actor,
                   "No activity in the 23:00–04:00 window.")
        _cdr_table("🌐 IPDR destination intelligence", analysis.ip_intel,
                   "No IPDR / destination-IP data present.")
    with right:
        _cdr_table("🔗 Shared IMEI / IMSI links", analysis.shared_identity,
                   "No shared-handset or SIM-cloning links detected.")
        _cdr_table("📍 Co-location links (same tower, minutes apart)",
                   analysis.co_location, "No co-location links detected.")
        _cdr_table("🚀 Rapid tower hand-offs", analysis.rapid_handoff,
                   "No implausibly fast tower changes detected.")

    st.divider()
    st.markdown("##### 🕵️ AI digital-forensics breakdown")
    if st.button("🧠 Run forensic investigation", type="primary",
                 use_container_width=True):
        with st.spinner("Correlating aggregated patterns…"):
            brief: str = cdr_analyzer.investigate(analysis)
        st.session_state["cdr_brief"] = (signature, brief)
        LOGGER.info("cdr breakdown generated for %s", signature)

    cached = st.session_state.get("cdr_brief")
    if isinstance(cached, tuple) and cached[0] == signature:
        with st.container(border=True):
            st.markdown(cached[1])


# --------------------------------------------------------------------------- #
# Feature 3 — Integrated OSINT Sandbox.                                       #
# --------------------------------------------------------------------------- #


def _osint_custody(filename: str, payload: bytes) -> None:
    """Render and log a SHA-256 chain-of-custody chip for an OSINT upload."""
    record: Dict[str, object] = osint_sandbox.hash_artifact(filename, payload)
    st.markdown(
        f"<div class='cs-hash'>📎 {record['filename']} · "
        f"{record['size_bytes']:,} bytes · {record['logged_utc']}<br>"
        f"SHA-256: {record['sha256']}</div>",
        unsafe_allow_html=True,
    )


def _osint_officer(tool: str, summary: str, state_key: str) -> None:
    """Shared 'AI OSINT officer' button + cached 3-bullet operational-risk read."""
    st.divider()
    st.markdown("##### 🕵️ AI OSINT Intelligence Officer")
    if st.button("🧠 Generate operational-risk read", key=f"osint_ai_{state_key}",
                 type="primary", use_container_width=True):
        with st.spinner("Correlating metadata into an intelligence read…"):
            read: str = osint_sandbox.summarize_for_officer(tool, summary)
        st.session_state[state_key] = read or (
            "_AI cascade is at capacity — the deterministic findings above stand "
            "on their own._")
    cached = st.session_state.get(state_key)
    if cached:
        with st.container(border=True):
            st.markdown(cached)


_OSINT_RISK_COLOR: Dict[str, str] = {
    "Low": "#1E7E34", "Suspicious": "#E0A800", "High": "#C0392B",
    "Clean": "#1E7E34", "Review": "#E0A800", "Anomalous": "#C0392B",
}


def _osint_email_tool() -> None:
    """Toolbed 1 — email header routing + SPF/DKIM/DMARC forensics."""
    st.markdown("##### ✉️ Email Header Analysis")
    st.caption(
        "Paste the FULL raw headers (in your client: 'Show original' / 'View "
        "source') **or a pure Base64 string** of the header/EML payload — Base64 "
        "is auto-detected and decoded. The engine reconstructs the routing path "
        "from every `Received` hop, reads SPF/DKIM/DMARC natively, and decodes "
        "RFC 2047 encoded-words (`=?utf-8?B?…?=`) in the From/Subject fields. No "
        "AI touches the parsing.")
    raw: str = st.text_area("Raw or Base64 email headers", height=220,
                            key="osint_email_raw",
                            placeholder="Return-Path: …\nReceived: from … by … ;\nFrom: …")
    if not st.button("🔎 Analyze headers", key="osint_email_run",
                     use_container_width=True):
        return
    if not raw.strip():
        st.warning("Paste the raw header block first.")
        return

    report = osint_sandbox.parse_email_headers(raw)
    if report.decoded_from_base64:
        st.info("🧬 Input was Base64-encoded — auto-decoded to UTF-8 before parsing.")
    cols: List[object] = st.columns(4)
    cols[0].metric("Routing hops", report.hop_count)
    cols[1].metric("SPF", report.spf.upper())
    cols[2].metric("DKIM", report.dkim.upper())
    cols[3].metric("DMARC", report.dmarc.upper())
    st.markdown(
        f"**From:** `{report.from_addr}` &nbsp;·&nbsp; **Originating IP:** "
        f"`{report.originating_ip}`<br>**Return-Path:** `{report.return_path}` "
        f"&nbsp;·&nbsp; **Reply-To:** `{report.reply_to}`<br>**Subject:** "
        f"{report.subject}", unsafe_allow_html=True)

    if report.hops:
        st.markdown("**📡 Routing path (chronological — origin first):**")
        frame = pd.DataFrame([{
            "Hop": h.index, "From": h.from_host[:40], "By": h.by_host[:40],
            "IP": h.ip or "—", "Public": "✅" if h.is_public else "—",
            "Protocol": h.protocol, "Timestamp": h.timestamp,
        } for h in report.hops])
        st.dataframe(frame, use_container_width=True, hide_index=True)

    if report.flags:
        st.markdown("**🚩 Authentication & spoofing flags:**")
        for flag in report.flags:
            st.markdown(f"- {flag}")
    else:
        st.success("No authentication or spoofing anomalies detected.")

    summary: str = (
        f"From={report.from_addr}; Return-Path={report.return_path}; "
        f"Reply-To={report.reply_to}; Originating-IP={report.originating_ip}; "
        f"SPF={report.spf}; DKIM={report.dkim}; DMARC={report.dmarc}; "
        f"hops={report.hop_count}; flags={' | '.join(report.flags) or 'none'}")
    _osint_officer("Email Header Analysis", summary, "osint_email_ai")


def _osint_whois_tool() -> None:
    """Toolbed 2 — domain WHOIS (python-whois with socket fallback)."""
    st.markdown("##### 🌐 Domain WHOIS Lookup")
    st.caption(
        "Resolve registrar, registration age, name servers and status for any "
        "domain. Uses `python-whois` when available and falls back to a native "
        "socket (port 43) query — no system `whois` binary required.")
    domain: str = st.text_input("Domain or URL", key="osint_whois_domain",
                                placeholder="example.com")
    if not st.button("🔎 Run WHOIS", key="osint_whois_run",
                     use_container_width=True):
        return
    if not domain.strip():
        st.warning("Enter a domain such as `example.com`.")
        return

    with st.spinner("Querying WHOIS registries…"):
        report = osint_sandbox.whois_lookup(domain)
    if not report.available:
        st.error(report.error or "WHOIS lookup failed.")
        return

    st.caption(f"Source: `{report.source}`")
    cols: List[object] = st.columns(4)
    cols[0].metric("Registrar", report.registrar[:18] if report.registrar != "—" else "—")
    cols[1].metric("Created", report.creation_date)
    cols[2].metric("Expires", report.expiration_date)
    cols[3].metric("Age (days)", report.age_days if report.age_days is not None else "—")

    left, right = st.columns(2)
    with left:
        st.markdown("**🌐 Name servers**")
        for nameserver in report.name_servers or ["—"]:
            st.markdown(f"- `{nameserver}`")
        st.markdown("**📌 Status**")
        for status in report.statuses or ["—"]:
            st.markdown(f"- {status}")
    with right:
        st.markdown("**🏷️ Registrant country:** "
                    f"{report.registrant_country}")
        st.markdown("**✉️ Contact emails**")
        for mail in report.emails or ["—"]:
            st.markdown(f"- `{mail}`")

    if report.flags:
        st.markdown("**🚩 Risk flags:**")
        for flag in report.flags:
            st.markdown(f"- {flag}")
    if report.raw:
        with st.expander("📄 Raw WHOIS record"):
            st.code(report.raw[:6000], language="text")

    summary: str = (
        f"domain={report.domain}; registrar={report.registrar}; "
        f"created={report.creation_date}; expires={report.expiration_date}; "
        f"age_days={report.age_days}; country={report.registrant_country}; "
        f"name_servers={', '.join(report.name_servers) or 'none'}; "
        f"statuses={', '.join(report.statuses) or 'none'}; "
        f"flags={' | '.join(report.flags) or 'none'}")
    _osint_officer("Domain WHOIS", summary, "osint_whois_ai")


def _osint_exif_tool() -> None:
    """Toolbed 3 — image EXIF + GPS extraction."""
    st.markdown("##### 📷 Image EXIF Metadata")
    st.caption(
        "Upload a JPEG/PNG/TIFF to extract camera make/model, capture software, "
        "timestamps and — where present — embedded GPS coordinates. Every upload "
        "is SHA-256 logged for chain-of-custody.")
    uploaded = st.file_uploader("Upload image", type=["jpg", "jpeg", "png", "tiff", "webp"],
                                key="osint_exif_file")
    if uploaded is None:
        st.info("Note: screenshots and social-media re-encodes usually have their "
                "EXIF stripped — a finding in itself.")
        return

    payload: bytes = uploaded.getvalue()
    _osint_custody(uploaded.name, payload)
    report = osint_sandbox.extract_exif(payload)

    img_col, meta_col = st.columns([1, 2])
    with img_col:
        st.image(payload, caption=report.dimensions, use_container_width=True)
    with meta_col:
        if not report.available:
            st.warning(report.note)
        else:
            st.markdown(
                f"**Make:** {report.make} &nbsp;·&nbsp; **Model:** {report.model}<br>"
                f"**Software:** {report.software}<br>**Captured:** "
                f"{report.datetime_original}", unsafe_allow_html=True)
        if report.has_gps:
            st.markdown(
                f"<div class='cs-golden'>📍 <b>GPS LOCATION DISCLOSED:</b> "
                f"{report.gps_lat}, {report.gps_lon} &nbsp; "
                f"<a href='{report.maps_url}' target='_blank'>Open in Maps ▸</a></div>",
                unsafe_allow_html=True)

    if report.has_gps:
        st.markdown("**🗺️ Capture location (decimal degrees from EXIF GPS):**")
        st.map(pd.DataFrame({"lat": [report.gps_lat], "lon": [report.gps_lon]}),
               zoom=11, use_container_width=True)

    if report.available and report.tags:
        with st.expander(f"📄 All EXIF tags ({len(report.tags)})"):
            st.dataframe(
                pd.DataFrame(sorted(report.tags.items()), columns=["Tag", "Value"]),
                use_container_width=True, hide_index=True)
    if report.flags:
        st.markdown("**🚩 Notes:**")
        for flag in report.flags:
            st.markdown(f"- {flag}")

    if report.available:
        summary: str = (
            f"make={report.make}; model={report.model}; software={report.software}; "
            f"captured={report.datetime_original}; gps="
            f"{report.gps_lat},{report.gps_lon}" if report.has_gps else
            f"make={report.make}; model={report.model}; software={report.software}; "
            f"captured={report.datetime_original}; gps=none")
        summary += f"; flags={' | '.join(report.flags) or 'none'}"
        _osint_officer("Image EXIF Metadata", summary, "osint_exif_ai")


def _render_url_verdicts(text: str) -> None:
    """Score every URL in ``text`` and render verdicts + an AI officer read."""
    verdicts = osint_sandbox.analyze_text(text)
    if not verdicts:
        st.info("No URL could be extracted from that text.")
        return
    lines: List[str] = []
    for verdict in verdicts:
        color: str = _OSINT_RISK_COLOR.get(verdict.level, "#7FA8C9")
        st.markdown(
            f"<span class='cs-sev' style='background:{color}'>"
            f"{verdict.level.upper()} · {verdict.risk_score}/100</span> &nbsp;"
            f"<code>{verdict.host}</code> &nbsp;<span style='color:#7FA8C9;"
            f"font-size:0.74rem'>({verdict.scheme})</span>",
            unsafe_allow_html=True)
        for flag in verdict.flags:
            st.markdown(f"- {flag}")
        st.markdown("")
        lines.append(f"{verdict.url} -> {verdict.level} {verdict.risk_score}/100 "
                     f"[{' | '.join(verdict.flags)}]")
    _osint_officer("URL/QR Risk Checker", "\n".join(lines), "osint_url_ai")


def _osint_url_tool() -> None:
    """Toolbed 4 — URL/QR reputation scoring (paste a URL or upload a QR image)."""
    st.markdown("##### 🔗 URL / QR Risk Checker")
    st.caption(
        "Score a URL for phishing & obfuscation tells: shorteners, punycode "
        "look-alikes, high-abuse TLDs, brand/KYC bait keywords and tracking "
        "parameters. Paste text directly, or upload a photo/screenshot of a QR "
        "code — it is decoded with OpenCV's `QRCodeDetector` (real computer "
        "vision, no mock) and the embedded URL is scored.")
    channel: str = st.radio(
        "Input channel", ["Paste URL / text", "Upload QR-code image"],
        horizontal=True, key="osint_url_channel")

    if channel == "Paste URL / text":
        text: str = st.text_area("URL(s) or decoded QR text", height=110,
                                 key="osint_url_text",
                                 placeholder="https://paytm-kyc-update.top/login")
        if not st.button("🔎 Check reputation", key="osint_url_run",
                         use_container_width=True):
            return
        if not text.strip():
            st.warning("Paste a URL or decoded QR string first.")
            return
        _render_url_verdicts(text)
        return

    uploaded = st.file_uploader("Upload QR-code image", type=["png", "jpg", "jpeg"],
                                key="osint_qr_file")
    if uploaded is None:
        st.info("Upload a clear, tightly-cropped image of the QR code.")
        return
    payload: bytes = uploaded.getvalue()
    _osint_custody(uploaded.name, payload)
    img_col, res_col = st.columns([1, 2])
    with img_col:
        st.image(payload, caption="Uploaded QR image", use_container_width=True)
    with res_col:
        with st.spinner("Decoding QR matrix with OpenCV…"):
            qr = osint_sandbox.decode_qr_image(payload)
        if not qr.payloads:
            st.error(qr.error or "No QR payload decoded.")
            return
        st.success(f"Decoded {len(qr.payloads)} QR payload(s).")
        for value in qr.payloads:
            st.code(value, language="text")
    _render_url_verdicts("\n".join(qr.payloads))


_DEEPFAKE_SUSPICION_COLOR: Dict[str, str] = {
    "Low": "#1E7E34", "Elevated": "#E0A800", "High": "#C0392B",
    "Inconclusive": "#4B5C6B",
}


def _osint_deepfake_block(payload: bytes, filename: str) -> str:
    """Render the dual-layer deepfake workflow (ELA + Hugging Face). Returns summary."""
    st.markdown("**🧪 Layer 1 — Error Level Analysis (deterministic, local)**")
    ela = osint_sandbox.error_level_analysis(payload)
    summary_parts: List[str] = []
    if not ela.available:
        st.warning(ela.note)
    else:
        color: str = _DEEPFAKE_SUSPICION_COLOR.get(ela.suspicion, "#7FA8C9")
        ela_col, orig_col = st.columns(2)
        with orig_col:
            st.image(payload, caption="Original", use_container_width=True)
        with ela_col:
            st.image(ela.ela_png, caption="ELA (autoscaled residue)",
                     use_container_width=True)
        st.markdown(
            f"<span class='cs-sev' style='background:{color}'>"
            f"ELA: {ela.suspicion.upper()}</span> &nbsp;"
            f"<span style='color:#7FA8C9;font-size:0.78rem'>max diff "
            f"{ela.max_diff} · mean {ela.mean_diff}</span>", unsafe_allow_html=True)
        for flag in ela.flags:
            st.markdown(f"- {flag}")
        summary_parts.append(f"ELA suspicion={ela.suspicion} (max {ela.max_diff}, "
                             f"mean {ela.mean_diff})")

    st.markdown("**🤗 Layer 2 — Hugging Face deepfake classifier (remote model)**")
    verdict = osint_sandbox.huggingface_deepfake_detect(payload)
    if verdict.source == "hf-live":
        st.success(verdict.note)
        st.dataframe(
            pd.DataFrame([{"label": s["label"], "score": round(float(s["score"]), 4)}
                          for s in verdict.scores]),
            use_container_width=True, hide_index=True)
        summary_parts.append(f"HF[{verdict.model}] top={verdict.top_label} "
                             f"@ {verdict.top_score:.2f}")
    elif verdict.source == "loading":
        st.info(verdict.note)
    elif verdict.source == "no-token":
        st.info(verdict.note)
    else:
        st.warning(verdict.note)
    st.caption(f"Model: `{verdict.model}`")
    return "; ".join(summary_parts)


def _osint_deepfake_tool() -> None:
    """Toolbed 5 — deepfake verification (ELA + HF) + container integrity + breaches."""
    st.markdown("##### 🪞 Deepfake Verification & Forensic Imaging")
    st.caption(
        "A dual-layer authenticity workflow: a deterministic local **Error Level "
        "Analysis** pass that surfaces splice/face-swap recompression edges, plus "
        "an optional **Hugging Face** deepfake classifier. ELA is an indicator, "
        "not proof — corroborate before concluding.")
    uploaded = st.file_uploader("Upload image to verify", type=["jpg", "jpeg", "png", "webp"],
                                key="osint_deepfake_file")
    if uploaded is not None:
        payload: bytes = uploaded.getvalue()
        _osint_custody(uploaded.name, payload)
        summary: str = _osint_deepfake_block(payload, uploaded.name)
        if summary:
            _osint_officer("Deepfake Verification", summary, "osint_deepfake_ai")

    st.divider()
    st.markdown("##### 🔍 Container integrity (magic-byte & EOF check)")
    st.caption(
        "Structural sanity check on any media container: magic-byte type vs. file "
        "extension, EOF-marker integrity and bytes appended past EOF (a "
        "steganography / polyglot / re-mux tell).")
    media_up = st.file_uploader(
        "Upload media file",
        type=["jpg", "jpeg", "png", "gif", "webp", "bmp", "mp4", "mov", "mp3", "pdf"],
        key="osint_media_file")
    if media_up is not None:
        payload = media_up.getvalue()
        _osint_custody(media_up.name, payload)
        report = osint_sandbox.inspect_media(payload, media_up.name)
        color = _OSINT_RISK_COLOR.get(report.severity, "#7FA8C9")
        st.markdown(
            f"<span class='cs-sev' style='background:{color}'>"
            f"{report.severity.upper()}</span> &nbsp;<b>{report.detected_type}</b> "
            f"&nbsp;<span style='color:#7FA8C9;font-size:0.74rem'>· {report.mime}</span>",
            unsafe_allow_html=True)
        cols: List[object] = st.columns(4)
        cols[0].metric("Declared ext", report.declared_ext)
        cols[1].metric("Ext matches", "✅" if report.extension_match else "❌")
        cols[2].metric("EOF intact", "✅" if report.eof_intact else "❌")
        cols[3].metric("Trailing bytes", f"{report.trailing_bytes:,}")
        st.markdown("**🚩 Structural findings:**")
        for flag in report.structural_flags:
            st.markdown(f"- {flag}")


def _osint_identity_tool() -> None:
    """Toolbed 6 — Identity Exposure Analyzer (credential-exposure lookup)."""
    st.markdown("##### 🪪 Identity Exposure Analyzer")
    st.caption(
        "Query an identifier against compiled credential-exposure registries to "
        "surface known data-dump appearances and breach records for an "
        "investigation subject (with the subject's lawful authorisation).")
    live: bool = bool(osint_sandbox.get_hibp_api_key())
    # Clinical, low-noise provenance line — states the registry actually queried
    # so a 'no exposure' result is never mistaken for an authoritative all-clear.
    st.caption("Registry: live HaveIBeenPwned v3 exposure index." if live else
               "Registry: localized offline exposure sample (no live key "
               "configured — results are indicative, not exhaustive).")
    account: str = st.text_input("Identifier (email address)",
                                 key="osint_identity_account",
                                 placeholder="subject@example.com")
    if st.button("🔎 Analyze identity exposure", key="osint_identity_run",
                 use_container_width=True) and account.strip():
        st.info("Cross-referencing parameters against the credential-exposure "
                "registry…")
        with st.spinner("Resolving exposure records…"):
            breach = osint_sandbox.hibp_check(account)
        registry: str = "live exposure index" if live else "localized sample registry"
        if breach.source == "error":
            st.warning(breach.note)
        elif breach.breached:
            st.error(f"⚠️ Exposure detected — the identifier appears in "
                     f"{len(breach.breaches)} record(s) in the {registry}.")
            st.dataframe(pd.DataFrame(breach.breaches),
                         use_container_width=True, hide_index=True)
        else:
            st.success(f"No exposure found for this identifier in the {registry}.")


def render_osint_tab() -> None:
    """Feature 3 — Integrated OSINT Sandbox (6 deterministic toolbeds)."""
    st.markdown("#### 🕵️ Integrated OSINT Sandbox")
    st.caption(
        "A unified investigator workbench of deterministic, native-Python "
        "forensic processors — email-header routing (raw or Base64), WHOIS, "
        "EXIF/GPS with live mapping, URL/QR reputation with OpenCV decoding, and "
        "deepfake/ELA imaging. Parsing is reproducible and court-defensible; the "
        "optional AI layer only adds an operational-risk read on top. Every "
        "uploaded artifact is SHA-256 logged for chain-of-custody. For "
        "authorized investigators on lawfully-held data.")
    tabs = st.tabs([
        "✉️ Email Headers", "🌐 Domain WHOIS", "📷 Image EXIF",
        "🔗 URL/QR Risk", "🪞 Deepfake & Integrity", "🪪 Identity Exposure Analyzer",
    ])
    with tabs[0]:
        _osint_email_tool()
    with tabs[1]:
        _osint_whois_tool()
    with tabs[2]:
        _osint_exif_tool()
    with tabs[3]:
        _osint_url_tool()
    with tabs[4]:
        _osint_deepfake_tool()
    with tabs[5]:
        _osint_identity_tool()


# --------------------------------------------------------------------------- #
# Feature 4 — Case-Building & Practice Lab.                                   #
# --------------------------------------------------------------------------- #

def _lab_battery() -> "practice_lab.LabBattery":
    """Resolve the active case battery once per session (remote → baseline)."""
    battery = st.session_state.get("lab_battery")
    if not isinstance(battery, practice_lab.LabBattery):
        with st.spinner("Syncing the quarterly case matrix…"):
            battery = practice_lab.CaseSyncManager().load()
        st.session_state["lab_battery"] = battery
    return battery


def _lab_solved_ids() -> set:
    """Return the per-session set of solved case ids (created once)."""
    solved = st.session_state.get("lab_solved_ids")
    if not isinstance(solved, set):
        solved = set()
        st.session_state["lab_solved_ids"] = solved
    return solved


def _parse_csv_block(raw: str) -> Optional[pd.DataFrame]:
    """Parse a CSV-ish telemetry block into a DataFrame, ignoring NOTE lines."""
    rows: List[str] = [ln for ln in raw.splitlines()
                       if ln.strip() and not ln.strip().upper().startswith("NOTE")]
    if len(rows) < 2:
        return None
    try:
        return pd.read_csv(io.StringIO("\n".join(rows)))
    except (ValueError, pd.errors.ParserError):
        return None


# ----- Embedded forensic toolbed (one self-contained widget per tool type). -- #


def _lab_tool_email_decoder(case: "practice_lab.LabCase") -> None:
    """EMAIL_DECODER: inline Base64 + RFC 2047 decoder."""
    st.caption("Paste a Base64 blob or any MIME encoded-word (=?utf-8?B?…?=) "
               "from the telemetry; it is decoded instantly, in-tab.")
    blob: str = st.text_area("Base64 / encoded input", height=90,
                             key=f"lab_emaildec_{case.case_id}",
                             placeholder="=?utf-8?B?…?=  or a Base64 EML string")
    if st.button("🧬 Decode", key=f"lab_emailbtn_{case.case_id}",
                 use_container_width=True) and blob.strip():
        result = practice_lab.decode_email_blob(blob)
        if result["was_base64"]:
            st.success("Base64 detected and decoded to UTF-8.")
        st.code(str(result["decoded_text"]), language="text")
        words = result["encoded_words"]
        if words:
            st.markdown("**Decoded MIME encoded-words:**")
            st.dataframe(pd.DataFrame(words, columns=["Encoded", "Decoded"]),
                         use_container_width=True, hide_index=True)


def _lab_tool_cdr_filter(case: "practice_lab.LabCase") -> None:
    """CDR_FILTER: micro query/value-counts over the record stream."""
    st.caption("Filter the record stream: pick a column and run value-counts or a "
               "substring query. Defaults to this case's telemetry; upload your "
               "own CSV stream to override.")
    upload = st.file_uploader("Optional: upload a CSV stream", type=["csv"],
                              key=f"lab_cdrfile_{case.case_id}")
    raw: str = (upload.getvalue().decode("utf-8", "ignore") if upload
                else case.telemetry_dump)
    frame = _parse_csv_block(raw)
    if frame is None or frame.empty:
        st.info("No tabular rows could be parsed from this stream.")
        return
    st.dataframe(frame, use_container_width=True, hide_index=True)
    column: str = st.selectbox("Column", list(frame.columns),
                               key=f"lab_cdrcol_{case.case_id}")
    mode: str = st.radio("Operation", ["Value counts", "Substring filter"],
                         horizontal=True, key=f"lab_cdrmode_{case.case_id}")
    if mode == "Value counts":
        counts = frame[column].astype(str).value_counts().reset_index()
        counts.columns = [column, "count"]
        st.dataframe(counts, use_container_width=True, hide_index=True)
    else:
        query: str = st.text_input("Rows where the column contains",
                                   key=f"lab_cdrq_{case.case_id}")
        if query:
            mask = frame[column].astype(str).str.contains(query, case=False, na=False)
            st.dataframe(frame[mask], use_container_width=True, hide_index=True)


def _lab_tool_geolocation_plotter(case: "practice_lab.LabCase") -> None:
    """GEOLOCATION_PLOTTER: DMS → decimal conversion plus a live st.map()."""
    st.caption("Enter the Degrees / Minutes / Seconds from the telemetry GPS "
               "block; convert to decimal degrees and plot the capture point.")
    lat_c: List[object] = st.columns(4)
    lat_d = lat_c[0].number_input("Lat °", value=0.0, key=f"lab_latd_{case.case_id}")
    lat_m = lat_c[1].number_input("Lat ′", value=0.0, key=f"lab_latm_{case.case_id}")
    lat_s = lat_c[2].number_input("Lat ″", value=0.0, key=f"lab_lats_{case.case_id}")
    lat_r = lat_c[3].selectbox("Ref", ["N", "S"], key=f"lab_latr_{case.case_id}")
    lon_c: List[object] = st.columns(4)
    lon_d = lon_c[0].number_input("Lon °", value=0.0, key=f"lab_lond_{case.case_id}")
    lon_m = lon_c[1].number_input("Lon ′", value=0.0, key=f"lab_lonm_{case.case_id}")
    lon_s = lon_c[2].number_input("Lon ″", value=0.0, key=f"lab_lons_{case.case_id}")
    lon_r = lon_c[3].selectbox("Ref", ["E", "W"], key=f"lab_lonr_{case.case_id}")
    if st.button("🗺️ Convert & plot", key=f"lab_geobtn_{case.case_id}",
                 use_container_width=True):
        lat: float = practice_lab.dms_to_decimal(lat_d, lat_m, lat_s, lat_r)
        lon: float = practice_lab.dms_to_decimal(lon_d, lon_m, lon_s, lon_r)
        cols: List[object] = st.columns(2)
        cols[0].metric("Latitude (decimal)", f"{lat:g}")
        cols[1].metric("Longitude (decimal)", f"{lon:g}")
        st.map(pd.DataFrame({"lat": [lat], "lon": [lon]}), zoom=11,
               use_container_width=True)


def _lab_tool_string_sanitizer(case: "practice_lab.LabCase") -> None:
    """STRING_SANITIZER: IOC extraction + a canonical-flag preview."""
    st.caption("Paste raw log text to extract indicators (IPs, URLs, domains, "
               "emails/VPAs, hashes, wallets). The preview shows how a value will "
               "be normalised before evaluation.")
    text: str = st.text_area("Raw text to parse", height=110,
                             key=f"lab_strtext_{case.case_id}",
                             value=case.telemetry_dump)
    if st.button("🔎 Extract indicators", key=f"lab_strbtn_{case.case_id}",
                 use_container_width=True) and text.strip():
        indicators = practice_lab.extract_indicators(text)
        if not indicators:
            st.info("No recognisable indicators found.")
        for label, items in indicators.items():
            st.markdown(f"**{label}:**")
            st.code("\n".join(items), language="text")
    preview: str = st.text_input("Canonical-flag preview",
                                 key=f"lab_strprev_{case.case_id}",
                                 placeholder="paste a value to see its sanitised form")
    if preview:
        st.markdown(f"Normalised → `{practice_lab.sanitize_flag_input(preview)}`")


_LAB_TOOL_DISPATCH = {
    "EMAIL_DECODER": _lab_tool_email_decoder,
    "CDR_FILTER": _lab_tool_cdr_filter,
    "GEOLOCATION_PLOTTER": _lab_tool_geolocation_plotter,
    "STRING_SANITIZER": _lab_tool_string_sanitizer,
}

_LAB_TOOL_TITLE = {
    "EMAIL_DECODER": "✉️ Embedded Email Decoder",
    "CDR_FILTER": "📞 Embedded CDR / Ledger Filter",
    "GEOLOCATION_PLOTTER": "🗺️ Embedded Geolocation Plotter",
    "STRING_SANITIZER": "🧷 Embedded String Sanitizer",
}


def _lab_render_notice_console(case: "practice_lab.LabCase") -> None:
    """Unlocked-on-solve Section 94 BNSS generation dashboard."""
    st.success("✅ Evidence verified — Section 94 BNSS legal console unlocked.")
    st.markdown("##### ⚖️ Section 94 BNSS Production-Notice Console")
    notes: str = st.text_area(
        "Investigating Officer's notes (optional)",
        key=f"lab_notes_{case.case_id}", height=90,
        placeholder="Add any narrative findings to embed in the WHEREAS recital…")
    meta: List[object] = st.columns(3)
    officer: str = meta[0].text_input("Officer name & rank",
                                      key=f"lab_off_{case.case_id}")
    station: str = meta[1].text_input("Cyber Crime Police Station",
                                      key=f"lab_ps_{case.case_id}")
    fir: str = meta[2].text_input("FIR / Case No.", key=f"lab_fir_{case.case_id}")
    if st.button("⚖️ Generate Section 94 BNSS Notice", type="primary",
                 key=f"lab_notice_{case.case_id}", use_container_width=True):
        verified: Dict[str, str] = dict(case.validation_matrix)
        with st.spinner("Drafting Section 94 BNSS production notice…"):
            notice, source = practice_lab.generate_section94_notice(
                case, verified, notes, officer_name=officer,
                police_station=station, fir_number=fir)
        st.session_state[f"lab_notice_out_{case.case_id}"] = (notice, source)

    cached = st.session_state.get(f"lab_notice_out_{case.case_id}")
    if isinstance(cached, tuple):
        notice, source = cached
        provenance: str = ("AI cascade" if source == "ai-cascade"
                           else "Deterministic statutory engine (AI at capacity)")
        st.caption(f"Drafted by: {provenance}")
        st.code(notice, language="text")
        st.download_button(
            "⬇️ Download notice (.txt)", data=notice,
            file_name=f"section94_bnss_{case.case_id}.txt", mime="text/plain",
            key=f"lab_dl_{case.case_id}", use_container_width=True)


def _lab_render_workspace(case: "practice_lab.LabCase") -> None:
    """Split mission-control viewport: evidence desk (3) + eval terminal (2)."""
    solved_ids: set = _lab_solved_ids()
    cleared: bool = case.case_id in solved_ids
    status: str = ("<span class='cs-card-tag'>CLEARED</span>" if cleared
                   else "<span class='cs-card-tag soon'>OPEN</span>")
    st.markdown(
        f"#### 🗂️ {case.title} &nbsp;<code>{case.case_id}</code> &nbsp;{status}",
        unsafe_allow_html=True)
    st.caption(f"Tier: {case.level} · Target entity: {case.target_entity}")

    desk, terminal = st.columns([3, 2])

    # ----------------- Left: Evidence & Analysis Desk (60%) ------------------ #
    with desk:
        st.markdown("##### 📋 Case dossier")
        st.markdown(f"<div class='cs-briefing'>{case.briefing}</div>",
                    unsafe_allow_html=True)
        st.markdown(f"<div class='cs-legal'><b>Statutory framework.</b> "
                    f"{case.statutory_context}</div>", unsafe_allow_html=True)

        st.markdown("##### 🧾 Raw telemetry on record")
        st.code(case.telemetry_dump, language="text")

        st.markdown("##### 📥 Download terminal")
        st.caption(f"Source artifact: `{case.download_url}`")
        st.download_button(
            f"⬇️ Download raw artifact — {case.artifact_filename}",
            data=case.telemetry_dump, file_name=case.artifact_filename,
            mime="text/plain", key=f"lab_artifact_{case.case_id}",
            use_container_width=True)

        st.divider()
        tool_type: str = case.embedded_tool_type
        st.markdown(f"##### 🛠️ {_LAB_TOOL_TITLE.get(tool_type, 'Embedded tool')}")
        renderer = _LAB_TOOL_DISPATCH.get(tool_type)
        if renderer is None:
            st.info("No embedded tool is configured for this case.")
        else:
            renderer(case)

    # --------------- Right: Interactive Evaluation Terminal (40%) ------------ #
    with terminal:
        st.markdown("##### 🎛️ Forensic flag matrix")
        st.caption("Submit every required ground-truth flag. Evaluation is a "
                   "strict logical AND — all flags must match exactly.")
        inputs: Dict[str, str] = {}
        for key in case.validation_matrix:
            inputs[key] = st.text_input(
                case.flag_label(key), key=f"lab_flag_{case.case_id}_{key}")

        if st.button("🔬 Verify Evidence", type="primary",
                     key=f"lab_verify_{case.case_id}", use_container_width=True):
            passed, results = practice_lab.validate_matrix(case, inputs)
            st.session_state[f"lab_results_{case.case_id}"] = results
            if passed:
                solved_ids.add(case.case_id)
                st.session_state["lab_solved_ids"] = solved_ids
                LOGGER.info("lab case cleared: %s", case.case_id)
                st.balloons()
            else:
                st.error("One or more flags are incorrect — re-examine the "
                         "telemetry with the embedded tool and resubmit.")

        results = st.session_state.get(f"lab_results_{case.case_id}")
        if isinstance(results, dict) and results:
            for key, ok in results.items():
                st.markdown(f"- {'✅' if ok else '❌'} {case.flag_label(key)}")

        if case.case_id in solved_ids:
            st.divider()
            _lab_render_notice_console(case)


def render_lab_tab() -> None:
    """Feature 4 — Case-Building & Practice Lab (self-contained, split viewport)."""
    battery = _lab_battery()
    solved_ids: set = _lab_solved_ids()
    st.markdown("#### 🎓 Case-Building & Practice Lab")
    st.caption(
        "A self-contained forensic training ecosystem. Each case ships an "
        "exhaustive dossier, a downloadable raw artifact, an embedded analysis "
        "tool, and a multi-flag ground-truth matrix — solve it entirely in this "
        "tab, then issue a statutory **Section 94 BNSS, 2023** production notice. "
        "Progress is held only in your browser session.")

    if battery.is_baseline:
        st.warning(f"📦 Running on Local Baseline Data (quarterly cycle "
                   f"{battery.cycle}) — the remote case mirror was unreachable.")
    else:
        st.success(f"🛰️ Synced remote case matrix — quarterly cycle {battery.cycle}.")

    cleared_count: int = sum(1 for c in battery.cases if c.case_id in solved_ids)
    total: int = len(battery.cases)
    dash: List[object] = st.columns(4)
    dash[0].metric("Current rank", practice_lab.rank_title(cleared_count))
    dash[1].metric("Cases cleared", f"{cleared_count} / {total}")
    dash[2].metric("Active cycle", battery.cycle)
    dash[3].progress(cleared_count / total if total else 0.0, text="Matrix progress")

    chosen_level: str = st.radio("Difficulty tier", list(practice_lab.LEVELS),
                                 horizontal=True, key="lab_level_radio")
    tier_cases = practice_lab.cases_for_level(battery, chosen_level)
    if not tier_cases:
        st.info("No cases in this tier for the active cycle.")
        return
    case_labels: List[str] = [
        f"{'✅ ' if c.case_id in solved_ids else ''}{c.title}" for c in tier_cases]
    picked: str = st.radio("Select a case file", case_labels,
                           key=f"lab_case_{chosen_level}")
    active_case = tier_cases[case_labels.index(picked)]

    st.divider()
    _lab_render_workspace(active_case)


def render_coming_soon(view_key: str) -> None:
    """Honest staging panel for modules landing in the next build phase."""
    meta = next((f for f in NAV_FEATURES if f[0] == view_key), None)
    if meta is None:
        st.error("Unknown module.")
        return
    _key, icon, title, blurb, _ready = meta
    st.markdown(f"#### {icon} {title}")
    st.caption(blurb)
    st.info(
        "All six grid modules — Strategic Threat Analytics, the Semantic Explorer, Victim "
        "Triage, the CDR/IPDR Analyzer, the OSINT Sandbox and the Case-Building "
        "Practice Lab — are live. Select one from the navigation bar above."
    )


# --------------------------------------------------------------------------- #
# Application assembly.                                                       #
# --------------------------------------------------------------------------- #


def main() -> None:
    """Assemble the wide-layout public research hub."""
    st.set_page_config(
        page_title="Cyber Shield India — Research Hub",
        page_icon="🛡️", layout="wide",
    )
    st.markdown(TERMINAL_CSS, unsafe_allow_html=True)
    with st.spinner("Initializing intelligence engine…"):
        warm_resources()
    render_header()
    corpus: int = cached_corpus_size(_minute_bucket())
    st.sidebar.metric("Curated datapoints", f"{corpus:,}")

    # Global data-integrity toggle: strip demo & NCRB-baseline records to view
    # pure operational (live-crawled) telemetry across every chart and map.
    st.sidebar.markdown("### 🧭 Data Integrity")
    exclude_demo: bool = st.sidebar.toggle(
        "Pure operational data only",
        value=False,
        help="Strip demo sample rows and the NCRB historical baseline overlay "
             "so charts and maps reflect only live-crawled telemetry.",
    )

    if corpus == 0:
        st.info("📡 Threat intelligence is being gathered. Use the Semantic "
                "Knowledge Explorer to query live cyber-threat data while the "
                "repository populates.")

    render_top_nav()
    st.markdown("")
    view: str = _active_view()
    if view == "home":
        render_home(corpus)
    elif view == "macro":
        render_macro_trends_tab(exclude_demo)
    elif view == "explorer":
        render_explorer_tab()
    elif view == "triage":
        render_triage_tab()
    elif view == "cdr":
        render_cdr_tab()
    elif view == "osint":
        render_osint_tab()
    elif view == "lab":
        render_lab_tab()
    else:  # unknown view key — honest staging panel
        render_coming_soon(view)
    LOGGER.info("Frame rendered (view=%s, corpus=%d, pure_operational=%s)",
                view, corpus, exclude_demo)


if __name__ == "__main__":
    main()
