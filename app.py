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
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from services import research_repository as rr
from services.research_agent import AnalyticalPlan, ResearchAgent, run_select

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
        st.info("No active telemetry records captured for this filter window.")
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
        advisories: List[Dict[str, object]] = rr.latest_advisories(
            interval, scam_vector=chosen, limit=6
        )
        if not advisories:
            st.info("No active telemetry records captured for this filter window.")
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
    states: List[str] = rr.distinct_states()
    if not states:
        render_empty_state("No state-level data in the corpus yet.")
        return
    default_index: int = states.index("Tamil Nadu") if "Tamil Nadu" in states else 0
    state: str = st.selectbox("Select your state context", states, index=default_index)
    snapshot: Dict[str, object] = rr.state_versus_national(
        interval, state, exclude_demo)
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

    if exclude_demo:
        # Pure operational view — live telemetry only, no NCRB baseline.
        st.caption("🟢 Pure operational mode — NCRB baseline overlay hidden.")
        metric_cols: List[object] = st.columns(2)
        with metric_cols[0]:
            st.metric(f"Live cases · {window_label}", f"{live_cases:,.0f}")
        with metric_cols[1]:
            st.metric(f"Live loss · {window_label}", _inr(live_loss))
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


def render_macro_trends_tab(exclude_demo: bool) -> None:
    """The four analytics modules under one chronological filter."""
    st.caption("Aggregated, AI-synthesized public-domain cybercrime trends. "
               "Use the chronological filter to scope every module below.")
    if exclude_demo:
        st.caption("🔒 **Pure operational mode** — demo & NCRB-baseline records "
                   "stripped; charts reflect live crawled telemetry only.")
    interval: str = st.radio(
        "Chronological filter", INTERVAL_ORDER,
        format_func=lambda key: INTERVAL_LABELS[key],
        horizontal=True, index=3,
    )
    briefing: str = cached_briefing(interval, exclude_demo, _cache_day())
    st.markdown(
        f"""<div class="cs-briefing">📰 <b>THREAT BRIEFING</b>
        &nbsp;·&nbsp; {INTERVAL_LABELS.get(interval, interval)}<br>{briefing}</div>""",
        unsafe_allow_html=True,
    )
    st.divider()
    render_geospatial(interval, exclude_demo)
    st.divider()
    render_vector_landscape(interval, exclude_demo)
    st.divider()
    render_demographic(interval, exclude_demo)
    st.divider()
    render_state_tracker(interval, exclude_demo)


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
    from langchain_google_genai._common import GoogleGenerativeAIError
    from core.config import get_google_api_key
    try:
        llm = ChatGoogleGenerativeAI(
            model="gemini-2.5-flash", temperature=0.1,
            google_api_key=get_google_api_key(),
        )
        completion = llm.invoke([
            SystemMessage(content=(
                "You are answering ONLY from the researcher's uploaded "
                "document excerpts below. If the answer is not present, say "
                "so plainly. Do not use outside knowledge.")),
            HumanMessage(content=f"EXCERPTS:\n{context}\n\nQUESTION: {question}"),
        ])
        st.markdown(str(completion.content))
    except (GoogleGenerativeAIError, RuntimeError, ValueError):
        LOGGER.exception("sandbox query failed")
        st.error("Could not query the uploaded document right now.")


def render_sandbox_sidebar() -> None:
    """Sidebar uploader for the isolated, session-only document sandbox."""
    st.sidebar.markdown("### 📎 Ad-Hoc Document Sandbox")
    st.sidebar.caption(
        "Upload a PDF/text file to query during this session only. It is "
        "embedded in volatile memory and **never** merged into the curated "
        "repository."
    )
    uploaded = st.sidebar.file_uploader("Upload PDF or text", type=["pdf", "txt"])
    if uploaded is not None and st.sidebar.button("Embed for this session"):
        text: str = _read_upload(uploaded)
        if len(text.strip()) < 40:
            st.sidebar.warning("Could not extract usable text.")
        else:
            count: int = _ingest_sandbox_document(text)
            st.sidebar.success(f"Embedded {count} passages (session-only).")
    if "sandbox_collection" in st.session_state:
        st.sidebar.info("A sandbox document is active this session.")


def render_explorer_tab() -> None:
    """Agentic chat + semantic explorer + sandbox querying."""
    st.markdown("#### 🔎 Semantic Knowledge Explorer")
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
# Application assembly.                                                       #
# --------------------------------------------------------------------------- #


def main() -> None:
    """Assemble the wide-layout public research hub."""
    st.set_page_config(
        page_title="Cyber Shield India — Research Hub",
        page_icon="🛡️", layout="wide",
    )
    st.markdown(TERMINAL_CSS, unsafe_allow_html=True)
    render_header()
    corpus: int = rr.corpus_size()
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
        st.info("The research corpus is empty. Run the ingestion worker "
                "(`python ingestion_worker.py --seed-demo` for sample data, "
                "or `python ingestion_worker.py` for live harvesting).")
    render_sandbox_sidebar()
    trends_tab, explorer_tab = st.tabs([
        "📊 Macro Trends", "🔎 Semantic Knowledge Explorer",
    ])
    with trends_tab:
        render_macro_trends_tab(exclude_demo)
    with explorer_tab:
        render_explorer_tab()
    LOGGER.info("Frame rendered (corpus=%d, pure_operational=%s)",
                corpus, exclude_demo)


if __name__ == "__main__":
    main()
