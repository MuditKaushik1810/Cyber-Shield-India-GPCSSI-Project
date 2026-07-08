"""Cyber Shield India — MAVI Mathematical Analytics Processor (Step 3.1).

The **Multi-Attribute Vulnerability & Incident (MAVI) processor**: an
asynchronous computing engine that aggregates records from the dual-tier
stores and executes a formal, normalized scoring matrix producing a final
MAVI Score on the 0.00–100.00 scale from three weighted parameters:

* **Severity constraint band (weight 0.40)** — incident severity levels
  mapped through a calibrated weight ladder.
* **Entity risk band (weight 0.35)** — the mean baseline risk of extracted
  digital identity indicators.
* **Tactical frequency band (weight 0.25)** — historical threat-vector
  frequency shares weighted by per-vector danger coefficients.

The module also carries the canonical **Mule Account Velocity Index**
formula mandated by the project spec for money-mule hotspot identification:

    MAVI_velocity = (Σ V_in / ΔT_out) × log(1 + C_mule)

where ``V_in`` is inward transfer volume, ``ΔT_out`` the egress time lapse,
and ``C_mule`` the count of cross-linked identity markers.

Heavy statistical loops run off the event loop via ``asyncio.to_thread``.
Arithmetic anomalies (``ZeroDivisionError``, ``OverflowError``, non-finite
floats, ``statistics.StatisticsError``) and ``aiosqlite.Error`` faults are
intercepted explicitly; traces rotate daily into ``logs/analytics.log``.
"""

import asyncio
import logging
import math
import statistics
import tempfile
from datetime import datetime, timedelta, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiosqlite
from pydantic import BaseModel, Field

from core.database import SQLITE_PATH, RelationalStoreManager

# --------------------------------------------------------------------------- #
# Forensic logging — dedicated daily-rotating channel: logs/analytics.log.    #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the analytics logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.analytics")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "analytics.log",
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
# Scoring matrix calibration.                                                 #
# --------------------------------------------------------------------------- #

# Component weights — must sum to 1.0.
WEIGHT_SEVERITY: float = 0.40
WEIGHT_ENTITY_RISK: float = 0.35
WEIGHT_TACTICAL: float = 0.25

# Severity constraint ladder (None = unrated incidents carry guarded mass).
SEVERITY_WEIGHTS: Dict[Optional[str], float] = {
    "CRITICAL": 1.00,
    "HIGH": 0.80,
    "MEDIUM": 0.50,
    "LOW": 0.25,
    None: 0.40,
}

# Per-vector danger coefficients for the tactical frequency band.
TACTICAL_DANGER_WEIGHTS: Dict[str, float] = {
    "digital_arrest": 0.95,
    "apk_sideloading": 0.90,
    "payment_fraud": 0.85,
    "investment_scam": 0.80,
    "voip_spoofing": 0.75,
    "sms_spoofing": 0.72,
    "sim_impersonation": 0.70,
    "accessibility_exploit": 0.65,
    "general_cyber": 0.40,
}
DEFAULT_TACTICAL_WEIGHT: float = 0.40

# Anomaly gate thresholds.
CRITICAL_CLUSTER_SHARE: float = 0.30      # >=30% CRITICAL incidents
HIGH_RISK_ENTITY_MEAN: float = 85.0       # mean entity risk band
VECTOR_CONCENTRATION_SHARE: float = 0.70  # one vector >=70% of incidents
ELEVATED_VARIANCE_GATE: float = 900.0     # population variance of signal bands
SPARSE_SIGNAL_FLOOR: int = 3              # fewer total records than this

# Threat level gates over the final MAVI score.
THREAT_LEVEL_GATES: Tuple[Tuple[float, str], ...] = (
    (75.0, "CRITICAL"),
    (50.0, "ELEVATED"),
    (25.0, "GUARDED"),
    (0.0, "LOW"),
)

# --------------------------------------------------------------------------- #
# Input/output structures.                                                    #
# --------------------------------------------------------------------------- #


class IncidentRecord(BaseModel):
    """One incident row entering the scoring matrix."""

    threat_category: str = Field(min_length=1)
    severity: Optional[str] = None
    jurisdiction: str = "National"


class EntityRecord(BaseModel):
    """One extracted indicator row entering the scoring matrix."""

    entity_type: str = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=100.0)


class AnalyticsResult(BaseModel):
    """Structured output of one MAVI matrix execution."""

    mavi_score: float = Field(ge=0.0, le=100.0)
    threat_level: str
    variance: float = Field(ge=0.0)
    anomaly_flags: List[str] = Field(default_factory=list)
    component_breakdown: Dict[str, float] = Field(default_factory=dict)
    dominant_vector: Optional[str] = None
    incident_count: int = Field(ge=0)
    entity_count: int = Field(ge=0)
    computed_at: str


# --------------------------------------------------------------------------- #
# Canonical Mule Account Velocity Index (project-spec formula).                  #
# --------------------------------------------------------------------------- #


def mule_account_velocity_index(
    inward_volume_inr: float,
    egress_lapse_hours: float,
    cross_linked_markers: int,
) -> float:
    """Compute MAVI_velocity = (Σ V_in / ΔT_out) × log(1 + C_mule).

    Raises:
        ValueError: If the egress lapse is non-positive (a zero lapse would
            be a division singularity, not a velocity), the volume is
            negative, or the marker count is negative.
    """
    if egress_lapse_hours <= 0.0:
        raise ValueError(
            f"Egress time lapse must be positive, got {egress_lapse_hours}"
        )
    if inward_volume_inr < 0.0 or cross_linked_markers < 0:
        raise ValueError("Inward volume and marker count must be non-negative")
    velocity: float = (inward_volume_inr / egress_lapse_hours) * math.log(
        1.0 + float(cross_linked_markers)
    )
    if not math.isfinite(velocity):
        raise OverflowError(
            f"Mule velocity computation overflowed: volume={inward_volume_inr}, "
            f"lapse={egress_lapse_hours}, markers={cross_linked_markers}"
        )
    return velocity


# --------------------------------------------------------------------------- #
# Pure synchronous matrix kernel (offloaded via asyncio.to_thread).           #
# --------------------------------------------------------------------------- #


def _execute_scoring_matrix(
    incidents: List[IncidentRecord], entities: List[EntityRecord]
) -> Tuple[float, float, Dict[str, float], List[str], Optional[str]]:
    """Run the normalized matrix equations over one record batch.

    Returns (score, variance, component_breakdown, anomaly_flags,
    dominant_vector). Pure and deterministic — identical batches always
    produce identical outputs.
    """
    anomaly_flags: List[str] = []
    total_records: int = len(incidents) + len(entities)

    if total_records < SPARSE_SIGNAL_FLOOR:
        anomaly_flags.append("sparse_signal")

    # -- Severity constraint band (0-100) --------------------------------- #
    severity_band: float = 0.0
    if incidents:
        severity_masses: List[float] = [
            SEVERITY_WEIGHTS.get(incident.severity, SEVERITY_WEIGHTS[None]) * 100.0
            for incident in incidents
        ]
        severity_band = math.fsum(severity_masses) / len(severity_masses)
        critical_share: float = sum(
            1 for incident in incidents if incident.severity == "CRITICAL"
        ) / len(incidents)
        if critical_share >= CRITICAL_CLUSTER_SHARE:
            anomaly_flags.append("critical_severity_cluster")
    else:
        severity_masses = []

    # -- Entity risk band (0-100) ------------------------------------------ #
    entity_band: float = 0.0
    entity_scores: List[float] = [entity.risk_score for entity in entities]
    if entity_scores:
        entity_band = math.fsum(entity_scores) / len(entity_scores)
        if entity_band >= HIGH_RISK_ENTITY_MEAN:
            anomaly_flags.append("high_risk_entity_band")

    # -- Tactical frequency band (0-100) ------------------------------------ #
    tactical_band: float = 0.0
    dominant_vector: Optional[str] = None
    if incidents:
        frequency: Dict[str, int] = {}
        for incident in incidents:
            frequency[incident.threat_category] = (
                frequency.get(incident.threat_category, 0) + 1
            )
        tactical_band = 100.0 * math.fsum(
            (count / len(incidents))
            * TACTICAL_DANGER_WEIGHTS.get(category, DEFAULT_TACTICAL_WEIGHT)
            for category, count in frequency.items()
        )
        dominant_vector, dominant_count = max(
            frequency.items(), key=lambda pair: (pair[1], pair[0])
        )
        if dominant_count / len(incidents) >= VECTOR_CONCENTRATION_SHARE:
            anomaly_flags.append("single_vector_concentration")

    # -- Weighted fusion ----------------------------------------------------- #
    raw_score: float = (
        WEIGHT_SEVERITY * severity_band
        + WEIGHT_ENTITY_RISK * entity_band
        + WEIGHT_TACTICAL * tactical_band
    )
    if not math.isfinite(raw_score):
        raise OverflowError(f"MAVI fusion produced non-finite score: {raw_score}")
    mavi_score: float = round(min(100.0, max(0.0, raw_score)), 2)

    # -- Statistical variance over the combined signal bands ----------------- #
    signal_bands: List[float] = severity_masses + entity_scores
    variance: float = (
        round(statistics.pvariance(signal_bands), 2) if len(signal_bands) >= 2 else 0.0
    )
    if variance >= ELEVATED_VARIANCE_GATE:
        anomaly_flags.append("elevated_variance")

    breakdown: Dict[str, float] = {
        "severity_band": round(severity_band, 2),
        "entity_risk_band": round(entity_band, 2),
        "tactical_band": round(tactical_band, 2),
        "weighted_severity": round(WEIGHT_SEVERITY * severity_band, 2),
        "weighted_entity_risk": round(WEIGHT_ENTITY_RISK * entity_band, 2),
        "weighted_tactical": round(WEIGHT_TACTICAL * tactical_band, 2),
    }
    return mavi_score, variance, breakdown, anomaly_flags, dominant_vector


def classify_threat_level(score: float) -> str:
    """Map a MAVI score onto its threshold gate."""
    for gate, label in THREAT_LEVEL_GATES:
        if score >= gate:
            return label
    return "LOW"


# --------------------------------------------------------------------------- #
# Asynchronous computing engine.                                              #
# --------------------------------------------------------------------------- #


class MaviAnalyticsProcessor:
    """Asynchronous MAVI engine aggregating the dual-tier stores."""

    def __init__(self, database_path: Path = SQLITE_PATH) -> None:
        self.database_path: Path = database_path

    async def compute(
        self, incidents: List[IncidentRecord], entities: List[EntityRecord]
    ) -> AnalyticsResult:
        """Execute the scoring matrix off-loop and assemble the result."""
        try:
            score: float
            variance: float
            breakdown: Dict[str, float]
            flags: List[str]
            dominant: Optional[str]
            score, variance, breakdown, flags, dominant = await asyncio.to_thread(
                _execute_scoring_matrix, incidents, entities
            )
        except ZeroDivisionError:
            LOGGER.exception("Division singularity inside scoring matrix")
            raise
        except OverflowError:
            LOGGER.exception("Floating-point overflow inside scoring matrix")
            raise
        except statistics.StatisticsError:
            LOGGER.exception("Statistical kernel anomaly inside scoring matrix")
            raise
        result: AnalyticsResult = AnalyticsResult(
            mavi_score=score,
            threat_level=classify_threat_level(score),
            variance=variance,
            anomaly_flags=flags,
            component_breakdown=breakdown,
            dominant_vector=dominant,
            incident_count=len(incidents),
            entity_count=len(entities),
            computed_at=datetime.now(timezone.utc).isoformat(),
        )
        LOGGER.info(
            "MAVI matrix executed: score=%.2f level=%s variance=%.2f flags=%s "
            "(incidents=%d, entities=%d)",
            result.mavi_score, result.threat_level, result.variance,
            ",".join(result.anomaly_flags) or "-",
            result.incident_count, result.entity_count,
        )
        return result

    async def compute_from_stores(self) -> AnalyticsResult:
        """Aggregate live rows from the relational tier and score them."""
        incidents: List[IncidentRecord] = []
        entities: List[EntityRecord] = []
        async with aiosqlite.connect(self.database_path) as connection:
            try:
                cursor: aiosqlite.Cursor = await connection.execute(
                    "SELECT threat_category, severity, jurisdiction FROM incidents"
                )
                incident_rows: List[Tuple[str, Optional[str], str]] = list(
                    await cursor.fetchall()
                )
                cursor = await connection.execute(
                    "SELECT entity_type, risk_score FROM entities"
                )
                entity_rows: List[Tuple[str, float]] = list(await cursor.fetchall())
            except aiosqlite.Error:
                LOGGER.exception("Dual-tier aggregation query failed")
                raise
        incidents = [
            IncidentRecord(
                threat_category=row[0], severity=row[1], jurisdiction=row[2]
            )
            for row in incident_rows
        ]
        entities = [
            EntityRecord(entity_type=row[0], risk_score=row[1])
            for row in entity_rows
        ]
        LOGGER.info(
            "Aggregated live stores: %d incidents, %d entities",
            len(incidents), len(entities),
        )
        return await self.compute(incidents, entities)


# --------------------------------------------------------------------------- #
# Step 3.2 — Kill Chain Vulnerability Index (KCVI) Aggregator.                #
# --------------------------------------------------------------------------- #

# Cyber Kill Chain stage taxonomy for the Indian fraud delivery fabric.
STAGE_INFILTRATION: str = "Infiltration"
STAGE_EXPLOITATION: str = "Exploitation"
STAGE_LATERAL_MOVEMENT: str = "Lateral Movement"
STAGE_EXFILTRATION: str = "Exfiltration/Action on Objectives"

KILL_CHAIN_STAGES: Tuple[str, ...] = (
    STAGE_INFILTRATION,
    STAGE_EXPLOITATION,
    STAGE_LATERAL_MOVEMENT,
    STAGE_EXFILTRATION,
)

# Delivery/threat vector -> kill chain stage. Unmapped vectors land in
# Exploitation as the conservative middle of the chain.
KILL_CHAIN_STAGE_MAP: Dict[str, str] = {
    "apk_sideloading": STAGE_INFILTRATION,
    "sms_spoofing": STAGE_INFILTRATION,
    "voip_spoofing": STAGE_INFILTRATION,
    "digital_arrest": STAGE_INFILTRATION,
    "accessibility_exploit": STAGE_EXPLOITATION,
    "mobile_os_vulnerability": STAGE_EXPLOITATION,
    "general_cyber": STAGE_EXPLOITATION,
    "sim_impersonation": STAGE_LATERAL_MOVEMENT,
    "payment_fraud": STAGE_EXFILTRATION,
    "investment_scam": STAGE_EXFILTRATION,
}
DEFAULT_KILL_CHAIN_STAGE: str = STAGE_EXPLOITATION


class KcviResult(BaseModel):
    """Structured output of one KCVI aggregation pass."""

    vector_distribution: Dict[str, float] = Field(
        default_factory=dict,
        description="Vector -> exact fractional share; shares sum to 1.0.",
    )
    stage_distribution: Dict[str, float] = Field(
        default_factory=dict,
        description="Kill chain stage -> aggregated fractional share.",
    )
    single_point_of_failure: str = Field(
        description="Stage carrying the highest danger-weighted concentration.",
    )
    vulnerability_index: float = Field(
        ge=0.0, le=100.0,
        description="Danger-weighted intensity of the failure stage (0-100).",
    )
    dominant_vector: Optional[str] = None
    sample_size: int = Field(ge=0)
    computed_at: str


def _execute_kcvi_kernel(
    frequency: Dict[str, int],
) -> Tuple[Dict[str, float], Dict[str, float], str, float, Optional[str]]:
    """Pure KCVI kernel over a vector frequency table.

    Returns (vector_distribution, stage_distribution, failure_stage,
    vulnerability_index, dominant_vector). Defensive against empty input:
    an empty table yields empty distributions and a zero index — no
    division singularities.
    """
    total: int = sum(frequency.values())
    if total <= 0:
        return {}, {}, "none", 0.0, None

    # Exact fractional shares — kept unrounded so the array sums to 1.0.
    vector_distribution: Dict[str, float] = {
        vector: count / total for vector, count in frequency.items()
    }
    drift: float = abs(math.fsum(vector_distribution.values()) - 1.0)
    if drift > 1e-9:
        raise ArithmeticError(
            f"KCVI normalization drift exceeded tolerance: {drift:.3e}"
        )

    # Stage aggregation and danger-weighted stage intensities.
    stage_distribution: Dict[str, float] = {stage: 0.0 for stage in KILL_CHAIN_STAGES}
    stage_intensity: Dict[str, float] = {stage: 0.0 for stage in KILL_CHAIN_STAGES}
    for vector, share in vector_distribution.items():
        stage: str = KILL_CHAIN_STAGE_MAP.get(vector, DEFAULT_KILL_CHAIN_STAGE)
        stage_distribution[stage] += share
        stage_intensity[stage] += share * TACTICAL_DANGER_WEIGHTS.get(
            vector, DEFAULT_TACTICAL_WEIGHT
        )

    failure_stage: str
    failure_intensity: float
    failure_stage, failure_intensity = max(
        stage_intensity.items(), key=lambda pair: (pair[1], pair[0])
    )
    vulnerability_index: float = round(min(100.0, max(0.0, 100.0 * failure_intensity)), 2)
    if not math.isfinite(vulnerability_index):
        raise OverflowError("KCVI produced a non-finite vulnerability index")

    dominant_vector: Optional[str] = max(
        vector_distribution.items(), key=lambda pair: (pair[1], pair[0])
    )[0]
    return (
        vector_distribution,
        stage_distribution,
        failure_stage,
        vulnerability_index,
        dominant_vector,
    )


async def calculate_kcvi(
    frequency: Optional[Dict[str, int]] = None,
    database_path: Path = SQLITE_PATH,
) -> KcviResult:
    """Compute the Kill Chain Vulnerability Index.

    With no ``frequency`` table supplied, aggregates real-time delivery
    vector counts from the relational ``incidents`` table; an injected
    table (used by tests and replay tooling) bypasses the database. The
    statistical kernel runs off-loop via ``asyncio.to_thread``.
    """
    if frequency is None:
        async with aiosqlite.connect(database_path) as connection:
            try:
                cursor: aiosqlite.Cursor = await connection.execute(
                    "SELECT threat_category, COUNT(*) FROM incidents "
                    "GROUP BY threat_category"
                )
                rows: List[Tuple[str, int]] = list(await cursor.fetchall())
            except aiosqlite.Error:
                LOGGER.exception("KCVI delivery-vector aggregation query failed")
                raise
        frequency = {row[0]: int(row[1]) for row in rows}

    try:
        (
            vector_distribution,
            stage_distribution,
            failure_stage,
            vulnerability_index,
            dominant_vector,
        ) = await asyncio.to_thread(_execute_kcvi_kernel, dict(frequency))
    except ZeroDivisionError:
        LOGGER.exception("Division singularity inside KCVI kernel")
        raise
    except (ArithmeticError, OverflowError):
        LOGGER.exception("Arithmetic anomaly inside KCVI kernel")
        raise

    result: KcviResult = KcviResult(
        vector_distribution=vector_distribution,
        stage_distribution=stage_distribution,
        single_point_of_failure=failure_stage,
        vulnerability_index=vulnerability_index,
        dominant_vector=dominant_vector,
        sample_size=sum(frequency.values()),
        computed_at=datetime.now(timezone.utc).isoformat(),
    )
    LOGGER.info(
        "KCVI aggregated: index=%.2f failure_stage=%s dominant=%s (n=%d)",
        result.vulnerability_index, result.single_point_of_failure,
        result.dominant_vector or "-", result.sample_size,
    )
    return result


# --------------------------------------------------------------------------- #
# Step 3.3 — Time-Horizon Aggregation Workers.                                #
# --------------------------------------------------------------------------- #

# Rolling temporal intervals for the dashboard Interval Matrix.
TIME_HORIZON_WINDOWS: Dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "1y": timedelta(days=365),
}


def _sqlite_timestamp(moment: datetime) -> str:
    """Render a timezone-aware moment in SQLite's datetime('now') format."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class HorizonSnapshot(BaseModel):
    """One rolling-window snapshot of incident and entity dynamics."""

    horizon: str
    window_start: str
    window_end: str
    incident_volume: int = Field(ge=0)
    previous_incident_volume: int = Field(ge=0)
    volume_delta: int
    vector_counts: Dict[str, int] = Field(default_factory=dict)
    vector_momentum: Dict[str, int] = Field(
        default_factory=dict,
        description="Vector -> count change vs the previous equivalent window.",
    )
    gaining_vectors: List[str] = Field(
        default_factory=list,
        description="Vectors with positive momentum, strongest first.",
    )
    new_entity_count: int = Field(ge=0)
    previous_new_entity_count: int = Field(ge=0)
    entity_volatility_index: float = Field(
        description="Relative change in new-indicator influx vs the previous "
                    "window; absolute influx when the previous window was silent.",
    )


class TimeHorizonMatrix(BaseModel):
    """The full four-interval snapshot matrix for dashboard consumption."""

    snapshots: Dict[str, HorizonSnapshot] = Field(default_factory=dict)
    generated_at: str


def _compute_delta_kernel(
    current_counts: Dict[str, int], previous_counts: Dict[str, int]
) -> Tuple[Dict[str, int], List[str]]:
    """Pure multi-window delta kernel (offloaded via asyncio.to_thread).

    Returns the per-vector momentum table and the gaining vectors ordered
    by strongest positive momentum (ties broken alphabetically).
    """
    momentum: Dict[str, int] = {}
    for vector in set(current_counts) | set(previous_counts):
        momentum[vector] = current_counts.get(vector, 0) - previous_counts.get(vector, 0)
    gaining: List[str] = sorted(
        (vector for vector, delta in momentum.items() if delta > 0),
        key=lambda vector: (-momentum[vector], vector),
    )
    return momentum, gaining


def _entity_volatility_index(current_new: int, previous_new: int) -> float:
    """Rate-of-influx change for new threat indicators.

    Relative change against the previous window; when the previous window
    saw zero new indicators, the absolute current influx is returned so a
    surge from silence registers proportionally to its size.
    """
    if previous_new == 0:
        return float(current_new)
    return round((current_new - previous_new) / previous_new, 2)


async def _window_vector_counts(
    connection: aiosqlite.Connection, start: str, end: str
) -> Dict[str, int]:
    """Grouped incident counts for one [start, end) window."""
    cursor: aiosqlite.Cursor = await connection.execute(
        "SELECT threat_category, COUNT(*) FROM incidents "
        "WHERE created_at IS NOT NULL AND created_at >= ? AND created_at < ? "
        "GROUP BY threat_category",
        (start, end),
    )
    rows: List[Tuple[str, int]] = list(await cursor.fetchall())
    return {row[0]: int(row[1]) for row in rows}


async def _window_new_entity_count(
    connection: aiosqlite.Connection, start: str, end: str
) -> int:
    """Count of indicators first seen inside one [start, end) window."""
    cursor: aiosqlite.Cursor = await connection.execute(
        "SELECT COUNT(*) FROM entities "
        "WHERE first_seen IS NOT NULL AND first_seen >= ? AND first_seen < ?",
        (start, end),
    )
    row: Tuple[int] = await cursor.fetchone()  # type: ignore[assignment]
    return int(row[0])


async def compute_time_horizons(
    reference_time: Optional[datetime] = None,
    database_path: Path = SQLITE_PATH,
) -> TimeHorizonMatrix:
    """Generate the rolling 24h/7d/30d/1y snapshot matrix.

    Each horizon is compared against its previous equivalent window
    ([now-2Δ, now-Δ)) to expose vector momentum and entity volatility.

    Raises:
        ValueError: If a supplied reference time lacks timezone awareness —
            naive datetimes would silently corrupt every window boundary.
    """
    if reference_time is not None and reference_time.tzinfo is None:
        raise ValueError(
            "reference_time must be timezone-aware; naive datetimes would "
            "misalign all window boundaries"
        )
    now: datetime = reference_time or datetime.now(timezone.utc)
    now_stamp: str = _sqlite_timestamp(now)

    snapshots: Dict[str, HorizonSnapshot] = {}
    async with aiosqlite.connect(database_path) as connection:
        for horizon, window in TIME_HORIZON_WINDOWS.items():
            current_start: str = _sqlite_timestamp(now - window)
            previous_start: str = _sqlite_timestamp(now - (2 * window))
            try:
                current_counts: Dict[str, int] = await _window_vector_counts(
                    connection, current_start, now_stamp
                )
                previous_counts: Dict[str, int] = await _window_vector_counts(
                    connection, previous_start, current_start
                )
                current_entities: int = await _window_new_entity_count(
                    connection, current_start, now_stamp
                )
                previous_entities: int = await _window_new_entity_count(
                    connection, previous_start, current_start
                )
            except aiosqlite.Error:
                LOGGER.exception(
                    "Time-horizon aggregation query failed for window %s", horizon
                )
                raise

            momentum: Dict[str, int]
            gaining: List[str]
            momentum, gaining = await asyncio.to_thread(
                _compute_delta_kernel, current_counts, previous_counts
            )
            incident_volume: int = sum(current_counts.values())
            previous_volume: int = sum(previous_counts.values())
            snapshots[horizon] = HorizonSnapshot(
                horizon=horizon,
                window_start=current_start,
                window_end=now_stamp,
                incident_volume=incident_volume,
                previous_incident_volume=previous_volume,
                volume_delta=incident_volume - previous_volume,
                vector_counts=current_counts,
                vector_momentum=momentum,
                gaining_vectors=gaining,
                new_entity_count=current_entities,
                previous_new_entity_count=previous_entities,
                entity_volatility_index=_entity_volatility_index(
                    current_entities, previous_entities
                ),
            )
            LOGGER.info(
                "Horizon %s: volume=%d (Δ%+d) gaining=%s entities=%d (vol=%.2f)",
                horizon, incident_volume, incident_volume - previous_volume,
                ",".join(gaining) or "-", current_entities,
                snapshots[horizon].entity_volatility_index,
            )

    return TimeHorizonMatrix(
        snapshots=snapshots,
        generated_at=now.isoformat(),
    )


# --------------------------------------------------------------------------- #
# In-module validation harness — mock high-threat 'Digital Arrest' campaign.  #
# --------------------------------------------------------------------------- #


def _mock_digital_arrest_campaign() -> Tuple[List[IncidentRecord], List[EntityRecord]]:
    """Mock data tensors modelling an active high-threat campaign."""
    incidents: List[IncidentRecord] = [
        IncidentRecord(threat_category="digital_arrest", severity="CRITICAL",
                       jurisdiction="Telangana"),
        IncidentRecord(threat_category="digital_arrest", severity="CRITICAL",
                       jurisdiction="Telangana"),
        IncidentRecord(threat_category="digital_arrest", severity="HIGH",
                       jurisdiction="Haryana"),
        IncidentRecord(threat_category="digital_arrest", severity="HIGH",
                       jurisdiction="Karnataka"),
        IncidentRecord(threat_category="digital_arrest", severity="HIGH",
                       jurisdiction="Delhi"),
        IncidentRecord(threat_category="payment_fraud", severity="MEDIUM",
                       jurisdiction="Maharashtra"),
    ]
    entities: List[EntityRecord] = [
        EntityRecord(entity_type="upi_id", risk_score=95.0),
        EntityRecord(entity_type="upi_id", risk_score=92.0),
        EntityRecord(entity_type="phone", risk_score=90.0),
        EntityRecord(entity_type="phone", risk_score=88.0),
        EntityRecord(entity_type="bank_account", risk_score=91.0),
        EntityRecord(entity_type="url", risk_score=86.0),
    ]
    return incidents, entities


def _mock_low_threat_batch() -> Tuple[List[IncidentRecord], List[EntityRecord]]:
    """Mock low-signal batch for the lower threshold gate."""
    incidents: List[IncidentRecord] = [
        IncidentRecord(threat_category="general_cyber", severity="LOW"),
        IncidentRecord(threat_category="general_cyber", severity="LOW"),
    ]
    entities: List[EntityRecord] = [
        EntityRecord(entity_type="url", risk_score=15.0),
        EntityRecord(entity_type="email", risk_score=10.0),
    ]
    return incidents, entities


async def _run_validation_harness() -> None:
    """Prove deterministic scaling and threshold gate behaviour."""
    processor: MaviAnalyticsProcessor = MaviAnalyticsProcessor()

    # High-threat campaign must breach the CRITICAL gate with the full
    # anomaly signature.
    incidents, entities = _mock_digital_arrest_campaign()
    first: AnalyticsResult = await processor.compute(incidents, entities)
    assert first.mavi_score >= 75.0, f"expected CRITICAL gate, got {first.mavi_score}"
    assert first.threat_level == "CRITICAL"
    assert first.dominant_vector == "digital_arrest"
    assert "critical_severity_cluster" in first.anomaly_flags
    assert "high_risk_entity_band" in first.anomaly_flags
    assert "single_vector_concentration" in first.anomaly_flags

    # Determinism: identical tensors must reproduce identical outputs.
    second: AnalyticsResult = await processor.compute(incidents, entities)
    assert first.mavi_score == second.mavi_score
    assert first.variance == second.variance
    assert first.anomaly_flags == second.anomaly_flags

    # Low-threat batch must settle into the LOW/GUARDED bands, flag-free.
    low_incidents, low_entities = _mock_low_threat_batch()
    low: AnalyticsResult = await processor.compute(low_incidents, low_entities)
    assert low.mavi_score < 40.0, f"expected sub-40 score, got {low.mavi_score}"
    assert low.threat_level in ("LOW", "GUARDED")
    assert "critical_severity_cluster" not in low.anomaly_flags
    assert low.mavi_score < first.mavi_score, "matrix must scale monotonically"

    # Empty batch: graceful zero with sparse-signal flag, no singularities.
    empty: AnalyticsResult = await processor.compute([], [])
    assert empty.mavi_score == 0.0 and empty.threat_level == "LOW"
    assert "sparse_signal" in empty.anomaly_flags

    # Canonical mule velocity formula: hand-checked reference value.
    velocity: float = mule_account_velocity_index(
        inward_volume_inr=1_800_000.0, egress_lapse_hours=2.0,
        cross_linked_markers=4,
    )
    expected: float = (1_800_000.0 / 2.0) * math.log(5.0)
    assert abs(velocity - expected) < 1e-9
    try:
        mule_account_velocity_index(1000.0, 0.0, 3)
        raise AssertionError("zero egress lapse must raise ValueError")
    except ValueError:
        pass

    print(f"High-threat campaign : score={first.mavi_score:.2f} "
          f"level={first.threat_level} variance={first.variance:.2f}")
    print(f"  flags              : {', '.join(first.anomaly_flags)}")
    print(f"  breakdown          : {first.component_breakdown}")
    print(f"Low-threat batch     : score={low.mavi_score:.2f} level={low.threat_level}")
    print(f"Empty batch          : score={empty.mavi_score:.2f} "
          f"flags={empty.anomaly_flags}")
    print(f"Mule velocity check  : {velocity:,.2f} INR/hr-equivalent")
    print("MAVI VALIDATION HARNESS: PASS")


async def _run_kcvi_validation_harness() -> None:
    """Prove KCVI normalization, dominance detection, and stage mapping."""
    # Synthetic mixed dataset: 60% APK delivery, 30% SMS spoofing, 10% VoIP.
    synthetic: Dict[str, int] = {
        "apk_sideloading": 60,
        "sms_spoofing": 30,
        "voip_spoofing": 10,
    }
    result: KcviResult = await calculate_kcvi(frequency=synthetic)

    # Percentage array must normalize flawlessly to 100%.
    distribution_sum: float = math.fsum(result.vector_distribution.values())
    assert math.isclose(distribution_sum, 1.0, abs_tol=1e-9), (
        f"distribution must sum to 1.0, got {distribution_sum}"
    )
    assert math.isclose(result.vector_distribution["apk_sideloading"], 0.60)
    assert math.isclose(result.vector_distribution["sms_spoofing"], 0.30)
    assert math.isclose(result.vector_distribution["voip_spoofing"], 0.10)

    # Dominant infiltration vector and single point of failure.
    assert result.dominant_vector == "apk_sideloading"
    assert result.single_point_of_failure == STAGE_INFILTRATION
    assert math.isclose(result.stage_distribution[STAGE_INFILTRATION], 1.0)
    expected_index: float = round(
        100.0 * (0.60 * 0.90 + 0.30 * 0.72 + 0.10 * 0.75), 2
    )
    assert result.vulnerability_index == expected_index, (
        f"expected index {expected_index}, got {result.vulnerability_index}"
    )

    # Multi-stage spread: exfiltration-heavy mix must move the failure point.
    spread: Dict[str, int] = {
        "payment_fraud": 50,
        "investment_scam": 20,
        "apk_sideloading": 20,
        "sim_impersonation": 10,
    }
    spread_result: KcviResult = await calculate_kcvi(frequency=spread)
    assert spread_result.single_point_of_failure == STAGE_EXFILTRATION
    assert math.isclose(
        math.fsum(spread_result.stage_distribution.values()), 1.0, abs_tol=1e-9
    )

    # Defensive gate: empty dataset yields a clean zero, no singularities.
    empty_result: KcviResult = await calculate_kcvi(frequency={})
    assert empty_result.vulnerability_index == 0.0
    assert empty_result.single_point_of_failure == "none"
    assert empty_result.sample_size == 0

    print("--- KCVI aggregation ---")
    print(f"Synthetic mix        : index={result.vulnerability_index:.2f} "
          f"SPOF={result.single_point_of_failure} "
          f"dominant={result.dominant_vector}")
    print(f"  distribution       : "
          f"{ {k: round(v, 4) for k, v in result.vector_distribution.items()} }")
    print(f"Exfiltration mix     : index={spread_result.vulnerability_index:.2f} "
          f"SPOF={spread_result.single_point_of_failure}")
    print(f"Empty dataset        : index={empty_result.vulnerability_index:.2f} "
          f"SPOF={empty_result.single_point_of_failure}")
    print("KCVI VALIDATION HARNESS: PASS")


async def _seed_temporal_fixture(database_path: Path, now: datetime) -> None:
    """Seed back-dated synthetic records spanning all four intervals."""
    # (title, threat_category, age_hours) — ages chosen so each horizon's
    # current AND previous window receives a known, distinct population.
    incident_rows: List[Tuple[str, str, int]] = [
        ("A1 fresh digital arrest case", "digital_arrest", 2),
        ("A2 fresh digital arrest case", "digital_arrest", 5),
        ("A3 fresh UPI mule chain", "payment_fraud", 10),
        ("B1 prior-day digital arrest", "digital_arrest", 30),       # 24h-prev
        ("C1 wedding invite APK wave", "apk_sideloading", 72),       # 3d
        ("C2 courier APK wave", "apk_sideloading", 96),              # 4d
        ("D1 trading app fraud", "investment_scam", 240),            # 7d-prev
        ("E1 QR collect scam", "payment_fraud", 480),                # 20d
        ("F1 misc cyber bulletin", "general_cyber", 1080),           # 30d-prev
        ("G1 spoofed VoIP array", "voip_spoofing", 4800),            # 200d
        ("H1 archived mule case", "payment_fraud", 9600),            # 1y-prev
    ]
    entity_rows: List[Tuple[str, str, int]] = [
        ("upi_id", "fraud.verify1@okax", 1),
        ("phone", "9000000001", 6),
        ("upi_id", "fraud.verify2@okax", 30),                        # 24h-prev
        ("url", "http://scam-invite.example", 120),                  # 5d
        ("phone", "9000000002", 216),                                # 7d-prev
        ("email", "mule.handler@scam.in", 600),                      # 25d
        ("phone", "9000000003", 960),                                # 30d-prev
        ("url", "http://archived-scam.example", 12000),              # 1y-prev
    ]
    async with aiosqlite.connect(database_path) as connection:
        try:
            await connection.executemany(
                "INSERT INTO incidents "
                "(title, source, threat_category, jurisdiction, created_at) "
                "VALUES (?, 'temporal-harness', ?, 'National', ?)",
                [
                    (title, category,
                     _sqlite_timestamp(now - timedelta(hours=age)))
                    for title, category, age in incident_rows
                ],
            )
            await connection.executemany(
                "INSERT INTO entities "
                "(entity_type, value, risk_score, first_seen, last_seen) "
                "VALUES (?, ?, 50.0, ?, ?)",
                [
                    (entity_type, value,
                     _sqlite_timestamp(now - timedelta(hours=age)),
                     _sqlite_timestamp(now - timedelta(hours=age)))
                    for entity_type, value, age in entity_rows
                ],
            )
            await connection.commit()
        except aiosqlite.Error:
            await connection.rollback()
            LOGGER.exception("Temporal fixture seeding failed — rolled back")
            raise


async def _run_time_horizon_validation_harness() -> None:
    """Prove window isolation, delta tracking, and leak-free aggregation."""
    now: datetime = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="cybershield-horizon-") as scratch:
        scratch_db: Path = Path(scratch) / "horizon_fixture.sqlite3"
        await RelationalStoreManager(scratch_db).init_schema()
        await _seed_temporal_fixture(scratch_db, now)
        matrix: TimeHorizonMatrix = await compute_time_horizons(
            reference_time=now, database_path=scratch_db
        )

    assert set(matrix.snapshots) == set(TIME_HORIZON_WINDOWS), (
        "matrix must carry exactly the four configured horizons"
    )

    # Exact window populations — any drift indicates a calculation leak.
    expected_volumes: Dict[str, Tuple[int, int]] = {
        "24h": (3, 1),   # (current, previous-equivalent)
        "7d": (6, 1),
        "30d": (8, 1),
        "1y": (10, 1),
    }
    expected_entities: Dict[str, Tuple[int, int, float]] = {
        "24h": (2, 1, 1.0),
        "7d": (4, 1, 3.0),
        "30d": (6, 1, 5.0),
        "1y": (7, 1, 6.0),
    }
    for horizon, (volume, previous) in expected_volumes.items():
        snapshot: HorizonSnapshot = matrix.snapshots[horizon]
        assert snapshot.incident_volume == volume, (
            f"{horizon}: expected {volume} incidents, got {snapshot.incident_volume}"
        )
        assert snapshot.previous_incident_volume == previous
        assert snapshot.volume_delta == volume - previous
        assert sum(snapshot.vector_counts.values()) == volume, (
            f"{horizon}: vector counts must reconcile with total volume"
        )
        entity_new, entity_prev, volatility = expected_entities[horizon]
        assert snapshot.new_entity_count == entity_new
        assert snapshot.previous_new_entity_count == entity_prev
        assert snapshot.entity_volatility_index == volatility

    # Momentum tracking: 7d window must surface the freshest gaining vectors
    # and never list a receding one.
    week: HorizonSnapshot = matrix.snapshots["7d"]
    assert week.vector_momentum["digital_arrest"] == 3
    assert week.vector_momentum["apk_sideloading"] == 2
    assert week.vector_momentum["investment_scam"] == -1
    assert week.gaining_vectors[0] == "digital_arrest"
    assert "apk_sideloading" in week.gaining_vectors
    assert "investment_scam" not in week.gaining_vectors

    # Boundary isolation: the 30-hour record must not leak into 24h-current.
    day: HorizonSnapshot = matrix.snapshots["24h"]
    assert day.vector_counts.get("digital_arrest") == 2
    assert day.vector_momentum["digital_arrest"] == 1

    # Missing date bounds: naive reference times must be rejected loudly.
    try:
        await compute_time_horizons(reference_time=datetime.now())
        raise AssertionError("naive reference_time must raise ValueError")
    except ValueError:
        pass

    print("--- Time-horizon matrix ---")
    for horizon in TIME_HORIZON_WINDOWS:
        snap: HorizonSnapshot = matrix.snapshots[horizon]
        print(f"{horizon:>3}: volume={snap.incident_volume:>2} (Δ{snap.volume_delta:+d}) "
              f"entities={snap.new_entity_count} "
              f"volatility={snap.entity_volatility_index:+.2f} "
              f"gaining={snap.gaining_vectors or '-'}")
    print("TIME-HORIZON VALIDATION HARNESS: PASS")


async def _run_all_harnesses() -> None:
    """Execute the MAVI, KCVI, and time-horizon harnesses sequentially."""
    await _run_validation_harness()
    await _run_kcvi_validation_harness()
    await _run_time_horizon_validation_harness()


if __name__ == "__main__":
    asyncio.run(_run_all_harnesses())
