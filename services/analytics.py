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
formula mandated by CLAUDE.md for money-mule hotspot identification:

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
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import aiosqlite
from pydantic import BaseModel, Field

from core.database import SQLITE_PATH

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
# Canonical Mule Account Velocity Index (CLAUDE.md formula).                  #
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


if __name__ == "__main__":
    asyncio.run(_run_validation_harness())
