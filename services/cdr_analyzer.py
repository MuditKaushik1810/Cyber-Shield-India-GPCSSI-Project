"""Cyber Shield India — CDR & IPDR Operational Analyzer (Feature 2).

A real Pandas forensic engine over Call Detail Records (CDR) and IP Detail
Records (IPDR). It ingests a CSV / Excel export, normalizes heterogeneous column
naming to a canonical schema, and runs deterministic analytical chains used in
live cyber-investigations:

* **B-Party analysis** — the top counterpart numbers / destinations by frequency,
  with call volume, talk-time and first/last-seen windows.
* **Odd-hour anomalies** — activity between 23:00 and 04:00 (operational hours of
  many fraud call-centres), summarised per subscriber.
* **Shared-identity links** — one IMEI used with several MSISDNs (handset reused
  across SIMs) or one IMSI seen on several handsets (SIM cloning / rotation).
* **Spatial-temporal links** — different numbers footprinting the *same* cell
  tower in sequence (co-location) and a single number making implausibly rapid
  tower jumps (cloning / spoofed location).

Only the *aggregated* summary tables — never the raw rows — are handed to
:mod:`services.llm_client` (the 503/429-safe cascade) for a digital-forensics
breakdown. If every model is unavailable, a deterministic investigative brief is
assembled from the same aggregates, so the analyst always gets findings.

Intended for authorized investigators / researchers working their own lawfully
obtained records.
"""

import io
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pandas as pd
from langchain_core.messages import HumanMessage, SystemMessage

from services.llm_client import invoke_text

LOGGER: logging.Logger = logging.getLogger("cybershield.cdr_analyzer")

# Night window flagged as "odd-hour": 23:00–03:59 inclusive.
ODD_HOUR_START: int = 23
ODD_HOUR_END: int = 4
# Two different numbers on the same tower within this gap = a co-location link.
CO_LOCATION_WINDOW_MIN: float = 30.0
# A single number changing tower faster than this = a rapid-handoff anomaly.
RAPID_HANDOFF_MIN: float = 8.0
# Hard caps so the LLM only ever sees small, aggregated tables.
_TOP_N: int = 5
_LINK_CAP: int = 25


class CDRSchemaError(ValueError):
    """Raised when an upload cannot be mapped to a usable CDR/IPDR schema."""


# Canonical column -> accepted header aliases (matched case/space/underscore-insensitive).
_COLUMN_ALIASES: Dict[str, List[str]] = {
    "caller": ["caller", "aparty", "calling", "callingnumber", "sourcenumber",
               "msisdn", "msisdna", "from", "subscriber", "anumber"],
    "callee": ["callee", "bparty", "called", "callednumber", "destinationnumber",
               "msisdnb", "to", "bnumber", "contact"],
    "timestamp": ["timestamp", "datetime", "datetime", "calltime", "starttime",
                  "sessionstart", "date", "calldate", "eventtime", "time"],
    "duration": ["duration", "durationsec", "callduration", "sessionduration",
                 "secs", "seconds", "durationseconds"],
    "cell_tower_id": ["celltowerid", "cellid", "towerid", "cgi", "laccid",
                      "tower", "celltower", "site", "lac"],
    "imei": ["imei"],
    "imsi": ["imsi"],
    "source_ip": ["sourceip", "srcip", "privateip", "clientip", "ipaddress"],
    "port": ["port", "sourceport", "srcport", "clientport"],
    "destination_ip": ["destinationip", "destip", "dstip", "serverip", "publicip"],
}


@dataclass
class CDRAnalysis:
    """Container for every aggregated forensic output (no raw rows retained)."""

    record_count: int
    cdr_count: int
    ipdr_count: int
    distinct_actors: int
    time_span: str
    available_fields: List[str]
    top_contacts: pd.DataFrame
    odd_hour_by_actor: pd.DataFrame
    odd_hour_events: int
    shared_identity: pd.DataFrame
    co_location: pd.DataFrame
    rapid_handoff: pd.DataFrame
    busiest_hours: pd.DataFrame
    ip_intel: pd.DataFrame = field(default_factory=pd.DataFrame)


# --------------------------------------------------------------------------- #
# Ingestion & normalization.                                                  #
# --------------------------------------------------------------------------- #


def _canon_key(name: str) -> str:
    """Collapse a header to its comparison key (lowercase, alnum only)."""
    return "".join(ch for ch in str(name).lower() if ch.isalnum())


def load_dataframe(buffer: bytes, filename: str) -> pd.DataFrame:
    """Read raw CSV/Excel bytes into a DataFrame, normalized to the canon schema."""
    name: str = (filename or "").lower()
    try:
        if name.endswith((".xlsx", ".xls")):
            frame: pd.DataFrame = pd.read_excel(io.BytesIO(buffer))
        else:
            frame = pd.read_csv(io.BytesIO(buffer))
    except (ValueError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise CDRSchemaError(f"Could not parse the file: {exc}") from exc
    except ImportError as exc:  # openpyxl missing for .xlsx
        raise CDRSchemaError(
            "Reading Excel needs the 'openpyxl' package — please upload CSV "
            "instead, or install openpyxl.") from exc
    if frame.empty:
        raise CDRSchemaError("The uploaded file contains no rows.")
    return normalize_schema(frame)


def normalize_schema(frame: pd.DataFrame) -> pd.DataFrame:
    """Rename recognised columns to canonical names and derive helper fields."""
    lookup: Dict[str, str] = {}
    for canon, aliases in _COLUMN_ALIASES.items():
        alias_keys = {_canon_key(a) for a in aliases} | {canon}
        for column in frame.columns:
            if _canon_key(column) in alias_keys and canon not in lookup.values():
                lookup[column] = canon
                break
    frame = frame.rename(columns=lookup)

    if "timestamp" not in frame.columns:
        raise CDRSchemaError(
            "No timestamp column found. Expected one of: Timestamp, DateTime, "
            "Call Time, Session Start.")
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    frame = frame.dropna(subset=["timestamp"])
    if frame.empty:
        raise CDRSchemaError("No rows had a parseable timestamp.")

    has_party: bool = any(c in frame.columns for c in ("caller", "callee"))
    has_ip: bool = any(c in frame.columns for c in ("source_ip", "destination_ip"))
    if not (has_party or has_ip):
        raise CDRSchemaError(
            "No identity columns found. Provide CDR fields (Caller/Callee) or "
            "IPDR fields (Source IP/Destination IP).")

    # Unified actor (initiator) and contact (counterpart) across CDR + IPDR.
    frame["actor"] = _first_present(frame, ["caller", "source_ip", "imsi", "imei"])
    frame["contact"] = _first_present(frame, ["callee", "destination_ip"])
    if "duration" in frame.columns:
        frame["duration"] = pd.to_numeric(frame["duration"], errors="coerce").fillna(0)
    frame["hour"] = frame["timestamp"].dt.hour
    return frame


def _first_present(frame: pd.DataFrame, candidates: List[str]) -> pd.Series:
    """Coalesce the first available column across candidates into one Series."""
    result: pd.Series = pd.Series([pd.NA] * len(frame), index=frame.index, dtype="object")
    for column in candidates:
        if column in frame.columns:
            result = result.fillna(frame[column].astype("object"))
    return result


# --------------------------------------------------------------------------- #
# Analytical chains.                                                          #
# --------------------------------------------------------------------------- #


def _top_contacts(frame: pd.DataFrame) -> pd.DataFrame:
    """B-Party analysis: most frequent counterparts with volume & talk-time."""
    sub: pd.DataFrame = frame.dropna(subset=["contact"])
    if sub.empty:
        return pd.DataFrame()
    grouped = sub.groupby("contact")
    out = pd.DataFrame({
        "contact": grouped.size().index,
        "events": grouped.size().values,
    })
    if "duration" in sub.columns:
        out["total_seconds"] = grouped["duration"].sum().values.astype(int)
    out["first_seen"] = grouped["timestamp"].min().dt.strftime("%Y-%m-%d %H:%M").values
    out["last_seen"] = grouped["timestamp"].max().dt.strftime("%Y-%m-%d %H:%M").values
    return out.sort_values("events", ascending=False).head(_TOP_N).reset_index(drop=True)


def _odd_hour(frame: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """Flag and summarise activity between 23:00 and 04:00 per actor."""
    mask = (frame["hour"] >= ODD_HOUR_START) | (frame["hour"] < ODD_HOUR_END)
    night: pd.DataFrame = frame[mask].dropna(subset=["actor"])
    if night.empty:
        return pd.DataFrame(), 0
    by_actor = (night.groupby("actor").size().sort_values(ascending=False)
                .head(_TOP_N).reset_index(name="odd_hour_events"))
    return by_actor, int(len(night))


def _shared_identity(frame: pd.DataFrame) -> pd.DataFrame:
    """Detect one IMEI across many numbers (SIM rotation in a reused handset)
    and one IMSI across many IMEIs (SIM cloning / handset hopping)."""
    rows: List[Dict[str, object]] = []
    # (identity col, label, partner col, what the partner represents).
    checks: List[Tuple[str, str, str, str]] = [
        ("imei", "IMEI", "actor", "numbers"),
        ("imsi", "IMSI", "imei", "handsets (IMEI)"),
    ]
    for id_col, label, partner_col, partner_name in checks:
        if id_col not in frame.columns or partner_col not in frame.columns:
            continue
        sub = frame.dropna(subset=[id_col, partner_col])
        if sub.empty:
            continue
        nun = sub.groupby(id_col)[partner_col].nunique()
        for ident, count in nun[nun > 1].items():
            partners = sorted({str(p) for p in sub.loc[sub[id_col] == ident, partner_col]})
            rows.append({
                "type": label,
                "identifier": str(ident),
                "distinct_count": int(count),
                "linked_to": f"{partner_name}: {', '.join(partners)}",
                "records": int((sub[id_col] == ident).sum()),
            })
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    return out.sort_values("distinct_count", ascending=False).head(_LINK_CAP).reset_index(drop=True)


def _co_location(frame: pd.DataFrame) -> pd.DataFrame:
    """Different numbers footprinting the same tower within the time window."""
    if "cell_tower_id" not in frame.columns:
        return pd.DataFrame()
    sub = frame.dropna(subset=["cell_tower_id", "actor"]).sort_values("timestamp")
    rows: List[Dict[str, object]] = []
    for tower, group in sub.groupby("cell_tower_id"):
        records = group[["actor", "timestamp"]].to_numpy()
        for i in range(1, len(records)):
            prev_actor, prev_ts = records[i - 1]
            cur_actor, cur_ts = records[i]
            if str(prev_actor) == str(cur_actor):
                continue
            gap_min: float = (cur_ts - prev_ts).total_seconds() / 60.0
            if gap_min <= CO_LOCATION_WINDOW_MIN:
                rows.append({
                    "cell_tower_id": str(tower),
                    "number_a": str(prev_actor),
                    "number_b": str(cur_actor),
                    "gap_minutes": round(gap_min, 1),
                    "window": f"{pd.Timestamp(prev_ts):%Y-%m-%d %H:%M} → "
                              f"{pd.Timestamp(cur_ts):%H:%M}",
                })
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    return out.sort_values("gap_minutes").head(_LINK_CAP).reset_index(drop=True)


def _rapid_handoff(frame: pd.DataFrame) -> pd.DataFrame:
    """One number jumping between distinct towers implausibly fast."""
    if "cell_tower_id" not in frame.columns:
        return pd.DataFrame()
    sub = frame.dropna(subset=["cell_tower_id", "actor"]).sort_values(["actor", "timestamp"])
    rows: List[Dict[str, object]] = []
    for actor, group in sub.groupby("actor"):
        records = group[["cell_tower_id", "timestamp"]].to_numpy()
        for i in range(1, len(records)):
            prev_tower, prev_ts = records[i - 1]
            cur_tower, cur_ts = records[i]
            if str(prev_tower) == str(cur_tower):
                continue
            gap_min: float = (cur_ts - prev_ts).total_seconds() / 60.0
            if 0 <= gap_min <= RAPID_HANDOFF_MIN:
                rows.append({
                    "number": str(actor),
                    "from_tower": str(prev_tower),
                    "to_tower": str(cur_tower),
                    "gap_minutes": round(gap_min, 1),
                    "at": f"{pd.Timestamp(cur_ts):%Y-%m-%d %H:%M}",
                })
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    return out.sort_values("gap_minutes").head(_LINK_CAP).reset_index(drop=True)


def _busiest_hours(frame: pd.DataFrame) -> pd.DataFrame:
    """Activity distribution across the 24-hour clock."""
    counts = frame.groupby("hour").size().reset_index(name="records")
    full = pd.DataFrame({"hour": range(24)}).merge(counts, on="hour", how="left")
    full["records"] = full["records"].fillna(0).astype(int)
    return full


def _ip_intel(frame: pd.DataFrame) -> pd.DataFrame:
    """IPDR destination intelligence: top servers by sessions and port spread."""
    if "destination_ip" not in frame.columns:
        return pd.DataFrame()
    sub = frame.dropna(subset=["destination_ip"])
    if sub.empty:
        return pd.DataFrame()
    grouped = sub.groupby("destination_ip")
    out = pd.DataFrame({
        "destination_ip": grouped.size().index,
        "sessions": grouped.size().values,
    })
    if "port" in sub.columns:
        out["distinct_ports"] = grouped["port"].nunique().values
    out["first_seen"] = grouped["timestamp"].min().dt.strftime("%Y-%m-%d %H:%M").values
    return out.sort_values("sessions", ascending=False).head(_TOP_N).reset_index(drop=True)


def build_analysis(frame: pd.DataFrame) -> CDRAnalysis:
    """Run every analytical chain and package the aggregated outputs."""
    cdr_rows: int = int(frame["callee"].notna().sum()) if "callee" in frame.columns else 0
    ipdr_rows: int = (int(frame["destination_ip"].notna().sum())
                      if "destination_ip" in frame.columns else 0)
    odd_by_actor, odd_events = _odd_hour(frame)
    span: str = (f"{frame['timestamp'].min():%Y-%m-%d %H:%M} → "
                 f"{frame['timestamp'].max():%Y-%m-%d %H:%M}")
    available: List[str] = [c for c in _COLUMN_ALIASES if c in frame.columns]
    analysis = CDRAnalysis(
        record_count=int(len(frame)),
        cdr_count=cdr_rows,
        ipdr_count=ipdr_rows,
        distinct_actors=int(frame["actor"].nunique()),
        time_span=span,
        available_fields=available,
        top_contacts=_top_contacts(frame),
        odd_hour_by_actor=odd_by_actor,
        odd_hour_events=odd_events,
        shared_identity=_shared_identity(frame),
        co_location=_co_location(frame),
        rapid_handoff=_rapid_handoff(frame),
        busiest_hours=_busiest_hours(frame),
        ip_intel=_ip_intel(frame),
    )
    LOGGER.info("CDR analysis: rows=%d actors=%d odd=%d shared=%d colo=%d rapid=%d",
                analysis.record_count, analysis.distinct_actors, odd_events,
                len(analysis.shared_identity), len(analysis.co_location),
                len(analysis.rapid_handoff))
    return analysis


# --------------------------------------------------------------------------- #
# LLM forensic breakdown (aggregates only).                                   #
# --------------------------------------------------------------------------- #


def _df_block(frame: pd.DataFrame, empty: str = "(none detected)") -> str:
    """Render a small DataFrame as a fixed-width block for the prompt."""
    if frame is None or frame.empty:
        return empty
    return frame.to_string(index=False)


def to_summary_text(analysis: CDRAnalysis) -> str:
    """Compact, aggregates-only textual brief handed to the model."""
    return (
        f"DATASET: {analysis.record_count} records "
        f"({analysis.cdr_count} CDR voice/SMS, {analysis.ipdr_count} IPDR data), "
        f"{analysis.distinct_actors} distinct numbers/actors. "
        f"Time span: {analysis.time_span}. "
        f"Fields present: {', '.join(analysis.available_fields)}.\n\n"
        f"TOP CONTACTS (B-Party frequency):\n{_df_block(analysis.top_contacts)}\n\n"
        f"ODD-HOUR ACTIVITY (23:00–04:00), total {analysis.odd_hour_events} events; "
        f"top actors:\n{_df_block(analysis.odd_hour_by_actor)}\n\n"
        f"SHARED-IDENTITY LINKS (one IMEI↔many numbers / one IMSI↔many handsets):\n"
        f"{_df_block(analysis.shared_identity)}\n\n"
        f"CO-LOCATION LINKS (different numbers, same tower, within "
        f"{int(CO_LOCATION_WINDOW_MIN)} min):\n{_df_block(analysis.co_location)}\n\n"
        f"RAPID TOWER HAND-OFFS (same number, distinct towers within "
        f"{int(RAPID_HANDOFF_MIN)} min):\n{_df_block(analysis.rapid_handoff)}\n\n"
        f"IPDR DESTINATION INTEL:\n{_df_block(analysis.ip_intel)}"
    )


_SYSTEM_PROMPT: str = (
    "You are an elite digital forensics investigator supporting an AUTHORIZED "
    "law-enforcement analysis of lawfully-obtained CDR/IPDR records. You are "
    "given ONLY aggregated summary tables — never raw records. From them, "
    "reconstruct the target's tactical operating pattern. Structure your output "
    "in three clearly headed sections using bullet points:\n"
    "1. BEHAVIOURAL PROFILE — routine, primary contacts, voice-vs-data habits, "
    "active hours.\n"
    "2. KEY ANOMALIES & TRADECRAFT — interpret each signal: shared IMEI/IMSI "
    "(handset reuse / SIM rotation / cloning), co-location links (physical "
    "meetings or coordinated cells), odd-hour clustering (call-centre shifts), "
    "and rapid tower hand-offs (spoofed location / cloned SIM / impossible "
    "travel). Reference the specific numbers, identifiers and counts.\n"
    "3. PRIORITISED INVESTIGATIVE NEXT STEPS — concrete, ranked actions (e.g. "
    "pull CAF/KYC for specific numbers or IMEIs, map co-located subscribers, "
    "subpoena destination IP owners).\n"
    "Be precise and cite the figures from the tables. Never invent data not "
    "present in the summaries."
)


def _deterministic_brief(analysis: CDRAnalysis) -> str:
    """Genuine rule-based investigative brief when the cascade is exhausted."""
    lines: List[str] = ["**Automated forensic brief (offline analytics engine):**", ""]
    lines.append(
        f"- Dataset of **{analysis.record_count}** records "
        f"({analysis.cdr_count} CDR / {analysis.ipdr_count} IPDR) across "
        f"**{analysis.distinct_actors}** distinct numbers, spanning "
        f"{analysis.time_span}.")
    if not analysis.top_contacts.empty:
        top = analysis.top_contacts.iloc[0]
        lines.append(
            f"- Dominant counterpart: **{top['contact']}** with "
            f"{int(top['events'])} interactions — prioritise CAF/KYC retrieval.")
    if analysis.odd_hour_events:
        lines.append(
            f"- **{analysis.odd_hour_events}** odd-hour (23:00–04:00) events "
            f"detected — consistent with shift-based / call-centre operations.")
    if not analysis.shared_identity.empty:
        lines.append(
            f"- **{len(analysis.shared_identity)}** shared-identity link(s): one "
            f"device/SIM mapped to multiple numbers — a strong SIM-rotation / "
            f"handset-reuse indicator. Subpoena the flagged IMEI/IMSI history.")
    if not analysis.co_location.empty:
        lines.append(
            f"- **{len(analysis.co_location)}** co-location link(s): distinct "
            f"numbers sharing a tower within minutes — map these subscribers for "
            f"a possible coordinated cell.")
    if not analysis.rapid_handoff.empty:
        lines.append(
            f"- **{len(analysis.rapid_handoff)}** rapid tower hand-off(s): "
            f"investigate for cloned SIMs or location spoofing.")
    if not analysis.ip_intel.empty:
        top_ip = analysis.ip_intel.iloc[0]
        lines.append(
            f"- Top IPDR destination **{top_ip['destination_ip']}** "
            f"({int(top_ip['sessions'])} sessions) — resolve owner / hosting ASN.")
    lines.append("")
    lines.append("_AI narrative is paused (models at capacity); findings above "
                 "are computed deterministically from the aggregated tables._")
    return "\n".join(lines)


def investigate(analysis: CDRAnalysis) -> str:
    """Produce the digital-forensics breakdown from aggregates (cascade-safe)."""
    messages = [
        SystemMessage(content=_SYSTEM_PROMPT),
        HumanMessage(content=to_summary_text(analysis)),
    ]
    breakdown: str = invoke_text(messages, origin="cdr_analyzer", temperature=0.25)
    if breakdown.strip():
        return breakdown
    LOGGER.warning("cdr investigate: cascade exhausted — deterministic brief")
    return _deterministic_brief(analysis)


# --------------------------------------------------------------------------- #
# Sample schema (downloadable from the UI).                                   #
# --------------------------------------------------------------------------- #


def sample_schema_csv() -> str:
    """A valid, mixed CDR+IPDR sample so users can test immediately."""
    header: str = ("Caller,Callee,Timestamp,Duration,Cell Tower ID,IMEI,IMSI,"
                   "Source IP,Port,Destination IP")
    rows: List[str] = [
        # Routine daytime activity for the target on its primary handset/SIM.
        "9876543210,9812345678,2026-06-18 09:15:00,142,CGI-DEL-014,356938035643809,404451234567890,,,",
        # Odd-hour call, then a second number footprints the SAME tower 8 min
        # later -> co-location link at CGI-DEL-014.
        "9876543210,9933221100,2026-06-18 23:42:00,38,CGI-DEL-014,356938035643809,404451234567890,,,",
        "9933221100,9876543210,2026-06-18 23:50:00,55,CGI-DEL-014,356938035643801,404459876543210,,,",
        # Target seen on two different Mumbai towers 4 min apart -> rapid
        # tower hand-off anomaly (cloning / location spoofing).
        "9876543210,9812345678,2026-06-19 02:05:00,77,CGI-MUM-221,356938035643809,404451234567890,,,",
        "9876543210,9700000001,2026-06-19 02:09:00,12,CGI-MUM-998,356938035643809,404451234567890,,,",
        # Hyderabad co-location: two numbers on CGI-HYD-007 within 10 min.
        "9700000001,9812345678,2026-06-19 11:30:00,200,CGI-HYD-007,356938035643777,404452222222222,,,",
        "9933221100,9700000001,2026-06-19 11:40:00,64,CGI-HYD-007,356938035643801,404459876543210,,,",
        # A DIFFERENT number reuses the target's IMEI -> shared-handset link.
        "9988776655,9876543210,2026-06-19 15:00:00,30,CGI-DEL-014,356938035643809,404457777777777,,,",
        # The target's IMSI surfaces on a SECOND handset -> SIM-cloning link.
        "9876543210,9812345678,2026-06-19 16:00:00,45,CGI-DEL-014,356938035643888,404451234567890,,,",
        # IPDR data sessions (no tower) — destination-IP intelligence.
        "9876543210,,2026-06-19 14:00:00,0,,356938035643809,404451234567890,10.21.4.9,51514,142.250.193.78",
        "9876543210,,2026-06-19 14:01:00,0,,356938035643809,404451234567890,10.21.4.9,51520,104.244.42.65",
        "9933221100,,2026-06-20 03:20:00,0,,356938035643801,404459876543210,10.21.4.55,40988,185.199.108.153",
    ]
    return header + "\n" + "\n".join(rows) + "\n"


# --------------------------------------------------------------------------- #
# Flexible arbitrary-schema ingestion + LLM forensic inference.               #
# --------------------------------------------------------------------------- #
#
# The chains above require a recognised CDR/IPDR schema. For arbitrary user CSVs
# (any column layout), this path reads the file WITHOUT structural validation and
# routes a bounded header+row sample through the 5-tier model cascade so the
# analyst always gets a forensic read — no hardcoded-column crash.

# How many rows of the upload to show the model (headers + a bounded sample keep
# the payload well inside the context budget on large files).
_FORENSIC_SAMPLE_ROWS: int = 50

_FORENSIC_SYSTEM_PROMPT: str = (
    "You are an elite digital-forensics intelligence analyst supporting an "
    "AUTHORIZED law-enforcement examination of lawfully-obtained telecom / "
    "financial records. You are handed the HEADER ROW and a SAMPLE of rows from "
    "an arbitrary CSV whose schema is UNKNOWN. Read it the way an expert analyst "
    "reads a raw log and produce a clinical report with these clearly-headed "
    "sections, using bullet points:\n"
    "1. SCHEMA DEDUCTION — infer what each column most likely represents "
    "(A-party/caller, B-party/callee, timestamps, call duration, cell-tower / "
    "CGI / LAC, IMEI, IMSI, source/destination IP & port, transaction amount, "
    "account/UPI handle, latitude/longitude, etc.) and note your confidence.\n"
    "2. PATTERN ISOLATION — describe the dominant call / transaction patterns: "
    "high-frequency counterparts, talk-time or amount concentration, repeated "
    "short-duration bursts, periodic activity.\n"
    "3. CRITICAL ANOMALY FLAGS — explicitly call out signals visible in the "
    "sample: continuous night-time / odd-hour movement, rapid geographic or "
    "cell-tower jumps, localized co-location correlation clusters, a single "
    "handset (IMEI) reused across SIMs or an IMSI seen on multiple handsets, "
    "and rapid fund layering across accounts.\n"
    "4. FORENSIC SUMMARY — a concise, descriptive narrative of the subject's "
    "operating pattern with prioritised investigative leads.\n"
    "Reason ONLY from the data shown. If the sample is insufficient to support a "
    "claim, say so plainly. NEVER fabricate values, names or figures that are "
    "not present in the sample."
)


def read_csv_flexible(buffer: bytes, filename: str) -> pd.DataFrame:
    """Read ANY CSV / Excel into a DataFrame — no schema-validation barrier.

    Raises :class:`CDRSchemaError` only on a genuine parse failure or an empty
    file, never for an unrecognised column layout.
    """
    name: str = (filename or "").lower()
    try:
        if name.endswith((".xlsx", ".xls")):
            frame: pd.DataFrame = pd.read_excel(io.BytesIO(buffer))
        else:
            frame = pd.read_csv(io.BytesIO(buffer))
    except (ValueError, pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        raise CDRSchemaError(f"Could not parse the file: {exc}") from exc
    except ImportError as exc:  # openpyxl missing for .xlsx
        raise CDRSchemaError(
            "Reading Excel needs the 'openpyxl' package — please upload CSV "
            "instead, or install openpyxl.") from exc
    if frame.empty:
        raise CDRSchemaError("The uploaded file contains no rows.")
    return frame


def try_build_analysis(frame: pd.DataFrame) -> Optional[CDRAnalysis]:
    """Run the deterministic engine if the schema is recognised, else None.

    Never raises for an unrecognised / partial layout — the rigid-lookup faults
    (missing canonical column, un-parseable timestamp, empty group) are caught so
    the caller can fall back to the LLM forensic inference without a crash.
    """
    try:
        return build_analysis(normalize_schema(frame.copy()))
    except (CDRSchemaError, KeyError, ValueError, IndexError) as exc:
        LOGGER.info("deterministic CDR chains skipped (%s) — arbitrary schema",
                    type(exc).__name__)
        return None


def _stringify_sample(frame: pd.DataFrame,
                      max_rows: int = _FORENSIC_SAMPLE_ROWS) -> str:
    """Render headers + a bounded row sample into a compact text payload."""
    sample: pd.DataFrame = frame.head(max_rows)
    header: str = ", ".join(str(c) for c in frame.columns)
    return (f"FILE COLUMNS ({len(frame.columns)}): {header}\n"
            f"TOTAL ROWS: {len(frame):,} (showing the first {len(sample)})\n\n"
            f"SAMPLE ROWS (CSV):\n{sample.to_csv(index=False)}")


def _forensic_fallback(frame: pd.DataFrame) -> str:
    """Deterministic descriptive read when every cascade model is unavailable."""
    columns: List[str] = [str(c) for c in frame.columns]
    lines: List[str] = [
        "### 🕵️ Forensic summary (deterministic — AI cascade at capacity)",
        "",
        "**Schema deduction**",
        f"- {len(frame):,} rows across {len(columns)} columns.",
        f"- Columns present: {', '.join(columns)}.",
        "",
        "**Column population**",
    ]
    for column in columns[:20]:
        non_null: int = int(frame[column].notna().sum())
        distinct: int = int(frame[column].nunique(dropna=True))
        lines.append(f"- `{column}`: {non_null:,} populated, "
                     f"{distinct:,} distinct values.")
    lines.append("")
    lines.append("_Re-run the AI forensic investigation once model capacity "
                 "recovers for column-identity deduction and anomaly flagging._")
    return "\n".join(lines)


def forensic_infer(frame: pd.DataFrame, filename: str = "") -> str:
    """LLM forensic inference over an arbitrary-schema record sample (cascade-safe).

    Routes the headers + a bounded row sample through the 5-tier ``invoke_text``
    cascade. Returns a deterministic descriptive read if every model is down.
    """
    payload: str = _stringify_sample(frame)
    messages = [
        SystemMessage(content=_FORENSIC_SYSTEM_PROMPT),
        HumanMessage(content=(f"SOURCE FILE: {filename or 'uploaded.csv'}\n\n"
                              f"{payload}")),
    ]
    report: str = invoke_text(messages, origin="cdr_analyzer.forensic_infer",
                              temperature=0.2)
    if report.strip():
        LOGGER.info("forensic_infer: report generated for %r (%d rows)",
                    filename, len(frame))
        return report
    LOGGER.warning("forensic_infer: cascade exhausted — deterministic fallback")
    return _forensic_fallback(frame)
