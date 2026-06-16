"""Cyber Shield India — First-Responder Forensic Triage Playbook engine.

Generates a rapid 4-point forensic action plan tailored to a threat domain and
target sector, with mandatory digital-evidence-preservation safeguards under
**Section 63(4) of the Bharatiya Sakshya Adhiniyam (BSA), 2023** — cryptographic
hashing, safe volatile/non-volatile memory capture, chain-of-custody integrity,
and the Part A / Part B certificate documentation required for admissibility.

Uses gemini-3.5-flash for a tailored plan, with a deterministic legal-compliant
fallback so the forensic guidance ALWAYS renders (the legally critical content
never depends on the LLM being reachable).
"""

import logging
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_google_genai._common import GoogleGenerativeAIError
from pydantic import BaseModel, Field, ValidationError

from core.config import GEMINI_FLASH_MODEL, get_google_api_key

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the playbook logger (midnight-rotating)."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.playbook")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "frontend.log", when="midnight",
        backupCount=14, encoding="utf-8",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


LOGGER: logging.Logger = _build_logger()


class PlaybookStep(BaseModel):
    """One step of the forensic action plan."""

    action: str = Field(description="Short imperative action title.")
    detail: str = Field(description="One or two sentences of specific guidance.")


class TriagePlaybook(BaseModel):
    """A 4-point first-responder forensic action plan."""

    steps: List[PlaybookStep] = Field(default_factory=list)


_PLAYBOOK_PROMPT: str = (
    "You are a senior digital-forensics first responder for Indian law "
    "enforcement. Produce a rapid 4-point First-Responder Forensic Action Plan "
    "tailored to the given threat domain and target sector. The four points "
    "MUST collectively cover: (1) scoping and isolating the affected assets for "
    "this specific threat and sector without destroying volatile evidence; "
    "(2) safely capturing volatile and non-volatile memory and IMMEDIATELY "
    "recording cryptographic hash values (e.g. SHA-256) of every artifact; "
    "(3) maintaining an unbroken, documented chain-of-custody; (4) fulfilling "
    "the Part A and Part B certificate documentation under Section 63(4) of the "
    "Bharatiya Sakshya Adhiniyam (BSA), 2023 to ensure courtroom admissibility. "
    "Each point: a short imperative action title and 1-2 sentences of specific, "
    "legally-aligned guidance. Never omit the hashing or the BSA 63(4) "
    "Part A / Part B requirements."
)


def _fallback_playbook(threat_domain: str, target_sector: str) -> List[Dict[str, str]]:
    """Deterministic, legally-compliant 4-point plan (always carries BSA 63(4))."""
    sector: str = target_sector or "the affected sector"
    return [
        {
            "action": "1. Scope & isolate the affected assets",
            "detail": (
                f"Identify every {threat_domain} indicator (malicious IPs, "
                f"phishing domains, or leaked datasets) impacting {sector}. "
                "Isolate affected hosts from the network WITHOUT powering them "
                "down, preserving volatile evidence in memory."),
        },
        {
            "action": "2. Capture evidence & record cryptographic hashes",
            "detail": (
                "Acquire forensic images plus volatile (RAM) and non-volatile "
                "memory safely using write-blockers. IMMEDIATELY compute and "
                "record SHA-256 hash values for every artifact to anchor "
                "integrity at the point of seizure."),
        },
        {
            "action": "3. Maintain an unbroken chain of custody",
            "detail": (
                "Log every handler, timestamp, location, and transfer of the "
                "evidence. Any gap in custody can render the electronic record "
                "inadmissible, so document continuously from acquisition "
                "onward."),
        },
        {
            "action": "4. Complete BSA Section 63(4) certification",
            "detail": (
                "Fulfil the certificate under Section 63(4) of the Bharatiya "
                "Sakshya Adhiniyam, 2023: Part A completed by the party "
                "producing the electronic record and Part B by the person in "
                "charge of the device/expert, attaching the recorded hash "
                "values to certify integrity for court admissibility."),
        },
    ]


def generate_triage_playbook(
    threat_domain: str, target_sector: str
) -> List[Dict[str, str]]:
    """Tailored 4-point forensic plan (gemini-3.5-flash, legal fallback)."""
    fallback: List[Dict[str, str]] = _fallback_playbook(threat_domain, target_sector)
    try:
        llm = ChatGoogleGenerativeAI(
            model=GEMINI_FLASH_MODEL, temperature=0.2,
            google_api_key=get_google_api_key(),
        ).with_structured_output(TriagePlaybook)
        plan: Optional[TriagePlaybook] = llm.invoke([
            SystemMessage(content=_PLAYBOOK_PROMPT),
            HumanMessage(content=(
                f"Threat domain: {threat_domain}\nTarget sector: {target_sector}")),
        ])
    except (GoogleGenerativeAIError, ValidationError, ValueError):
        LOGGER.exception("playbook generation failed — using legal fallback")
        return fallback
    if plan is None or len(plan.steps) < 3:
        return fallback
    LOGGER.info("playbook generated for %s / %s", threat_domain, target_sector)
    return [{"action": s.action, "detail": s.detail} for s in plan.steps[:4]]


PLAYBOOK_DISCLAIMER: str = (
    "⚠️ INVESTIGATIVE TRIAGE NOTE: This playbook provides automated "
    "first-responder guidance and digital forensics preservation templates. "
    "It does not constitute formal legal advice. Always cross-verify final "
    "certificate formats and chain-of-custody protocols with designated legal "
    "counsel or cyber cell prosecutors before formal judicial submission."
)


def compile_case_brief(
    timestamp: str, threat_domain: str, target_sector: str,
    compromised_assets: str, steps: List[Dict[str, str]],
) -> str:
    """Compile a downloadable investigator packet: brief + BSA 63(4) draft.

    Produces a clean, legally-actionable markdown/text packet — incident
    header, the 4-point forensic action plan, and a fill-in-the-blank BSA
    Section 63(4) Part A / Part B certificate draft.
    """
    bar: str = "=" * 70
    rule: str = "-" * 70
    generated: str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    plan_lines: List[str] = []
    for index, step in enumerate(steps, start=1):
        action: str = str(step.get("action", "")).lstrip("0123456789. ").strip()
        plan_lines.append(f"{index}. {action}\n   {step.get('detail', '')}")
    plan_block: str = "\n\n".join(plan_lines)

    return f"""{bar}
CYBER THREAT INVESTIGATIVE BRIEFING
Cyber Shield India — Automated First-Responder Packet
{bar}

INCIDENT TIMESTAMP : {timestamp or 'N/A'}
THREAT DOMAIN      : {threat_domain or 'N/A'}
TARGET SECTOR      : {target_sector or 'N/A'}
COMPROMISED ASSETS : {compromised_assets or 'N/A'}

{rule}
FIRST-RESPONDER FORENSIC ACTION PLAN
{rule}

{plan_block}

{rule}
BHARATIYA SAKSHYA ADHINIYAM (BSA), 2023 — SECTION 63(4) CERTIFICATE (DRAFT)
{rule}

PART A — Declaration by the person in charge of the device
(To be completed and signed by the person lawfully in control of the device.)

  Name                : ______________________________________________
  Designation         : ______________________________________________
  Organisation / Unit : ______________________________________________
  Device details      : (make / model / serial / IMEI)
                        ______________________________________________
  Period of operation : ______________________________________________
  Hash verification   : I declare that the electronic record was produced
                        by the above device in regular use, that the device
                        was operating properly, and that the SHA-256 hash
                        values recorded in Part B match the seized record.
  Signature           : ____________________    Date / Time : ___________

PART B — Certificate regarding hash values of electronic records
(One row per artifact; hashes recorded at the point of seizure.)

  File Name              | Hash Type | Hash Value (SHA-256) | Date/Time of Capture
  ----------------------- | --------- | -------------------- | --------------------
  _____________________ | SHA-256   | ____________________ | ____________________
  _____________________ | SHA-256   | ____________________ | ____________________
  _____________________ | SHA-256   | ____________________ | ____________________

  Certified by (Name)       : __________________________________________
  Designation / Expert role : __________________________________________
  Signature                 : ____________________  Date / Time : ________

{rule}
DISCLAIMER
{rule}
{PLAYBOOK_DISCLAIMER}

Generated by Cyber Shield India on {generated}.
{bar}
"""
