"""Cyber Shield India — Victim Triage & First-Action engine (Feature 1).

Turns a victim's plain-English / Hinglish incident narrative plus structured
telemetry (transaction ids, URLs, phone numbers, hashed evidence) into an
actionable first-response package:

* a threat-vector classification,
* the applicable statutory provisions under the **Bharatiya Nyaya Sanhita
  (BNS), 2023** and the **Information Technology (IT) Act, 2000**,
* step-by-step immediate advisories (Golden-Hour banking-freeze guidance,
  helpline 1930, NCRP portal), and
* a ready-to-send complaint/email body addressed to the Nodal Officer / Cyber
  Cell containing the exact parsed telemetry.

The Gemini call routes through :mod:`services.llm_client` (multi-model cascade,
503/429-safe). If *every* model is unavailable, a fully-deterministic,
keyword-driven classifier produces a genuine — not placeholder — assessment from
the same statutory knowledge base, so the victim is never left without guidance.
"""

import hashlib
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from services.llm_client import invoke_structured

LOGGER: logging.Logger = logging.getLogger("cybershield.victim_triage")

# National Cyber Crime Reporting Portal essentials (static, authoritative).
NCRP_HELPLINE: str = "1930"
NCRP_PORTAL: str = "https://cybercrime.gov.in"
GOLDEN_HOUR_NOTE: str = (
    "Golden Hour rule: report financial fraud to helpline 1930 / "
    f"{NCRP_PORTAL} within the first 60 minutes. A complaint filed before the "
    "money is layered onward lets the bank's nodal officer issue a hold on the "
    "beneficiary account under the RBI / I4C citizen-financial-cyber-fraud "
    "framework — recovery odds fall sharply once funds are withdrawn or split."
)


# --------------------------------------------------------------------------- #
# Structured schema (rendered deterministically in the UI).                   #
# --------------------------------------------------------------------------- #


class LegalProvision(BaseModel):
    """One statutory hook tying the incident to a section of law."""

    statute: str = Field(description="'BNS, 2023' or 'IT Act, 2000'")
    section: str = Field(description="Section number, e.g. 'Section 318(4)'")
    title: str = Field(description="Short title of the offence")
    relevance: str = Field(description="One line: why it applies to this case")


class TriageAssessment(BaseModel):
    """Complete first-action package for a single reported incident."""

    threat_vector: str = Field(description="canonical snake_case vector id")
    vector_label: str = Field(description="human-readable vector name")
    severity: str = Field(description="Low | Medium | High | Critical")
    golden_hour_applicable: bool = Field(
        description="True if money moved and a banking freeze is time-critical")
    summary: str = Field(description="2-3 sentence neutral case summary")
    legal_provisions: List[LegalProvision] = Field(default_factory=list)
    immediate_actions: List[str] = Field(default_factory=list)
    advisories: List[str] = Field(default_factory=list)
    complaint_subject: str = Field(description="email/complaint subject line")
    complaint_body: str = Field(description="full complaint body, ready to send")
    source: str = Field(default="ai-cascade",
                        description="provenance: ai-cascade | deterministic")


# --------------------------------------------------------------------------- #
# Statutory knowledge base — drives both the LLM prompt and the fallback.     #
# --------------------------------------------------------------------------- #

VECTOR_PROFILES: Dict[str, Dict[str, object]] = {
    "upi_financial_fraud": {
        "label": "UPI / Bank-Transfer Financial Fraud",
        "keywords": ["upi", "phonepe", "google pay", "gpay", "paytm", "neft",
                     "imps", "rtgs", "debited", "debit", "bank", "account",
                     "money", "transferred", "refund", "transaction", "wallet"],
        "severity": "High",
        "golden_hour": True,
        "legal": [
            ("BNS, 2023", "Section 318(4)", "Cheating & dishonestly inducing "
             "delivery of property", "Victim was deceived into transferring "
             "funds to the fraudster."),
            ("BNS, 2023", "Section 319(2)", "Cheating by personation",
             "Fraudster impersonated a trusted entity to obtain the transfer."),
            ("IT Act, 2000", "Section 66D", "Cheating by personation using a "
             "computer resource", "Deception executed over a digital channel."),
            ("IT Act, 2000", "Section 66C", "Identity theft",
             "Use of stolen credentials / OTP / payment identifiers."),
        ],
        "actions": [
            "Call 1930 immediately and file at cybercrime.gov.in — quote the "
            "transaction/UTR id so the beneficiary account can be frozen.",
            "Phone your bank's 24x7 fraud line, report the unauthorised debit "
            "and request a transaction dispute + account hold in writing.",
            "Do NOT share any further OTP, CVV, PIN or 'refund' link with anyone.",
            "Preserve SMS debit alerts, UPI reference ids and chat screenshots.",
        ],
        "advisories": [
            GOLDEN_HOUR_NOTE,
            "Banks are bound to acknowledge a digital-fraud dispute; note the "
            "complaint/acknowledgement number for the chargeback trail.",
        ],
    },
    "sim_swap": {
        "label": "SIM Swap / SIM Cloning",
        "keywords": ["sim", "network lost", "no signal", "porting", "otp not "
                     "received", "number deactivated", "sim swap", "esim"],
        "severity": "Critical",
        "golden_hour": True,
        "legal": [
            ("BNS, 2023", "Section 319(2)", "Cheating by personation",
             "Attacker impersonated the victim to the telecom operator."),
            ("IT Act, 2000", "Section 66C", "Identity theft",
             "Hijacking of the victim's mobile identity / OTP channel."),
            ("IT Act, 2000", "Section 66", "Computer-related offences",
             "Dishonest takeover of the victim's authentication factor."),
        ],
        "actions": [
            "Call your telecom operator NOW and demand the rogue SIM be "
            "deactivated and your number restored.",
            "Freeze net-banking and UPI from another device; change all "
            "passwords tied to the compromised number.",
            "File at 1930 / cybercrime.gov.in citing SIM-swap account takeover.",
            "Report the loss of telecom service in writing to create a record.",
        ],
        "advisories": [
            "A sudden, unexplained loss of mobile signal is the classic "
            "SIM-swap tell — treat it as an active attack, not a network fault.",
            GOLDEN_HOUR_NOTE,
        ],
    },
    "sextortion": {
        "label": "Sextortion / Intimate-Image Blackmail",
        "keywords": ["nude", "video call", "blackmail", "extort", "morphed",
                     "obscene", "screen record", "private photo", "leak",
                     "sextortion", "intimate", "threat to share"],
        "severity": "Critical",
        "golden_hour": False,
        "legal": [
            ("BNS, 2023", "Section 308", "Extortion",
             "Threat to release content unless money is paid."),
            ("BNS, 2023", "Section 351", "Criminal intimidation",
             "Threats made to coerce the victim."),
            ("IT Act, 2000", "Section 67", "Publishing/transmitting obscene "
             "material in electronic form", "Threatened or actual circulation "
             "of obscene content."),
            ("IT Act, 2000", "Section 66E", "Violation of privacy",
             "Capture/transmission of private images without consent."),
        ],
        "actions": [
            "Do NOT pay — payment invites escalation, not closure.",
            "Stop all contact but DO NOT delete chats/call logs — they are "
            "evidence. Screenshot the profile, numbers and demands.",
            "Report at 1930 / cybercrime.gov.in and to the platform; use the "
            "NCMEC/StopNCII takedown route if images were shared.",
            "Tighten privacy settings and tell a trusted person — isolation is "
            "the offender's leverage.",
        ],
        "advisories": [
            "Sextortion thrives on shame and urgency; the threat to 'send to "
            "your contacts' is the standard script — reporting breaks it.",
            "Helplines: 1930 (cyber) and 1098 (childline) if a minor is involved.",
        ],
    },
    "investment_scam": {
        "label": "Investment / Trading / Crypto Scam",
        "keywords": ["investment", "trading", "stock tip", "crypto", "bitcoin",
                     "guaranteed return", "double your money", "telegram group",
                     "whatsapp group", "task based", "ponzi", "scheme",
                     "withdrawal blocked", "deposit more"],
        "severity": "High",
        "golden_hour": True,
        "legal": [
            ("BNS, 2023", "Section 318(4)", "Cheating & dishonestly inducing "
             "delivery of property", "Victim lured to 'invest' under false "
             "promises of return."),
            ("BNS, 2023", "Section 316(2)", "Criminal breach of trust",
             "Funds entrusted for investment were misappropriated."),
            ("IT Act, 2000", "Section 66D", "Cheating by personation using a "
             "computer resource", "Fake apps/portals/'managers' used to "
             "execute the fraud."),
        ],
        "actions": [
            "Stop all further deposits immediately — 'pay to withdraw' is the "
            "core trap; you will never recover by paying more.",
            "Capture the app/website URL, the 'relationship manager' numbers, "
            "group links and every transaction id, then file at 1930.",
            "Report the beneficiary accounts so banks can attempt a freeze.",
            "Check SEBI's registered-intermediary list — unregistered = fraud.",
        ],
        "advisories": [
            GOLDEN_HOUR_NOTE,
            "Guaranteed/abnormal returns and 'unlock your profit by paying tax' "
            "messages are definitive scam signatures.",
        ],
    },
    "digital_arrest": {
        "label": "Digital Arrest / Fake Law-Enforcement Scam",
        "keywords": ["digital arrest", "cbi", "police", "customs", "parcel",
                     "courier", "trai", "narcotics", "money laundering",
                     "video call police", "uniform", "warrant", "fedex"],
        "severity": "Critical",
        "golden_hour": True,
        "legal": [
            ("BNS, 2023", "Section 319(2)", "Cheating by personation",
             "Fraudster posed as police/CBI/customs to coerce payment."),
            ("BNS, 2023", "Section 308", "Extortion",
             "Threat of fake arrest used to extract money."),
            ("IT Act, 2000", "Section 66D", "Cheating by personation using a "
             "computer resource", "Fake 'court'/'police' video call used to "
             "defraud the victim."),
        ],
        "actions": [
            "Disconnect — NO Indian agency conducts arrests or interrogations "
            "over video call, and none demands money to 'clear' your name.",
            "Do not transfer any 'verification' or 'security deposit' amount.",
            "If money was already sent, call 1930 instantly for an account "
            "freeze and file at cybercrime.gov.in.",
            "Record the caller numbers, the fake ID cards shown and the app used.",
        ],
        "advisories": [
            "'Digital arrest' is not a legal concept in India — its existence "
            "in the demand is itself proof of fraud.",
            GOLDEN_HOUR_NOTE,
        ],
    },
    "phishing_account_takeover": {
        "label": "Phishing / Credential Theft / Account Takeover",
        "keywords": ["phishing", "link", "login", "password", "credential",
                     "fake website", "email link", "reset", "hacked",
                     "unauthorised login", "spoof", "kyc update", "verify"],
        "severity": "High",
        "golden_hour": False,
        "legal": [
            ("BNS, 2023", "Section 319(2)", "Cheating by personation",
             "Spoofed brand/identity used to harvest credentials."),
            ("IT Act, 2000", "Section 66C", "Identity theft",
             "Dishonest use of the victim's stolen credentials."),
            ("IT Act, 2000", "Section 66", "Computer-related offences",
             "Unauthorised access to the victim's account."),
            ("IT Act, 2000", "Section 43", "Penalty for damage to computer/"
             "data", "Unauthorised access and data extraction."),
        ],
        "actions": [
            "Change the password from a clean device and enable two-factor "
            "authentication on every linked account.",
            "Revoke active sessions / connected apps and update recovery email "
            "+ phone.",
            "Report the phishing URL at 1930 / cybercrime.gov.in and to the "
            "impersonated brand's abuse channel.",
            "Watch for follow-on fraud using the harvested data.",
        ],
        "advisories": [
            "Legitimate banks/brands never ask for full KYC, OTP or passwords "
            "via a link — inspect the real domain before acting.",
        ],
    },
    "job_loan_app": {
        "label": "Fake Job / Loan-App Harassment",
        "keywords": ["job offer", "work from home", "registration fee", "loan "
                     "app", "instant loan", "recovery agent", "harass",
                     "contacts accessed", "abusive call", "interest", "emi",
                     "part time job", "task"],
        "severity": "High",
        "golden_hour": False,
        "legal": [
            ("BNS, 2023", "Section 318(4)", "Cheating & dishonestly inducing "
             "delivery of property", "Advance 'fee'/'registration' taken under "
             "a false job/loan pretext."),
            ("BNS, 2023", "Section 351", "Criminal intimidation",
             "Recovery-agent threats and harassment."),
            ("IT Act, 2000", "Section 66E", "Violation of privacy",
             "Unauthorised access to contacts/gallery for shaming."),
            ("IT Act, 2000", "Section 43", "Penalty for damage to data",
             "Predatory app over-collected and abused device data."),
        ],
        "actions": [
            "Stop paying any 'fee', 'tax' or 'processing' charge.",
            "Uninstall the predatory app and revoke its contacts/storage "
            "permissions; report it on the app store.",
            "Save abusive/threatening messages and caller numbers as evidence.",
            "File at 1930 / cybercrime.gov.in; harassment threats are "
            "separately punishable.",
        ],
        "advisories": [
            "A genuine employer/lender never charges an up-front fee; contact-"
            "list access by a loan app is a harassment red flag.",
        ],
    },
}

# Default profile when nothing matches confidently — still a real assessment.
_GENERIC_VECTOR: str = "general_cyber_fraud"
_GENERIC_PROFILE: Dict[str, object] = {
    "label": "General Cyber Fraud / Online Offence",
    "keywords": [],
    "severity": "Medium",
    "golden_hour": False,
    "legal": [
        ("BNS, 2023", "Section 318(4)", "Cheating & dishonestly inducing "
         "delivery of property", "Dishonest deception causing loss."),
        ("IT Act, 2000", "Section 66D", "Cheating by personation using a "
         "computer resource", "Offence committed through a computer resource."),
        ("IT Act, 2000", "Section 66", "Computer-related offences",
         "Dishonest or fraudulent use of a computer resource."),
    ],
    "actions": [
        "File the incident at 1930 / cybercrime.gov.in with all available "
        "details and identifiers.",
        "Preserve every screenshot, message, URL, number and transaction id.",
        "Do not engage further with the suspect or click any new links.",
        "Inform your bank if any financial credential was exposed.",
    ],
    "advisories": [
        "Report early and preserve evidence intact — chain-of-custody and "
        "timing materially affect investigation and recovery.",
    ],
}


# --------------------------------------------------------------------------- #
# Evidence chain-of-custody.                                                  #
# --------------------------------------------------------------------------- #


def sha256_of_bytes(payload: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of an evidence blob."""
    return hashlib.sha256(payload).hexdigest()


def hash_evidence(filename: str, payload: bytes) -> Dict[str, object]:
    """Build a chain-of-custody record for one uploaded proof file."""
    return {
        "filename": filename,
        "size_bytes": len(payload),
        "sha256": sha256_of_bytes(payload),
        "logged_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


# --------------------------------------------------------------------------- #
# Telemetry parsing (deterministic — never an LLM).                           #
# --------------------------------------------------------------------------- #

_PHONE_RE: re.Pattern = re.compile(r"(?:\+?91[\-\s]?)?[6-9]\d{9}\b")
_URL_RE: re.Pattern = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
_UPI_RE: re.Pattern = re.compile(r"\b[\w.\-]{2,}@[a-zA-Z]{2,}\b")
_TXN_RE: re.Pattern = re.compile(r"\b[A-Z0-9]{10,22}\b")


def extract_telemetry(narrative: str) -> Dict[str, List[str]]:
    """Pull phone numbers, URLs, UPI handles and txn-like ids from free text."""
    phones: List[str] = sorted({m.group(0).strip() for m in _PHONE_RE.finditer(narrative)})
    urls: List[str] = sorted({m.group(0).strip() for m in _URL_RE.finditer(narrative)})
    upi: List[str] = sorted({m.group(0) for m in _UPI_RE.finditer(narrative)
                             if "@" in m.group(0) and "." not in m.group(0).split("@")[-1]})
    # Phone digits (with their country/area prefix stripped) must not masquerade
    # as transaction ids.
    phone_digits: set = {re.sub(r"\D", "", p) for p in phones}
    phone_digits |= {d[-10:] for d in phone_digits if len(d) >= 10}
    txns: List[str] = sorted({m.group(0) for m in _TXN_RE.finditer(narrative)
                              if any(ch.isdigit() for ch in m.group(0))
                              and m.group(0) not in phone_digits})
    return {"phones": phones, "urls": urls, "upi": upi, "transactions": txns}


# --------------------------------------------------------------------------- #
# Deterministic classifier (LLM-independent fallback).                        #
# --------------------------------------------------------------------------- #


def classify_vector(narrative: str) -> str:
    """Keyword-score the narrative against the profile base; return best id."""
    text: str = narrative.lower()
    best_id: str = _GENERIC_VECTOR
    best_score: int = 0
    for vector_id, profile in VECTOR_PROFILES.items():
        keywords: List[str] = profile["keywords"]  # type: ignore[assignment]
        score: int = sum(1 for kw in keywords if kw in text)
        if score > best_score:
            best_score, best_id = score, vector_id
    return best_id


def _profile_for(vector_id: str) -> Dict[str, object]:
    return VECTOR_PROFILES.get(vector_id, _GENERIC_PROFILE)


def _provisions_from(profile: Dict[str, object]) -> List[LegalProvision]:
    return [LegalProvision(statute=s, section=sec, title=t, relevance=r)
            for (s, sec, t, r) in profile["legal"]]  # type: ignore[index]


def _complaint_body(
    vector_label: str, narrative: str, metadata: Dict[str, object],
    telemetry: Dict[str, List[str]],
) -> str:
    """Assemble a real, send-ready complaint body from parsed telemetry."""
    today: str = datetime.now(timezone.utc).strftime("%d %B %Y")
    txn_ids: List[str] = list(dict.fromkeys(
        list(metadata.get("transaction_ids", [])) + telemetry["transactions"]))
    urls: List[str] = list(dict.fromkeys(
        list(metadata.get("urls", [])) + telemetry["urls"]))
    phones: List[str] = list(dict.fromkeys(
        list(metadata.get("phones", [])) + telemetry["phones"]))
    loss: object = metadata.get("amount_lost") or "as detailed in the narrative"

    def _block(label: str, items: List[str]) -> str:
        return (f"{label}:\n" + "\n".join(f"  - {i}" for i in items) + "\n"
                if items else "")

    return (
        f"To,\nThe Nodal Officer / Cyber Crime Cell\n\n"
        f"Date: {today}\n\n"
        f"Subject: Complaint regarding {vector_label} and request for urgent action\n\n"
        f"Respected Sir/Madam,\n\n"
        f"I wish to report that I have been the victim of a {vector_label.lower()}. "
        f"A brief account of the incident is as follows:\n\n"
        f"{narrative.strip()}\n\n"
        f"The approximate financial loss is {loss}.\n\n"
        f"Relevant identifiers captured during the incident are listed below for "
        f"your investigation:\n"
        f"{_block('Suspect phone number(s)', phones)}"
        f"{_block('Transaction / UTR reference(s)', txn_ids)}"
        f"{_block('Malicious URL(s) / handle(s)', urls)}"
        f"\nI request you to kindly register my complaint, initiate freezing of "
        f"the beneficiary account(s) where applicable, and take action against "
        f"the perpetrator(s) under the applicable provisions of the Bharatiya "
        f"Nyaya Sanhita, 2023 and the Information Technology Act, 2000. I have "
        f"preserved all available digital evidence and can produce it on request.\n\n"
        f"I have also lodged this incident on the National Cyber Crime Reporting "
        f"Portal ({NCRP_PORTAL}) / helpline {NCRP_HELPLINE}.\n\n"
        f"Yours faithfully,\n"
        f"{metadata.get('complainant_name') or '[Your Name]'}\n"
        f"{metadata.get('complainant_contact') or '[Your Contact Number / Email]'}"
    )


def _deterministic_assessment(
    narrative: str, metadata: Dict[str, object], telemetry: Dict[str, List[str]],
) -> TriageAssessment:
    """Build a full, genuine assessment without any LLM (cascade exhausted)."""
    vector_id: str = classify_vector(narrative)
    profile: Dict[str, object] = _profile_for(vector_id)
    label: str = str(profile["label"])
    golden: bool = bool(profile["golden_hour"]) or bool(metadata.get("money_lost"))
    summary: str = (
        f"The reported incident is consistent with a {label.lower()}. "
        f"{'Funds appear to have moved, making the banking Golden-Hour window '
           'time-critical. ' if golden else ''}"
        f"Parsed telemetry: {len(telemetry['phones'])} phone number(s), "
        f"{len(telemetry['transactions'])} transaction id(s), "
        f"{len(telemetry['urls'])} URL/handle(s)."
    )
    return TriageAssessment(
        threat_vector=vector_id,
        vector_label=label,
        severity=str(profile["severity"]),
        golden_hour_applicable=golden,
        summary=summary,
        legal_provisions=_provisions_from(profile),
        immediate_actions=list(profile["actions"]),       # type: ignore[arg-type]
        advisories=list(profile["advisories"]),           # type: ignore[arg-type]
        complaint_subject=f"Complaint: {label} — request for urgent action",
        complaint_body=_complaint_body(label, narrative, metadata, telemetry),
        source="deterministic",
    )


# --------------------------------------------------------------------------- #
# Public entry point.                                                         #
# --------------------------------------------------------------------------- #

_SYSTEM_PROMPT: str = (
    "You are a senior Indian cyber-crime first-responder and legal analyst. "
    "Given a victim's incident narrative and parsed telemetry, produce a "
    "precise first-action assessment. Classify the threat vector, set a "
    "severity (Low/Medium/High/Critical), and decide if the banking "
    "Golden-Hour freeze window applies (true only if money moved). Map the "
    "incident to ACCURATE sections of the Bharatiya Nyaya Sanhita (BNS), 2023 "
    "and the Information Technology (IT) Act, 2000 — never cite the repealed "
    "IPC. Give concrete, sequenced immediate_actions and advisories. Draft a "
    "polished complaint_body addressed to the Nodal Officer / Cyber Cell that "
    "embeds the exact telemetry provided. Use ONLY the facts given; never "
    "invent transaction ids, names or amounts."
)


def analyze_incident(
    narrative: str, metadata: Optional[Dict[str, object]] = None,
) -> TriageAssessment:
    """Classify an incident and build its first-action package.

    Routes through the Gemini cascade; on total cascade exhaustion falls back to
    the deterministic, statute-backed classifier so guidance is always returned.
    """
    meta: Dict[str, object] = metadata or {}
    telemetry: Dict[str, List[str]] = extract_telemetry(narrative)
    payload: str = (
        f"INCIDENT NARRATIVE:\n{narrative.strip()}\n\n"
        f"STRUCTURED TELEMETRY (victim-supplied + auto-parsed):\n"
        f"- Transaction IDs: {list(meta.get('transaction_ids', [])) + telemetry['transactions']}\n"
        f"- URLs / handles: {list(meta.get('urls', [])) + telemetry['urls']}\n"
        f"- Phone numbers: {list(meta.get('phones', [])) + telemetry['phones']}\n"
        f"- UPI handles: {telemetry['upi']}\n"
        f"- Amount lost (INR): {meta.get('amount_lost') or 'not stated'}\n"
        f"- Money confirmed moved: {bool(meta.get('money_lost'))}\n"
        f"- Evidence files hashed (chain-of-custody): {meta.get('evidence_count', 0)}\n"
        f"- Complainant: {meta.get('complainant_name') or 'not given'} "
        f"({meta.get('complainant_contact') or 'no contact'})"
    )
    messages = [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=payload)]
    result: Optional[TriageAssessment] = invoke_structured(
        messages, TriageAssessment, origin="victim_triage", temperature=0.2,
    )
    if result is not None:
        result.source = "ai-cascade"
        # Guarantee a usable complaint body even if the model under-fills it.
        if not result.complaint_body.strip():
            result.complaint_body = _complaint_body(
                result.vector_label, narrative, meta, telemetry)
        LOGGER.info("triage: AI assessment vector=%s severity=%s",
                    result.threat_vector, result.severity)
        return result
    LOGGER.warning("triage: cascade exhausted — deterministic fallback engaged")
    return _deterministic_assessment(narrative, meta, telemetry)
