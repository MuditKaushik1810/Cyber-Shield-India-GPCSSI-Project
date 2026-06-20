"""Cyber Shield India — Case-Building & Practice Lab engine (Feature 4).

A fully self-contained forensic training ecosystem. Every artifact an
investigator needs to solve a case lives inside the case object itself — an
exhaustive briefing, the statutory frame, a raw downloadable telemetry artifact,
the embedded-tool selector, and a multi-key ground-truth validation matrix — so
the lab never depends on the other module tabs.

Three subsystems live here:

* **The 10-case baseline battery** — granular, non-truncated mock cases spanning
  Beginner / Intermediate / Advanced, each declaring which embedded mini-tool
  (``EMAIL_DECODER`` / ``CDR_FILTER`` / ``GEOLOCATION_PLOTTER`` /
  ``STRING_SANITIZER``) the workspace should initialise.
* **The :class:`CaseSyncManager` rotation engine** — computes the active
  three-month cycle, attempts to fetch that cycle's case matrix from
  ``REMOTE_LAB_URL``, and on *any* network/parse failure falls back to the local
  baseline battery with a clearly-flagged badge.
* **The deterministic evaluation subsystem** — :func:`sanitize_flag_input` plus
  :func:`validate_matrix`, a strict logical-AND check across every required flag.

The capstone is a **Section 94 Bharatiya Nagarik Suraksha Sanhita (BNSS), 2023**
production notice, drafted by the shared 503/429-safe Gemini cascade
(:mod:`services.llm_client`) with a statute-correct deterministic fallback so the
legally-critical artifact always renders.

Native embedded-tool primitives (Base64/MIME decode, DMS→decimal, indicator
extraction) are implemented here too, keeping the lab a closed ecosystem.
"""

import logging
import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.header import decode_header, make_header
from typing import Dict, List, Optional, Tuple

import httpx
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field, ValidationError

from services.llm_client import invoke_text

LOGGER: logging.Logger = logging.getLogger("cybershield.practice_lab")

# Ordered difficulty ladder.
LEVELS: Tuple[str, str, str] = ("Beginner", "Intermediate", "Advanced")

# The four embedded mini-utilities a case may request inside its workspace.
EMBEDDED_TOOLS: Tuple[str, ...] = (
    "EMAIL_DECODER", "CDR_FILTER", "GEOLOCATION_PLOTTER", "STRING_SANITIZER")

# Remote rotation endpoint (env-overridable). The default host does not resolve,
# so in the absence of a provisioned mirror the sync cleanly degrades to the
# local baseline battery — exactly the designed failure mode.
REMOTE_LAB_URL: str = os.environ.get(
    "REMOTE_LAB_URL",
    "https://grid.cybershield.local/practice_lab/cycle_{cycle}_{year}.json")
_SYNC_TIMEOUT: float = 5.0


# --------------------------------------------------------------------------- #
# Case object schema.                                                          #
# --------------------------------------------------------------------------- #


class LabCase(BaseModel):
    """One fully self-contained mock investigation."""

    case_id: str = Field(description="Unique identification token")
    title: str = Field(description="Domain-specific case nomenclature")
    level: str = Field(description="Beginner | Intermediate | Advanced")
    briefing: str = Field(description="Exhaustive operational narrative")
    statutory_context: str = Field(description="BNS, 2023 / IT-Act section mapping")
    telemetry_dump: str = Field(description="Raw log text rendered in the UI")
    download_url: str = Field(description="Provenance vector for the raw artifact")
    artifact_filename: str = Field(description="Suggested filename for the download")
    embedded_tool_type: str = Field(description="One of EMBEDDED_TOOLS")
    validation_matrix: Dict[str, str] = Field(
        description="Ground-truth forensic flags (key -> exact value)")
    validation_hints: Dict[str, str] = Field(
        default_factory=dict,
        description="Optional analyst-facing label/instruction per flag key")
    target_entity: str = Field(description="Recipient of the Section 94 notice")

    def flag_label(self, key: str) -> str:
        """Return a human label for a validation-matrix key."""
        return self.validation_hints.get(key) or key.replace("_", " ").title()


@dataclass
class LabBattery:
    """The resolved set of active cases plus their provenance."""

    cases: List[LabCase]
    cycle: int
    source: str          # "remote" | "local-baseline"
    is_baseline: bool


# --------------------------------------------------------------------------- #
# The 10-case baseline battery (hardcoded, granular, non-truncated).          #
# --------------------------------------------------------------------------- #

BASELINE_CASES: List[LabCase] = [
    # ----------------------------- BEGINNER ------------------------------- #
    LabCase(
        case_id="CASE-B01",
        title="Operation SIM-Swap Fraud",
        level="Beginner",
        briefing=(
            "At 02:14 hrs a salaried complainant in Pune observed his handset drop "
            "to 'No Service'. Over the next forty minutes three OTP-authenticated "
            "transfers drained ₹4,80,000 from his savings account. The bank "
            "confirms each transfer was validated by a one-time password delivered "
            "to his registered mobile number; the complainant maintains he was "
            "asleep and disclosed nothing. The operating vector is a fraudulent "
            "SIM re-provisioning (SIM-swap): the attacker socially engineered or "
            "bribed a point-of-sale agent to port the victim's MSISDN onto a SIM "
            "under attacker control, thereby intercepting every banking OTP. You "
            "have been handed the carrier's subscriber event log for the victim "
            "MSISDN spanning 21:00 the previous evening to the incident window. "
            "Reconstruct the timeline and prove the swap by isolating the rogue "
            "IMSI that began receiving the OTPs and the specific provisioning "
            "event that effected the swap."),
        statutory_context=(
            "BNS, 2023 §319 (cheating by personation), §318(4) (cheating); "
            "IT Act, 2000 §66C (identity theft), §66D (cheating by personation "
            "using a computer resource)."),
        telemetry_dump=(
            "MSISDN,Event,Timestamp,IMSI,IMEI,Cell Tower ID\n"
            "9822011234,LOCATION_UPDATE,2026-02-11 21:40:03,404201112223334,356938035643809,CGI-PUN-021\n"
            "9822011234,SIM_PROVISION,2026-02-11 02:05:51,404209998887776,860120048221117,CGI-DEL-114\n"
            "9822011234,LOCATION_UPDATE,2026-02-11 02:09:12,404209998887776,860120048221117,CGI-DEL-114\n"
            "9822011234,OTP_SMS_DELIVERED,2026-02-11 02:18:44,404209998887776,860120048221117,CGI-DEL-114\n"
            "9822011234,OTP_SMS_DELIVERED,2026-02-11 02:31:09,404209998887776,860120048221117,CGI-DEL-114"),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-B01_subscriber_log.csv",
        artifact_filename="CASE-B01_subscriber_log.csv",
        embedded_tool_type="CDR_FILTER",
        validation_matrix={
            "rogue_imsi": "404209998887776",
            "swap_event_type": "SIM_PROVISION",
        },
        validation_hints={
            "rogue_imsi": "IMSI of the fraudulently re-provisioned SIM receiving the OTPs",
            "swap_event_type": "The event label in the log that effected the swap",
        },
        target_entity="Nodal Officer, Telecom Operator Alpha (Licensed Service Provider)",
    ),
    LabCase(
        case_id="CASE-B02",
        title="Phishing Email Header Spoof",
        level="Beginner",
        briefing=(
            "An accounts executive at a logistics firm received an 'urgent KYC "
            "re-verification' email purporting to originate from her bank and "
            "followed an embedded link to a credential-harvesting page. She grew "
            "suspicious before submitting anything and escalated the message to "
            "your unit with full headers intact. The operating vector is "
            "credential phishing fronted by sender-domain spoofing. Your task is "
            "to determine whether the sending domain is authenticated (SPF / DKIM "
            "/ DMARC) and to recover the true originating relay IP — the earliest "
            "public Received hop — so the hosting and transit provider can be "
            "served for subscriber attribution. The embedded Email Decoder lets "
            "you decode any Base64 or MIME-encoded fields inline."),
        statutory_context=(
            "BNS, 2023 §319 (personation), §336 (forgery); IT Act, 2000 §66C, "
            "§66D, §43 (unauthorised access / data harvesting)."),
        telemetry_dump=(
            "Return-Path: <alerts@secure-kyc-verify.top>\n"
            "Received: from mx.transit-relay.ru (mx.transit-relay.ru [185.220.101.47])\n"
            "  by mail.victimcorp.in with ESMTPS id 4Z; Wed, 04 Mar 2026 11:22:51 +0530\n"
            "Received: from localhost (localhost [127.0.0.1])\n"
            "  by mx.transit-relay.ru with SMTP id 9K; Wed, 04 Mar 2026 05:52:40 +0000\n"
            "Authentication-Results: mail.victimcorp.in; spf=fail "
            "(sender 185.220.101.47 not permitted) smtp.mailfrom=secure-kyc-verify.top; "
            "dkim=fail; dmarc=fail\n"
            "From: \"HDFC Bank Security\" <alerts@secure-kyc-verify.top>\n"
            "Subject: =?utf-8?B?VXJnZW50OiBSZS12ZXJpZnkgeW91ciBLWUM=?=\n"
            "Message-ID: <8841@secure-kyc-verify.top>"),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-B02_headers.eml",
        artifact_filename="CASE-B02_headers.eml",
        embedded_tool_type="EMAIL_DECODER",
        validation_matrix={
            "originating_ip": "185.220.101.47",
            "spf_result": "fail",
        },
        validation_hints={
            "originating_ip": "True originating relay IP (first public Received hop)",
            "spf_result": "The SPF authentication verdict in Authentication-Results",
        },
        target_entity="Nodal Officer, Hosting / Transit Provider for 185.220.101.47",
    ),
    LabCase(
        case_id="CASE-B03",
        title="UPI Collect-Request Reversal Scam",
        level="Beginner",
        briefing=(
            "A homemaker listed a sofa on an online marketplace. A 'buyer' agreed "
            "instantly and said he would send an advance over UPI. She received an "
            "app notification and approved it, believing she was RECEIVING money — "
            "instead ₹15,000 left her account. The operating vector is a UPI "
            "collect-request (pull) masquerading as a payment (push): approving a "
            "collect request authorises a debit, not a credit. You have the raw "
            "transaction notification payload and the callback link. Establish "
            "that the transaction type was a collect/pull debit and isolate the "
            "beneficiary VPA that pulled the funds. The embedded String Sanitizer "
            "will extract the handles, URLs and indicators from the payload."),
        statutory_context=(
            "BNS, 2023 §318(4) (cheating); IT Act, 2000 §66D (cheating by "
            "personation using a computer resource)."),
        telemetry_dump=(
            "UPI_TXN_TYPE: COLLECT (PULL) REQUEST\n"
            "REQUESTING_VPA: quickbuy-deals@okhdfcbank\n"
            "PAYER_VPA: complainant9920@oksbi\n"
            "AMOUNT: 15000.00 DR\n"
            "REMARK: 'Sofa advance - approve to RECEIVE'\n"
            "CALLBACK_LINK: https://upi-collect-verify.win/approve?vpa=quickbuy-deals@okhdfcbank"),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-B03_upi_payload.txt",
        artifact_filename="CASE-B03_upi_payload.txt",
        embedded_tool_type="STRING_SANITIZER",
        validation_matrix={
            "beneficiary_vpa": "quickbuy-deals@okhdfcbank",
            "txn_type": "COLLECT",
        },
        validation_hints={
            "beneficiary_vpa": "The VPA/UPI handle that pulled the funds",
            "txn_type": "Transaction type proving this was a debit, not a credit",
        },
        target_entity="Grievance Officer, Payment Service Provider (HDFC Bank UPI)",
    ),
    LabCase(
        case_id="CASE-B04",
        title="Geotagged Extortion Image",
        level="Beginner",
        briefing=(
            "A complainant received a threatening message accompanied by a "
            "photograph implying the sender knew her location. The image was "
            "shared as an original file (not a re-encoded screenshot), so its EXIF "
            "metadata survived. The operating vector is intimidation/extortion "
            "leveraging a geotagged image. You have the EXIF GPS block in raw "
            "Degrees-Minutes-Seconds (DMS) form. Convert the DMS rationals to "
            "decimal degrees and plot the capture point so the jurisdiction can be "
            "established. Use the embedded Geolocation Plotter: enter the DMS "
            "components, convert to decimal, and read off the latitude and "
            "longitude to submit as your forensic flags."),
        statutory_context=(
            "BNS, 2023 §308 (extortion), §351 (criminal intimidation); IT Act, "
            "2000 §66E (violation of privacy)."),
        telemetry_dump=(
            "EXIF GPS BLOCK (raw):\n"
            "GPSLatitudeRef: N\n"
            "GPSLatitude: 28 deg 36' 50.04\"\n"
            "GPSLongitudeRef: E\n"
            "GPSLongitude: 77 deg 12' 32.4\"\n"
            "Make: Xiaomi   Model: Redmi Note 12   Software: MIUI 14\n"
            "DateTimeOriginal: 2026:03:22 19:41:07\n"
            "Decimal conversion: DD = Degrees + Minutes/60 + Seconds/3600 "
            "(negate if Ref is S or W)."),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-B04_exif_gps.txt",
        artifact_filename="CASE-B04_exif_gps.txt",
        embedded_tool_type="GEOLOCATION_PLOTTER",
        validation_matrix={
            "latitude": "28.6139",
            "longitude": "77.209",
        },
        validation_hints={
            "latitude": "Decimal latitude from the DMS conversion (4 dp)",
            "longitude": "Decimal longitude from the DMS conversion (3 dp)",
        },
        target_entity="Nodal Officer, Internet Service Provider (subscriber attribution)",
    ),
    # --------------------------- INTERMEDIATE ----------------------------- #
    LabCase(
        case_id="CASE-I01",
        title="BEC Wire Manipulation",
        level="Intermediate",
        briefing=(
            "A mid-size exporter's finance team paid a ₹38,00,000 supplier invoice "
            "to 'updated bank details' supplied over email; the genuine supplier "
            "never received the funds. This is a Business Email Compromise: the "
            "attacker injected a look-alike domain into an existing thread and "
            "silently redirected replies and remittance. The visible From-address "
            "spoofs the genuine supplier domain to defeat a casual glance, while "
            "the Reply-To and Message-ID quietly carry a typosquatted look-alike. "
            "You hold the header of the 'updated-details' message. Prove the "
            "reply-path hijack: identify the look-alike domain and the relay IP "
            "that injected the message. The Email Decoder handles any encoded "
            "fields inline."),
        statutory_context=(
            "BNS, 2023 §318(4) (cheating), §336/§340 (forgery of electronic "
            "record); IT Act, 2000 §66C, §66D."),
        telemetry_dump=(
            "Return-Path: <accounts@supplier-co.com>\n"
            "Received: from smtp.maildiversion.cc (smtp.maildiversion.cc [45.137.21.9])\n"
            "  by mail.exporter.co.in with ESMTPS id 2F; Mon, 13 Apr 2026 16:08:02 +0530\n"
            "Authentication-Results: mail.exporter.co.in; spf=pass "
            "smtp.mailfrom=supplier-co.com; dkim=none; dmarc=none\n"
            "From: \"Supplier Accounts\" <accounts@supplier-co.com>\n"
            "Reply-To: \"Supplier Accounts\" <accounts@suppller-co.com>\n"
            "Subject: RE: Pending PO 7741 - UPDATED bank account for remittance\n"
            "X-Original-Supplier-Domain: supplier-co.com\n"
            "Message-ID: <inv7741@suppller-co.com>"),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-I01_bec_headers.eml",
        artifact_filename="CASE-I01_bec_headers.eml",
        embedded_tool_type="EMAIL_DECODER",
        validation_matrix={
            "lookalike_domain": "suppller-co.com",
            "relay_ip": "45.137.21.9",
        },
        validation_hints={
            "lookalike_domain": "The typosquatted domain in Reply-To / Message-ID",
            "relay_ip": "The relay IP that injected the diverted message",
        },
        target_entity="Grievance Head, Beneficiary Bank Beta (and the look-alike domain registrar)",
    ),
    LabCase(
        case_id="CASE-I02",
        title="Mule Account Layering Network",
        level="Intermediate",
        briefing=(
            "Funds defrauded from a victim were credited to a first-hop account "
            "and, within minutes, fanned out across a layer of accounts before "
            "ATM cash-out — the classic mule-layering pattern. Speed is the tell: "
            "a large inflow liquidated almost entirely within a tiny egress-time "
            "window yields a very high Mule Account Velocity Index. You hold a "
            "transaction ledger snippet. Identify the primary first-hop mule "
            "account that received the victim credit and immediately split it "
            "onward, and confirm the inbound amount, so that account's bank can be "
            "served for KYC and an account hold. The embedded CDR/Ledger Filter "
            "lets you sort and run value-counts across the rows."),
        statutory_context=(
            "BNS, 2023 §318(4), §111 (organised crime — syndicate layering); "
            "IT Act, 2000 §66D; referral under the Prevention of Money "
            "Laundering Act, 2002."),
        telemetry_dump=(
            "Txn ID,From Account,To Account,Amount,Timestamp,Channel\n"
            "T1001,VICTIM-XXXX4412,MULE-A-55012377,250000,2026-05-02 13:01:09,IMPS\n"
            "T1002,MULE-A-55012377,MULE-B-66023188,120000,2026-05-02 13:04:41,IMPS\n"
            "T1003,MULE-A-55012377,MULE-C-77034199,110000,2026-05-02 13:06:55,UPI\n"
            "T1004,MULE-B-66023188,ATM-CASHOUT-DEL,118000,2026-05-02 13:19:02,ATM\n"
            "T1005,MULE-C-77034199,ATM-CASHOUT-MUM,108000,2026-05-02 13:22:37,ATM"),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-I02_ledger.csv",
        artifact_filename="CASE-I02_ledger.csv",
        embedded_tool_type="CDR_FILTER",
        validation_matrix={
            "primary_mule": "MULE-A-55012377",
            "inbound_amount": "250000",
        },
        validation_hints={
            "primary_mule": "First-hop mule account that received the victim credit",
            "inbound_amount": "The inbound victim credit amount (digits only)",
        },
        target_entity="Nodal Officer, Bank Gamma (holding mule account MULE-A-55012377)",
    ),
    LabCase(
        case_id="CASE-I03",
        title="Sideloaded APK — Fake Wedding Invite",
        level="Intermediate",
        briefing=(
            "Victims across a district received a WhatsApp 'wedding invitation' "
            "carrying a .apk attachment. Installing it and granting SMS and "
            "accessibility permissions allowed the malware to silently read "
            "inbound OTPs and exfiltrate them to a command-and-control server on a "
            "fixed beacon interval. The operating vector is mobile malware "
            "distributed by social-engineering sideload. You hold the dropper URL, "
            "the APK hash and the outbound beacon log. Distinguish the dropper "
            "host (where the APK is served) from the exfiltration endpoint (the "
            "C2 the OTPs are POSTed to) and capture the APK SHA-256 for "
            "indicator-sharing. The String Sanitizer extracts the URLs, domains "
            "and hash from the dump."),
        statutory_context=(
            "BNS, 2023 §319, §318(4); IT Act, 2000 §66, §66C, §66D, §43 "
            "(introduction of a computer contaminant)."),
        telemetry_dump=(
            "DROPPER_URL: https://shaadi-invite-card.in/Wedding_Invitation.apk\n"
            "APK_SHA256: 9f2c7b1a44de3c0991aa55ef2210bb77cc8841ee22ff3300aa11bb22cc33dd44\n"
            "REQUESTED_PERMISSIONS: READ_SMS, RECEIVE_SMS, BIND_ACCESSIBILITY_SERVICE\n"
            "OUTBOUND_BEACON: POST https://c2-panel.optatrk.xyz/gate.php?bot=IN&sms=1\n"
            "BEACON_INTERVAL: every 15s exfiltrating inbound SMS/OTP bodies"),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-I03_iocs.txt",
        artifact_filename="CASE-I03_iocs.txt",
        embedded_tool_type="STRING_SANITIZER",
        validation_matrix={
            "c2_domain": "c2-panel.optatrk.xyz",
            "apk_sha256": "9f2c7b1a44de3c0991aa55ef2210bb77cc8841ee22ff3300aa11bb22cc33dd44",
        },
        validation_hints={
            "c2_domain": "The command-and-control host the OTPs are exfiltrated to",
            "apk_sha256": "The APK SHA-256 hash for indicator-sharing",
        },
        target_entity="Nodal Officer, Hosting Provider for c2-panel.optatrk.xyz (CC: CERT-In)",
    ),
    # ----------------------------- ADVANCED ------------------------------- #
    LabCase(
        case_id="CASE-A01",
        title="Coordinated Ransomware Triage",
        level="Advanced",
        briefing=(
            "A hospital's electronic medical records were encrypted overnight and "
            "clinical systems now display a ransom note demanding cryptocurrency. "
            "You are leading triage under acute time pressure: patient care is "
            "degraded and the attacker is on a 72-hour countdown. You hold the "
            "ransom note, the encryptor's appended file extension, the negotiation "
            "portal address and the demanded wallet. While infrastructure "
            "preservation and the Section 70B/CERT-In engagement proceed in "
            "parallel, the immediate financial action is to capture and circulate "
            "the attacker's bitcoin wallet to exchanges and the Financial "
            "Intelligence Unit, and to record the encryptor extension that "
            "fingerprints the locker family. The String Sanitizer isolates the "
            "wallet, onion and extension from the note."),
        statutory_context=(
            "BNS, 2023 §324 (mischief), §308 (extortion), §111 (organised crime); "
            "IT Act, 2000 §66, §66F (cyber terrorism where critical "
            "infrastructure is targeted), §43; referral under §70B."),
        telemetry_dump=(
            "RANSOM_NOTE_FILE: HOW_TO_RESTORE_FILES.txt\n"
            "ENCRYPTED_EXT: .LOCKBITX\n"
            "ENCRYPTOR_PE_TIMESTAMP: 2026-06-01 03:11:00 UTC\n"
            "NEGOTIATION_PORTAL: http://lockbitnegxyz3f5q.onion/login\n"
            "RANSOM_DEMAND: 0.85 BTC within 72h\n"
            "BTC_WALLET: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\n"
            "CONTACT: restore@lockbit-support.cc"),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-A01_ransom_note.txt",
        artifact_filename="CASE-A01_ransom_note.txt",
        embedded_tool_type="STRING_SANITIZER",
        validation_matrix={
            "btc_wallet": "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
            "ransom_extension": ".LOCKBITX",
        },
        validation_hints={
            "btc_wallet": "The attacker BTC wallet to flag to exchanges / FIU",
            "ransom_extension": "The appended extension fingerprinting the locker",
        },
        target_entity="Nodal Officer, ISP Delta (victim ingress) — CC CERT-In / I4C",
    ),
    LabCase(
        case_id="CASE-A02",
        title="Cross-Border Investment Scam Syndicate",
        level="Advanced",
        briefing=(
            "A 'stock advisory' syndicate runs WhatsApp groups funnelling victims "
            "to a polished trading portal that displays fabricated gains and then "
            "blocks withdrawals. Intelligence indicates the portal operates behind "
            "a rotating cluster of mirror domains. You hold WHOIS-style "
            "registration data for the portal and two mirrors. The pivot that ties "
            "the cluster to a single operator is the shared registrant email and "
            "the common fast-flux name server — all three domains are only days "
            "old. Identify the common registrant email and the shared name server "
            "so the registrar can be served and the entire cluster sink-holed. The "
            "String Sanitizer extracts the registrant identifiers from the dump."),
        statutory_context=(
            "BNS, 2023 §318(4), §111 (organised crime), §112 (petty organised "
            "crime); IT Act, 2000 §66D; referral under PMLA, 2002 and FEMA, 1999."),
        telemetry_dump=(
            "DOMAIN: prime-fx-wealth.live\n"
            "  CREATED: 2026-05-20  (age 14 days)   REGISTRAR: ShadowReg LLC\n"
            "  NS: ns1.fastflux-host.cc / ns2.fastflux-host.cc\n"
            "  REGISTRANT_EMAIL: returns-desk@protonmail-burner.cc\n"
            "MIRROR: prime-fx-wealth.click  CREATED 2026-05-21  REGISTRANT returns-desk@protonmail-burner.cc\n"
            "MIRROR: primefx-payouts.top    CREATED 2026-05-22  REGISTRANT returns-desk@protonmail-burner.cc\n"
            "VICTIM_DEPOSIT_GATEWAY: https://prime-fx-wealth.live/wallet/deposit"),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-A02_whois.txt",
        artifact_filename="CASE-A02_whois.txt",
        embedded_tool_type="STRING_SANITIZER",
        validation_matrix={
            "registrant_email": "returns-desk@protonmail-burner.cc",
            "fastflux_nameserver": "ns1.fastflux-host.cc",
        },
        validation_hints={
            "registrant_email": "The common registrant email linking the cluster",
            "fastflux_nameserver": "The shared name server (ns1...) across mirrors",
        },
        target_entity="Domain Registrar ShadowReg LLC (and beneficiary banks of the deposit gateway)",
    ),
    LabCase(
        case_id="CASE-A03",
        title="Deepfake CEO Voice Wire Fraud",
        level="Advanced",
        briefing=(
            "A finance controller received a WhatsApp voice note 'from the CEO' "
            "authorising an urgent ₹1.2 crore transfer to close an acquisition. "
            "The voice was an AI clone. The operating vector is synthetic-media "
            "social engineering: a text-to-speech voice-clone with no genuine "
            "acoustic capture chain. You hold the media metadata for the voice "
            "note and the destination account. The decisive forensic tell is the "
            "synthesis-tool signature embedded in the encoder/creation tags — a "
            "genuine recording would carry a microphone-and-codec capture chain "
            "and room tone, both absent here. Capture the synthesis-tool signature "
            "and the beneficiary account so the bank can be served. The String "
            "Sanitizer surfaces the encoder tag and the account token."),
        statutory_context=(
            "BNS, 2023 §319 (personation), §318(4), §336/§340 (forgery); IT Act, "
            "2000 §66C, §66D, §66E."),
        telemetry_dump=(
            "MEDIA_FILE: ceo_urgent_authorisation.ogg\n"
            "CONTAINER: OGG/Opus   DURATION: 00:00:41\n"
            "ENCODER_TAG: ElevenLabs-TTS v2.3 (voice-clone)\n"
            "CREATION_TOOL: synthesised_audio_pipeline\n"
            "ORIGINAL_RECORDING_DEVICE: <none - no microphone/codec capture chain>\n"
            "BENEFICIARY_ACCOUNT: BANK-EPSILON-AC-99213044\n"
            "NOTE: no acoustic room-tone; spectral floor consistent with TTS synthesis."),
        download_url="https://grid.cybershield.local/lab/artifacts/CASE-A03_media_meta.txt",
        artifact_filename="CASE-A03_media_meta.txt",
        embedded_tool_type="STRING_SANITIZER",
        validation_matrix={
            "synthesis_tool": "ElevenLabs-TTS",
            "beneficiary_account": "BANK-EPSILON-AC-99213044",
        },
        validation_hints={
            "synthesis_tool": "The synthesis-tool signature in the encoder tag",
            "beneficiary_account": "The destination account token",
        },
        target_entity="Grievance Head, Beneficiary Bank Epsilon (account BANK-EPSILON-AC-99213044)",
    ),
]


# --------------------------------------------------------------------------- #
# Dynamic three-month rotation engine.                                        #
# --------------------------------------------------------------------------- #


def current_cycle_id(now: Optional[datetime] = None) -> int:
    """Return the active quarterly cycle id: floor((month - 1) / 3) + 1.

    January–March → 1, April–June → 2, July–September → 3, October–December → 4.
    """
    moment: datetime = now or datetime.now(timezone.utc)
    return math.floor((moment.month - 1) / 3) + 1


class CaseSyncManager:
    """Resolves the active case battery, preferring the remote quarterly mirror."""

    def __init__(self, remote_url: str = REMOTE_LAB_URL,
                 timeout: float = _SYNC_TIMEOUT) -> None:
        self.remote_url: str = remote_url
        self.timeout: float = timeout

    def _remote_endpoint(self, cycle: int, now: datetime) -> str:
        """Interpolate the cycle/year into the configured remote template."""
        try:
            return self.remote_url.format(cycle=cycle, year=now.year)
        except (KeyError, IndexError):
            return self.remote_url

    def load(self, now: Optional[datetime] = None) -> LabBattery:
        """Fetch the active cycle's matrix; fall back to the local baseline.

        Any network, timeout, HTTP, JSON or schema-validation failure is caught,
        logged, and resolved to the bundled 10-case baseline battery so the lab
        is always operational and never blocks on the network.
        """
        moment: datetime = now or datetime.now(timezone.utc)
        cycle: int = current_cycle_id(moment)
        endpoint: str = self._remote_endpoint(cycle, moment)
        try:
            response = httpx.get(endpoint, timeout=self.timeout,
                                 follow_redirects=True)
            response.raise_for_status()
            payload = response.json()
            raw_cases = payload["cases"] if isinstance(payload, dict) else payload
            cases: List[LabCase] = [LabCase.model_validate(item) for item in raw_cases]
            if not cases:
                raise ValueError("remote matrix contained zero cases")
            LOGGER.info("lab sync: loaded %d remote cases for cycle %d",
                        len(cases), cycle)
            return LabBattery(cases=cases, cycle=cycle, source="remote",
                              is_baseline=False)
        except (httpx.HTTPError, ValueError, KeyError, TypeError,
                ValidationError) as exc:
            LOGGER.warning("lab sync: remote cycle %d unavailable (%s) — running "
                           "on local baseline data", cycle, type(exc).__name__)
            return LabBattery(cases=list(BASELINE_CASES), cycle=cycle,
                              source="local-baseline", is_baseline=True)


# --------------------------------------------------------------------------- #
# Deterministic evaluation subsystem.                                         #
# --------------------------------------------------------------------------- #


def sanitize_flag_input(value: str) -> str:
    """Normalise an analyst flag for strict comparison.

    Enforces absolute lowercase, strips surrounding quotes/backticks, removes all
    internal whitespace, and trims stray leading/trailing punctuation — so
    cosmetic format variants ('  185.220.101.47 ', '"FAIL"', 'fail.') all
    collapse to one canonical token, while structural characters
    (``. , : @ - _ /``) are preserved.
    """
    text: str = (value or "").strip().lower()
    text = text.strip("'\"`")
    text = re.sub(r"\s+", "", text)
    text = text.strip(".,;)( ")
    return text


def validate_matrix(case: LabCase, inputs: Dict[str, str]) -> Tuple[bool, Dict[str, bool]]:
    """Strict logical-AND evaluation across every required flag.

    Returns ``(all_passed, per_key_results)``. ``all_passed`` is True only when
    every key in the case's validation matrix is present and matches its
    ground-truth value after sanitisation.
    """
    results: Dict[str, bool] = {}
    for key, ground_truth in case.validation_matrix.items():
        submitted: str = sanitize_flag_input(inputs.get(key, ""))
        results[key] = bool(submitted) and submitted == sanitize_flag_input(ground_truth)
    all_passed: bool = len(results) == len(case.validation_matrix) and all(results.values())
    if all_passed:
        LOGGER.info("lab case %s fully validated", case.case_id)
    return all_passed, results


# --------------------------------------------------------------------------- #
# Native embedded-tool primitives (keep the lab a closed ecosystem).          #
# --------------------------------------------------------------------------- #

_HEADER_TOKEN_RE: re.Pattern = re.compile(
    r"^(Received|From|To|Subject|Return-Path|Authentication-Results|"
    r"Message-ID|DKIM-Signature|Content-Type|MIME-Version)\b",
    re.IGNORECASE | re.MULTILINE)
_B64_CHARSET_RE: re.Pattern = re.compile(r"^[A-Za-z0-9+/=\s]+$")
_MIME_WORD_RE: re.Pattern = re.compile(r"=\?[^?]+\?[BbQq]\?[^?]*\?=")


def _maybe_b64(raw: str) -> Tuple[str, bool]:
    """Auto-detect and decode a Base64 header/EML payload to UTF-8 text."""
    candidate: str = raw.strip()
    if len(candidate) < 16 or _HEADER_TOKEN_RE.search(raw):
        return raw, False
    compact: str = re.sub(r"\s+", "", candidate)
    if len(compact) % 4 != 0 or not _B64_CHARSET_RE.match(candidate):
        return raw, False
    import base64
    import binascii
    try:
        decoded_bytes: bytes = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return raw, False
    try:
        decoded: str = decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        decoded = decoded_bytes.decode("latin-1", "ignore")
    return (decoded, True) if decoded.isprintable() or "\n" in decoded else (raw, False)


def decode_email_blob(raw: str) -> Dict[str, object]:
    """Embedded EMAIL_DECODER primitive: Base64 + RFC 2047 decoding.

    Returns the decoded text plus a list of any MIME encoded-words found and
    their decoded forms.
    """
    text, was_b64 = _maybe_b64(raw)
    encoded_words: List[Tuple[str, str]] = []
    for match in _MIME_WORD_RE.finditer(text):
        word: str = match.group(0)
        try:
            decoded_word: str = str(make_header(decode_header(word)))
        except (UnicodeDecodeError, LookupError, ValueError):
            decoded_word = word
        encoded_words.append((word, decoded_word))
    return {"was_base64": was_b64, "decoded_text": text, "encoded_words": encoded_words}


def dms_to_decimal(degrees: float, minutes: float, seconds: float, ref: str) -> float:
    """Embedded GEOLOCATION_PLOTTER primitive: DMS rationals → decimal degrees."""
    decimal: float = float(degrees) + float(minutes) / 60.0 + float(seconds) / 3600.0
    if str(ref).strip().upper() in {"S", "W"}:
        decimal = -decimal
    return round(decimal, 6)


_INDICATOR_PATTERNS: Dict[str, re.Pattern] = {
    "IPv4 addresses": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "URLs": re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE),
    "Onion services": re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE),
    "Email / VPA handles": re.compile(r"\b[\w.\-]{2,}@[\w.\-]{2,}\b"),
    "Domains": re.compile(
        r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
        r"(?:com|in|net|org|live|click|top|xyz|cc|win|ru|onion)\b", re.IGNORECASE),
    "SHA-256 hashes": re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE),
    "BTC wallets": re.compile(
        r"\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
}


def extract_indicators(text: str) -> Dict[str, List[str]]:
    """Embedded STRING_SANITIZER primitive: pull IOCs out of raw text."""
    found: Dict[str, List[str]] = {}
    for label, pattern in _INDICATOR_PATTERNS.items():
        hits = sorted({match.group(0) for match in pattern.finditer(text)})
        if hits:
            found[label] = hits
    return found


# --------------------------------------------------------------------------- #
# Progression helpers (driven by the session's solved-id set).                #
# --------------------------------------------------------------------------- #

_RANK_LADDER: Tuple[Tuple[int, str], ...] = (
    (10, "Cyber Forensic Inspector (Distinction)"),
    (7, "Cyber Forensic Inspector"),
    (4, "Senior Forensic Investigator"),
    (1, "Cyber Crime Investigator"),
    (0, "Trainee Cyber Analyst"),
)


def rank_title(cleared: int) -> str:
    """Confer a rank from the number of cleared cases this session."""
    for threshold, title in _RANK_LADDER:
        if cleared >= threshold:
            return title
    return _RANK_LADDER[-1][1]


def cases_for_level(battery: LabBattery, level: str) -> List[LabCase]:
    """Return the active battery's cases for one difficulty tier."""
    return [case for case in battery.cases if case.level == level]


# --------------------------------------------------------------------------- #
# Section 94 BNSS legal-notice engine (cascade-safe).                         #
# --------------------------------------------------------------------------- #


_NOTICE_SYSTEM_PROMPT: str = (
    "You are a Cyber Forensic Inspector attached to a Cyber Crime Police Station "
    "in India, drafting a statutory production notice. Draft a complete, "
    "authoritative LEGAL NOTICE UNDER SECTION 94 OF THE BHARATIYA NAGARIK "
    "SURAKSHA SANHITA (BNSS), 2023 — the power to summon production of documents, "
    "electronic records or devices (successor to CrPC Section 91). Requirements:\n"
    "1. Use a formal, authoritative Indian legal-administrative register.\n"
    "2. Open with an official letterhead block: 'OFFICE OF THE INVESTIGATING "
    "OFFICER', the Cyber Crime Police Station, and reference/date lines.\n"
    "3. Leave clearly-marked square-bracket placeholders an officer must fill: "
    "[FIR No. ____], [DD Entry No. ____], [Case/CR No. ____], [Date], "
    "[Officer Name & Rank], [Designation], [Jurisdiction/District], "
    "[Official Seal].\n"
    "4. Address the named TARGET ENTITY precisely.\n"
    "5. Recite a 'WHEREAS' factual preamble drawn ONLY from the case facts and "
    "the investigator's verified forensic flags provided — never invent facts.\n"
    "6. Cite Section 94 BNSS, 2023 as the enabling provision and reference the "
    "supplied statutory context.\n"
    "7. Include a clearly-numbered 'SCHEDULE OF DOCUMENTS / ELECTRONIC RECORDS "
    "REQUIRED TO BE PRODUCED' specific to this case's evidence type.\n"
    "8. Specify a production deadline ([within 7 days]), certified mode of "
    "production, and the duty to preserve records with a Section 63 Bharatiya "
    "Sakshya Adhiniyam (BSA), 2023 certificate for electronic records.\n"
    "9. State the consequence of non-compliance under law.\n"
    "10. Close with the officer signature/seal block (placeholders).\n"
    "Output ONLY the finished notice text — no commentary, no markdown fences."
)


def _evidence_schedule(case: LabCase) -> List[str]:
    """Derive a case-appropriate evidence array keyed on the embedded tool type."""
    common: List[str] = [
        "Complete subscriber / account KYC records (proof of identity and "
        "address) for the entity or identifier named above.",
        "Certified copies of all related electronic records accompanied by a "
        "certificate under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023.",
    ]
    by_tool: Dict[str, List[str]] = {
        "CDR_FILTER": [
            "Call Detail Records (CDR) and IPDR for the identifier for the period "
            "[from ____ to ____], including IMEI, IMSI, cell-tower (CGI) and "
            "first-cell-id data.",
            "SIM allocation / re-provisioning history, point-of-sale activation "
            "records, the activating retailer's KYC, and the full transaction "
            "trail for the account(s) in question.",
        ],
        "EMAIL_DECODER": [
            "Subscriber and login/IP attribution records for the originating "
            "relay/IP, with timestamps in IST and source ports.",
            "Mailbox/domain registration data, recovery identifiers and access "
            "logs for the offending account/domain.",
        ],
        "STRING_SANITIZER": [
            "Domain registrant (WHOIS) data, hosting and name-server records, and "
            "any payment/wallet/account details linked to the identifiers above.",
            "Server access logs, IP allocation and uploader/owner attribution for "
            "the hosted resource for the period [from ____ to ____].",
        ],
        "GEOLOCATION_PLOTTER": [
            "Device, account and subscriber attribution for the identifier(s) "
            "associated with the geotagged artifact.",
            "Upload/transfer logs and originating IP attribution for the media, "
            "and cell-site/Wi-Fi data corroborating the plotted coordinates.",
        ],
    }
    return by_tool.get(case.embedded_tool_type, []) + common


def _deterministic_notice(
    case: LabCase, verified_flags: Dict[str, str], investigation_notes: str,
    officer_name: str, police_station: str, fir_number: str,
) -> str:
    """Statute-correct Section 94 BNSS template (renders when the cascade is down)."""
    today: str = datetime.now(timezone.utc).strftime("%d %B %Y")
    officer: str = officer_name.strip() or "[Officer Name & Rank]"
    station: str = police_station.strip() or "[Cyber Crime Police Station, District]"
    fir: str = fir_number.strip() or "[FIR No. ____ / Year ____]"
    notes: str = investigation_notes.strip() or (
        "Investigation notes to be appended by the Investigating Officer.")
    flags_block: str = "\n".join(
        f"        - {case.flag_label(key)}: {value}"
        for key, value in verified_flags.items()) or "        - (flags on record)"
    schedule: str = "\n".join(
        f"    {i}. {item}" for i, item in enumerate(_evidence_schedule(case), 1))

    return (
        "OFFICE OF THE INVESTIGATING OFFICER\n"
        f"{station}\n"
        "(Constituted under the Bharatiya Nagarik Suraksha Sanhita, 2023)\n"
        "--------------------------------------------------------------------\n"
        f"Reference No.: [CYB/ ____ /{datetime.now(timezone.utc):%Y}]      "
        f"Dated: {today}\n"
        f"FIR / Case No.: {fir}        DD Entry No.: [____]\n\n"
        "To,\n"
        f"    {case.target_entity}\n\n"
        "Subject: NOTICE UNDER SECTION 94 OF THE BHARATIYA NAGARIK SURAKSHA "
        "SANHITA (BNSS), 2023 — PRODUCTION OF DOCUMENTS, ELECTRONIC RECORDS AND "
        "DEVICES.\n\n"
        f"Reference Case: \"{case.title}\" ({case.case_id}).\n"
        f"Statutory context under investigation: {case.statutory_context}\n\n"
        "WHEREAS an investigation is being lawfully conducted by this office into "
        "the above-referenced case, the facts of which are as follows:\n\n"
        f"    {case.briefing}\n\n"
        "AND WHEREAS the following forensic findings have been established on "
        "record by the Investigating Officer:\n"
        f"{flags_block}\n\n"
        "AND WHEREAS the Investigating Officer further records that:\n\n"
        f"    {notes}\n\n"
        "AND WHEREAS the documents and electronic records specified in the "
        "Schedule below are necessary and desirable for the purposes of the said "
        "investigation;\n\n"
        "NOW, THEREFORE, in exercise of the powers conferred under Section 94 of "
        "the Bharatiya Nagarik Suraksha Sanhita, 2023, you are hereby REQUIRED to "
        "produce, or cause to be produced, before the undersigned the following:\n\n"
        "SCHEDULE OF DOCUMENTS / ELECTRONIC RECORDS REQUIRED TO BE PRODUCED:\n"
        f"{schedule}\n\n"
        "The aforesaid records shall be produced within [7 (seven) days] of "
        "receipt of this notice, in a sealed and certified manner, before the "
        f"undersigned at {station}. All electronic records SHALL be accompanied "
        "by a certificate under Section 63 of the Bharatiya Sakshya Adhiniyam, "
        "2023, failing which their admissibility may stand vitiated, and you are "
        "directed to PRESERVE the said records and to refrain from their "
        "deletion, alteration or destruction pending this investigation.\n\n"
        "TAKE NOTICE that failure to comply with this lawful requisition without "
        "reasonable cause shall render you liable for the consequences provided "
        "under the Bharatiya Nyaya Sanhita, 2023 (including Sections 209 and 223) "
        "and shall be deemed obstruction of a lawful investigation, in addition "
        "to such other action as may be warranted in law.\n\n"
        "Issued under my hand and seal on this day.\n\n"
        f"    ( {officer} )\n"
        "    Investigating Officer / [Designation]\n"
        f"    {station}\n"
        "    [Jurisdiction / District]        [Official Seal]\n"
    )


def generate_section94_notice(
    case: LabCase, verified_flags: Dict[str, str], investigation_notes: str = "", *,
    officer_name: str = "", police_station: str = "", fir_number: str = "",
) -> Tuple[str, str]:
    """Draft a Section 94 BNSS production notice for a solved case (cascade-safe).

    Returns ``(notice_text, source)`` where source is ``"ai-cascade"`` or
    ``"deterministic"``. The deterministic template is statute-correct and is
    used whenever every cascade model is unavailable.
    """
    flags_text: str = "\n".join(f"- {case.flag_label(k)}: {v}"
                                for k, v in verified_flags.items())
    payload: str = (
        f"CASE ID: {case.case_id}\n"
        f"CASE TITLE: {case.title}\n"
        f"DIFFICULTY TIER: {case.level}\n"
        f"TARGET ENTITY (recipient of the notice): {case.target_entity}\n"
        f"STATUTORY CONTEXT: {case.statutory_context}\n"
        f"EVIDENCE TYPE (embedded tool): {case.embedded_tool_type}\n\n"
        f"CASE BRIEFING (facts):\n{case.briefing}\n\n"
        f"VERIFIED FORENSIC FLAGS (established on record):\n{flags_text}\n\n"
        f"RAW TELEMETRY ON RECORD:\n{case.telemetry_dump}\n\n"
        f"INVESTIGATING OFFICER'S NOTES:\n"
        f"{investigation_notes.strip() or '(none supplied)'}\n\n"
        f"OFFICER NAME/RANK: {officer_name.strip() or '[leave placeholder]'}\n"
        f"POLICE STATION: {police_station.strip() or '[leave placeholder]'}\n"
        f"FIR NUMBER: {fir_number.strip() or '[leave placeholder]'}\n\n"
        "Draft the complete Section 94 BNSS, 2023 production notice now."
    )
    messages = [
        SystemMessage(content=_NOTICE_SYSTEM_PROMPT),
        HumanMessage(content=payload),
    ]
    notice: str = invoke_text(messages, origin="practice_lab", temperature=0.2)
    if notice.strip():
        LOGGER.info("lab notice generated via cascade for %s", case.case_id)
        return notice, "ai-cascade"
    LOGGER.warning("lab notice: cascade exhausted for %s — deterministic template",
                   case.case_id)
    return _deterministic_notice(
        case, verified_flags, investigation_notes, officer_name, police_station,
        fir_number), "deterministic"
