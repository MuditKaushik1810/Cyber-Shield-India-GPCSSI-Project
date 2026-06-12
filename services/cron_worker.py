"""Cyber Shield India — Background Data Harvest Pipelines (STATUS.md Step 6.1).

Continuous background execution loop framework built on ``asyncio`` sleep
patterns that simulates a live harvest of public Indian digital-policing
threat indices — CERT-In vulnerability bulletins and MHA Cyberdost warnings.

Each cycle the worker synthesizes a realistic raw bulletin payload (rotating
threat vectors, jurisdictions, CVE identifiers, and fresh mule indicators),
pipes it through the live gateway via ``POST /api/v1/ingest/text`` over an
``httpx.AsyncClient``, and probes the analytical endpoints afterwards to
verify the relational and vector tiers updated dynamically without
destabilizing the serving process.

The transport is injectable: production runs ride real HTTP to
``http://localhost:8000``; the Phase 6 system suite mounts the FastAPI app
in-process through ``httpx.ASGITransport``. Unified automation telemetry
rotates daily into ``logs/automation.log``.

Run standalone (gateway must be live):  python -m services.cron_worker
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import httpx

# --------------------------------------------------------------------------- #
# Unified automation telemetry — daily-rotating: logs/automation.log.         #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"


def _build_logger() -> logging.Logger:
    """Construct the automation logger with a midnight-rotating handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.automation")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "automation.log",
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
# Bulletin simulation — rotating CERT-In / Cyberdost style payloads.          #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class BulletinTemplate:
    """One rotating threat-index template for the harvest simulator."""

    agency: str
    vector: str
    body: str  # format slots: {cycle}, {city}, {handle}, {phone}, {stamp}


BULLETIN_TEMPLATES: Tuple[BulletinTemplate, ...] = (
    BulletinTemplate(
        agency="cert-in",
        vector="apk_sideloading",
        body=(
            "CERT-In Vulnerability Bulletin (cycle {cycle}, issued {stamp}): "
            "a malicious Android APK campaign distributing fake wedding "
            "invitation packages over WhatsApp has been observed targeting "
            "users in {city}. The trojan, tracked alongside CVE-2026-21443, "
            "abuses accessibility permissions to intercept OTP messages and "
            "stage unauthorized UPI collect requests routed to the mule "
            "handle {handle}. Severity is rated HIGH. Users must disable "
            "installation from unknown sources, audit accessibility access, "
            "and apply the current Android security patch level immediately."
        ),
    ),
    BulletinTemplate(
        agency="cyberdost",
        vector="digital_arrest",
        body=(
            "MHA Cyberdost Public Warning (cycle {cycle}, issued {stamp}): "
            "citizens in {city} are reporting 'digital arrest' video calls "
            "from impostors posing as CBI and customs officers over spoofed "
            "VoIP gateways. Victims are coerced into transferring funds to "
            "{handle} for fake 'verification', with callbacks from {phone}. "
            "This operation is classified CRITICAL severity. No Indian "
            "agency conducts arrests over video calls — disconnect at once "
            "and report to the 1930 national cyber helpline."
        ),
    ),
    BulletinTemplate(
        agency="cert-in",
        vector="payment_fraud",
        body=(
            "CERT-In Advisory Note (cycle {cycle}, issued {stamp}): an "
            "organised QR-code payment fraud ring active in {city} is "
            "staging fraudulent UPI collect requests against small "
            "merchants. Proceeds aggregate through the mule handle {handle} "
            "before rapid egress to layered accounts, with coordination "
            "numbers including {phone}. Severity is rated HIGH. Merchants "
            "must verify every collect request and report suspicious "
            "transactions to their bank and cybercrime.gov.in within the "
            "golden hour."
        ),
    ),
)

HARVEST_CITIES: Tuple[str, ...] = (
    "Faridabad", "Hyderabad", "Bengaluru", "Mumbai", "Gurugram", "Jamtara",
)


def synthesize_bulletin(cycle: int) -> Tuple[str, str]:
    """Build one realistic raw bulletin for a harvest cycle.

    Returns (bulletin_text, source_agency). Indicators rotate per cycle so
    every harvest contributes fresh entities to the live stores.
    """
    template: BulletinTemplate = BULLETIN_TEMPLATES[cycle % len(BULLETIN_TEMPLATES)]
    text: str = template.body.format(
        cycle=cycle,
        city=HARVEST_CITIES[cycle % len(HARVEST_CITIES)],
        handle=f"mule{cycle:03d}@okfraud",
        phone=f"98{cycle:08d}"[:10],
        stamp=datetime.now(timezone.utc).strftime("%d %B %Y"),
    )
    return text, template.agency


# --------------------------------------------------------------------------- #
# Background harvest worker.                                                  #
# --------------------------------------------------------------------------- #

DEFAULT_GATEWAY_BASE: str = "http://localhost:8000/api/v1"
DEFAULT_INTERVAL_SECONDS: float = 900.0  # 15-minute production cadence
HARVEST_TIMEOUT_SECONDS: float = 240.0


class CronWorker:
    """Continuous asyncio harvest loop feeding the live ingestion gateway."""

    def __init__(
        self,
        gateway_base: str = DEFAULT_GATEWAY_BASE,
        interval_seconds: float = DEFAULT_INTERVAL_SECONDS,
        max_cycles: Optional[int] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        self.gateway_base: str = gateway_base.rstrip("/")
        self.interval_seconds: float = interval_seconds
        self.max_cycles: Optional[int] = max_cycles
        self._transport: Optional[httpx.AsyncBaseTransport] = transport
        self.cycles_completed: int = 0

    def _make_client(self) -> httpx.AsyncClient:
        """Build the async client (real network or injected ASGI transport)."""
        return httpx.AsyncClient(
            transport=self._transport,
            timeout=HARVEST_TIMEOUT_SECONDS,
        )

    async def harvest_once(
        self, client: httpx.AsyncClient, cycle: int
    ) -> Optional[Dict[str, object]]:
        """Run one harvest cycle: synthesize → ingest → verify liveness."""
        bulletin_text: str
        agency: str
        bulletin_text, agency = synthesize_bulletin(cycle)
        try:
            response: httpx.Response = await client.post(
                f"{self.gateway_base}/ingest/text",
                json={
                    "text": bulletin_text,
                    "origin": f"cron-cycle-{cycle}",
                    "source": f"{agency}-cron",
                    "url": f"https://cron.local/{agency}/bulletin-{cycle}",
                },
            )
        except httpx.ConnectError:
            LOGGER.error("cycle %d: gateway unreachable — harvest skipped", cycle)
            return None
        except httpx.TimeoutException:
            LOGGER.error("cycle %d: harvest timed out", cycle)
            return None
        if response.status_code != 201:
            LOGGER.error("cycle %d: gateway rejected bulletin (HTTP %d)",
                         cycle, response.status_code)
            return None
        try:
            manifest: Dict[str, object] = response.json()
        except ValueError:
            LOGGER.exception("cycle %d: unparseable ingest manifest", cycle)
            return None

        # Liveness probe: the analytical tier must answer immediately after
        # the write — a dynamic update with zero server destabilization.
        try:
            probe: httpx.Response = await client.get(
                f"{self.gateway_base}/analytics/mavi"
            )
            probe.raise_for_status()
            probe_body: Dict[str, object] = probe.json()
        except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError):
            LOGGER.exception("cycle %d: post-harvest analytics probe failed", cycle)
            return None
        except ValueError:
            LOGGER.exception("cycle %d: unparseable analytics probe body", cycle)
            return None

        LOGGER.info(
            "cycle %d [%s]: ingested incidents=%s entities=%s chunks=%s | "
            "live MAVI=%.2f (%s) over %s incidents",
            cycle, agency,
            manifest.get("incidents_inserted"),
            manifest.get("entities_upserted"),
            manifest.get("chunks_committed"),
            float(probe_body.get("mavi_score", 0.0)),  # type: ignore[arg-type]
            probe_body.get("threat_level"),
            probe_body.get("incident_count"),
        )
        return manifest

    async def run(self) -> List[Dict[str, object]]:
        """Execute the harvest loop; returns every successful manifest.

        Runs until ``max_cycles`` completes (or forever when None). A
        cancellation request drains gracefully — no harvest is left
        half-committed because each cycle awaits its full round trip.
        """
        manifests: List[Dict[str, object]] = []
        cycle: int = 0
        LOGGER.info(
            "Harvest loop online: gateway=%s interval=%.1fs max_cycles=%s",
            self.gateway_base, self.interval_seconds, self.max_cycles,
        )
        try:
            async with self._make_client() as client:
                while self.max_cycles is None or cycle < self.max_cycles:
                    manifest: Optional[Dict[str, object]] = await self.harvest_once(
                        client, cycle
                    )
                    if manifest is not None:
                        manifests.append(manifest)
                        self.cycles_completed += 1
                    cycle += 1
                    if self.max_cycles is not None and cycle >= self.max_cycles:
                        break
                    await asyncio.sleep(self.interval_seconds)
        except asyncio.CancelledError:
            LOGGER.info("Harvest loop cancelled after %d completed cycles",
                        self.cycles_completed)
            raise
        LOGGER.info("Harvest loop drained: %d/%d cycles successful",
                    self.cycles_completed, cycle)
        return manifests


if __name__ == "__main__":
    asyncio.run(CronWorker().run())
