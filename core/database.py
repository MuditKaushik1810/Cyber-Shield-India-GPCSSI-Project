"""Cyber Shield India — Dual-Tier Persistence Layer (STATUS.md Steps 2.1 & 2.2).

**Vector Tier (Step 2.1).** A ``chromadb.PersistentClient`` matrix anchored
under the protected ``data/chroma_store`` path with two cosine-similarity
collections:

* ``threat_intel_chunks`` — semantic analysis of scraper documents and
  CERT-In advisories (Phase 2.1 metadata: source, url, date_published,
  jurisdiction, threat_category).
* ``expert_feed_chunks`` — streaming triage and cross-referencing of
  tactical advice from verified expert channels.

Embeddings ride Chroma's native default embedding component, which is the
ONNX build of HuggingFace ``all-MiniLM-L6-v2`` — the exact open-source
model mandated by CLAUDE.md.

**Relational Tier (Step 2.2).** An asynchronous ``aiosqlite`` engine
compiling eight normalized tables: the four core tracking tables
(``incidents``, ``entities``, ``tactics``, ``expert_advisories``) plus the
four analytical tables consumed by Phase 3 analytics and the Phase 5
dashboard (``historical_ncrb_cases``, ``i4c_financial_metrics``,
``demographic_risk_profiles``, ``apprehension_ledger``). The ``tactics``
table is seeded with the 7-vector detection lattice shared with
``services/expert_feed.py``.

Every connection is opened via ``async with``; every transaction catches
``aiosqlite.Error`` explicitly and rolls back before re-raising. Forensic
traces rotate daily into ``logs/database.log``.
"""

import asyncio
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Dict, List, Tuple

import aiosqlite
import chromadb
from chromadb.api.models.Collection import Collection
from chromadb.utils import embedding_functions

# --------------------------------------------------------------------------- #
# Forensic logging — dedicated daily-rotating channel: logs/database.log.     #
# --------------------------------------------------------------------------- #

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
LOG_DIR: Path = PROJECT_ROOT / "logs"

DATA_DIR: Path = PROJECT_ROOT / "data"
SQLITE_PATH: Path = DATA_DIR / "cyber_shield.sqlite3"
CHROMA_PERSIST_DIR: Path = DATA_DIR / "chroma_store"


def _build_logger() -> logging.Logger:
    """Construct the database logger with a midnight-rotating file handler."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger: logging.Logger = logging.getLogger("cybershield.database")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    formatter: logging.Formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    )
    file_handler: TimedRotatingFileHandler = TimedRotatingFileHandler(
        filename=LOG_DIR / "database.log",
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
# Step 2.1 — ChromaDB vector persistence matrix.                              #
# --------------------------------------------------------------------------- #

# Collection name -> descriptive metadata. ``hnsw:space: cosine`` pins both
# collections to cosine similarity for semantic retrieval.
VECTOR_COLLECTION_SPECS: Dict[str, Dict[str, str]] = {
    "threat_intel_chunks": {
        "hnsw:space": "cosine",
        "description": (
            "Semantic analysis space for multi-agency scraper documents "
            "and CERT-In vulnerability advisories."
        ),
    },
    "expert_feed_chunks": {
        "hnsw:space": "cosine",
        "description": (
            "Streaming triage space cross-referencing tactical advisories "
            "from verified digital policing experts."
        ),
    },
    "research_corpus": {
        "hnsw:space": "cosine",
        "description": (
            "Open-access research corpus: high-density text chunks from the "
            "autonomous ingestion worker, each mapped back to its "
            "fraud_records.id for clean source attribution during RAG."
        ),
    },
}


class VectorStoreManager:
    """Manages the ChromaDB persistence matrix and its two collections."""

    def __init__(self, persist_directory: Path = CHROMA_PERSIST_DIR) -> None:
        self.persist_directory: Path = persist_directory
        self._client: chromadb.api.ClientAPI = None  # type: ignore[assignment]

    @property
    def client(self) -> chromadb.api.ClientAPI:
        """Lazily construct the persistent client under the protected path."""
        if self._client is None:
            self.persist_directory.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=str(self.persist_directory)
            )
            LOGGER.info("ChromaDB persistent client anchored at %s",
                        self.persist_directory)
        return self._client

    @staticmethod
    def embedding_function() -> embedding_functions.DefaultEmbeddingFunction:
        """Chroma's native default embedder: ONNX all-MiniLM-L6-v2."""
        return embedding_functions.DefaultEmbeddingFunction()

    def get_collection(self, name: str) -> Collection:
        """Fetch-or-create one configured collection by name."""
        if name not in VECTOR_COLLECTION_SPECS:
            raise KeyError(f"Unknown vector collection requested: {name}")
        return self.client.get_or_create_collection(
            name=name,
            metadata=VECTOR_COLLECTION_SPECS[name],
            embedding_function=self.embedding_function(),
        )

    def init_collections(self) -> List[str]:
        """Instantiate every configured collection and report their names."""
        created: List[str] = []
        for name in VECTOR_COLLECTION_SPECS:
            collection: Collection = self.get_collection(name)
            created.append(collection.name)
            LOGGER.info(
                "Vector collection ready: %s (space=%s, count=%d)",
                collection.name,
                VECTOR_COLLECTION_SPECS[name]["hnsw:space"],
                collection.count(),
            )
        return created


# --------------------------------------------------------------------------- #
# Step 2.2 — aiosqlite relational schema compilation.                         #
# --------------------------------------------------------------------------- #

SCHEMA_DDL: Tuple[str, ...] = (
    # -- Core tracking tables ------------------------------------------------
    """
    CREATE TABLE IF NOT EXISTS incidents (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        title           TEXT    NOT NULL,
        source          TEXT    NOT NULL,
        url             TEXT,
        date_published  TEXT,
        threat_category TEXT    NOT NULL,
        jurisdiction    TEXT    NOT NULL DEFAULT 'National',
        severity        TEXT    CHECK (severity IS NULL OR
                                       severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
        created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
        UNIQUE (title, url)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS entities (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        entity_type TEXT    NOT NULL CHECK (entity_type IN
                        ('phone','upi_id','bank_account','imei','url',
                         'email','app_package','ip_address','crypto_wallet',
                         'aadhaar_masked')),
        value       TEXT    NOT NULL,
        risk_score  REAL    NOT NULL DEFAULT 0.0
                            CHECK (risk_score >= 0.0 AND risk_score <= 100.0),
        first_seen  TEXT    NOT NULL DEFAULT (datetime('now')),
        last_seen   TEXT    NOT NULL DEFAULT (datetime('now')),
        UNIQUE (entity_type, value)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS tactics (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        tactic_name         TEXT    NOT NULL UNIQUE,
        description         TEXT    NOT NULL,
        mitigation_strategy TEXT    NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS expert_advisories (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        expert_name   TEXT    NOT NULL,
        advisory_text TEXT    NOT NULL,
        target_vector TEXT    NOT NULL REFERENCES tactics (tactic_name),
        cve_id        TEXT,
        created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    )
    """,
    # -- Analytical tables (STATUS.md Step 2.2 ledger set) --------------------
    """
    CREATE TABLE IF NOT EXISTS historical_ncrb_cases (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        state            TEXT    NOT NULL,
        year             INTEGER NOT NULL CHECK (year >= 2000),
        category         TEXT    NOT NULL,
        incidents        INTEGER NOT NULL DEFAULT 0,
        convictions      INTEGER NOT NULL DEFAULT 0,
        chargesheet_rate REAL    CHECK (chargesheet_rate IS NULL OR
                                        (chargesheet_rate >= 0.0 AND
                                         chargesheet_rate <= 100.0)),
        UNIQUE (state, year, category)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS i4c_financial_metrics (
        id                INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp         TEXT    NOT NULL,
        incurred_loss     REAL    NOT NULL DEFAULT 0.0,
        prevented_capital REAL    NOT NULL DEFAULT 0.0,
        recovery_ratio    REAL    CHECK (recovery_ratio IS NULL OR
                                         (recovery_ratio >= 0.0 AND
                                          recovery_ratio <= 1.0))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS demographic_risk_profiles (
        id                       INTEGER PRIMARY KEY AUTOINCREMENT,
        age_group                TEXT NOT NULL,
        gender                   TEXT NOT NULL,
        geographic_tier          TEXT NOT NULL,
        occupation               TEXT NOT NULL,
        dominant_modus_operandi  TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS apprehension_ledger (
        arrest_id        INTEGER PRIMARY KEY AUTOINCREMENT,
        date             TEXT    NOT NULL,
        state            TEXT    NOT NULL,
        enforcement_unit TEXT    NOT NULL,
        criminals_caught INTEGER NOT NULL DEFAULT 0,
        scam_type        TEXT    NOT NULL
    )
    """,
    # -- Open-access research repository (autonomous ingestion worker) --------
    # One row per AI-synthesized document extract. Raw chunks live in the
    # ChromaDB ``research_corpus`` collection, keyed by this table's id.
    """
    CREATE TABLE IF NOT EXISTS fraud_records (
        id                            INTEGER PRIMARY KEY AUTOINCREMENT,
        source_platform               TEXT    NOT NULL,
        source_tier                   TEXT    NOT NULL DEFAULT 'dynamic'
                                          CHECK (source_tier IN ('static','dynamic','demo')),
        publish_timestamp             TEXT,
        state                         TEXT,
        city                          TEXT,
        scam_vector_type              TEXT,
        -- Unified threat-domain taxonomy (financial + non-financial).
        threat_domain                 TEXT    NOT NULL DEFAULT 'Financial Fraud',
        extracted_case_count          INTEGER NOT NULL DEFAULT 0,
        financial_loss_inr            REAL    NOT NULL DEFAULT 0.0,
        -- Optional non-monetary impact metrics (nullable; never break the
        -- existing financial summaries).
        records_exposed               INTEGER,
        incident_count                INTEGER,
        compromised_assets            TEXT,
        target_sector                 TEXT,
        severity_level                TEXT,
        -- Temporal classification (Phase 2): isolated case vs macro summary.
        is_isolated_incident          INTEGER NOT NULL DEFAULT 1,
        incident_loss_inr             REAL    NOT NULL DEFAULT 0.0,
        is_macro_historical_summary   INTEGER NOT NULL DEFAULT 0,
        macro_summary_loss_inr        REAL    NOT NULL DEFAULT 0.0,
        demographic_age_bracket       TEXT,
        demographic_gender_ratio      TEXT,
        demographic_profession_target TEXT,
        official_safety_advisory      TEXT,
        source_url                    TEXT,
        content_hash                  TEXT    UNIQUE,
        ingested_at                   TEXT    NOT NULL DEFAULT (datetime('now'))
    )
    """,
    # -- National NCRB baseline model (Phase 1) ------------------------------
    # Approximate annualized 'Crime in India' anchors per state/UT, used as a
    # prorated statistical floor so the frontend never shows a baseline zero.
    """
    CREATE TABLE IF NOT EXISTS state_baselines (
        id                       INTEGER PRIMARY KEY AUTOINCREMENT,
        state_name               TEXT    NOT NULL UNIQUE,
        annual_cases             INTEGER NOT NULL DEFAULT 0,
        annual_loss_inr          REAL    NOT NULL DEFAULT 0.0,
        prorated_weekly_cases    REAL    NOT NULL DEFAULT 0.0,
        prorated_weekly_loss_inr REAL    NOT NULL DEFAULT 0.0,
        primary_vector           TEXT    NOT NULL DEFAULT 'UPI Payment Fraud'
    )
    """,
)

INDEX_DDL: Tuple[str, ...] = (
    "CREATE INDEX IF NOT EXISTS idx_incidents_category ON incidents (threat_category)",
    "CREATE INDEX IF NOT EXISTS idx_incidents_date ON incidents (date_published)",
    "CREATE INDEX IF NOT EXISTS idx_entities_type ON entities (entity_type)",
    "CREATE INDEX IF NOT EXISTS idx_advisories_vector ON expert_advisories (target_vector)",
    "CREATE INDEX IF NOT EXISTS idx_ncrb_state_year ON historical_ncrb_cases (state, year)",
    "CREATE INDEX IF NOT EXISTS idx_i4c_timestamp ON i4c_financial_metrics (timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_apprehension_state ON apprehension_ledger (state)",
    "CREATE INDEX IF NOT EXISTS idx_fraud_state ON fraud_records (state)",
    "CREATE INDEX IF NOT EXISTS idx_fraud_vector ON fraud_records (scam_vector_type)",
    "CREATE INDEX IF NOT EXISTS idx_fraud_published ON fraud_records (publish_timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_fraud_tier ON fraud_records (source_tier)",
    "CREATE INDEX IF NOT EXISTS idx_fraud_isolated ON fraud_records (is_isolated_incident)",
    "CREATE INDEX IF NOT EXISTS idx_fraud_domain ON fraud_records (threat_domain)",
    "CREATE INDEX IF NOT EXISTS idx_baseline_state ON state_baselines (state_name)",
)

EXPECTED_TABLES: Tuple[str, ...] = (
    "incidents",
    "entities",
    "tactics",
    "expert_advisories",
    "historical_ncrb_cases",
    "i4c_financial_metrics",
    "demographic_risk_profiles",
    "apprehension_ledger",
    "fraud_records",
    "state_baselines",
)

# Seed rows mapping the 7-vector tactic lattice (services/expert_feed.py).
TACTIC_SEED_ROWS: Tuple[Tuple[str, str, str], ...] = (
    (
        "digital_arrest",
        "Remote coercion scam: victims held in fake video-call custody by "
        "impersonated CBI/police/customs officials over virtual gateways.",
        "Never accept video-call interrogation; verify via 1930 helpline; "
        "no agency conducts arrest or fund verification over video calls.",
    ),
    (
        "apk_sideloading",
        "Malicious Android APKs delivered as fake wedding invites, courier "
        "notices, or bank utilities via messaging platforms.",
        "Block installs from unknown sources; never open APK attachments; "
        "verify apps only through official stores.",
    ),
    (
        "accessibility_exploit",
        "Trojan abuse of Android accessibility APIs to read screens, "
        "capture OTPs, and automate fraudulent UPI flows.",
        "Audit accessibility permissions; revoke for non-system apps; "
        "apply current Android security patch levels.",
    ),
    (
        "voip_spoofing",
        "Spoofed VoIP/WhatsApp call arrays masking international fraud "
        "operations behind Indian caller identities.",
        "Treat +countrycode unknown video calls as hostile; report headers "
        "via Sanchar Saathi Chakshu; never share OTP on inbound calls.",
    ),
    (
        "sim_impersonation",
        "SIM swap and cloning operations intercepting OTP channels to "
        "hijack banking and UPI credentials.",
        "Lock SIM with carrier PIN; monitor TAFCOP for connections issued "
        "in your name; act on sudden signal loss immediately.",
    ),
    (
        "payment_fraud",
        "UPI/AePS rail abuse: mule account chains, QR-code lures, and "
        "fraudulent collect requests draining victim accounts.",
        "Verify collect requests before approval; never scan QR codes to "
        "*receive* money; report within golden hour to 1930.",
    ),
    (
        "investment_scam",
        "Ponzi/task/crypto trading app frauds with staged early payouts "
        "leading to large terminal losses (pig butchering).",
        "Verify platforms against SEBI/RBI registries; treat guaranteed "
        "returns as fraud signals; never escalate deposits to 'unlock' funds.",
    ),
)


# National NCRB baseline model (Phase 1) — (state, annual_cases, primary_vector).
# Approximate 'Crime in India' cyber-case anchors covering all 28 states + 8 UTs
# so no jurisdiction ever renders a baseline zero. Loss is modelled at a flat
# per-case average; values are an illustrative baseline, not exact NCRB figures.
_AVG_LOSS_PER_CASE_INR: float = 250_000.0

_STATE_BASELINE_ANCHORS: Tuple[Tuple[str, int, str], ...] = (
    ("Karnataka", 21_800, "UPI Payment Fraud"),
    ("Telangana", 18_200, "Digital Arrest"),
    ("Uttar Pradesh", 10_700, "Phishing"),
    ("Maharashtra", 8_100, "Investment Scam"),
    ("Tamil Nadu", 4_100, "UPI Payment Fraud"),
    ("Rajasthan", 3_800, "SIM Swap"),
    ("Gujarat", 3_600, "Investment Scam"),
    ("Madhya Pradesh", 3_200, "UPI Payment Fraud"),
    ("Haryana", 2_900, "Digital Arrest"),
    ("Andhra Pradesh", 2_700, "UPI Payment Fraud"),
    ("West Bengal", 2_400, "Phishing"),
    ("Bihar", 2_200, "UPI Payment Fraud"),
    ("Kerala", 2_000, "Loan App Extortion"),
    ("Odisha", 1_700, "UPI Payment Fraud"),
    ("Punjab", 1_500, "Digital Arrest"),
    ("Jharkhand", 1_300, "UPI Payment Fraud"),
    ("Assam", 1_200, "Phishing"),
    ("Chhattisgarh", 1_100, "UPI Payment Fraud"),
    ("Uttarakhand", 900, "Digital Arrest"),
    ("Himachal Pradesh", 700, "Phishing"),
    ("Goa", 600, "Investment Scam"),
    ("Delhi", 400, "Digital Arrest"),
    ("Tripura", 300, "UPI Payment Fraud"),
    ("Manipur", 250, "Phishing"),
    ("Meghalaya", 220, "UPI Payment Fraud"),
    ("Nagaland", 150, "Phishing"),
    ("Arunachal Pradesh", 140, "UPI Payment Fraud"),
    ("Mizoram", 120, "Phishing"),
    ("Sikkim", 90, "UPI Payment Fraud"),
    # Union Territories
    ("Jammu and Kashmir", 800, "Phishing"),
    ("Chandigarh", 500, "Digital Arrest"),
    ("Puducherry", 300, "UPI Payment Fraud"),
    ("Dadra and Nagar Haveli and Daman and Diu", 80, "UPI Payment Fraud"),
    ("Andaman and Nicobar Islands", 60, "Phishing"),
    ("Ladakh", 50, "UPI Payment Fraud"),
    ("Lakshadweep", 20, "Phishing"),
)


def _build_state_baseline_rows() -> Tuple[Tuple[str, int, float, float, float, str], ...]:
    """Expand the anchors into full seed rows with prorated weekly figures."""
    rows: List[Tuple[str, int, float, float, float, str]] = []
    for state, annual_cases, vector in _STATE_BASELINE_ANCHORS:
        annual_loss: float = annual_cases * _AVG_LOSS_PER_CASE_INR
        rows.append((
            state, annual_cases, annual_loss,
            round(annual_cases / 52.0, 4), round(annual_loss / 52.0, 2), vector,
        ))
    return tuple(rows)


STATE_BASELINE_SEED: Tuple[Tuple[str, int, float, float, float, str], ...] = (
    _build_state_baseline_rows()
)

# Columns added to fraud_records after its original ship (online migrations).
_FRAUD_MIGRATION_COLUMNS: Tuple[Tuple[str, str], ...] = (
    ("is_isolated_incident", "INTEGER NOT NULL DEFAULT 1"),
    ("incident_loss_inr", "REAL NOT NULL DEFAULT 0.0"),
    ("is_macro_historical_summary", "INTEGER NOT NULL DEFAULT 0"),
    ("macro_summary_loss_inr", "REAL NOT NULL DEFAULT 0.0"),
    # Unified multi-domain extension (financial + non-financial).
    ("threat_domain", "TEXT NOT NULL DEFAULT 'Financial Fraud'"),
    ("records_exposed", "INTEGER"),
    ("incident_count", "INTEGER"),
    ("severity_level", "TEXT"),
    # Phase 2: generalizable web-seeded impact descriptors.
    ("compromised_assets", "TEXT"),
    ("target_sector", "TEXT"),
)


class RelationalStoreManager:
    """Asynchronous aiosqlite engine compiling the normalized grid schemas."""

    def __init__(self, database_path: Path = SQLITE_PATH) -> None:
        self.database_path: Path = database_path

    async def _migrate_fraud_records(self, connection: aiosqlite.Connection) -> None:
        """Add Phase 2 temporal columns to a pre-existing fraud_records table."""
        cursor: aiosqlite.Cursor = await connection.execute(
            "PRAGMA table_info(fraud_records)"
        )
        existing: set = {row[1] for row in await cursor.fetchall()}
        added: bool = False
        for column, ddl in _FRAUD_MIGRATION_COLUMNS:
            if column not in existing:
                await connection.execute(
                    f"ALTER TABLE fraud_records ADD COLUMN {column} {ddl}"
                )
                added = True
        if added:
            # Backfill legacy rows: treat prior data as isolated incidents so
            # existing financial figures remain attributed to their window.
            await connection.execute(
                "UPDATE fraud_records "
                "SET incident_loss_inr = financial_loss_inr, "
                "    is_isolated_incident = 1 "
                "WHERE incident_loss_inr = 0.0 AND financial_loss_inr > 0.0"
            )
            LOGGER.info("fraud_records migrated with Phase 2 temporal columns")

    async def init_schema(self) -> None:
        """Compile every table, index, and seed row inside one transaction."""
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.database_path) as connection:
            try:
                await connection.execute("PRAGMA foreign_keys = ON")
                # Write-Ahead Logging: lets the autonomous ingestion worker
                # write while the Streamlit frontend reads concurrently
                # without lock contention. WAL persists on the DB file.
                await connection.execute("PRAGMA journal_mode=WAL")
                await connection.execute("PRAGMA synchronous=NORMAL")
                for ddl in SCHEMA_DDL:
                    await connection.execute(ddl)
                await self._migrate_fraud_records(connection)
                for ddl in INDEX_DDL:
                    await connection.execute(ddl)
                await connection.executemany(
                    "INSERT OR IGNORE INTO tactics "
                    "(tactic_name, description, mitigation_strategy) "
                    "VALUES (?, ?, ?)",
                    TACTIC_SEED_ROWS,
                )
                await connection.executemany(
                    "INSERT OR IGNORE INTO state_baselines "
                    "(state_name, annual_cases, annual_loss_inr, "
                    " prorated_weekly_cases, prorated_weekly_loss_inr, "
                    " primary_vector) VALUES (?, ?, ?, ?, ?, ?)",
                    STATE_BASELINE_SEED,
                )
                await connection.commit()
                LOGGER.info(
                    "Relational schema compiled: %d tables, %d indexes, "
                    "%d tactic + %d state-baseline seed rows at %s",
                    len(SCHEMA_DDL), len(INDEX_DDL), len(TACTIC_SEED_ROWS),
                    len(STATE_BASELINE_SEED), self.database_path,
                )
            except aiosqlite.Error:
                await connection.rollback()
                LOGGER.exception(
                    "Schema compilation failed — transaction rolled back"
                )
                raise

    async def verify_tables(self) -> List[str]:
        """Return the physical table list, asserting every expected table."""
        async with aiosqlite.connect(self.database_path) as connection:
            try:
                cursor: aiosqlite.Cursor = await connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                    "ORDER BY name"
                )
                rows: List[Tuple[str]] = list(await cursor.fetchall())
            except aiosqlite.Error:
                LOGGER.exception("Table verification query failed")
                raise
        present: List[str] = [row[0] for row in rows]
        missing: List[str] = [
            table for table in EXPECTED_TABLES if table not in present
        ]
        if missing:
            raise RuntimeError(
                f"Relational schema incomplete — missing tables: {missing}"
            )
        LOGGER.info("Relational verification passed: %s", ", ".join(present))
        return present

    async def seeded_tactic_count(self) -> int:
        """Return the number of tactic lattice rows present."""
        async with aiosqlite.connect(self.database_path) as connection:
            try:
                cursor: aiosqlite.Cursor = await connection.execute(
                    "SELECT COUNT(*) FROM tactics"
                )
                row: Tuple[int] = await cursor.fetchone()  # type: ignore[assignment]
            except aiosqlite.Error:
                LOGGER.exception("Tactic count query failed")
                raise
        return int(row[0])


# --------------------------------------------------------------------------- #
# Initialization runtime.                                                     #
# --------------------------------------------------------------------------- #


async def init_db() -> Dict[str, List[str]]:
    """Safely create and verify both persistence tiers under data/.

    Idempotent: existing stores are validated, never clobbered. Returns a
    summary mapping of physical tables and vector collections brought online.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CHROMA_PERSIST_DIR.mkdir(parents=True, exist_ok=True)
    LOGGER.info("Protected data path verified: %s", DATA_DIR)

    relational: RelationalStoreManager = RelationalStoreManager()
    await relational.init_schema()
    tables: List[str] = await relational.verify_tables()
    tactic_count: int = await relational.seeded_tactic_count()
    if tactic_count < len(TACTIC_SEED_ROWS):
        raise RuntimeError(
            f"Tactic lattice underseeded: {tactic_count}/{len(TACTIC_SEED_ROWS)}"
        )

    # Chroma's client API is synchronous — run it off the event loop thread.
    vector_store: VectorStoreManager = VectorStoreManager()
    collections: List[str] = await asyncio.to_thread(vector_store.init_collections)

    if not SQLITE_PATH.exists():
        raise RuntimeError(f"SQLite physical file missing after init: {SQLITE_PATH}")
    LOGGER.info(
        "init_db complete: %d tables, %d vector collections, %d tactic vectors",
        len(tables), len(collections), tactic_count,
    )
    return {"sqlite_tables": tables, "vector_collections": collections}


if __name__ == "__main__":
    summary: Dict[str, List[str]] = asyncio.run(init_db())
    print(f"SQLite tables      : {', '.join(summary['sqlite_tables'])}")
    print(f"Vector collections : {', '.join(summary['vector_collections'])}")
    print("DUAL-TIER INITIALIZATION: OK")
