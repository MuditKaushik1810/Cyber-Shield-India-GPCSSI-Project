# Project Status & Lifecycle Ledger: Cyber Shield India

## 🎯 Overarching Goal
Build a working, production-ready, submittable RAG-LLM chatbot and interactive cybercrime visualization dashboard utilizing multi-agency government scrapers and automated news/expert entity extraction.

## 🚀 Active Milestone
- [x] Phase 1: Environment Provisioning & Multi-Agency Asynchronous Ingestion Grid ✅ (Completed 2026-06-12)
- [x] Phase 2: Vector Engineering & Relational Schema Compilation ✅ (Completed 2026-06-12)
- [x] Phase 3: Analytical Engine Execution & Multi-Interval Triage Processing ✅ (Completed 2026-06-12)
- [x] Phase 4: FastAPI Gateway Foundations & Prompt Guardrails ✅ (Completed 2026-06-12)
- [x] Phase 5: Production Streamlit Command Center Interface Assembly ✅ (Completed 2026-06-12)
- [ ] Phase 6: Automated Verification & Adversarial Stress Testing (Active)

## 📋 Granular Development Lifecycle Checklist

### 🔹 Phase 1: Environment Provisioning & Multi-Agency Ingestion Grid
- [x] **Step 1.1:** Build physical workspace shell layout: ✅ (2026-06-12)
  ```text
  ├── app.py (Streamlit UI Engine)
  ├── main.py (FastAPI Gateway)
  ├── core/ (Configuration & Environmental Wrappers)
  ├── database/ (SQLite schemas & ChromaDB persistence layers)
  ├── services/ (RAG Inference, Expert Extractors, MAVI Analytics)
  ├── utils/ (Asynchronous Scrapers, Rotating Agent Utilities)
  └── tests/ (Automated Validation Test Suites)
  ```
- [x] **Step 1.2:** ✅ (2026-06-12) Generate `requirements.txt` containing exact, Python 3.13-compliant, verified packages (`fastapi`, `uvicorn`, `streamlit`, `langchain-google-genai`, `python-dotenv`, `chromadb`, `aiosqlite`, `httpx`, `beautifulsoup4`, `plotly`, `pandas`, `pydantic`).
- [x] **Step 1.3:** ✅ (2026-06-12) Construct `.env` template configuration validating the `GOOGLE_API_KEY` environment target.
- [x] **Step 1.4:** ✅ (2026-06-12) Government Web Scraper Matrix (`utils/scraper.py`): Code fully async, user-agent rotating extraction modules pointing to:
  - MHA Cyberdost Portal: Continuous polling of trending alert feeds and public threat advisories.
  - DoT & Sanchar Saathi (TAFCOP/CEIR): Capture bulk connections disconnected for fraud, and device/IMEI blacklists.
  - TRAI: Monitor SMS spoofing registry definitions and Unsolicited Commercial Communications (UCC) headers.
  - NPCI & RBI Cyber Cells: Target payment rail circulars, UPI/AePS vulnerability reports, and digital lending app blocklists.
  - NCIIPC & UIDAI: Parse cross-sector infrastructure protection sheets and Aadhaar biometric locking parameters.
  - Statutory Legal Bases: Load text representations of the Information Technology Act (focusing on Sections 66A/C/D amendments) and the Digital Personal Data Protection (DPDP) Act.
  - State Cyber Bureaus: Ingest bulletins from Telangana Cyber Security Bureau (TCSB), Maharashtra Cyber, Karnataka CEN, and Haryana/Delhi Police.
- [x] **Step 1.5:** ✅ (2026-06-12) Expert Intelligence Stream Parser (`services/expert_feed.py`): Build target filters to ingest unstructured commentary, case logs, and investigative analysis from verified channels of top digital policing strategists, including Dr. Rakshit Tandon and Amit Dubey.
- [x] **Step 1.6:** ✅ (2026-06-12) Structured News Triage Engine: Aggregate cybersecurity articles from top business/tech publications (ET Telecom, MediaNama, Inc42, Gadgets360) into continuous raw text string queues.
- [x] **Step 1.7:** ✅ (2026-06-12) Document Extraction Pipeline (`services/ingestion.py`): Create continuous data streaming parsers to segment dense government handbooks into clean arrays using `RecursiveCharacterTextSplitter` configured to an exact 800-token size and 100-token overlap framework.

### 🔹 Phase 2: Vector Engineering & Relational Schema Compilation
- [x] **Step 2.1:** ✅ (2026-06-12) Instantiate ChromaDB collection maps with complete architectural indexing parameters (`source`, `url`, `date_published`, `jurisdiction`, `threat_category`).
- [x] **Step 2.2:** ✅ (2026-06-12) Code explicit SQL migration definitions via `aiosqlite` establishing these real-world database tables (plus core tracking tables: `incidents`, `entities`, `tactics`, `expert_advisories`):
  - `historical_ncrb_cases`: Schema covering [State, Year, Category, Incidents, Convictions, Chargesheet_Rate].
  - `i4c_financial_metrics`: Schema covering [Timestamp, Incurred_Loss, Prevented_Capital, Recovery_Ratio].
  - `demographic_risk_profiles`: Schema covering [Age_Group, Gender, Geographic_Tier, Occupation, Dominant_Modus_Operandi].
  - `apprehension_ledger`: Schema covering [Arrest_ID, Date, State, Enforcement_Unit, Criminals_Caught, Scam_Type].
- [x] **Step 2.3:** ✅ (2026-06-12) Downstream Extraction Controller: Write zero-shot structured Pydantic models paired with Gemini 2.5 Flash to automatically process raw, unstructured news and expert feeds into clean, database-insertable JSON blocks.

### 🔹 Phase 3: Analytical Engine Execution & Multi-Interval Triage Processing
- [x] **Step 3.1:** ✅ (2026-06-12) Code the mathematical processor for Mule Account Velocity Index (MAVI) inside `services/analytics.py` to identify operational money mule hotspots (extended into the full Multi-Attribute Vulnerability & Incident scoring matrix).
- [x] **Step 3.2:** ✅ (2026-06-12) Execute the Kill Chain Vulnerability Index aggregator to output dynamic real-time percentage breakdowns of distribution vectors.
- [x] **Step 3.3:** ✅ (2026-06-12) Build downstream aggregation workers to process all analytical relational streams into specific, time-horizon snapshots: 24 Hours, 7 Days, 30 Days, and 1 Year.

### 🔹 Phase 4: FastAPI Gateway Foundations & Prompt Guardrails
- [x] **Step 4.1:** ✅ (2026-06-12) Establish the global ASGI server framework (`main.py`) declaring endpoint routing channels for analytical data retrievals.
- [x] **Step 4.2:** ✅ (2026-06-12) Build `services/rag_service.py` using `ChatGoogleGenerativeAI` targeting the Gemini 2.5 extended configuration.
- [x] **Step 4.3:** ✅ (2026-06-12) Hardcode system prompt architectures enforcing the strict government safety boundary fallback and citation assembly logic.

### 🔹 Phase 5: Production Streamlit Command Center Interface Assembly (`app.py`)
- [x] **Step 5.1:** ✅ (2026-06-12) Initiate a modern, wide-layout Streamlit application frame using localized CSS components for a high-fidelity visual design.
- [x] **Step 5.2:** ✅ (2026-06-12) Tab Architecture (🛡️ Assistant Interface): Construct stateful conversational chat fields incorporating custom HTML citation cards (delivered as Tab 3, RAG Chat, per revised three-tab spec).
- [x] **Step 5.3:** ✅ (2026-06-12) Tab Architecture (📊 Threat Radar Dashboard): Implement interactive dashboard zones (delivered as Tab 2, Advanced Math Analytics — Interval Matrix, MAVI KPI blocks, KCVI vector/stage charts — per revised three-tab spec):
  - Interval Matrix: Top horizontal menu selectors to dynamically toggle metrics across 24 Hours, 7 Days, 30 Days, and 1 Year scales.
  - KPI Monitoring Strip: High-visibility reactive cards showing Total Frauds Reported, Total Capital Frozen/Saved (via I4C 1930 mechanics), Cybercriminals Apprehended, and active Top Threat Vectors.
  - Geographic Balance Matrix: A Plotly horizontal grouped chart analyzing states (Telangana, Haryana, Karnataka, etc.) by comparing total damage metrics against proactive averted fund ratios.
  - Demographic Risk Mapping: Grouped multi-axis radar charts tracing relationships between victim occupations, age clusters, and specific scam types.
  - Live Incident Stream Panel: A real-time data table reflecting live processed scam events with corresponding platform tags.
- [x] **Step 5.4:** ✅ (2026-06-12) Cross-Tab RAG Query Injection Hook: Inject the communication layer that captures precise web event coordinate selections from Plotly elements and automatically pipes that localized telemetry into the Tab 1 conversation buffer for immediate natural language interrogation.
- [x] **Step 5.5:** ✅ (2026-06-12) Bind clear global caching wrappers (`@st.cache_data`) across heavy data retrieval modules.

### 🔹 Phase 6: Automated Verification & Adversarial Stress Testing
- [ ] **Step 6.1:** Build background event workers that simulate cron loops to update system repositories with real-time CERT-In bulletins.
- [ ] **Step 6.2:** Develop an automated test configuration (`tests/test_system.py`) to run programmatic assertions on database payloads.
- [ ] **Step 6.3:** Run targeted adversarial prompts against the prompt engine to verify that safety boundaries cannot be bypassed.

## ⚠️ Blockers & Deferred Decisions
- None. Explicitly configured for production-grade standalone deployment using SQLite, local ChromaDB persistence, and the Gemini 2.5 API.
