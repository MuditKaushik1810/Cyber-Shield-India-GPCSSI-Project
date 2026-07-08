# Cyber Shield India: Threat Intelligence Grid & Cyber Security Utility Suite

An interactive, multi-modular **Cyber Awareness, OSINT Sandbox, and Digital Forensics Simulator** built to bridge the gap between raw cyber telemetry and investigative training. Engineered with Python, Streamlit, and a resilient **5-tier multi-model AI cascade**.

> Developed as a core project for the **Gurugram Police Cyber Security Summer Internship (GPCSSI)**.

<p align="center">
  <img width="900" alt="Cyber Shield India — Operational Intelligence Desk (home)" src="https://github.com/user-attachments/assets/066cc4eb-ea2c-47b1-a9f3-cad1ac6644ed" />
  <br><sub><b>Home — Operational Intelligence Desk & live module grid</b></sub>
</p>

<p align="center">
  <img width="900" alt="Strategic Threat Analytics — geospatial crime hot-spots" src="https://github.com/user-attachments/assets/3b949952-e6d3-4ab5-b575-561c8ebc80dd" />
  <br><sub><b>Strategic Threat Analytics — geospatial hot-spots & state-wise impact</b></sub>
</p>

<p align="center">
  <img width="900" alt="State & UT threat directory with tag-matched vector and regional threat matrix" src="https://github.com/user-attachments/assets/107f57e2-6eb3-4a61-9eaa-47212f8741df" />
  <br><sub><b>State & UT Threat Directory — nodal cell, reporting portal & a tag-matched regional threat matrix</b></sub>
</p>

## 🚀 Key Features

1. **Strategic Threat Analytics Grid** — Regional telemetry mapping across all **28 states and 8 union territories**, cross-referencing open-source feeds from cyber experts, cell bulletins, and official government sites, with a unified threat-tag matrix.
2. **AI-Powered CDR / IPDR Analyser** — Schema-agnostic log parser that ingests *arbitrary* `.csv` call records and extracts structural anomalies, nighttime call spikes, and tower hops via deep LLM forensic inference (with deterministic Pandas analytics for recognised formats).
3. **Live Identity Exposed Analyser** — Programmatic OSINT aggregator that queries live, unauthenticated breach indices (XposedOrNot for emails, HIBP public breaches for domains), parses exfiltrated credential dumps, and renders exposed PII profiles on-screen — no lazy external links.
4. **Domain WHOIS & Operational Risk Engine** — Validates domain structure via strict pre-execution regex, retrieves infrastructure registries, and generates live AI behavioural risk analyses.
5. **Error Level Analysis (ELA) Deepfake Detector** — Dual-layer verification combining localized pixel-variance analysis with a remote Hugging Face classifier for image-manipulation detection.
6. **Practice Case-Building Lab & Victim Triage Engine** — Guided wizards mapping incident metadata to legal boundaries under the **Bharatiya Nyaya Sanhita (BNS)** and the **IT Act**, paired with critical financial "Golden Hour" triage guidance and a Section-94 BNSS legal-notice engine.

---

## 🛡️ Fail-Safe Architecture

Engineered with a **5-tier Gemini model cascade** for defensive fault-tolerance — on a quota (429) or overload (503) error, the system automatically steps down through backup model tiers, and every critical module has a deterministic fallback. The result: the app stays fully operational even during upstream API disruptions.

## 🧰 Tech Stack

**Python 3.13+ · Streamlit · Google Gemini (LangChain) · ChromaDB · OpenCV · Pillow · httpx · Pandas · SerpAPI · FastAPI**

---

## 🛠️ Prerequisites

- **Python 3.13+**
- A valid **Google AI Studio API key** (fuels the 5-tier Gemini cascade) — required
- *(Optional)* **SerpAPI**, **Hugging Face**, **NewsAPI**, and **HIBP** keys to unlock live web advisories, the deepfake classifier, the media-aggregation worker, and breach checks

---

## 📦 Local Installation & Setup

### Step 1 — Clone the repository

```bash
git clone https://github.com/MuditKaushik1810/Cyber-Shield-India-GPCSSI-Project.git
cd Cyber-Shield-India-GPCSSI-Project
```

### Step 2 — Create a virtual environment

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

**Windows (PowerShell):**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 3 — Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## ⚙️ Environment Configuration

Copy the template and fill in your credentials. Only `GOOGLE_API_KEY` is required — every other value is optional, and the app degrades gracefully without it.

```bash
cp .env.example .env      # Windows: copy .env.example .env
```

```bash
# ── Required ──────────────────────────────────────────────
GOOGLE_API_KEY="..."            # Google AI Studio — powers the 5-tier Gemini cascade

# ── Optional: live web intelligence ───────────────────────
SERPAPI_API_KEY="..."           # live web advisories & OSINT identity search
NEWS_API_KEY="..."              # news/media aggregation (background ingestion worker)
GOOGLE_CUSTOM_SEARCH_KEY="..."  # reserved: alternate Programmable Search backend
GOOGLE_SEARCH_ENGINE_ID="..."   # reserved: Programmable Search engine id

# ── Optional: OSINT forensic layers ───────────────────────
HF_API_TOKEN="..."              # remote Hugging Face deepfake classifier (falls back to local ELA)
HIBP_API_KEY="..."              # breach checks (degrades gracefully without it)

# ── Optional: advanced overrides (defaults ship in code) ──
# HF_DEEPFAKE_MODEL=prithivirajdamodaran/deepfake-image-detector
# GEMINI_MODEL=gemini-3.5-flash
```

> ⚠️ Never commit your `.env` — it is git-ignored. Only the `.env.example` template is tracked.

---

## 🏃 Running the Application

```bash
streamlit run app.py
```

Streamlit opens your browser to **http://localhost:8501** (or the next free port).

*(Optional: run the background data harvester separately with `python ingestion_worker.py`.)*

---

## 📂 Project Architecture Overview

```
Cyber-Shield-India-GPCSSI-Project/
│
├── app.py                    # Core Streamlit UI — routing, tabs, layouts
├── requirements.txt          # Dependency index
├── .env.example              # Environment-variable template
│
├── core/
│   └── config.py             # Env loading & validated key access
│
├── services/                 # Backend engines
│   ├── llm_client.py         # 5-tier fallback model cascade controller
│   ├── llm_errors.py         # Transient (429/503) error trapping
│   ├── cdr_analyzer.py       # Schema-agnostic CDR/IPDR forensic engine
│   ├── osint_sandbox.py      # Email / WHOIS / EXIF / QR / deepfake / breach tools
│   ├── threat_registry.py    # 28-state + 8-UT threat directory & tag matrix
│   ├── web_seed.py           # Live web advisory & insight seeding
│   ├── victim_triage.py      # BNS/IT-Act legal-mapping triage engine
│   ├── practice_lab.py       # Case-building lab + Section-94 BNSS notices
│   └── rag_service.py        # Retrieval-augmented semantic explorer
│
├── data/                     # ChromaDB vector store + SQLite tier
└── tests/                    # System & stress test harnesses
```

---

## ⚖️ Responsible Use

Intended for **authorized investigators, researchers, and citizen cyber-safety education**. All forensic and OSINT utilities operate on lawfully obtained data. This is a research and training tool and does not constitute legal advice.

## 🎓 About

Built during the **Gurugram Police Cyber Security Summer Internship (GPCSSI)** as an exploration of resilient, real-world security tooling — from retrieval-augmented intelligence to digital forensics and graceful failure handling.
