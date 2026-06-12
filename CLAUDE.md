# Project: Cyber Shield India (Production-Grade Threat Intelligence Grid)

## 1. Enterprise Architecture & Tech Stack
- **Runtime Environment:** Python 3.13+ (Strictly asynchronous execution model).
- **Asynchronous Web Engine:** ASGI-compliant FastAPI backend utilizing clean controller/service separation. Network calls driven exclusively via `httpx` and file operations via `aiofiles`.
- **User Interface Layer:** Streamlit (v1.55+) running deep-injected custom HTML/JS communication strings to manage advanced cross-component state synchronization natively.
- **Dual-Tier Storage Infrastructure:**
  - *Vector Tier:* ChromaDB persistence layer parsing semantic text blocks into dense mathematical matrices using open-source `all-MiniLM-L6-v2` embeddings.
  - *Relational & Analytics Tier:* `aiosqlite` driving fully normalized transaction tables to track live incident frequencies, geographic distribution patterns, and financial data.
- **LLM Cognitive Backbone:** LangChain abstraction framework connected via `langchain-google-genai` directly targeting the Gemini 2.5 extended model (Knowledge Cutoff: May 2026, context capacity up to 1M tokens) to handle multi-dialect Hinglish translation and entity extraction.

## 2. Advanced Investigative Formulas & Analytical Modules
- **Mule Account Velocity Index (MAVI):** Computes risk coefficients by processing intra-day transaction influx rates against rapid liquidation markers across localized branch nodes:

  $$MAVI = \frac{\sum V_{in}}{\Delta T_{out}} \times \log(1 + C_{mule})$$

  Where $V_{in}$ is volume of inward transfers, $\Delta T_{out}$ is egress time lapse, and $C_{mule}$ is cross-linked identity markers.
- **Kill Chain Vulnerability Index:** Matrix tracking structural cracks within underlying telecom/ISP carrier fabrics by processing delivery channels: Malicious Sideloaded APKs (e.g., fake wedding invites), WhatsApp VoIP spoof arrays, Skype virtual gateways, and SIM impersonation.
- **Cross-Tab RAG Query Injection Hook:** Custom session state listener that maps real-time coordinate clicks on Plotly analytical visual elements and injects that telemetry data as a structured JSON context payload into the active RAG conversational prompt buffer.

## 3. Strict Coding Standards & Software Engineering Mandates
- **Type Safety:** 100% complete explicit type hinting across all module architectures using native Python typing (`Coroutine`, `AsyncGenerator`, `Dict`, `List`).
- **Error Handling & Forensic Logging:** Zero naked `except Exception:` blocks permitted. Catch explicit, deterministic exceptions. Write comprehensive tracebacks directly to structured daily rotating internal system logs to maintain diagnostic clarity.
- **Security Protocols:** Absolute zero hardcoding of authentication keys. The `GOOGLE_API_KEY` must be fetched securely from local memory variables handled via `python-dotenv`.
- **RAG Integrity Guardrail:** If retrieved vector context chunks fail to solve the user's intent, the system must trigger an unyielding fallback message: "I am sorry, but I can only provide cyber safety protocols verified by official government sources."

## 4. Git Version Control & Commit Specifications
- **Conventional Commits:** All commit headers must strictly adhere to prefix boundaries: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`.
- **Grammatical Directive:** Commit messaging must utilize the active, imperative mood (e.g., "Add async parser for Sanchar Saathi feeds"). No passive or historical tense descriptions.
