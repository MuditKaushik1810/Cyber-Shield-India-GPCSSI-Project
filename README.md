# Cyber Shield India: Threat Intelligence Grid & Cyber Security Utility Suite

An interactive, multi-modular Cyber Awareness, OSINT Sandbox, and Digital Forensics Simulator built to bridge the gap between raw cyber telemetry and investigative training. Engineered using Python, Streamlit, and a resilient multi-model AI cascade layer.

---

## 🚀 Key Features

1. **Strategic Threat Analytics Grid:** Regional telemetry mapping cross-referencing open-source feeds from cyber experts, cell bulletins, and official government sites.
2. **AI-Powered Call Detail Record (CDR) Analyser:** Schema-agnostic log parser that ingests arbitrary `.csv` cell files and extracts structural anomalies, nighttime call spikes, and tower hops via deep LLM forensic inference.
3. **Live Identity Exposed Analyser:** Programmatic OSINT data aggregator that queries live threat indices, parses exfiltrated credential dumps, and displays exposed PII profiles on-screen without dropping lazy external links.
4. **Domain WHOIS & Operational Risk Engine:** Validates domain structural patterns via strict pre-execution regex, retrieves infrastructure registries, and generates live AI behavioral risk analyses.
5. **Error Level Analysis (ELA) Deepfake Detector:** Dual-layer visual verification tool utilizing localized pixel-variance calculations paired with remote Hugging Face neural networks for image cloning detection.
6. **Practice Case Building Lab & Victim Triage Engine:** Guided form wizards maps incident metadata to exact legal boundaries under the Bharatiya Nyaya Sanhita (BNS) and the IT Act, paired with critical financial "Golden Hour" triage maps.

---

## 🛠️ Prerequisites

Before installing, ensure your local development machine has the following:
* **Python 3.10 to 3.14** installed on your system.
* A valid **Google AI Studio API Key** (to fuel the 5-Tier Gemini Model Cascade).
* (Optional) A **Hugging Face Inference API Token** (for the remote deepfake image classifier block).

---

## 📦 Local Installation & Setup

Follow these exact terminal commands step-by-step to deploy and run the suite locally.


### Step 1: Clone the Repository
Open your terminal or command prompt, navigate to your workspace folder, and pull the source code:
```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/cyber-shield-india.git](https://github.com/YOUR_GITHUB_USERNAME/cyber-shield-india.git)
cd cyber-shield-india


Step 2: Set Up a Virtual Environment
Isolate your package versions using a dedicated clean environment.


On macOS / Linux:


Bash
python3 -m venv venv
source venv/bin/activate
On Windows (Command Prompt):


DOS
python -m venv venv
call venv\Scripts\activate
On Windows (PowerShell):


PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
Step 3: Install Required Dependencies
Upgrade pip to its latest version and install the core framework libraries:


Bash
pip install --upgrade pip
pip install -r requirements.txt
(Note: If your root folder lacks a requirements.txt file, a list of explicit dependencies is provided at the bottom of this document to let you create one).

⚙️ Environment Configuration
The backend looks for API access variables inside a local .env configuration file.

Create a brand-new file named .env in the root folder of your project:


Bash
touch .env
Open the .env file in your preferred text editor and supply your secure credentials:


Code snippet
# Core AI Orchestration Gateway
GEMINI_API_KEY="your_actual_google_gemini_api_key_here"


# Remote Forensic Classifiers
HF_API_TOKEN="your_actual_hugging_face_token_here"
🏃 Running the Application
With your virtual environment active and keys securely configured, execute the local Streamlit compilation runtime:


Bash
streamlit run app.py
Once executed, your terminal will display local development endpoints. The software will automatically spin open your default web browser to:
👉 http://localhost:8501



📂 Project Architecture Overview
Plaintext
cyber-shield-india/
│
├── app.py                  # Core Application UI Routing & Tab Layouts
├── requirements.txt        # Hardcoded Dependency Index
├── .env                    # System Secret Environment Variable Store (Hidden)
│
├── services/               # Core Ingestion & Extraction Networks
│   ├── web_seed.py         # Live Expert Feed Parsing Framework
│   └── threat_registry.py  # Regional Threat Telemetry Layouts
│
└── utils/                  # Forensic Analysis Modules & AI Wrappers
    ├── llm_client.py       # 5-Tier Fallback Model Cascade Controller
    └── llm_errors.py       # Network Error Handlers & 503 Trapping Layers



📝 Reference requirements.txt File Content
Ensure your requirements.txt file matches this exact library matrix to prevent runtime version dependency collisions:

Plaintext
streamlit>=1.35.0
pandas>=2.2.0
numpy>=1.26.0
requests>=2.31.0
python-dotenv>=1.0.1
google-genai>=0.1.1
langchain-core>=0.2.0
Pillow>=10.3.0
