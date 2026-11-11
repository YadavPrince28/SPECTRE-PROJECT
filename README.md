# SPECTRE: Multi-Modal Android Threat Reconstruction Engine

> **Multi-dimensional structural fingerprinting, MobSF dynamic sandbox orchestration, runtime behavioral telemetry, and semantic social engineering intent analysis for Android malware detection.**

---

## 1. Executive Summary

**SPECTRE** (Synthetic Predictive Evaluation & Threat Reconstruction Engine) is an enterprise-grade multi-modal Android malware detection and analysis platform designed to inspect, deconstruct, and classify Android application packages (APKs).

Unlike conventional antivirus engines that rely purely on static signatures or permission thresholds, SPECTRE synthesizes five independent vectors of telemetry:

1. **Module 1 (Static Analysis):** Permissions heatmap, critical security capabilities, trojan persistence markers, and advertising SDK detection via `androguard`+ `quark-engine`.
2. **Module 2 (Behavioral DNA):** Package-level Markov call graphs and TF-IDF class transition graphs matched against known historical trojan families.
3. **Module 3 (Dynamic Sandbox & MobSF Orchestration):** Headless runtime execution inside an instrumented Android Virtual Device (AVD/Emulator) orchestrated via Mobile Security Framework (MobSF), monitoring dynamic API chains, runtime permission deltas, and mitmproxy socket exfiltration.
4. **Module 4 (Social Engineering Engine):** Semantic intent classification using spaCy NLP across dual-encoded (UTF-8 and UTF-16LE) resources, extracting deceptive privilege traps, scareware prompts, and generating an interactive 4-step attack storyboard.
5. **Module 5 (GenAI Synthesis):** Automated threat narrative compilation, forensic indicator mapping, and regulatory compliance reporting (RBI Section 7.4 Cyber Security Framework).

At the core of the pipeline is a **Calibrated Meta-Classifier** trained on verified multi-modal telemetry features, achieving **75.46% Cross-Validated Accuracy** and **0.8273 ROC-AUC** across a benchmark suite of clean banking applications, complex benign utilities, and malicious Android trojans.

---

## 2. System Architecture

```
                                  [ INCOMING APK ]
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
          ┌─────────────┐         ┌─────────────┐         ┌─────────────┐
          │  MODULE 1   │         │  MODULE 2   │         │  MODULE 4   │
          │   Static    │         │ Behavioral  │         │   Social    │
          │ Decompilation│        │ Markov DNA  │         │ Engineering │
          └──────┬──────┘         └──────┬──────┘         └──────┬──────┘
                 │                       │                       │
                 ▼                       ▼                       │
          ┌─────────────────────────────────────┐                │
          │              MODULE 3               │                │
          │      Dynamic Sandbox Engine         │                │
          │  ┌───────────────────────────────┐  │                │
          │  │ MobSF Orchestrator + REST API │  │                │
          │  └───────────────┬───────────────┘  │                │
          │                  ▼                  │                │
          │  ┌───────────────────────────────┐  │                │
          │  │   Android Emulator (AVD)      │  │                │
          │  │ Runtime Hooks + mitmproxy TLS │  │                │
          │  └───────────────────────────────┘  │                │
          └──────────────────┬──────────────────┘                │
                             │                                   │
                             ▼                                   │
                      ┌─────────────┐                            │
                      │  MODULE 5   │◄───────────────────────────┘
                      │    GenAI    │  (Deceptive UI Traps &
                      │  Synthesis  │   Screenplay Storyboard)
                      └──────┬──────┘
                             │
                 ┌───────────┴───────────┐
                 ▼                       ▼
         ┌───────────────┐       ┌───────────────┐
         │ Static Delta  │       │ Network State │
         │ (Decl vs Run) │       │ (Live Streams)│
         └───────┬───────┘       └───────┬───────┘
                 │                       │
                 └───────────┬───────────┘
                             ▼
             ┌───────────────────────────────┐
             │       META-CLASSIFIER         │
             │   Balanced Random Forest      │
             │   P(Malicious) >= 0.46        │
             │   Accuracy: 75.46%            │
             │   ROC-AUC:  0.8273            │
             └───────────────┬───────────────┘
                             │
                             ▼
             ┌───────────────────────────────┐
             │       NEXT.JS DASHBOARD       │
             │  View 01: Ingestion Hub       │
             │  View 02: Analysis Terminal   │
             │  View 03: GenAI Suite         │
             └───────────────────────────────┘
```

---

## 3. Dynamic Analysis & MobSF Integration

SPECTRE integrates **Mobile Security Framework (MobSF)** as its primary execution and instrumentation orchestrator for **Module 3**:

* **Automated Headless Detonation:** The pipeline pushes the candidate APK to the MobSF REST API gateway, triggering automated installation onto a connected Android Emulator (AVD).
* **Dynamic Hooking & Tracing:** Captures runtime API invocations, cryptographic operations, reflection loading, and dynamic broadcast registrations during the interactive/headless execution window.
* **Mitmproxy Interception:** Operates in tandem with MobSF's network monitoring to log TLS socket flows, HTTP/S POST payloads, and dynamic data leaks.
* **Runtime Delta Generation:** Contrasts declared manifest permissions from Module 1 against actual runtime capability utilization recorded by MobSF, exposing hidden execution paths and dormant trojan logic.

---

## 4. Meta-Classifier Benchmark Performance

The meta-classifier is evaluated via **5-Fold Stratified Cross-Validation** over 163 unique verified APK samples (comprising legacy droppers, repackaged game trojans, modern banking droppers, complex benign utilities, and whitelisted Tier-0 Indian retail banking applications).

```
================================================================================
SPECTRE META-CLASSIFIER (5-FOLD STRATIFIED CROSS-VALIDATION REPORT)
================================================================================
Total Dataset Scope : 163 samples
Decision Boundary   : P(Malicious) >= 0.46
--------------------------------------------------------------------------------
CONFUSION MATRIX:
  True Positives  (TP): 49    | False Positives (FP): 14  
  False Negatives (FN): 26    | True Negatives  (TN): 74  
--------------------------------------------------------------------------------
CROSS-VALIDATED PERFORMANCE:
  Overall Accuracy     : 75.46%
  Precision            : 77.78%
  Recall (Detection)   : 65.33%
  Specificity (Clean)  : 84.09%
  F1-Score             : 71.01%
  ROC-AUC              : 0.8273
================================================================================
```

### Feature Selection & Discriminative Rationale

To break through the feature inversion bottleneck (where benign utility apps with advertising SDKs resemble trojans), the meta-classifier selects the 5 highest-signal discriminators:

1. **`m1_perm`:** Cumulative permission threat index (Static Analysis).
2. **`m2_markov`:** Transition probability distance against malware family call graphs (Behavioral DNA).
3. **`m3_runtime`:** Dynamic runtime hazard index derived from MobSF execution telemetry.
4. **`m5_genai`:** Multi-agent synthesis severity rating.
5. **`has_trojan_perm`:** Binary presence of privilege-escalation permissions (`SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`, `RECEIVE_BOOT_COMPLETED`, `REQUEST_INSTALL_PACKAGES`).

---

## 5. Key Module Capabilities

### Module 4: Deceptive UI & Social Engineering Screenplay
* **Dual-Encoding Extraction:** Decodes user-facing UI strings from `resources.arsc` and `AndroidManifest.xml` in both UTF-8 and UTF-16LE binary formats.
* **Semantic Intent Classification:** Leverages spaCy phrase and intent matchers targeting urgency, privilege coercion, counterfeit updates, and credential harvesting.
* **Dynamic Phone Viewport:** Feeds the Next.js interactive phone simulator with app-specific screen states (`SPLASH`, `ALERT_MODAL`, `FORM`, `OTP`) reflecting the actual analyzed package metadata.

### Dual-Layer Network Telemetry
* **Runtime Socket Monitoring:** Mitmproxy and MobSF network captures isolate active HTTP/HTTPS POST payloads during dynamic sandbox execution.
* **Static Host Inventory:** Distinguishes between dormant Command & Control (C2) domains embedded in raw code and legitimate advertising/analytics endpoints (e.g., Google AdMob, Firebase, AppLovin).

---

## 6. Repository Structure

```
SPECTRE/
├── backend/
│   ├── app.py                         # FastAPI REST & WebSocket server
│   ├── pipeline.py                    # Master 5-module coordination pipeline
│   ├── models/
│   │   └── meta_classifier.joblib     # Serialized balanced Random Forest model
│   └── modules/
│       ├── static_analysis.py         # Module 1: Permissions & capability extractor
│       ├── behavioral_dna.py          # Module 2: Markov graph transition analyzer
│       ├── dynamic_analysis.py        # Module 3: MobSF orchestrator & runtime sniffer
│       ├── social_engineering.py      # Module 4: spaCy deceptive UI & storyboard engine
│       └── genai_layer.py             # Module 5: LLM synthesis & regulatory reporting
│
├── frontend/
│   ├── app/
│   │   ├── layout.tsx                 # Root UI layout and theme wrapper
│   │   └── page.tsx                   # View switcher (Ingestion -> Terminal -> GenAI)
│   ├── components/
│   │   └── spectre/
│   │       ├── ingestion-hub.tsx      # View 01: Drag-and-drop APK upload & progress
│   │       ├── analysis-terminal.tsx  # View 02: Risk gauge, network, & permission heatmap
│   │       ├── phone-frame.tsx        # Dynamic mobile device mockup for screenplays
│   │       ├── risk-gauge.tsx         # Circular multi-tier threat vector gauge
│   │       └── genai-suite.tsx        # View 03: Executive forensic reporting & audit
│   └── lib/
│       └── spectre-data.ts            # Frontend types and default telemetry contracts
│
├── data/
│   └── validation/
│       ├── benchmark_execution_log.csv  # 163-sample evaluated telemetry dataset
│       ├── meta_classifier_confusion_roc.png # Output ROC & Confusion Matrix plot
│       └── apks/                        # Local benchmark APK storage
│
├── scripts/
│   ├── train_meta_classifier.py       # Stratified 5-fold CV & model exporter
│   ├── enrich_m4_spacy.py             # High-speed offline Module 4 feature backfill
│   └── train_spacy_m4.py              # Multi-label text categorizer trainer
│
├── requirements.txt                   # Pinned Python dependencies
└── README.md                          # Platform documentation
```

---

## 7. Prerequisites & Environment Setup

### System Prerequisites
* **Operating System:** Windows 10/11, Ubuntu 22.04 LTS, or macOS
* **Python:** Version 3.10 or 3.11
* **Node.js:** Version 18.x or 20.x LTS
* **Android Studio & SDK:** Android SDK Command-line Tools, Build-Tools, Platform-Tools (`adb`)
* **Android Emulator (AVD):** Android 9.0 (API 28) to Android 11.0 (API 30), Google APIs system image (x86 or x86_64)
* **Mobile Security Framework (MobSF):** Running locally or in Docker

---

### Step 1: Android Emulator Setup

1. Open Android Studio AVD Manager and create an emulator:
   * **Device:** Pixel 4 / Pixel 6
   * **System Image:** API 28 or API 29 (Google APIs, **not** Google Play store image, to permit root ADB access).
2. Start the emulator with writable system privileges:
   ```powershell
   emulator -avd <Your_AVD_Name> -writable-system -no-snapshot
   ```
3. Verify ADB connectivity:
   ```powershell
   adb devices
   ```

---

### Step 2: MobSF Service Setup

MobSF handles the dynamic instrumentation layer and can be run via Docker or source:

#### Option A: Docker (Recommended)
```powershell
docker pull opensecurity/mobsf:latest
docker run -it --rm -p 8001:8000 opensecurity/mobsf:latest
```

#### Option B: Local Python Environment
Follow the official MobSF installation guide and execute:
```powershell
run.bat 127.0.0.1:8001
```

*Note: MobSF runs on port `8001` so that port `8000` remains available for the SPECTRE backend API.*

Retrieve your **MobSF REST API Key** from the MobSF terminal banner or via the web portal (`http://localhost:8001/api_docs`).

---

### Step 3: Backend Setup

1. Open a new PowerShell terminal in the project directory:
   ```powershell
   cd D:\Spectre_BOI_project\SPECTRE
   ```

2. Create and activate a Python virtual environment:
   ```powershell
   python -m venv spectre-env
   .\spectre-env\Scripts\Activate.ps1
   ```

3. Install required dependencies:
   ```powershell
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Download the base spaCy English language pipeline:
   ```powershell
   python -m spacy download en_core_web_sm
   ```

5. Configure environment variables (or specify in your `.env` file):
   ```powershell
   $env:MOBSF_URL = "http://127.0.0.1:8001"
   $env:MOBSF_API_KEY = "<YOUR_MOBSF_API_KEY>"
   $env:TEMP = "D:\Spectre_BOI_project\temp"
   ```

---

### Step 4: Frontend Setup

1. In a separate terminal, navigate to the frontend directory:
   ```powershell
   cd frontend
   ```

2. Install dependencies:
   ```powershell
   npm install
   ```

---

## 8. Operational Execution

### 1. Launching the Platform

Start services in the following order:

1. **Android Emulator (AVD):**
   ```powershell
   emulator -avd <Your_AVD_Name>
   ```
2. **MobSF Service:**
   ```powershell
   docker run -it --rm -p 8001:8000 opensecurity/mobsf:latest
   ```
3. **SPECTRE Backend API:**
   ```powershell
   uvicorn backend.app:app --host 0.0.0.0 --port 8000 --reload
   ```
4. **SPECTRE Next.js Dashboard:**
   ```powershell
   cd frontend
   npm run dev
   ```

* **Frontend Dashboard:** `http://localhost:3000`
* **Backend OpenAPI Docs:** `http://localhost:8000/docs`
* **MobSF Dynamic Console:** `http://localhost:8001`

---

### 2. Model Retraining & Feature Backfill (Optional)

To refresh telemetry features or retrain the decision ensemble across `benchmark_execution_log.csv`:

```powershell
# Fast backfill of Module 4 social engineering scores (<60s)
python scripts\enrich_m4_spacy.py

# Retrain 5-fold cross-validated meta-classifier and export confusion matrix/ROC curve
python scripts\train_meta_classifier.py
```

---

## 9. Dashboard Views

### View 01: Ingestion Hub
* Drag-and-drop file uploader for `.apk` binaries.
* Live WebSocket telemetry stream tracking static extraction, behavioral fingerprinting, MobSF dynamic sandbox detonation, and GenAI synthesis.

### View 02: Advanced Analysis Terminal
* **Composite Risk Vector:** Calibrated 0–100 risk score and 4-tier verdict (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`).
* **Behavioral Graph Match:** Top-1 family similarity, Markov transition frequency, and class-IDF matching.
* **Network Exfiltration Card:** Active socket streams vs. dormant static C2 infrastructure.
* **Permission Matrix Heatmap:** High-risk permission identification with capability summaries.
* **Social Engineering Screenplay:** Step-by-step attack reconstruction rendered in a simulated mobile device frame.
* **Mitmproxy Interception Console & Runtime Delta:** Real-time socket flows and declared vs. runtime capability discrepancies from MobSF.

### View 03: GenAI Intelligence Suite
* Executive risk assessment and attack vector breakdown.
* Regulatory compliance mapping compliant with **RBI Master Direction on Digital Payment Security Controls & Cyber Security Framework (Section 7.4)**.
* Automated MITRE ATT&CK Mobile matrix tagging.

---

## 10. License & Disclaimer

This software is developed strictly for authorized security research, vulnerability assessment, and malware analysis. All testing must be conducted in an isolated, sandboxed environment.