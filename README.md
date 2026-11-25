# SPECTRE: Multi-Modal Android Threat Reconstruction Engine

> **Multi-dimensional structural fingerprinting, high-speed DEX feature extraction, MobSF + Redroid dynamic sandbox orchestration, behavioral Markov DNA analysis, semantic social engineering detection, and GenAI forensic synthesis for Android malware detection.**

---

## 1. Executive Summary

**SPECTRE** (*Synthetic Predictive Evaluation & Threat Reconstruction Engine*) is an enterprise-grade, multi-modal Android malware detection and threat reconstruction platform designed to inspect, deconstruct, and classify Android Application Packages (APKs).

Unlike conventional signature-based antivirus engines that break under obfuscation or trigger false alarms on benign apps using advertising SDKs, SPECTRE fuses five independent telemetry layers:

1. **Module 1 (Static & High-Speed DEX Analysis):** Extracts permissions heatmaps, critical security capabilities, trojan persistence markers, advertising SDK indicators, and rapid DEX bytecode features via `androguard`, and a custom `fast_dex_extractor` pipeline.
2. **Module 2 (Behavioral Markov DNA):** Constructs package-level Markov call graphs and TF-IDF class transition graphs matched against a full **Drebin** malware family reference inventory (`models/drebin_graphs_v3/full_drebin_family_inventory.csv`).
3. **Module 3 (Dynamic Sandbox & MobSF Orchestration):** Executes APKs inside an isolated, containerized Android 11 runtime (**Redroid**) orchestrated through **Mobile Security Framework (MobSF)** with support for mandatory fresh execution runs to defeat sandbox evasion, capturing runtime API chains, declared-vs-runtime permission deltas, and `mitmproxy` TLS socket exfiltration.
4. **Module 4 (Social Engineering Engine):** Applies spaCy NLP (`PhraseMatcher` and semantic intent classification) across dual-encoded (UTF-8 and UTF-16LE) `resources.arsc` and `AndroidManifest.xml` strings to uncover scareware prompts, credential harvesting forms, and deceptive privilege traps, rendering an interactive 4-step mobile attack storyboard.
5. **Module 5 (GenAI Forensic Synthesis):** Compiles automated executive threat narratives, MITRE ATT&CK Mobile mappings, forensic indicator breakdowns, and regulatory compliance reports aligned with the **RBI Master Direction on Digital Payment Security Controls & Cyber Security Framework (Section 7.4)**.

With the **SPECTRE v3 Accuracy Upgrade**, the decision layer transitions from the baseline Balanced Random Forest meta-classifier to a tuned **XGBoost v3 Classifier** backed by expanded Drebin behavioral DNA references and high-throughput DEX feature extraction—elevating held-out performance to **93.1% Accuracy (93.15%)**, **0.972 ROC-AUC**, **95.58% Precision**, and **96.67% Specificity** across **978 held-out APK samples**.

---

## 2. Production & System Architecture

SPECTRE operates as a decoupled cloud-native architecture: the Next.js frontend is deployed on **Vercel** (`https://spectre-project.vercel.app`) and communicates over TLS with an **Oracle Cloud Ubuntu** host behind a **Caddy** reverse proxy (`https://spectre-pro.duckdns.org`). All internal analysis services (FastAPI, MobSF, and Redroid) are bound strictly to `127.0.0.1` for localhost isolation.

```
                      [ NEXT.JS FRONTEND ON VERCEL ]
                   (https://spectre-project.vercel.app)
                                     │
                     HTTPS / TLS + Strict CORS + API Key
                                     ▼
                    [ CADDY REVERSE PROXY (Ports 80/443) ]
                     (https://spectre-pro.duckdns.org)
                         HSTS | X-Frame-Options | nosniff
                                     │
                           Localhost Proxy Pass
                                     ▼
                  [ FASTAPI BACKEND (127.0.0.1:8080) ]
                                     │
            ┌────────────────────────┼────────────────────────┐
            ▼                        ▼                        ▼
     ┌─────────────┐          ┌─────────────┐          ┌─────────────┐
     │  MODULE 1   │          │  MODULE 2   │          │  MODULE 4   │
     │ Static &    │          │ Full Drebin │          │   Social    │
     │ Fast DEX    │          │ Markov DNA  │          │ Engineering │
     └──────┬──────┘          └──────┬──────┘          └──────┬──────┘
            │                        │                        │
            ▼                        ▼                        │
     ┌────────────────────────────────────────┐               │
     │               MODULE 3                 │               │
     │    Dynamic Sandbox & Fresh Run Engine  │               │
     │  ┌──────────────────────────────────┐  │               │
     │  │  MobSF Container (127.0.0.1:8000)│  │               │
     │  └────────────────┬─────────────────┘  │               │
     │                   ▼                    │               │
     │  ┌──────────────────────────────────┐  │               │
     │  │ Redroid Android 11 (127.0.0.1:5555)│ │               │
     │  │  ADB + Runtime Hooks + mitmproxy │  │               │
     │  └──────────────────────────────────┘  │               │
     └───────────────────┬────────────────────┘               │
                         │                                    │
                         ▼                                    │
                  ┌─────────────┐                             │
                  │  MODULE 5   │◄────────────────────────────┘
                  │    GenAI    │  (Deceptive UI Traps &
                  │  Synthesis  │   4-Step Attack Storyboard)
                  └──────┬──────┘
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
    ┌───────────────┐         ┌───────────────┐
    │ Runtime Delta │         │ Network State │
    │ (Decl vs Run) │         │ (C2 vs AdSDK) │
    └───────┬───────┘         └───────┬───────┘
            │                         │
            └────────────┬────────────┘
                         ▼
         ┌───────────────────────────────┐
         │     SPECTRE v3 CLASSIFIER     │
         │         XGBoost v3            │
         │   Held-Out Accuracy: 93.15%   │
         │   Held-Out ROC-AUC : 0.972    │
         │   Precision / Spec : 95.6/96.7│
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

## 3. Model Evolution & v3 Benchmark Performance

### 3.1 Baseline (v1/v2) vs. SPECTRE v3 Comparison

Upgrading the feature extraction pipeline (`fast_dex_extractor.py`), expanding Module 2 behavioral DNA references to the full Drebin family corpus, and replacing the baseline Balanced Random Forest with **XGBoost v3** produced substantial gains across every classification metric while scaling evaluation from 163 cross-validated samples to a **978-sample held-out test set**.

| Metric | Baseline (v1/v2 Balanced RF) | SPECTRE v3 (XGBoost) | Improvement |
| :--- | :---: | :---: | :---: |
| **Evaluation Protocol** | 5-Fold Stratified CV (`n = 163`) | Held-Out Test Set (`n = 978`) | **6x Evaluation Scale** |
| **Overall Accuracy** | 75.46% | **93.15% (93.1%)** | **+17.69 pp** |
| **ROC-AUC** | 0.8273 | **0.9720** | **+0.1447** |
| **Precision (Alert Class)** | 77.78% | **95.58%** | **+17.80 pp** |
| **Recall / TPR (Alert Class)** | 65.33% | **88.81%** | **+23.48 pp** |
| **Specificity / TNR (Clean Class)** | 84.09% | **96.67%** | **+12.58 pp** |
| **False Positive Rate (FPR)** | 15.91% | **3.33%** | **-12.58 pp (79% reduction)** |
| **F1-Score (Alert Class)** | 71.01% | **92.07%** | **+21.06 pp** |

---

### 3.2 SPECTRE v3 Held-Out Evaluation Report

```
================================================================================
SPECTRE v3 XGBOOST CLASSIFIER (HELD-OUT BENCHMARK EVALUATION)
================================================================================
Total Held-Out Scope : 978 samples (540 Clean | 438 Alert)
Model Architecture   : XGBoost v3
--------------------------------------------------------------------------------
CONFUSION MATRIX:
  True Negatives  (TN, Clean -> Clean) : 522  |  False Positives (FP, Clean -> Alert) : 18
  False Negatives (FN, Alert -> Clean) :  49  |  True Positives  (TP, Alert -> Alert) : 389
--------------------------------------------------------------------------------
HELD-OUT PERFORMANCE METRICS:
  Overall Accuracy     : 93.15%  (911 / 978)
  ROC-AUC              : 0.972
  Precision (Alert)    : 95.58%  (389 / 407)
  Recall / TPR (Alert) : 88.81%  (389 / 438)
  Specificity (Clean)  : 96.67%  (522 / 540)
  False Positive Rate  :  3.33%  ( 18 / 540)
  False Negative Rate  : 11.19%  ( 49 / 438)
  F1-Score (Alert)     : 92.07%
================================================================================
```

![SPECTRE v3 XGBoost Confusion Matrix and Held-Out ROC Curve](v3_xgboost_confusion_roc.png)

### 3.3 Key Analytical Takeaways
* **Minimal Analyst Fatigue (`18 / 540` False Positives):** Achieving **96.67% specificity** (only **3.33% FPR**) solves the classic feature-inversion problem where legitimate banking apps and complex utilities embedding analytics/advertising SDKs are misclassified as trojans.
* **Strong Threshold Separation (`0.972` ROC-AUC):** The steep ROC curve near the y-axis demonstrates clean probability separation between benign and malicious binaries. In high-security banking SOC deployments, operators can lower the classification threshold slightly—or combine it with static high-severity overrides—to capture borderline/evasive samples among the `49` false negatives while preserving high precision.

---

## 4. Experiment & Engineering Changelog (v3 Upgrade)

The following engineering milestones were completed on `exp/v3-accuracy-upgrade` and merged into `main` for production deployment:

1. **High-Speed DEX Feature Extraction (`backend/modules/fast_dex_extractor.py`):** Introduced a dedicated fast DEX bytecode parsing module to extract structural API signals and opcode/class telemetry rapidly without introducing external package bloat.
2. **Full Drebin Family Reference Expansion (`module2_full_drebin_reference_builder_v2.py`):** Expanded Module 2 behavioral DNA matching with a comprehensive Drebin malware family inventory (`models/drebin_graphs_v3/full_drebin_family_inventory.csv`) and precomputed behavioral graph references.
3. **Mandatory Fresh Dynamic Analysis (Anti-Evasion Hardening):** Updated the Module 3 dynamic orchestration path to support mandatory fresh detonation runs, preventing stale cached scans from masking evasive or time-delayed runtime payloads.
4. **Cross-Platform Path Portability (`pathlib` & Env Resolution):** Eliminated hardcoded Windows drive paths (`D:\Spectre_BOI_project\SPECTRE\...`) in favor of dynamic `pathlib.Path(__file__)` project-root resolution and environment-variable overrides (`SPECTRE_ROOT`, etc.), ensuring seamless parity between local Windows development and the Oracle Cloud Ubuntu server.
5. **Repository & Binary Hygiene:** Removed obsolete artifacts (`backend/models.py`, legacy `.quark.log` files) and purged oversized binary graph caches (`full_drebin_sample_dna_cache.pkl` at `494.60 MB` and `full_drebin_family_references.pkl` at `77.32 MB`) from Git history, enforcing `models/drebin_graphs_v3/*.pkl` in `.gitignore` to comply with GitHub storage limits.
6. **Zero Additional Dependency Overhead:** All v3 feature extraction, evaluation, and path-portability upgrades operate strictly on Python's standard library alongside the existing SPECTRE core stack (`requests`, `androguard`, `spacy`, `pandas`, `xgboost`, `fastapi`, `uvicorn`).

---

## 5. Core Module Capabilities

### Module 1: Static & Fast DEX Analysis
* Decompiles manifest declarations, permission risk heatmaps, trojan privilege-escalation capabilities (`SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`, `RECEIVE_BOOT_COMPLETED`, `REQUEST_INSTALL_PACKAGES`), and DEX structural features via `androguard`, `quark-engine`, and `fast_dex_extractor.py`.

### Module 2: Behavioral DNA (Full Drebin Markov Graphs)
* Builds package-level Markov call transition graphs and TF-IDF class transition signatures matched against the expanded Drebin family inventory to detect repackaged trojans and polymorphic malware variants.

### Module 3: Dynamic Sandbox & MobSF + Redroid Orchestration
* **Automated Headless Detonation:** Submits candidate APKs to the MobSF REST API (`127.0.0.1:8000`) backed by a containerized Android 11 **Redroid** instance (`127.0.0.1:5555`).
* **Runtime Hooking & Mitmproxy Telemetry:** Logs dynamic API calls, reflection loading, cryptographic routines, and live HTTP/HTTPS socket exfiltration.
* **Declared vs. Runtime Delta:** Contrasts static manifest claims against live execution telemetry to uncover dormant or conditionally triggered trojan routines.

### Module 4: Deceptive UI & Social Engineering Screenplay
* **Dual-Encoding String Extraction:** Decodes UI prompts from `resources.arsc` and `AndroidManifest.xml` in both UTF-8 and UTF-16LE formats.
* **Semantic Intent Matching:** Uses spaCy `PhraseMatcher` and intent classifiers to flag urgency traps, fake update prompts, accessibility coercion, and OTP/credential harvesting.
* **Interactive Attack Storyboard:** Feeds the Next.js phone viewport (`SPLASH`, `ALERT_MODAL`, `FORM`, `OTP`) with package-specific reconstructed screens.

### Module 5: GenAI Forensic Intelligence Suite
* Synthesizes structured telemetry from Modules 1–4 into executive incident briefings, MITRE ATT&CK Mobile technique tags, and **RBI Section 7.4 Cyber Security Framework** compliance assessments.

---

## 6. Cloud Deployment & Security Architecture

### 6.1 Service Topology & Port Isolation

| Service / Component | Host / Platform | Binding / Endpoint | Exposure |
| :--- | :--- | :--- | :--- |
| **Next.js Dashboard** | Vercel | `https://spectre-project.vercel.app` | Public HTTPS |
| **Caddy Reverse Proxy** | Oracle Cloud Ubuntu | `*:80`, `*:443` (`https://spectre-pro.duckdns.org`) | Public HTTPS (TLS + HSTS) |
| **SPECTRE FastAPI (`uvicorn`)** | Oracle Cloud Ubuntu | `127.0.0.1:8080` | Localhost-Only (via Caddy) |
| **MobSF Container** | Docker on Oracle VM | `127.0.0.1:8000`, `127.0.0.1:1337` | Localhost-Only |
| **Redroid Android 11** | Docker on Oracle VM | `127.0.0.1:5555` (ADB) | Localhost-Only |

### 6.2 Security Controls & Hardening Posture
* **Internal Service Isolation:** Neither the FastAPI port (`8080`), MobSF (`8000`/`1337`), nor ADB/Redroid (`5555`) is exposed on public network interfaces; all external requests must traverse Caddy over HTTPS.
* **Transport & Browser Security Headers:** Verified live on `https://spectre-pro.duckdns.org` with `Strict-Transport-Security: max-age=31536000; includeSubDomains`, `X-Content-Type-Options: nosniff`, and `X-Frame-Options: DENY`.
* **Strict CORS Policy:** Explicitly allowlists `Access-Control-Allow-Origin: https://spectre-project.vercel.app` with `Access-Control-Allow-Credentials: true`.
* **API Key Enforcement Architecture:** Backend endpoints validate API keys server-side rather than trusting CORS alone. Because client-prefixed frontend variables (`NEXT_PUBLIC_*`) are visible in browser bundles, secret backend API keys should be routed through Vercel server-side routes/actions for production deployments, paired with rate limiting and disabled/gated public `/docs` and `/openapi.json` routes.

---

## 7. Repository Structure

```
SPECTRE/
├── backend/
│   ├── main.py                        # FastAPI REST & WebSocket server (127.0.0.1:8080)
│   ├── pipeline.py                    # Master 5-module orchestration pipeline
│   ├── modules/
│   │   ├── static_analysis.py         # Module 1: Permissions & capability extractor
│   │   ├── fast_dex_extractor.py      # Module 1 (v3): High-speed DEX bytecode extractor
│   │   ├── behavioral_dna.py          # Module 2: Markov graph transition analyzer
│   │   ├── dynamic_analysis.py        # Module 3: MobSF + Redroid runtime orchestrator
│   │   ├── social_engineering.py      # Module 4: spaCy deceptive UI & storyboard engine
│   │   └── genai_layer.py             # Module 5: LLM synthesis & RBI compliance engine
│   └── scripts/
│       └── module2_full_drebin_reference_builder_v2.py  # Drebin DNA reference builder
│
├── models/
│   └── drebin_graphs_v3/
│       └── full_drebin_family_inventory.csv  # Tracked Drebin family inventory (*.pkl gitignored)
│
├── frontend/                          # Next.js dashboard (deployed on Vercel)
│   ├── app/
│   │   ├── layout.tsx                 # Root UI layout and theme wrapper
│   │   └── page.tsx                   # View switcher (Ingestion -> Terminal -> GenAI)
│   ├── components/spectre/
│   │   ├── ingestion-hub.tsx          # View 01: Drag-and-drop APK upload & telemetry stream
│   │   ├── analysis-terminal.tsx      # View 02: Risk gauge, network, & permission heatmap
│   │   ├── phone-frame.tsx            # Interactive mobile mockup for social engineering plays
│   │   ├── risk-gauge.tsx             # Calibrated multi-tier threat vector gauge
│   │   └── genai-suite.tsx            # View 03: Executive forensic reporting & RBI audit
│   └── lib/
│       └── spectre-data.ts            # Frontend types and API contracts
│
├── scripts/
│   ├── train_meta_classifier.py       # Model training & evaluation plot exporter
│   ├── enrich_m4_spacy.py             # Offline Module 4 NLP feature backfill
│   └── train_spacy_m4.py              # Multi-label text categorizer trainer
│
├── healthcheck.sh                     # Cloud stack verification script (DNS/API/MobSF/ADB)
├── requirements.txt                   # Python dependencies
└── README.md                          # Platform documentation
```

---

## 8. Setup, Execution & Health Verification

### 8.1 Prerequisites
* **OS:** Ubuntu 22.04+ LTS (recommended for cloud production with Redroid) or Windows 10/11 / macOS (local development)
* **Python:** 3.10 or 3.11
* **Node.js:** 18.x or 20.x LTS
* **Docker:** Required for containerized **Redroid** (`redroid/redroid:11.0.0-latest`) and **MobSF** (`opensecurity/mobile-security-framework-mobsf:latest`)
* **Android Platform Tools:** `adb`

---

### 8.2 Cloud / Docker Production Stack (Oracle Ubuntu)

1. **Start Redroid (Android 11) and MobSF bound strictly to localhost:**
   ```bash
   # Redroid Android 11 container on 127.0.0.1:5555
   docker run -d --name redroid --privileged \
     -p 127.0.0.1:5555:5555 \
     redroid/redroid:11.0.0-latest

   # Connect host ADB to Redroid
   adb connect 127.0.0.1:5555

   # MobSF container on 127.0.0.1:8000 & 1337
   docker run -d --name mobsf \
     -p 127.0.0.1:8000:8000 \
     -p 127.0.0.1:1337:1337 \
     opensecurity/mobile-security-framework-mobsf:latest
   ```

2. **Configure Python Environment & Launch SPECTRE Backend:**
   ```bash
   python3 -m venv spectre-env
   source spectre-env/bin/activate
   pip install --upgrade pip
   pip install -r requirements.txt
   python3 -m spacy download en_core_web_sm

   # Verify core imports
   python3 -c "import requests, spacy, pandas, androguard; print('All required packages ready!')"

   # Start FastAPI strictly on localhost:8080 behind Caddy
   uvicorn backend.app:app --host 127.0.0.1 --port 8080
   ```

3. **Configure `.env` (using portable Linux paths):**
   ```env
   SPECTRE_ROOT=/home/ubuntu/SPECTRE
   MOBSF_URL=http://127.0.0.1:8000
   MOBSF_API_KEY=<YOUR_MOBSF_API_KEY>
   MOBSF_DEVICE=127.0.0.1:5555
   ```

---

### 8.3 Local Development Setup (Windows PowerShell)

```powershell
# 1. Activate environment & install dependencies
python -m venv spectre-env
.\spectre-env\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Launch FastAPI backend locally
uvicorn backend.app:app --host 127.0.0.1 --port 8080 --reload

# 3. Launch Next.js frontend (in a separate terminal)
cd frontend
npm install
npm run dev
```

---

### 8.4 End-to-End Health & CORS Verification

Run `~/healthcheck.sh` on the Oracle instance to verify the full stack (`spectre-pro.duckdns.org` -> Caddy -> FastAPI `8080` -> MobSF `8000` -> Redroid/ADB `5555` -> Host Resources):

```bash
#!/usr/bin/env bash
set -u

echo "=== 1. DNS & Public Domain (spectre-pro.duckdns.org) ==="
getent ahosts spectre-pro.duckdns.org | head -n 2 || true
curl -sS -m 6 -w "HTTPS %{http_code} (%{time_total}s)\n" https://spectre-pro.duckdns.org/openapi.json -o /dev/null || echo "Public domain check failed"

echo "=== 2. SPECTRE Backend (127.0.0.1:8080) ==="
curl -sS -m 5 -w "HTTP %{http_code} (%{time_total}s)\n" http://127.0.0.1:8080/openapi.json -o /dev/null || echo "Backend check failed"

echo "=== 3. ADB / Redroid & MobSF (127.0.0.1:8000) ==="
adb devices 2>&1 || true
curl -sS -m 5 -w "MobSF HTTP %{http_code} (%{time_total}s)\n" http://127.0.0.1:8000/ -o /dev/null || echo "MobSF check failed"

echo "=== 4. Docker Containers ==="
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo "=== 5. Memory & Disk ==="
free -h | awk 'NR==1 || NR==2 {print}'
df -h / | awk 'NR==1 || NR==2 {print}'
```

Verify external TLS + CORS preflight from Windows PowerShell against your live Vercel origin:

```powershell
curl.exe -sS -i -m 8 -X OPTIONS `
  -H "Origin: https://spectre-project.vercel.app" `
  -H "Access-Control-Request-Method: POST" `
  https://spectre-pro.duckdns.org/
```

---

## 9. Dashboard Views

### View 01: Ingestion Hub
* Drag-and-drop `.apk` upload interface with live WebSocket progress streaming across static extraction, Drebin behavioral DNA matching, MobSF/Redroid dynamic detonation, and GenAI synthesis.

### View 02: Advanced Analysis Terminal
* **Composite Risk Vector:** Calibrated 0–100 risk score and 4-tier verdict (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`) backed by the XGBoost v3 classifier.
* **Behavioral Graph Match:** Top family similarity scores, Markov transition frequencies, and class-IDF matches against the Drebin reference inventory.
* **Dual-Layer Network Telemetry:** Isolates active runtime exfiltration streams from dormant static C2 domains and legitimate advertising/analytics endpoints.
* **Permission Matrix Heatmap & Runtime Delta:** Highlights high-risk manifest permissions alongside live MobSF runtime capability usage.
* **Social Engineering Screenplay:** Interactive 4-step attack simulation inside a dynamic mobile phone viewport.

### View 03: GenAI Intelligence Suite
* Automated executive risk briefing and forensic attack reconstruction.
* Regulatory compliance mapping aligned with **RBI Master Direction on Digital Payment Security Controls & Cyber Security Framework (Section 7.4)**.
* Structured MITRE ATT&CK Mobile matrix tagging.

---

## 10. License & Disclaimer

This software is developed strictly for authorized security research, academic evaluation, vulnerability assessment, and malware analysis. All dynamic testing and APK detonation must be conducted exclusively within isolated, sandboxed environments.