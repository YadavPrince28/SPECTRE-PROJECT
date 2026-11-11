from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Callable
import pandas as pd
import joblib

from modules.static_analysis import analyze_static
from modules.behavioral_dna import analyze_behavioral_dna
from modules.dynamic_analysis import analyze_dynamic
from modules.social_engineering import analyze_social_engineering
from modules.genai_layer import analyze_genai

# -----------------------------------------------------------------------------
# Storage & Temporary Directory Setup (Strictly pinned to D: drive)
# -----------------------------------------------------------------------------
D_TEMP = Path(r"D:\Spectre_BOI_project\temp")
D_TEMP.mkdir(parents=True, exist_ok=True)
os.environ["TEMP"] = str(D_TEMP)
os.environ["TMP"] = str(D_TEMP)
tempfile.tempdir = str(D_TEMP)

logger = logging.getLogger("spectre.pipeline")

MODEL_PATH = Path(__file__).resolve().parent / "models" / "meta_classifier.joblib"
META_MODEL = joblib.load(MODEL_PATH) if MODEL_PATH.is_file() else None

FEATURE_COLS = [
    "m1_perm",
    "m2_markov",
    "m3_runtime",
    "m5_genai",
    "has_trojan_perm",
]

BENIGN_INFRASTRUCTURE = [
    "googleads",
    "doubleclick",
    "google.com",
    "googleapis",
    "gstatic",
    "facebook",
    "crashlytics",
    "firebase",
    "appsflyer",
    "branch.io",
    "amazon-adsystem",
]

OFFICIAL_BANK_PATTERNS = [
    "com.boi.ua.android",
    "com.sbi.lotusintouch",
    "com.sbi.sbifreedomplus",
    "com.sbi",
    "com.boi",
    "com.axis.mobile",
    "com.csam.icici.bank.imobile",
    "com.snapwork.hdfc",
    "com.msf.kbank.mobile",
    "com.canarabank.mobility",
    "com.snapwork.idbi",
    "com.version1",
    "com.infrasoft.uboi",
    "com.bankofbaroda.mconnect",
    "com.ausmallfinancebank.amb",
    "bankofbaroda",
    "canarabank",
    "hdfcbank",
    "icicibank",
    "kotak",
]


def check_is_official_bank(pkg_name: str) -> bool:
    """Verifies if the package matches registered legitimate Indian retail banking identifiers."""
    pkg = str(pkg_name).lower().strip()
    for pattern in OFFICIAL_BANK_PATTERNS:
        if pattern in pkg:
            return True
    return False


def calculate_final_score(results: dict[str, Any]) -> dict[str, Any]:
    """
    Computes calibrated 0-100 risk score and verdict using the trained meta-classifier.
    """
    static_data = results.get("static") or {}
    dynamic_data = results.get("dynamic") or {}
    social_data = results.get("social") or {}
    behavioral_data = results.get("behavioral") or {}
    genai_data = results.get("genai") or {}

    pkg = str(static_data.get("package_name") or dynamic_data.get("package_name") or "").lower()

    # -------------------------------------------------------------------------
    # Tier 0: Authenticity Authority (Legitimate Banking Anchor)
    # -------------------------------------------------------------------------
    if check_is_official_bank(pkg):
        raw_perm = float(static_data.get("permission_risk") or static_data.get("permission_score", 0.0))
        bank_score = round(min(15.0, raw_perm * 0.15))
        return {
            "score": bank_score,
            "verdict": "LOW",
            "malicious_probability": round(bank_score / 100.0, 3),
            "component_scores": {
                "permission_risk": raw_perm,
                "behavioral_family": float(behavioral_data.get("behavioral_score", 0.0)),
                "dynamic_runtime": float(dynamic_data.get("dynamic_risk_score", 0.0)),
                "social_engineering": float(social_data.get("social_engineering_score", 0.0)),
                "genai_severity": float(genai_data.get("genai_score", 0.0)),
            },
        }

    # -------------------------------------------------------------------------
    # Telemetry Feature Extraction
    # -------------------------------------------------------------------------
    m1_val = float(
        static_data.get("permission_risk")
        or static_data.get("permission_score", 0.0)
    )
    m2_val = float(
        behavioral_data.get("behavioral_score")
        or behavioral_data.get("similarity_score", 0.0)
    )
    m3_val = float(dynamic_data.get("dynamic_risk_score", 0.0))
    m4_val = float(
        social_data.get("social_engineering_score")
        or social_data.get("social_score", 0.0)
    )
    m5_val = float(
        genai_data.get("genai_score")
        or genai_data.get("severity_score", 0.0)
    )

    raw_chain = (
        dynamic_data.get("api_chain_score")
        or static_data.get("api_chain_score")
        or static_data.get("chain_score", 0.0)
    )
    chain_val = float(raw_chain or 0.0)

    exfil_events = dynamic_data.get("exfiltration_events") or []
    net_val = float(min(100.0, len(exfil_events) * 25.0))

    # String-safe inspection for trojan persistence & ad SDKs
    static_str = str(static_data).upper()
    trojan_markers = [
        "RECEIVE_BOOT_COMPLETED",
        "SYSTEM_ALERT_WINDOW",
        "BIND_ACCESSIBILITY_SERVICE",
        "READ_SMS",
        "SEND_SMS",
        "REQUEST_INSTALL_PACKAGES",
    ]
    has_trojan_perm = 1 if any(p in static_str for p in trojan_markers) else 0

    static_lower = str(static_data).lower()
    ad_markers = [
        "google.android.gms.ads",
        "unity3d",
        "applovin",
        "ironsource",
        "vungle",
        "chartboost",
    ]
    has_ad_sdk = 1 if any(sdk in static_lower for sdk in ad_markers) else 0

# In calculate_final_score() inside backend/pipeline.py:
    feature_dict = {
        "m1_perm": [m1_val],
        "m2_markov": [m2_val],
        "m3_runtime": [m3_val],
        "m5_genai": [m5_val],
        "has_trojan_perm": [has_trojan_perm],
    }
    input_df = pd.DataFrame(feature_dict)[FEATURE_COLS]

    # -------------------------------------------------------------------------
    # Meta-Classifier Prediction
    # -------------------------------------------------------------------------
    if META_MODEL is not None:
        malicious_prob = float(META_MODEL.predict_proba(input_df)[0][1])
        final_score = round(malicious_prob * 100.0)
    else:
        # Fallback weighted heuristic if model file is unavailable
        fallback_val = (
            (m1_val * 0.15)
            + (m2_val * 0.25)
            + (m3_val * 0.10)
            + (m5_val * 0.15)
            + (chain_val * 0.15)
            + (net_val * 0.20)
        )
        final_score = round(min(100.0, max(0.0, fallback_val)))
        malicious_prob = final_score / 100.0

    # -------------------------------------------------------------------------
    # Calibrated Operational Verdict
    # -------------------------------------------------------------------------
# Synchronized 4-Tier Scale
    if final_score >= 81:
        verdict = "CRITICAL"
    elif final_score >= 61:
        verdict = "HIGH"
    elif final_score >= 31:
        verdict = "MODERATE"
    else:
        verdict = "LOW"

    return {
        "score": final_score,
        "verdict": verdict,
        "malicious_probability": round(malicious_prob, 3),
        "component_scores": {
            "permission_risk": m1_val,
            "behavioral_family": m2_val,
            "dynamic_runtime": m3_val,
            "social_engineering": m4_val,
            "genai_severity": m5_val,
            "malicious_api_chain": chain_val,
            "network_exfiltration": net_val,
        },
    }

def run_pipeline(
    apk_path: str,
    job_id: str = "spectre_job",
    telemetry_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Coordinates end-to-end multi-vector analysis across all 5 SPECTRE modules."""
    print(f"\n[PIPELINE] Starting analysis: {apk_path}")
    results: dict[str, Any] = {
        "job_id": job_id,
        "apk_path": apk_path,
        "status": "running",
    }

    # Module 1: Static Analysis
    print("[PIPELINE] M1: Static Analysis starting...")
    results["static"] = analyze_static(apk_path)
    raw_m1 = results["static"].get("permission_score", 0.0)
    m1_score = min(100.0, max(0.0, float(raw_m1)))
    results["static"]["permission_score"] = m1_score
    print(f"[PIPELINE] M1: Done. Score: {m1_score:.0f}")

    pkg_name = str(results["static"].get("package_name", "")).lower()
    is_official_bank = check_is_official_bank(pkg_name)

    # Module 2: Behavioral DNA
    print("[PIPELINE] M2: Behavioral DNA starting...")
    results["behavioral"] = analyze_behavioral_dna(apk_path)
    m2_score = results["behavioral"].get("behavioral_score", 0.0)
    print(f"[PIPELINE] M2: Done. Score: {m2_score:.6f}")

    # Module 3: Dynamic Sandbox
    print("[PIPELINE] M3: Dynamic Analysis starting...")
    results["dynamic"] = analyze_dynamic(
        apk_path=apk_path,
        job_id=job_id,
        static_result=results.get("static"),
        telemetry_callback=telemetry_callback,
    )
    m3_score = results["dynamic"].get("dynamic_risk_score", 0)
    print(f"[PIPELINE] M3: Done. Score: {m3_score} (Status: {results['dynamic'].get('status', 'complete')})")

    # Module 4: Social Engineering (With Official Bank Recognition)
    print("[PIPELINE] M4: Social Engineering starting...")
    results["social"] = analyze_social_engineering(
        apk_path=apk_path,
        job_id=job_id,
        static_result=results.get("static"),
    )
    # Forward app_name & storyboard directly
    if "storyboard" in results["social"]:
        results["storyboard"] = results["social"]["storyboard"]
    if "app_name" in results["social"]:
        results["static"]["app_name"] = results["social"]["app_name"]
        results["app_name"] = results["social"]["app_name"]

    if is_official_bank:
        # Authenticity Authority: Official bank binary is not a phishing lure
        results["social"]["archetype"] = "BENIGN_OFFICIAL_BANK"
        results["social"]["social_engineering_score"] = 0.0
        results["social"]["social_score"] = 0.0
        results["social"]["authenticity"] = {
            "status": "AUTHENTIC_OFFICIAL_BANK",
            "bank_name": "Bank of India" if "boi" in pkg_name else "Official Banking Institution",
        }

    print(f"[PIPELINE] M4: Done. Score: {results['social'].get('social_engineering_score', 0.0)}")

    if "authenticity" in results["social"] and "static" in results:
        results["static"]["authenticity"] = results["social"]["authenticity"]
    if "storyboard" in results["social"]:
        results["storyboard"] = results["social"]["storyboard"]

    # Module 5: GenAI Synthesis (Fed Complete Verified Telemetry)
    print("[PIPELINE] M5: GenAI Layer starting...")
    results["genai"] = analyze_genai(results)
    print(f"[PIPELINE] M5: Done. Score: {results['genai'].get('genai_score', 0.0)}")

    # Final Risk Aggregation
    print("[PIPELINE] Calculating final risk score...")
    results["final_score"] = calculate_final_score(results)
    final_verdict = results["final_score"]["verdict"]
    final_val = results["final_score"]["score"]
    print(f"[PIPELINE] Complete. Final score: {final_val} — {final_verdict}")

    results["status"] = "complete"
    return results