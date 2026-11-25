from __future__ import annotations

import logging
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Callable

import joblib
import pandas as pd

from modules.static_analysis import analyze_static
from modules.behavioral_dna import analyze_behavioral_dna, MODERN_FAMILIES
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

V3_FEATURE_COLS = [
    "m1_perm",
    "m2_markov",
    "m2_raw_sim",
    "m2_class_idf",
    "m2_pkg_markov",
    "m2_margin",
    "m2_transitions",
    "m2_closest_modern",
    "m4_social",
    "chain_score",
    "combo_count",
    "suspicious_chain_count",
    "has_trojan_perm",
    "trojan_marker_count",
    "dex_count",
    "is_multidex",
    "apk_size_mb",
    "manifest_parse_error",
]

# Calibrated SPECTRE v3 thresholds (93.15% held-out accuracy, 0.9715 ROC-AUC)
SUSPICIOUS_FLOOR = 0.35
MALICIOUS_THRESHOLD = 0.52

_LOADED_BUNDLE = joblib.load(MODEL_PATH) if MODEL_PATH.is_file() else None
if isinstance(_LOADED_BUNDLE, dict) and "model" in _LOADED_BUNDLE:
    META_MODEL = _LOADED_BUNDLE["model"]
    FEATURE_COLS = list(_LOADED_BUNDLE.get("feature_cols", V3_FEATURE_COLS))
    MALICIOUS_THRESHOLD = float(_LOADED_BUNDLE.get("threshold", 0.52))
else:
    META_MODEL = _LOADED_BUNDLE
    FEATURE_COLS = ["m1_perm", "m2_markov", "m3_runtime", "m5_genai", "has_trojan_perm"]

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

TROJAN_MARKERS = [
    "RECEIVE_BOOT_COMPLETED",
    "SYSTEM_ALERT_WINDOW",
    "BIND_ACCESSIBILITY_SERVICE",
    "READ_SMS",
    "SEND_SMS",
    "REQUEST_INSTALL_PACKAGES",
]


def check_is_official_bank(pkg_name: str) -> bool:
    """Verifies if the package matches registered legitimate Indian retail banking identifiers."""
    pkg = str(pkg_name).lower().strip()
    return any(pattern in pkg for pattern in OFFICIAL_BANK_PATTERNS)


def calculate_final_score(results: dict[str, Any]) -> dict[str, Any]:
    """
    Computes calibrated 0-100 risk score and verdict using the trained SPECTRE v3 meta-classifier.
    """
    static_data = results.get("static") or {}
    dynamic_data = results.get("dynamic") or {}
    social_data = results.get("social") or {}
    behavioral_data = results.get("behavioral") or {}
    genai_data = results.get("genai") or {}
    apk_path = str(results.get("apk_path") or "")

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
            "triage_tier": "CLEAN",
            "malicious_probability": round(bank_score / 100.0, 3),
            "threshold_used": MALICIOUS_THRESHOLD,
            "component_scores": {
                "permission_risk": raw_perm,
                "behavioral_family": float(behavioral_data.get("behavioral_score", 0.0)),
                "dynamic_runtime": float(dynamic_data.get("dynamic_risk_score", 0.0)),
                "social_engineering": float(social_data.get("social_engineering_score", 0.0)),
                "genai_severity": float(genai_data.get("genai_score", 0.0)),
            },
        }

    # -------------------------------------------------------------------------
    # Telemetry Feature Extraction (18-feature SPECTRE v3 vector)
    # -------------------------------------------------------------------------
    m1_val = min(100.0, max(0.0, float(
        static_data.get("permission_risk")
        or static_data.get("permission_score", 0.0)
        or 0.0
    )))
    m2_val = float(
        behavioral_data.get("behavioral_score")
        or behavioral_data.get("similarity_score", 0.0)
        or 0.0
    )
    m2_raw_sim = float(behavioral_data.get("behavioral_similarity", m2_val / 100.0) or 0.0)
    m2_class_idf = float(behavioral_data.get("class_idf_score", 0.0) or 0.0)
    m2_pkg_markov = float(behavioral_data.get("package_markov_score", 0.0) or 0.0)
    m2_margin = float(behavioral_data.get("top1_margin", 0.0) or 0.0)
    m2_transitions = int(behavioral_data.get("unique_class_transitions", 0) or 0)
    closest_fam = str(behavioral_data.get("closest_family", ""))
    m2_closest_modern = int(
        behavioral_data.get("closest_modern_family", 1 if closest_fam in MODERN_FAMILIES else 0)
    )

    m3_val = float(dynamic_data.get("dynamic_risk_score", 0.0) or 0.0)
    m4_val = float(
        social_data.get("social_engineering_score")
        or social_data.get("social_score", 0.0)
        or 0.0
    )
    m5_val = float(
        genai_data.get("genai_score")
        or genai_data.get("severity_score", 0.0)
        or 0.0
    )

    raw_chain = (
        static_data.get("api_chain_score")
        or static_data.get("chain_score")
        or dynamic_data.get("api_chain_score", 0.0)
    )
    chain_val = float(raw_chain or 0.0)
    combo_count = len(static_data.get("combo_alerts") or [])
    suspicious_chain_count = len(static_data.get("suspicious_api_chains") or [])

    exfil_events = dynamic_data.get("exfiltration_events") or []
    net_val = float(min(100.0, len(exfil_events) * 25.0))

    static_upper = str(static_data).upper()
    trojan_hits = sum(1 for marker in TROJAN_MARKERS if marker in static_upper)
    has_trojan_perm = 1 if trojan_hits > 0 else 0
    manifest_parse_error = 1 if static_data.get("status") == "error" or not static_data.get("package_name") else 0

    dex_count = int(static_data.get("dex_files") or behavioral_data.get("dex_files") or 0)
    apk_size_mb = 0.0
    if apk_path:
        p_obj = Path(apk_path)
        if p_obj.exists():
            apk_size_mb = round(p_obj.stat().st_size / (1024 * 1024), 3)
            if dex_count <= 0:
                try:
                    with zipfile.ZipFile(p_obj, "r") as zf:
                        dex_count = sum(1 for n in zf.namelist() if n.startswith("classes") and n.endswith(".dex"))
                except Exception:
                    dex_count = 0

    all_features = {
        "m1_perm": m1_val,
        "m2_markov": m2_val,
        "m2_raw_sim": m2_raw_sim,
        "m2_class_idf": m2_class_idf,
        "m2_pkg_markov": m2_pkg_markov,
        "m2_margin": m2_margin,
        "m2_transitions": m2_transitions,
        "m2_closest_modern": m2_closest_modern,
        "m3_runtime": m3_val,
        "m4_social": m4_val,
        "m5_genai": m5_val,
        "chain_score": chain_val,
        "combo_count": combo_count,
        "suspicious_chain_count": suspicious_chain_count,
        "has_trojan_perm": has_trojan_perm,
        "trojan_marker_count": trojan_hits,
        "dex_count": dex_count,
        "is_multidex": 1 if dex_count > 1 else 0,
        "apk_size_mb": apk_size_mb,
        "manifest_parse_error": manifest_parse_error,
    }

    input_df = pd.DataFrame([{col: all_features[col] for col in FEATURE_COLS}])[FEATURE_COLS]

    # -------------------------------------------------------------------------
    # Meta-Classifier Prediction
    # -------------------------------------------------------------------------
    if META_MODEL is not None:
        malicious_prob = float(META_MODEL.predict_proba(input_df)[0][1])
        # Runtime escalation boost if dynamic sandbox observed confirmed exfiltration
        if m3_val >= 70.0 and malicious_prob < MALICIOUS_THRESHOLD:
            malicious_prob = max(malicious_prob, min(0.95, m3_val / 100.0))
        final_score = round(malicious_prob * 100.0)
    else:
        fallback_val = (
            (m1_val * 0.25)
            + (m2_val * 0.35)
            + (m3_val * 0.15)
            + (m4_val * 0.15)
            + (chain_val * 0.10)
        )
        final_score = round(min(100.0, max(0.0, fallback_val)))
        malicious_prob = final_score / 100.0

    # -------------------------------------------------------------------------
    # Calibrated Operational Verdict (Synchronized with 0.35 / 0.52 v3 bands)
    # -------------------------------------------------------------------------
    if malicious_prob >= 0.80:
        verdict = "CRITICAL"
        triage_tier = "MALICIOUS"
    elif malicious_prob >= MALICIOUS_THRESHOLD:
        verdict = "HIGH"
        triage_tier = "MALICIOUS"
    elif malicious_prob >= SUSPICIOUS_FLOOR:
        verdict = "MODERATE"
        triage_tier = "SUSPICIOUS"
    else:
        verdict = "LOW"
        triage_tier = "CLEAN"

    return {
        "score": final_score,
        "verdict": verdict,
        "triage_tier": triage_tier,
        "malicious_probability": round(malicious_prob, 4),
        "threshold_used": MALICIOUS_THRESHOLD,
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

    # Module 2: Behavioral DNA (v3 195-family vectorized scorer)
    print("[PIPELINE] M2: Behavioral DNA starting...")
    results["behavioral"] = analyze_behavioral_dna(apk_path)
    m2_score = results["behavioral"].get("behavioral_score", 0.0)
    print(f"[PIPELINE] M2: Done. Score: {m2_score:.6f} ({results['behavioral'].get('closest_family', 'unknown')})")

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
    if "storyboard" in results["social"]:
        results["storyboard"] = results["social"]["storyboard"]
    if "app_name" in results["social"]:
        results["static"]["app_name"] = results["social"]["app_name"]
        results["app_name"] = results["social"]["app_name"]

    if is_official_bank:
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

    # Module 5: GenAI Synthesis
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