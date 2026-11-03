

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import math
import os
import sys
import time
from collections import Counter
from pathlib import Path

import numpy as np

from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    GridSearchCV,
    StratifiedKFold,
)


ROOT = Path(r"D:\Spectre_BOI_project\SPECTRE")
VALIDATION_DIR = ROOT / "data" / "validation"
PRIMARY_MANIFEST = VALIDATION_DIR / "module2_validation_manifest.csv"
PRIMARY_DIR = VALIDATION_DIR / "apks"
BANKING_MANIFEST = VALIDATION_DIR / "legitimate_banking_manifest.csv"
BANKING_DIR = VALIDATION_DIR / "banking_apks"

DEFAULT_MODULE = ROOT / "backend" / "modules" / "static_analysis_spectre_v5_1_api_chain_flow.py"
DEFAULT_MODEL = ROOT / "models" / "module1_api_chain_calibrator_v5_20apk.joblib"
DEFAULT_METADATA = ROOT / "models" / "module1_api_chain_calibrator_v5_20apk.json"
DEFAULT_FEATURES = ROOT / "models" / "module1_api_chain_evidence_v5_20apk.csv"
DEFAULT_OOF = ROOT / "models" / "module1_api_chain_oof_v5_20apk.csv"
DEFAULT_BANKING = ROOT / "models" / "module1_api_chain_banking_holdout_v5_20apk.csv"
DEFAULT_REPORT = ROOT / "models" / "module1_api_chain_calibration_report_v5_20apk.txt"

EXPECTED_PRIMARY = {"malicious": 75, "benign": 75}
EXPECTED_BANKING = 20
QUICK_MALICIOUS = 10
QUICK_BENIGN = 10
QUICK_TOTAL = QUICK_MALICIOUS + QUICK_BENIGN


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def load_module(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"V5 analyzer not found: {path}")
    spec = importlib.util.spec_from_file_location("spectre_m1_v5", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load analyzer: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path, apk_dir: Path, *, cohort_override: str | None = None) -> list[dict]:
    """Load a validation manifest with schema-tolerant metadata handling.

    Primary 150 manifest is expected to contain cohort/package/VT metadata.
    The legitimate-banking holdout manifest predates that schema and may omit
    pkg_name and/or vt_detection, so those fields are normalized when present
    and never required for the holdout.
    """
    if not path.exists():
        raise FileNotFoundError(f"Manifest not found: {path}")

    with path.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    if not rows:
        raise RuntimeError(f"Manifest {path} is empty")
    if "sha256" not in rows[0]:
        raise RuntimeError(f"Manifest {path} missing required column: sha256")

    # Normalize common package-name aliases so downstream reporting works
    # with both the primary and legacy legitimate-banking manifest schemas.
    package_aliases = (
        "pkg_name",
        "package_name",
        "package",
        "app_package",
    )
    vt_aliases = (
        "vt_detection",
        "vt",
        "virus_total_detection",
    )

    out = []
    for row in rows:
        normalized = dict(row)

        if not normalized.get("pkg_name", "").strip():
            for key in package_aliases[1:]:
                value = str(normalized.get(key, "")).strip()
                if value:
                    normalized["pkg_name"] = value
                    break
            else:
                normalized["pkg_name"] = ""

        if not normalized.get("vt_detection", "").strip():
            for key in vt_aliases[1:]:
                value = str(normalized.get(key, "")).strip()
                if value:
                    normalized["vt_detection"] = value
                    break
            else:
                normalized["vt_detection"] = ""

        if cohort_override is not None:
            normalized["cohort"] = cohort_override
        elif not str(normalized.get("cohort", "")).strip():
            raise RuntimeError(
                f"Manifest {path} missing cohort; pass cohort_override for a holdout manifest"
            )
        else:
            normalized["cohort"] = str(normalized["cohort"]).strip().lower()

        sha = str(normalized["sha256"]).strip().lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise RuntimeError(f"Invalid SHA256 in {path}: {sha}")

        apk = apk_dir / f"{sha}.apk"
        if not apk.exists():
            raise FileNotFoundError(f"APK missing for manifest row: {apk}")

        normalized["sha256"] = sha
        normalized["_apk"] = str(apk)
        out.append(normalized)

    return out


def validate_primary(rows: list[dict]) -> None:
    counts = Counter(r["cohort"].strip().lower() for r in rows)
    if counts.get("malicious", 0) != EXPECTED_PRIMARY["malicious"]:
        raise RuntimeError(f"Primary malicious count must be 75, got {counts.get('malicious', 0)}")
    if counts.get("benign", 0) != EXPECTED_PRIMARY["benign"]:
        raise RuntimeError(f"Primary benign count must be 75, got {counts.get('benign', 0)}")
    if len(rows) != 150:
        raise RuntimeError(f"Primary manifest must contain exactly 150 rows, got {len(rows)}")
    shas = [r["sha256"] for r in rows]
    if len(shas) != len(set(shas)):
        raise RuntimeError("Primary manifest contains duplicate SHA256 values")


def validate_banking(rows: list[dict]) -> None:
    if len(rows) != EXPECTED_BANKING:
        raise RuntimeError(f"Legitimate banking holdout must contain 20 rows, got {len(rows)}")
    shas = [r["sha256"] for r in rows]
    if len(shas) != len(set(shas)):
        raise RuntimeError("Banking holdout contains duplicate SHA256 values")


def _json_safe(value):
    """Convert common non-JSON-native values emitted by analyzers to JSON-safe types."""
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_json_safe(v) for v in value), key=lambda x: str(x))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, np.ndarray):
        return [_json_safe(v) for v in value.tolist()]
    return value


def run_extraction(module, row: dict, verify_sha: bool = True) -> dict:
    apk = Path(row["_apk"])
    if verify_sha:
        actual = sha256_file(apk)
        if actual != row["sha256"]:
            raise RuntimeError(f"SHA256 mismatch for {apk.name}: expected {row['sha256']}, got {actual}")
    start = time.perf_counter()
    result = module.analyze_static(str(apk))
    elapsed = time.perf_counter() - start
    if result.get("status") != "complete":
        raise RuntimeError(f"Analyzer status={result.get('status')}: {result.get('error', '')}")
    features = result.get("api_chain_feature_vector", {}) or {}
    names = list(module.API_FEATURE_NAMES)
    missing = [name for name in names if name not in features]
    if missing:
        raise RuntimeError(f"Analyzer did not emit required feature(s): {missing}")
    out = {
        "cohort": row.get("cohort", "").strip().lower(),
        "true_label": 1 if row.get("cohort", "").strip().lower() == "malicious" else 0,
        "sha256": row["sha256"],
        "pkg_name_manifest": row.get("pkg_name", ""),
        "package_name_detected": result.get("package_name", ""),
        "vt_detection": row.get("vt_detection", ""),
        "apk": str(apk),
        "api_chain_status": result.get("api_chain_score_status", "NOT_CALIBRATED"),
        "authenticity": result.get("authenticity", {}).get("status", "unknown"),
        "chain_count": int(result.get("chain_count", 0) or 0),
        "dataflow_finding_count": int(features.get("dataflow_finding_count", 0)),
        "ordered_control_finding_count": int(features.get("ordered_control_finding_count", 0)),
        "strong_finding_count": int(features.get("strong_finding_count", 0)),
        "medium_finding_count": int(features.get("medium_finding_count", 0)),
        "elapsed_seconds": round(elapsed, 3),
        "rule_counts_json": json.dumps(_json_safe(result.get("api_chain_rule_counts", {})), sort_keys=True),
        "suspicious_chains_json": json.dumps(_json_safe((result.get("suspicious_api_chains", []) or [])[:100]), sort_keys=True),
    }
    for name in names:
        out[name] = float(features.get(name, 0.0))
    return out


def select_c(X, y, seed: int):
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    base = LogisticRegression(
        solver="liblinear",
        max_iter=5000,
        random_state=seed,
    )
    grid = GridSearchCV(
        base,
        {"C": [0.01, 0.03, 0.1, 0.3, 1.0, 3.0, 10.0, 30.0]},
        scoring="roc_auc",
        cv=cv,
        n_jobs=-1,
        refit=True,
    )
    grid.fit(X, y)
    return grid.best_estimator_, float(grid.best_params_["C"]), float(grid.best_score_)


def nested_oof_calibrated(X: np.ndarray, y: np.ndarray, seed: int) -> tuple[np.ndarray, list[dict]]:
    """Nested 5x5 CV: choose C inside each outer train fold, calibrate inside that fold, predict outer test."""
    outer = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    probs = np.zeros(len(y), dtype=float)
    fold_records = []
    for fold, (train_idx, test_idx) in enumerate(outer.split(X, y), start=1):
        Xtr, Xte = X[train_idx], X[test_idx]
        ytr = y[train_idx]
        fold_model, fold_c, fold_grid_auc = select_c(Xtr, ytr, seed + fold)
        fold_calibrated = CalibratedClassifierCV(
            estimator=fold_model,
            method="sigmoid",
            cv=5,
            ensemble=False,
        )
        fold_calibrated.fit(Xtr, ytr)
        probs[test_idx] = fold_calibrated.predict_proba(Xte)[:, 1]
        fold_records.append({"fold": fold, "C": fold_c, "grid_cv_auc": fold_grid_auc, "train_n": len(train_idx), "test_n": len(test_idx)})
    return probs, fold_records


def candidate_thresholds(probs: np.ndarray) -> list[float]:
    vals = sorted(set(float(x) for x in probs))
    # Include conventional boundaries for complete coverage.
    return [0.0] + vals + [1.0]


def threshold_metrics(y: np.ndarray, p: np.ndarray, threshold: float) -> dict:
    pred = (p >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    tpr = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "threshold": float(threshold),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "tpr": tpr, "fpr": fpr,
        "balanced_accuracy": 0.5 * (tpr + (tn / (tn + fp) if (tn + fp) else 0.0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "youden_j": tpr - fpr,
    }


def choose_threshold(y: np.ndarray, p: np.ndarray) -> tuple[dict, dict, dict]:
    metrics = [threshold_metrics(y, p, t) for t in candidate_thresholds(p)]
    best_youden = max(metrics, key=lambda m: (m["youden_j"], m["balanced_accuracy"], -m["threshold"]))
    fpr5 = [m for m in metrics if m["fpr"] <= 0.05 and m["tpr"] > 0]
    best_fpr5 = max(fpr5, key=lambda m: (m["tpr"], m["youden_j"], -m["threshold"])) if fpr5 else None
    best_f1 = max(metrics, key=lambda m: (m["f1"], m["balanced_accuracy"], -m["threshold"]))
    return best_youden, best_f1, best_fpr5


def summarize_scores(rows: list[dict], prob_key: str) -> dict:
    by = {}
    for label_name in ("malicious", "benign", "legitimate_banking"):
        vals = [float(r[prob_key]) for r in rows if r.get("cohort") == label_name]
        if vals:
            by[label_name] = {
                "n": len(vals),
                "min": min(vals),
                "median": float(np.median(vals)),
                "mean": float(np.mean(vals)),
                "max": max(vals),
            }
    return by


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", type=Path, default=DEFAULT_MODULE)
    ap.add_argument("--primary-manifest", type=Path, default=PRIMARY_MANIFEST)
    ap.add_argument("--primary-dir", type=Path, default=PRIMARY_DIR)
    ap.add_argument("--banking-manifest", type=Path, default=BANKING_MANIFEST)
    ap.add_argument("--banking-dir", type=Path, default=BANKING_DIR)
    ap.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    ap.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    ap.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    ap.add_argument("--oof", type=Path, default=DEFAULT_OOF)
    ap.add_argument("--banking-output", type=Path, default=DEFAULT_BANKING)
    ap.add_argument("--report", type=Path, default=DEFAULT_REPORT)
    ap.add_argument("--seed", type=int, default=20261008)
    ap.add_argument("--malicious-limit", type=int, default=QUICK_MALICIOUS)
    ap.add_argument("--benign-limit", type=int, default=QUICK_BENIGN)
    ap.add_argument("--skip-sha", action="store_true")
    args = ap.parse_args()

    if args.malicious_limit + args.benign_limit != QUICK_TOTAL:
        raise RuntimeError(
            f"This quick calibration intentionally uses exactly {QUICK_TOTAL} APKs: "
            f"{QUICK_MALICIOUS} malicious + {QUICK_BENIGN} benign."
        )
    if args.malicious_limit < 5 or args.benign_limit < 5:
        raise RuntimeError("Need at least 5 samples per class for the 5-fold exploratory CV.")

    module = load_module(args.module)
    primary = load_manifest(args.primary_manifest, args.primary_dir)
    validate_primary(primary)

    malicious = [r for r in primary if r["cohort"].strip().lower() == "malicious"]
    benign = [r for r in primary if r["cohort"].strip().lower() == "benign"]
    # Deterministic selection from the manifest order; no score-based cherry-picking.
    quick_primary = malicious[:args.malicious_limit] + benign[:args.benign_limit]

    if len(quick_primary) != QUICK_TOTAL:
        raise RuntimeError(f"Could not build the required {QUICK_TOTAL}-APK balanced subset.")

    print("=" * 100)
    print("SPECTRE MODULE 1 — API-CHAIN V5 EVIDENCE CALIBRATION (20-APK QUICK RUN)")
    print("=" * 100)
    print(f"Primary subset : {len(quick_primary)} APKs ({args.malicious_limit} malicious + {args.benign_limit} benign)")
    print("Legitimate banking holdout : NOT USED in this 20-APK run")
    print("Numeric API score is disabled during feature extraction.")
    print("This is an exploratory calibration run, not the final validation benchmark.")
    print()

    feature_rows = []
    all_rows = [(r, "primary") for r in quick_primary]
    for idx, (row, source_set) in enumerate(all_rows, start=1):
        label = row.get("cohort", "").strip().lower() or source_set
        print(f"[{idx:03d}/{len(all_rows)}] {source_set:<20} {row['sha256'][:16]} {row.get('pkg_name','')[:42]}", flush=True)
        extracted = run_extraction(module, row, verify_sha=not args.skip_sha)
        extracted["source_set"] = source_set
        if source_set == "legitimate_banking":
            extracted["cohort"] = "legitimate_banking"
            extracted["true_label"] = 0
        feature_rows.append(extracted)
        print(f"    chains={extracted['chain_count']} dataflow={extracted['dataflow_finding_count']} control={extracted['ordered_control_finding_count']}", flush=True)

    names = list(module.API_FEATURE_NAMES)
    primary_rows = [r for r in feature_rows if r["source_set"] == "primary"]
    banking_rows = [r for r in feature_rows if r["source_set"] == "legitimate_banking"]
    X = np.array([[r[name] for name in names] for r in primary_rows], dtype=float)
    y = np.array([r["true_label"] for r in primary_rows], dtype=int)
    X_bank = np.array([[r[name] for name in names] for r in banking_rows], dtype=float)

    varying = [name for i, name in enumerate(names) if np.ptp(X[:, i]) > 0]
    if not varying:
        raise RuntimeError(f"All API-chain evidence features are zero/constant on the {len(primary_rows)}-APK quick subset. Do not fit a fake score. Fix extraction first.")

    # Final C is selected on all 150 development labels for the deployed model.
    base_model, best_c, grid_auc = select_c(X, y, args.seed)

    # Honest nested OOF probabilities: hyperparameter selection and calibration
    # happen inside each outer fold, so the held-out fold is never used to choose C.
    oof_prob, nested_folds = nested_oof_calibrated(X, y, args.seed + 1)

    oof_auc = float(roc_auc_score(y, oof_prob))
    oof_ap = float(average_precision_score(y, oof_prob))
    oof_brier = float(brier_score_loss(y, oof_prob))
    oof_logloss = float(log_loss(y, np.c_[1 - oof_prob, oof_prob], labels=[0, 1]))
    youden, best_f1, fpr5 = choose_threshold(y, oof_prob)

    # Fit final calibrated model on the 20-APK exploratory calibration subset.
    final_calibrated = CalibratedClassifierCV(
        estimator=base_model,
        method="sigmoid",
        cv=5,
        ensemble=False,
    )
    final_calibrated.fit(X, y)
    base_model.fit(X, y)

    # Exploratory in-sample probabilities are used only to illustrate the
    # learned score distribution. Independent performance is represented by OOF.
    train_prob = final_calibrated.predict_proba(X)[:, 1]

    for r, p in zip(primary_rows, train_prob):
        r["calibrated_probability_in_final_model"] = float(p)
        r["api_chain_score_final_model"] = int(round(100 * p))

    bank_prob = np.array([], dtype=float)
    bank_eval = {}

    # Save the actual model. The analyzer consumes this object and its feature order.
    for output_path in (args.model, args.metadata, args.features, args.oof, args.banking_output, args.report):
        output_path.parent.mkdir(parents=True, exist_ok=True)
    import joblib
    payload = {
        "model": final_calibrated,
        "base_model": base_model,
        "feature_names": names,
        "metadata": {
            "model_version": "module1_api_chain_calibrator_v5",
            "trained_on": "20-APK exploratory primary subset (10 malicious + 10 benign)",
            "primary_counts": {"malicious": args.malicious_limit, "benign": args.benign_limit},
            "external_holdout": "not used in quick run",
            "regularization_C": best_c,
            "nested_oof_folds": nested_folds,
            "grid_cv_auc": grid_auc,
            "calibration": "sigmoid / Platt-style, 5-fold CV, ensemble=False",
            "feature_extraction": "method-local intra-procedural register-taint evidence + conservative control-sequence evidence",
            "score_definition": "100 * calibrated P(MALICIOUS | API-chain evidence)",
            "threshold_selection": "reported from OOF probabilities; threshold does not alter the stored score",
            "selected_threshold_youden": youden,
            "selected_threshold_best_f1": best_f1,
            "selected_threshold_fpr5": fpr5,
            "external_bank_holdout_at_thresholds": bank_eval,
            "seed": args.seed,
        },
    }
    joblib.dump(payload, args.model)

    # Write evidence/features CSV.
    all_feature_fields = [
        "source_set", "cohort", "true_label", "sha256", "pkg_name_manifest", "package_name_detected",
        "vt_detection", "apk", "api_chain_status", "chain_count", "dataflow_finding_count",
        "ordered_control_finding_count", "strong_finding_count", "medium_finding_count", "elapsed_seconds",
        "rule_counts_json", "suspicious_chains_json",
    ] + names
    with args.features.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=all_feature_fields)
        w.writeheader()
        for r in feature_rows:
            w.writerow({k: r.get(k, "") for k in all_feature_fields})

    # OOF output for honest evaluation.
    oof_rows = []
    for r, p in zip(primary_rows, oof_prob):
        rr = {
            "sha256": r["sha256"], "package_name": r["package_name_detected"], "true_label": r["true_label"],
            "cohort": r["cohort"], "oof_probability": float(p), "oof_score": int(round(100 * p)),
        }
        oof_rows.append(rr)
    with args.oof.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(oof_rows[0].keys()))
        w.writeheader(); w.writerows(oof_rows)

    # Banking holdout is intentionally not evaluated in the 20-APK quick run.
    with args.banking_output.open("w", encoding="utf-8", newline="") as f:
        fields = ["sha256", "package_name", "probability", "api_chain_score", "vt_detection", "authenticity"]
        csv.DictWriter(f, fieldnames=fields).writeheader()

    # Metadata JSON.
    score_distribution = {
        "primary_final_model": summarize_scores(
            [{**r, "cohort": r["cohort"], "prob": r["calibrated_probability_in_final_model"]} for r in primary_rows], "prob"
        ),
        "primary_oof": summarize_scores(
            [{**r, "prob": float(p)} for r, p in zip(primary_rows, oof_prob)], "prob"
        ),
        "legitimate_banking_holdout": {
            "n": 0,
            "status": "not_used_in_20apk_quick_run",
        },
    }
    metadata = {
        "model_path": str(args.model),
        "feature_count": len(names),
        "feature_names": names,
        "nonconstant_features_on_primary": varying,
        "selected_C": best_c,
        "inner_grid_cv_auc": grid_auc,
        "nested_oof_folds": nested_folds,
        "oof_metrics": {
            "roc_auc": oof_auc,
            "average_precision": oof_ap,
            "brier_score": oof_brier,
            "log_loss": oof_logloss,
        },
        "oof_thresholds": {"youden": youden, "best_f1": best_f1, "best_tpr_at_fpr_le_5pct": fpr5},
        "banking_holdout_threshold_evaluation": {"status": "not_used_in_20apk_quick_run"},
        "score_definition": "100 * calibrated P(MALICIOUS | API-chain evidence)",
        "score_semantics": "risk-oriented probability derived from the labeled calibration corpus; not a probability of real-world compromise",
        "score_distribution": score_distribution,
        "caveat": "This report is based on only 20 primary APKs (10 malicious + 10 benign) for exploratory calibration. It is not a final independent benchmark. The separate 20 legitimate banking apps were intentionally not used in this run.",
    }
    args.metadata.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    report = []
    report.append("=" * 100)
    report.append("SPECTRE MODULE 1 — API-CHAIN V5 CALIBRATION REPORT")
    report.append("=" * 100)
    report.append("")
    report.append("METHOD")
    report.append("- Evidence extraction: intra-procedural register-taint + conservative control-sequence evidence")
    report.append("- Numeric score: 100 * calibrated P(MALICIOUS | evidence)")
    report.append("- Training/development: 20 APKs = 10 malicious + 10 benign (exploratory quick run)")
    report.append("- External benign safety holdout: not evaluated in this quick run")
    report.append("- Model: L2 logistic regression; C selected by 5-fold stratified CV")
    report.append("- Probability calibration: sigmoid / Platt-style 5-fold CV")
    report.append("")
    report.append("PRIMARY 20 OOF PERFORMANCE")
    report.append(f"ROC-AUC         : {oof_auc:.4f}")
    report.append(f"Average Precision: {oof_ap:.4f}")
    report.append(f"Brier Score     : {oof_brier:.6f}")
    report.append(f"Log Loss        : {oof_logloss:.6f}")
    report.append("")
    report.append("OOF THRESHOLDS")
    for title, val in (("Youden J", youden), ("Best F1", best_f1), ("Best TPR with FPR<=5%", fpr5)):
        if val is None:
            report.append(f"{title:<28}: N/A")
        else:
            report.append(
                f"{title:<28}: score={100*val['threshold']:.2f}, "
                f"TPR={100*val['tpr']:.2f}%, FPR={100*val['fpr']:.2f}%"
            )
    report.append("")
    report.append("LEGITIMATE BANKING HOLDOUT")
    report.append("Not used in this 20-APK quick calibration run.")
    report.append("")
    report.append("TOP LEARNED BASE-MODEL FEATURES")
    coef = base_model.coef_[0]
    pairs = sorted(zip(names, coef), key=lambda x: abs(x[1]), reverse=True)
    for name, weight in pairs[:15]:
        report.append(f"{name:<42} coefficient={weight:+.6f}")
    report.append("")
    report.append("FILES")
    report.append(f"Model   : {args.model}")
    report.append(f"Metadata: {args.metadata}")
    report.append(f"Features: {args.features}")
    report.append(f"OOF     : {args.oof}")
    report.append(f"Banking : {args.banking_output}")
    report.append("=" * 100)
    args.report.write_text("\n".join(report), encoding="utf-8")

    print()
    print("=" * 100)
    print("V5 CALIBRATION COMPLETE")
    print("=" * 100)
    print(f"OOF ROC-AUC      : {oof_auc:.4f}")
    print(f"OOF PR-AUC       : {oof_ap:.4f}")
    print(f"OOF Brier        : {oof_brier:.6f}")
    print(f"OOF LogLoss      : {oof_logloss:.6f}")
    print(f"Selected C       : {best_c}")
    print(f"Youden score     : {100*youden['threshold']:.2f}/100")
    if fpr5:
        print(f"<=5% FPR score   : {100*fpr5['threshold']:.2f}/100")
    print("Bank holdout     : NOT USED in 20-APK quick run")
    print()
    print("Do NOT treat this 20-APK run as the final threshold calibration. Use the score only after the larger independent validation pass.")
    print(f"Model   : {args.model}")
    print(f"Metadata: {args.metadata}")
    print(f"Report  : {args.report}")
    print("=" * 100)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
