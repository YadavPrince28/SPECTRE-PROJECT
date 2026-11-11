"""
SPECTRE — Resumable Multi-Modal Pipeline Benchmark & Telemetry Extraction Engine
Features:
  - Full feature vector logging for offline XGBoost/GBDT meta-classification
  - Automatic resume logic tracking unique completed package names
  - Safe terminal reporting prior to graphic generation
  - Host RAM, guest emulator, and WSL2 working-set purging per sample
  - Immediate append-mode disk checkpointing to protect against power/process interruption
"""
from __future__ import annotations

import argparse
import ctypes
import gc
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import psutil
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)

# -----------------------------------------------------------------------------
# 1. Environment & Path Initialization
# -----------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
BACKEND_DIR = PROJECT_ROOT / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Force scratch files to D: drive
D_TEMP = PROJECT_ROOT / "temp"
D_TEMP.mkdir(parents=True, exist_ok=True)
os.environ["TEMP"] = str(D_TEMP)
os.environ["TMP"] = str(D_TEMP)

try:
    from pipeline import run_pipeline
except ImportError as err:
    print(f"[FATAL] Failed to import run_pipeline from backend/pipeline.py: {err}")
    sys.exit(1)


# -----------------------------------------------------------------------------
# 2. Resource Telemetry & Memory Reclamation Watchdogs
# -----------------------------------------------------------------------------
def get_system_telemetry() -> dict[str, float]:
    """Measures physical RAM utilization, available memory, and disk headroom."""
    vmem = psutil.virtual_memory()
    c_free = shutil.disk_usage("C:\\").free / (1024**3)
    d_free = shutil.disk_usage("D:\\").free / (1024**3)
    return {
        "c_free_gb": round(c_free, 2),
        "d_free_gb": round(d_free, 2),
        "ram_pct": round(vmem.percent, 1),
        "ram_avail_gb": round(vmem.available / (1024**3), 2),
    }


def purge_wsl_memory() -> None:
    """Drops Linux page cache inside WSL2 to keep vmmem from expanding."""
    try:
        subprocess.run(
            ["wsl", "-u", "root", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
    except Exception:
        pass


def purge_host_ram() -> None:
    """Collects Python cyclic garbage and flushes process working set memory."""
    gc.collect()
    gc.collect()
    if sys.platform == "win32":
        try:
            ctypes.windll.psapi.EmptyWorkingSet(ctypes.windll.kernel32.GetCurrentProcess())
        except Exception:
            pass


def purge_guest_emulator(pkg_name: str) -> None:
    """Teardown routines executed inside the Android guest emulator."""
    if not pkg_name:
        return

    commands = [
        ["adb", "shell", "am", "force-stop", pkg_name],
        ["adb", "uninstall", pkg_name],
        ["adb", "shell", "pm", "trim-caches", "999G"],
        ["adb", "shell", "echo 3 > /proc/sys/vm/drop_caches"],
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4)
        except Exception:
            pass


def purge_disk_scratch(pkg_name: str) -> None:
    """Cleans temporary decompilation directories and lockfiles."""
    if D_TEMP.exists():
        for item in D_TEMP.glob(f"*{pkg_name}*"):
            try:
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item, ignore_errors=True)
            except Exception:
                pass

    user_temp = Path(os.environ.get("LOCALAPPDATA", "")) / "Temp"
    if user_temp.exists():
        for pattern in (f"*{pkg_name}*", "androguard*", "mobsf*"):
            for entry in user_temp.glob(pattern):
                try:
                    if entry.is_file():
                        entry.unlink()
                    elif entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=True)
                except Exception:
                    pass


def isolate_and_stabilize(
    pkg_name: str,
    cooldown_seconds: float = 1.0,
    min_avail_gb: float = 0.6,
) -> None:
    """Fast inter-sample teardown with memory health validation."""
    purge_guest_emulator(pkg_name)
    purge_disk_scratch(pkg_name)
    purge_wsl_memory()
    purge_host_ram()

    time.sleep(cooldown_seconds)

    telemetry = get_system_telemetry()
    retries = 0
    while telemetry["ram_avail_gb"] < min_avail_gb and retries < 3:
        print(f"[THROTTLE] Physical RAM tight ({telemetry['ram_avail_gb']} GB avail). Settling 2s...")
        purge_wsl_memory()
        purge_host_ram()
        time.sleep(2.0)
        telemetry = get_system_telemetry()
        retries += 1

    if telemetry["c_free_gb"] < 2.0:
        print(f"\n[RESOURCE GUARD] CRITICAL: Only {telemetry['c_free_gb']} GB left on C:. Halting benchmark.")
        sys.exit(1)


# -----------------------------------------------------------------------------
# 3. Path Resolution & Dataset Selection
# -----------------------------------------------------------------------------
def resolve_apk_path(raw_path: str, pkg_name: str) -> Path | None:
    """Locates target APK files across validation directories."""
    candidates = [
        Path(raw_path),
        PROJECT_ROOT / raw_path,
        PROJECT_ROOT / "data" / "validation" / "apks" / Path(raw_path).name,
        PROJECT_ROOT / "data" / "validation" / "banking_apks" / Path(raw_path).name,
    ]
    for cand in candidates:
        if cand.is_file():
            return cand
    return None


def load_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Filters CSV for valid existing APKs on disk."""
    valid_rows = []
    for _, row in df.iterrows():
        apk_p = resolve_apk_path(str(row.get("apk_path", "")), str(row.get("package_name", "")))
        if apk_p and apk_p.is_file():
            row_dict = row.to_dict()
            row_dict["resolved_apk_path"] = str(apk_p)
            valid_rows.append(row_dict)

    clean_df = pd.DataFrame(valid_rows)
    if clean_df.empty:
        raise ValueError("No valid APK files found on disk matching paths in dataset CSV.")
    return clean_df.reset_index(drop=True)


# -----------------------------------------------------------------------------
# 4. Evaluation & Visualization Engine
# -----------------------------------------------------------------------------
def plot_benchmark_results(
    y_true: list[int],
    y_scores: list[float],
    y_pred: list[int],
    output_path: Path,
) -> None:
    """Generates and exports the Confusion Matrix and ROC Curve."""
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    # Subplot 1: Confusion Matrix
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    im = axes[0].imshow(cm, interpolation="nearest", cmap="Blues")
    axes[0].figure.colorbar(im, ax=axes[0], fraction=0.046, pad=0.04)
    axes[0].set(
        xticks=np.arange(2),
        yticks=np.arange(2),
        xticklabels=["Clean (0)", "Alert (1)"],
        yticklabels=["Clean (0)", "Alert (1)"],
        xlabel="Predicted Label",
        ylabel="Ground Truth",
        title="SPECTRE Confusion Matrix",
    )
    thresh = cm.max() / 2.0 if cm.max() > 0 else 1.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            axes[0].text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
                fontsize=14, fontweight="bold",
            )

    # Subplot 2: ROC Curve
    if len(set(y_true)) > 1:
        fpr, tpr, _ = roc_curve(y_true, y_scores)
        auc_val = roc_auc_score(y_true, y_scores)
        axes[1].plot(fpr, tpr, color="#0052cc", lw=2.5, label=f"ROC curve (AUC = {auc_val:.3f})")
    else:
        axes[1].plot([0, 1], [0, 1], color="#0052cc", lw=2.5, label="ROC curve (Single-class)")
        auc_val = 0.5

    axes[1].plot([0, 1], [0, 1], color="gray", lw=1.5, linestyle="--")
    axes[1].set(
        xlim=[-0.02, 1.02],
        ylim=[-0.02, 1.05],
        xlabel="False Positive Rate (1 - Specificity)",
        ylabel="True Positive Rate (Recall)",
        title="Detection Receiver Operating Characteristic",
    )
    axes[1].legend(loc="lower right", frameon=True)
    axes[1].grid(True, linestyle=":", alpha=0.6)

    plt.tight_layout()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path, dpi=300)
    plt.close()
    print(f"[BENCHMARK] Plot exported to: {output_path}")


def generate_consolidated_report(
    log_csv: Path,
    alert_threshold: float,
    plot_path: Path | None,
    mode: str = "LIVE",
) -> None:
    """Reads the full execution log and prints comprehensive benchmark metrics."""
    if not log_csv.exists():
        print("[BENCHMARK] No execution log found to evaluate.")
        return

    try:
        df = pd.read_csv(log_csv)
    except Exception as exc:
        print(f"[BENCHMARK] Failed to read log: {exc}")
        return

    if df.empty:
        print("[BENCHMARK] Execution log is empty.")
        return

    df = df.drop_duplicates(subset=["package_name"], keep="last").reset_index(drop=True)

    y_true = df["ground_truth"].astype(int).tolist()
    y_scores = df["score"].astype(float).tolist()
    y_pred = [1 if s >= alert_threshold else 0 for s in y_scores]

    total_eval = len(y_true)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1])

    accuracy = accuracy_score(y_true, y_pred) if total_eval > 0 else 0.0
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = f1_score(y_true, y_pred, zero_division=0)
    overall_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    roc_auc = roc_auc_score(y_true, y_scores) if len(set(y_true)) > 1 else 0.5

    bank_rows = df[df["cohort"] == "legitimate_banking"]
    bank_tested = len(bank_rows)
    bank_false_alarms = int((bank_rows["score"] >= alert_threshold).sum())
    banking_fpr = (bank_false_alarms / bank_tested * 100.0) if bank_tested > 0 else 0.0

    # 1. PRINT TEXT METRICS IMMEDIATELY
    print("\n" + "=" * 80)
    print(f"SPECTRE ACCURACY BENCHMARK REPORT ({mode.upper()}_PIPELINE_EVALUATION)")
    print("=" * 80)
    print(f"Total Evaluated Samples : {total_eval}")
    print(f"Alert Decision Threshold: Risk Score >= {alert_threshold}")
    print("-" * 80)
    print("CONFUSION MATRIX:")
    print(f"  True Positives  (TP): {tp:<4} | False Positives (FP): {fp:<4}")
    print(f"  False Negatives (FN): {fn:<4} | True Negatives  (TN): {tn:<4}")
    print("-" * 80)
    print("PERFORMANCE METRICS:")
    print(f"  Overall Accuracy     : {accuracy * 100:.2f}%")
    print(f"  Precision            : {precision * 100:.2f}%")
    print(f"  Recall (Detection)   : {recall * 100:.2f}%")
    print(f"  Specificity (Clean)  : {specificity * 100:.2f}%")
    print(f"  F1-Score             : {f1 * 100:.2f}%")
    print(f"  False Positive Rate  : {overall_fpr * 100:.2f}%")
    print(f"  ROC-AUC              : {roc_auc:.3f}")
    print("-" * 80)
    print("LEGITIMATE BANKING APP INTEGRITY:")
    print(f"  Legitimate Banking APKs Tested: {bank_tested}")
    print(f"  False Alarms Triggered        : {bank_false_alarms}")
    print(f"  Banking False Positive Rate   : {banking_fpr:.1f}%")
    print("=" * 80 + "\n")

    # 2. GENERATE AND SAVE PLOT SAFELY
    if plot_path:
        try:
            plot_benchmark_results(y_true, y_scores, y_pred, plot_path)
        except (Exception, KeyboardInterrupt) as exc:
            print(f"[WARN] Skipped saving plot image: {exc}")


# -----------------------------------------------------------------------------
# 5. Core Pipeline Benchmark Execution & Telemetry Extraction
# -----------------------------------------------------------------------------
def run_benchmark(
    csv_path: Path,
    mode: str = "live",
    resume: bool = True,
    max_samples: int | None = None,
    alert_threshold: float = 33.0,
    plot_path: Path | None = None,
    cooldown_seconds: float = 1.0,
) -> None:
    print(f"\n[BENCHMARK] Initializing {mode.upper()} run (Resume: {resume}).")
    raw_df = pd.read_csv(csv_path)
    clean_df = load_dataset(raw_df)

    checkpoint_csv = PROJECT_ROOT / "data" / "validation" / "benchmark_execution_log.csv"
    completed_packages: set[str] = set()

    if resume and checkpoint_csv.exists():
        try:
            existing_log = pd.read_csv(checkpoint_csv)
            completed_packages = set(existing_log["package_name"].dropna().astype(str))
            print(f"[RESUME] Found existing execution log with {len(completed_packages)} completed sample(s).")
        except Exception as exc:
            print(f"[WARN] Failed to read existing log for resume: {exc}")
    elif not resume and checkpoint_csv.exists():
        backup_name = checkpoint_csv.with_name(f"benchmark_execution_log_backup_{int(time.time())}.csv")
        try:
            shutil.copy(checkpoint_csv, backup_name)
            checkpoint_csv.unlink(missing_ok=True)
            print(f"[FRESH] Previous log backed up to: {backup_name.name}")
        except Exception:
            pass

    # Unprocessed sample filtering
    unprocessed_df = clean_df[~clean_df["package_name"].isin(completed_packages)].reset_index(drop=True)

    total_target = len(clean_df)
    completed_count = len(completed_packages)
    total_remaining = len(unprocessed_df)

    if max_samples and max_samples > 0:
        remaining_df = unprocessed_df.head(max_samples)
    else:
        remaining_df = unprocessed_df

    remaining_count = len(remaining_df)

    print(f"[BENCHMARK] Total Dataset Scope : {total_target} samples")
    print(f"            Already Completed   : {completed_count} samples")
    print(f"            Remaining to Execute: {total_remaining} samples (Batch Queue: {remaining_count})\n")

    if remaining_df.empty:
        print("[BENCHMARK] All target samples are completed! Generating consolidated report...")
        generate_consolidated_report(checkpoint_csv, alert_threshold, plot_path, mode=mode)
        return

    interrupted = False

    try:
        # Loop starts explicitly from completed_count + 1
        for idx, (_, row) in enumerate(remaining_df.iterrows(), start=completed_count + 1):
            pkg = str(row["package_name"])
            cohort = str(row["cohort"])
            apk_file = str(row["resolved_apk_path"])
            ground_truth = 1 if cohort == "malicious" else 0

            initial_telemetry = get_system_telemetry()
            print(
                f"[{idx}/{total_target}] Target: {pkg} ({cohort})\n"
                f"       Resource Baseline: [RAM: {initial_telemetry['ram_pct']}% | "
                f"Avail: {initial_telemetry['ram_avail_gb']}GB | "
                f"C: {initial_telemetry['c_free_gb']}GB | "
                f"D: {initial_telemetry['d_free_gb']}GB]"
            )

            start_t = time.time()

            try:
                pipeline_out = run_pipeline(apk_file, job_id=f"bench_{idx}_{int(time.time())}")
                duration = round(time.time() - start_t, 2)

                final_data = pipeline_out.get("final_score") or {}
                final_score = float(final_data.get("score", 0.0))
                verdict_str = str(final_data.get("verdict", "LOW"))
                comp_scores = final_data.get("component_scores") or {}

                # 1. Extract Individual Module Telemetry
                static_res = pipeline_out.get("static") or {}
                dynamic_res = pipeline_out.get("dynamic") or {}
                social_res = pipeline_out.get("social") or {}
                behavioral_res = pipeline_out.get("behavioral") or {}
                genai_res = pipeline_out.get("genai") or {}

                m1_val = float(comp_scores.get("permission_risk") or static_res.get("permission_risk") or static_res.get("permission_score", 0.0))
                m2_val = float(comp_scores.get("behavioral_family") or behavioral_res.get("behavioral_score") or behavioral_res.get("similarity_score", 0.0))
                m3_val = float(comp_scores.get("dynamic_runtime") or dynamic_res.get("dynamic_risk_score", 0.0))
                m4_val = float(comp_scores.get("social_engineering") or social_res.get("social_engineering_score") or social_res.get("social_score", 0.0))
                m5_val = float(comp_scores.get("genai_severity") or genai_res.get("genai_score") or genai_res.get("severity_score", 0.0))

                raw_chain = (
                    comp_scores.get("malicious_api_chain")
                    or dynamic_res.get("api_chain_score")
                    or static_res.get("api_chain_score")
                    or static_res.get("chain_score", 0.0)
                )
                chain_val = float(raw_chain or 0.0)

                exfil_events = dynamic_res.get("exfiltration_events") or []
                net_val = float(comp_scores.get("network_exfiltration") or (min(100.0, len(exfil_events) * 25.0)))

                # 2. Extract Structural Indicators for XGBoost
                # WITH THIS ROBUST BLOCK:
                static_str = str(static_res).upper()
                trojan_perms = [
                    "RECEIVE_BOOT_COMPLETED",
                    "SYSTEM_ALERT_WINDOW",
                    "BIND_ACCESSIBILITY_SERVICE",
                    "READ_SMS",
                    "SEND_SMS",
                    "REQUEST_INSTALL_PACKAGES",
                ]
                has_trojan_perm = 1 if any(p in static_str for p in trojan_perms) else 0

                static_lower = str(static_res).lower()
                ad_markers = ["google.android.gms.ads", "unity3d", "applovin", "ironsource", "vungle", "chartboost"]
                has_ad_sdk = 1 if any(sdk in static_lower for sdk in ad_markers) else 0

                predicted_alert = 1 if final_score >= alert_threshold else 0
                pred_label = "ALERT" if predicted_alert == 1 else "CLEAN"
                print(f"  -> Score: {final_score:.1f} | Pred: {pred_label} | Truth: {cohort} ({duration}s)")

                # 3. Formulate Complete Feature Row
                record = {
                    "sample_idx": idx,
                    "package_name": pkg,
                    "cohort": cohort,
                    "ground_truth": ground_truth,
                    "m1_perm": round(m1_val, 2),
                    "m2_markov": round(m2_val, 2),
                    "m3_runtime": round(m3_val, 2),
                    "m4_social": round(m4_val, 2),
                    "m5_genai": round(m5_val, 2),
                    "chain_score": round(chain_val, 2),
                    "net_exfil": round(net_val, 2),
                    "has_trojan_perm": has_trojan_perm,
                    "has_ad_sdk": has_ad_sdk,
                    "score": final_score,
                    "predicted": predicted_alert,
                    "verdict": verdict_str,
                    "duration_seconds": duration,
                    "completed_at": pd.Timestamp.now().isoformat(),
                }

                pd.DataFrame([record]).to_csv(
                    checkpoint_csv,
                    mode="a",
                    header=not checkpoint_csv.exists(),
                    index=False,
                )

            except Exception as exc:
                duration = round(time.time() - start_t, 2)
                print(f"  [ERROR] Execution failure on {pkg}: {exc} ({duration}s)")
                record = {
                    "sample_idx": idx,
                    "package_name": pkg,
                    "cohort": cohort,
                    "ground_truth": ground_truth,
                    "m1_perm": 0.0,
                    "m2_markov": 0.0,
                    "m3_runtime": 0.0,
                    "m4_social": 0.0,
                    "m5_genai": 0.0,
                    "chain_score": 0.0,
                    "net_exfil": 0.0,
                    "has_trojan_perm": 0,
                    "has_ad_sdk": 0,
                    "score": 0.0,
                    "predicted": 0,
                    "verdict": "ERROR",
                    "duration_seconds": duration,
                    "completed_at": pd.Timestamp.now().isoformat(),
                }
                pd.DataFrame([record]).to_csv(
                    checkpoint_csv,
                    mode="a",
                    header=not checkpoint_csv.exists(),
                    index=False,
                )
            finally:
                isolate_and_stabilize(pkg, cooldown_seconds=cooldown_seconds)
                post_clean_telemetry = get_system_telemetry()
                print(
                    f"       Post-Teardown    : [RAM: {post_clean_telemetry['ram_pct']}% | "
                    f"Avail: {post_clean_telemetry['ram_avail_gb']}GB | "
                    f"C: {post_clean_telemetry['c_free_gb']}GB]\n"
                )

    except KeyboardInterrupt:
        print("\n\n[USER INTERRUPT] Received Ctrl+C. Gracefully stopping benchmark loop...")
        interrupted = True
    finally:
        print("\n[BENCHMARK] Generating metrics from all accumulated samples...")
        generate_consolidated_report(checkpoint_csv, alert_threshold, plot_path, mode=mode)
        if interrupted:
            print("[INFO] You can resume remaining samples at any time by re-running the exact same command.")


# -----------------------------------------------------------------------------
# 6. CLI Entrypoint
# -----------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description="SPECTRE Resumable Benchmark & Feature Extraction Harness")
    parser.add_argument("--mode", type=str, default="live", choices=["live", "simulation"], help="Execution mode")
    parser.add_argument(
        "--csv",
        type=str,
        default=str(PROJECT_ROOT / "data" / "validation" / "module2_validation_results.csv"),
        help="Validation dataset CSV path",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        default=True,
        help="Resume from existing log by skipping already analyzed packages (Default: True)",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Ignore previous logs, create backup, and evaluate from sample 1",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Number of remaining samples to evaluate in this batch run",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=33.0,
        help="Alert cutoff threshold (Default: 33.0)",
    )
    parser.add_argument(
        "--plot",
        type=str,
        default=str(PROJECT_ROOT / "data" / "validation" / "live_pipeline_confusion_roc.png"),
        help="Confusion & ROC plot export path",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=1.0,
        help="Inter-sample resource cooldown in seconds (Default: 1.0)",
    )
    args = parser.parse_args()

    should_resume = not args.fresh

    run_benchmark(
        csv_path=Path(args.csv),
        mode=args.mode,
        resume=should_resume,
        max_samples=args.max_samples,
        alert_threshold=args.threshold,
        plot_path=Path(args.plot),
        cooldown_seconds=args.cooldown,
    )


if __name__ == "__main__":
    main()