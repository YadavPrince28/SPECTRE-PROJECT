"""
SPECTRE — High-Speed Offline spaCy M4 Telemetry Backfill
Processes all 163 samples in ~15 to 25 seconds with live stdout progress.
"""
from pathlib import Path
import sys
import time
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from modules.social_engineering import analyze_social_engineering

LOG_CSV = PROJECT_ROOT / "data" / "validation" / "benchmark_execution_log.csv"
DATASET_CSV = PROJECT_ROOT / "data" / "validation" / "module2_validation_results.csv"


def resolve_apk_path(raw_path: str) -> Path | None:
    if not raw_path or raw_path == "nan":
        return None
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


def build_package_to_path_map() -> dict[str, Path]:
    mapping: dict[str, Path] = {}
    if DATASET_CSV.is_file():
        try:
            ds_df = pd.read_csv(DATASET_CSV)
            for _, row in ds_df.iterrows():
                pkg = str(row.get("package_name", "")).strip()
                raw_path = str(row.get("apk_path", "")).strip()
                resolved = resolve_apk_path(raw_path)
                if pkg and resolved and resolved.is_file():
                    mapping[pkg] = resolved
        except Exception:
            pass
    return mapping


def main() -> None:
    if not LOG_CSV.is_file():
        print(f"[ERROR] Could not find {LOG_CSV}")
        return

    df = pd.read_csv(LOG_CSV)
    total = len(df)
    print(f"[LOAD] Processing {total} samples from {LOG_CSV.name}...")

    pkg_map = build_package_to_path_map()
    print(f"[MAP] Resolved {len(pkg_map)} APK paths from dataset registry.\n")

    updated_m4_scores: list[float] = []
    start_total = time.time()

    for idx, row in df.iterrows():
        pkg = str(row["package_name"]).strip()
        apk_p = pkg_map.get(pkg)

        t0 = time.time()
        if apk_p and apk_p.is_file():
            res = analyze_social_engineering(apk_p)
            score = float(res.get("social_engineering_score", 0.0))
        else:
            score = float(row.get("m4_social", 0.0))

        updated_m4_scores.append(score)
        elapsed = time.time() - t0

        # Live unbuffered stdout progress for every sample
        print(f"[{idx+1:>3}/{total}] {pkg:<42} ({elapsed:.2f}s) -> M4: {score:.1f}")
        sys.stdout.flush()

    df["m4_social"] = updated_m4_scores
    df.to_csv(LOG_CSV, index=False)

    total_time = round(time.time() - start_total, 2)
    print("\n" + "=" * 65)
    print(f"[COMPLETE] Processed {total} samples in {total_time} seconds!")
    print(f"  Non-Zero Phishing/Lure Count : {sum(1 for s in updated_m4_scores if s > 0)} / {total}")
    print(f"  Updated Dataset Saved to     : {LOG_CSV.name}")
    print("=" * 65)


if __name__ == "__main__":
    main()