"""
SPECTRE — Fast Offline Feature Enrichment
Maps SHA-256 APK paths from dataset registry and extracts zip archive indicators:
  - has_hidden_payload: Secondary .dex/.jar/.apk/.bin/.dat in assets/ or res/raw/
  - is_multidex: classes2.dex+ secondary code splits
  - has_root_exploit_asset: Known privilege-escalation binaries in assets
  - apk_size_mb: Physical APK binary footprint
"""
from pathlib import Path
import os
import zipfile
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_CSV = PROJECT_ROOT / "data" / "validation" / "benchmark_execution_log.csv"
DATASET_CSV = PROJECT_ROOT / "data" / "validation" / "module2_validation_results.csv"

APK_SEARCH_DIRS = [
    PROJECT_ROOT / "data" / "validation" / "apks",
    PROJECT_ROOT / "data" / "validation" / "banking_apks",
]


def resolve_apk_path(raw_path: str) -> Path | None:
    """Finds existing file from relative or absolute CSV path."""
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
    """Builds package_name -> disk Path mapping from validation dataset CSV."""
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
        except Exception as exc:
            print(f"[WARN] Failed reading {DATASET_CSV.name}: {exc}")
    return mapping


def scan_apk_indicators(apk_path: Path) -> dict[str, float | int]:
    """Inspects APK zip archive entries in milliseconds."""
    indicators = {
        "has_hidden_payload": 0,
        "is_multidex": 0,
        "has_root_exploit_asset": 0,
        "apk_size_mb": round(os.path.getsize(apk_path) / (1024 * 1024), 2),
    }

    exploit_keywords = {
        "rageagainstthecage", "gingerbreak", "zergRush", "mempodroid",
        "dirtycow", "busybox", "install-recovery", "su"
    }

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = z.namelist()
            for name in names:
                lower = name.lower()

                # Multidex detection
                if "classes2.dex" in lower or "classes3.dex" in lower:
                    indicators["is_multidex"] = 1

                # Hidden executable payloads in assets/ or raw/
                if lower.startswith("assets/") or lower.startswith("res/raw/"):
                    if lower.endswith((".dex", ".jar", ".apk", ".bin", ".dat", ".class", ".so")):
                        indicators["has_hidden_payload"] = 1

                    # Root exploit binaries stored in assets
                    file_stem = Path(lower).stem
                    if file_stem in exploit_keywords or any(exp in lower for exp in exploit_keywords):
                        indicators["has_root_exploit_asset"] = 1
    except Exception:
        pass

    return indicators


def main():
    if not LOG_CSV.is_file():
        print(f"[ERROR] Could not find {LOG_CSV}")
        return

    df = pd.read_csv(LOG_CSV)
    print(f"[LOAD] Loaded {len(df)} samples from {LOG_CSV.name}")

    pkg_map = build_package_to_path_map()
    print(f"[MAP] Resolved {len(pkg_map)} package-to-file paths from dataset registry.")

    # Fallback to direct directory scan if any packages are unmapped
    # missing_pkgs = set(df["package_name"]) - set(pkg_map.keys())
    # if missing_pkgs:
    #     print(f"[SCAN] Searching directories for {len(missing_pkgs)} unmapped packages via androguard...")
    #     try:
    #         from androguard.core.bytecodes.apk import APK
    #         for d in APK_SEARCH_DIRS:
    #             if not d.is_dir():
    #                 continue
    #             for apk_file in d.glob("*.apk"):
    #                 try:
    #                     apk_obj = APK(str(apk_file))
    #                     found_pkg = apk_obj.get_package()
    #                     if found_pkg in missing_pkgs:
    #                         pkg_map[found_pkg] = apk_file
    #                         missing_pkgs.discard(found_pkg)
    #                 except Exception:
    #                     pass
    #     except ImportError:
    #         pass

    hidden_flags = []
    multidex_flags = []
    root_flags = []
    size_mb_list = []

    matched = 0
    for _, row in df.iterrows():
        pkg = str(row["package_name"]).strip()
        apk_p = pkg_map.get(pkg)

        if apk_p and apk_p.is_file():
            metrics = scan_apk_indicators(apk_p)
            matched += 1
        else:
            metrics = {
                "has_hidden_payload": 0,
                "is_multidex": 0,
                "has_root_exploit_asset": 0,
                "apk_size_mb": 0.0,
            }

        hidden_flags.append(indicators_hidden := metrics["has_hidden_payload"])
        multidex_flags.append(metrics["is_multidex"])
        root_flags.append(metrics["has_root_exploit_asset"])
        size_mb_list.append(metrics["apk_size_mb"])

    df["has_hidden_payload"] = hidden_flags
    df["is_multidex"] = multidex_flags
    df["has_root_exploit_asset"] = root_flags
    df["apk_size_mb"] = size_mb_list

    # Save enriched dataset
    df.to_csv(LOG_CSV, index=False)
    print("\n" + "=" * 60)
    print(f"[COMPLETE] Successfully enriched {matched}/{len(df)} samples!")
    print(f"  Hidden Dropper Payloads : {sum(hidden_flags)}")
    print(f"  Multidex Packages       : {sum(multidex_flags)}")
    print(f"  Root Exploit Assets     : {sum(root_flags)}")
    print("=" * 60)


if __name__ == "__main__":
    main()