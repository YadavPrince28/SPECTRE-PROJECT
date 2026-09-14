from __future__ import annotations

import csv
import gzip
import hashlib
import heapq
import os
import random
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ============================================================
# CONFIG
# ============================================================

PROJECT_ROOT = Path(r"D:\Spectre_BOI_project\SPECTRE")

ANDROZOO_METADATA = (
    PROJECT_ROOT / "data" / "androzoo" / "latest_with-added-date.csv.gz"
)

DREBIN_CACHE = (
    PROJECT_ROOT
    / "models"
    / "drebin_graphs_v2"
    / "full_drebin_sample_dna_cache.pkl"
)

OUTPUT_DIR = PROJECT_ROOT / "data" / "validation"

MANIFEST_PATH = OUTPUT_DIR / "module2_validation_manifest.csv"
SUMMARY_PATH = OUTPUT_DIR / "module2_validation_selection_summary.txt"

MALICIOUS_COUNT = 75
BENIGN_COUNT = 75

# Number of rows retained in memory per cohort.
# 5000 is tiny compared with millions of candidates.
POOL_SIZE = 5000

SEED = 20260913


# ============================================================
# DREBIN HASH LOADING
# ============================================================

def load_drebin_hashes() -> set[str]:
    """
    Load SHA256 values from the existing full Drebin cache.

    Supports the known pickle structure used by SPECTRE.
    """

    import pickle

    print("Loading Drebin reference cache...")

    with open(DREBIN_CACHE, "rb") as f:
        obj = pickle.load(f)

    hashes = set()

    def walk(value):
        if isinstance(value, dict):
            for k, v in value.items():
                if isinstance(k, str) and len(k) == 64:
                    if all(c in "0123456789abcdefABCDEF" for c in k):
                        hashes.add(k.lower())

                if isinstance(v, str) and len(v) == 64:
                    if all(c in "0123456789abcdefABCDEF" for c in v):
                        hashes.add(v.lower())

                walk(v)

        elif isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)

    walk(obj)

    print(f"Drebin reference hashes loaded: {len(hashes):,}")
    return hashes


# ============================================================
# DATE HELPERS
# ============================================================

def parse_added_date(value: str) -> datetime | None:
    value = (value or "").strip()

    if not value:
        return None

    formats = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d",
        "%Y/%m/%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass

    return None


# ============================================================
# DETERMINISTIC BOUNDED POOL
# ============================================================

class CandidatePool:
    """
    Keep only the N best candidates according to SHA256.

    This gives:
        - deterministic selection
        - bounded RAM usage
        - no giant Python lists
    """

    def __init__(self, max_size: int):
        self.max_size = max_size

        # heap entries:
        # (negative_rank, sha256, row)
        #
        # SHA256 is converted to an integer ranking.
        self.heap = []

    @staticmethod
    def rank(sha256: str) -> int:
        return int(sha256, 16)

    def add(self, row: dict):
        sha256 = row["sha256"].strip().lower()

        if len(sha256) != 64:
            return

        try:
            rank = self.rank(sha256)
        except ValueError:
            return

        # Max-heap behavior by using negative rank.
        entry = (-rank, sha256, row)

        if len(self.heap) < self.max_size:
            heapq.heappush(self.heap, entry)
            return

        # Current worst candidate is heap[0]
        if entry > self.heap[0]:
            heapq.heapreplace(self.heap, entry)

    def rows(self) -> list[dict]:
        return [
            entry[2]
            for entry in sorted(
                self.heap,
                key=lambda x: x[1]
            )
        ]


# ============================================================
# MARKET TEST
# ============================================================

def is_google_play(markets: str) -> bool:
    return "play.google.com" in (markets or "").lower()


# ============================================================
# TEMPORAL SELECTION
# ============================================================

def choose_diverse(
    candidates: list[dict],
    count: int,
    seed: int,
) -> list[dict]:

    rng = random.Random(seed)

    if len(candidates) <= count:
        return candidates[:]

    # --------------------------------------------------------
    # 1. Group by month where possible.
    # --------------------------------------------------------

    buckets: dict[str, list[dict]] = defaultdict(list)

    for row in candidates:
        dt = parse_added_date(row.get("added", ""))

        if dt:
            bucket = dt.strftime("%Y-%m")
        else:
            bucket = "UNKNOWN"

        buckets[bucket].append(row)

    # Sort buckets chronologically.
    ordered_buckets = sorted(
        buckets.keys(),
        key=lambda x: (x == "UNKNOWN", x)
    )

    for bucket in ordered_buckets:
        rng.shuffle(buckets[bucket])

    # --------------------------------------------------------
    # 2. First pass: prefer unique package names.
    # --------------------------------------------------------

    selected = []
    used_packages = set()
    used_sha = set()

    # Round-robin through temporal buckets.
    while len(selected) < count:

        progress = False

        for bucket in ordered_buckets:

            if len(selected) >= count:
                break

            bucket_rows = buckets[bucket]

            while bucket_rows:

                row = bucket_rows.pop()
                sha = row["sha256"].lower()
                pkg = row.get("pkg_name", "").strip()

                if sha in used_sha:
                    continue

                if pkg and pkg in used_packages:
                    continue

                selected.append(row)
                used_sha.add(sha)

                if pkg:
                    used_packages.add(pkg)

                progress = True
                break

        if not progress:
            break

    # --------------------------------------------------------
    # 3. Fill any remaining slots regardless of package.
    # --------------------------------------------------------

    if len(selected) < count:

        remaining = []

        for bucket_rows in buckets.values():
            remaining.extend(bucket_rows)

        rng.shuffle(remaining)

        for row in remaining:

            if len(selected) >= count:
                break

            sha = row["sha256"].lower()

            if sha in used_sha:
                continue

            selected.append(row)
            used_sha.add(sha)

    return selected[:count]


# ============================================================
# MAIN BUILDER
# ============================================================

def build_manifest():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    drebin_hashes = load_drebin_hashes()

    malicious_pool = CandidatePool(POOL_SIZE)
    benign_pool = CandidatePool(POOL_SIZE)

    processed = 0
    invalid_rows = 0
    drebin_overlaps = 0
    malicious_candidates = 0
    benign_candidates = 0

    print()
    print("=" * 90)
    print("SPECTRE MODULE 2")
    print("VALIDATION MANIFEST BUILDER — MEMORY SAFE V2")
    print("=" * 90)
    print()
    print("Streaming AndroZoo metadata...")
    print("Candidate storage is bounded; RAM usage should remain small.")
    print()

    # --------------------------------------------------------
    # STREAM METADATA
    # --------------------------------------------------------

    with gzip.open(
        ANDROZOO_METADATA,
        mode="rt",
        encoding="utf-8",
        newline="",
    ) as gz:

        reader = csv.DictReader(gz)

        required_columns = {
            "sha256",
            "pkg_name",
            "vt_detection",
            "markets",
            "added",
        }

        missing = required_columns - set(reader.fieldnames or [])

        if missing:
            raise RuntimeError(
                f"Missing required metadata columns: {sorted(missing)}"
            )

        for row in reader:

            processed += 1

            sha256 = (row.get("sha256") or "").strip().lower()

            if len(sha256) != 64:
                invalid_rows += 1
                continue

            try:
                vt = int((row.get("vt_detection") or "").strip())
            except ValueError:
                invalid_rows += 1
                continue

            # ------------------------------------------------
            # Exclude Drebin overlap
            # ------------------------------------------------

            if sha256 in drebin_hashes:
                drebin_overlaps += 1
                continue

            # ------------------------------------------------
            # MALICIOUS
            # ------------------------------------------------

            if vt >= 10:

                malicious_candidates += 1

                row_copy = {
                    "sha256": sha256,
                    "sha1": row.get("sha1", ""),
                    "md5": row.get("md5", ""),
                    "pkg_name": row.get("pkg_name", ""),
                    "vercode": row.get("vercode", ""),
                    "apk_size": row.get("apk_size", ""),
                    "dex_size": row.get("dex_size", ""),
                    "vt_detection": str(vt),
                    "vt_scan_date": row.get("vt_scan_date", ""),
                    "added": row.get("added", ""),
                    "markets": row.get("markets", ""),
                    "selection_rule": "vt_detection>=10",
                    "cohort": "malicious",
                }

                malicious_pool.add(row_copy)

            # ------------------------------------------------
            # BENIGN
            # ------------------------------------------------

            elif vt == 0 and is_google_play(
                row.get("markets", "")
            ):

                benign_candidates += 1

                row_copy = {
                    "sha256": sha256,
                    "sha1": row.get("sha1", ""),
                    "md5": row.get("md5", ""),
                    "pkg_name": row.get("pkg_name", ""),
                    "vercode": row.get("vercode", ""),
                    "apk_size": row.get("apk_size", ""),
                    "dex_size": row.get("dex_size", ""),
                    "vt_detection": "0",
                    "vt_scan_date": row.get("vt_scan_date", ""),
                    "added": row.get("added", ""),
                    "markets": row.get("markets", ""),
                    "selection_rule":
                        "vt_detection=0 AND markets contains play.google.com",
                    "cohort": "benign",
                }

                benign_pool.add(row_copy)

            # ------------------------------------------------
            # Progress
            # ------------------------------------------------

            if processed % 5_000_000 == 0:

                print(
                    f"Processed {processed:,} rows | "
                    f"malicious candidates={malicious_candidates:,} | "
                    f"benign candidates={benign_candidates:,} | "
                    f"RAM pools={len(malicious_pool.heap) + len(benign_pool.heap):,}"
                )

    # --------------------------------------------------------
    # SELECT FINAL SAMPLE
    # --------------------------------------------------------

    malicious_candidates_small = malicious_pool.rows()
    benign_candidates_small = benign_pool.rows()

    malicious_selected = choose_diverse(
        malicious_candidates_small,
        MALICIOUS_COUNT,
        SEED + 1,
    )

    benign_selected = choose_diverse(
        benign_candidates_small,
        BENIGN_COUNT,
        SEED + 2,
    )

    selected = malicious_selected + benign_selected

    # --------------------------------------------------------
    # SAFETY CHECKS
    # --------------------------------------------------------

    selected_sha = [r["sha256"] for r in selected]

    if len(selected_sha) != len(set(selected_sha)):
        raise RuntimeError("Duplicate SHA256 values detected.")

    for row in selected:
        if row["sha256"] in drebin_hashes:
            raise RuntimeError(
                f"Drebin overlap survived selection: {row['sha256']}"
            )

    # --------------------------------------------------------
    # WRITE MANIFEST
    # --------------------------------------------------------

    fieldnames = [
        "cohort",
        "sha256",
        "pkg_name",
        "vercode",
        "apk_size",
        "dex_size",
        "vt_detection",
        "vt_scan_date",
        "added",
        "markets",
        "selection_rule",
    ]

    with open(
        MANIFEST_PATH,
        "w",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        for row in selected:
            writer.writerow(
                {
                    key: row.get(key, "")
                    for key in fieldnames
                }
            )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    summary = []

    summary.append("=" * 90)
    summary.append("SPECTRE MODULE 2 VALIDATION MANIFEST")
    summary.append("=" * 90)
    summary.append("")
    summary.append(f"Metadata rows processed: {processed:,}")
    summary.append(f"Invalid rows: {invalid_rows:,}")
    summary.append(
        f"Drebin overlaps removed: {drebin_overlaps:,}"
    )
    summary.append(
        f"Malicious candidates encountered: "
        f"{malicious_candidates:,}"
    )
    summary.append(
        f"Benign candidates encountered: "
        f"{benign_candidates:,}"
    )
    summary.append("")
    summary.append(
        f"Malicious selected: {len(malicious_selected)}"
    )
    summary.append(
        f"Benign selected: {len(benign_selected)}"
    )
    summary.append(
        f"Total selected: {len(selected)}"
    )
    summary.append("")
    summary.append("Selection rules:")
    summary.append(
        "Malicious: vt_detection >= 10"
    )
    summary.append(
        "Benign: vt_detection == 0 AND "
        "markets contains play.google.com"
    )
    summary.append(
        "Drebin SHA256 overlaps excluded"
    )
    summary.append(
        "Deterministic bounded SHA256 candidate pool"
    )
    summary.append(
        "Temporal/package diversity applied during final selection"
    )
    summary.append("")
    summary.append(f"Manifest: {MANIFEST_PATH}")
    summary.append("")

    with open(
        SUMMARY_PATH,
        "w",
        encoding="utf-8",
    ) as f:
        f.write("\n".join(summary))

    print()
    print("=" * 90)
    print("MANIFEST BUILD COMPLETE")
    print("=" * 90)
    print()
    print(f"Processed rows       : {processed:,}")
    print(f"Invalid rows         : {invalid_rows:,}")
    print(f"Drebin overlaps      : {drebin_overlaps:,}")
    print(f"Malicious candidates : {malicious_candidates:,}")
    print(f"Benign candidates    : {benign_candidates:,}")
    print()
    print(f"Malicious selected   : {len(malicious_selected)}")
    print(f"Benign selected      : {len(benign_selected)}")
    print(f"Total selected       : {len(selected)}")
    print()
    print(f"Manifest:")
    print(MANIFEST_PATH)
    print()
    print(f"Summary:")
    print(SUMMARY_PATH)


if __name__ == "__main__":
    build_manifest()