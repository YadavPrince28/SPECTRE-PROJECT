from __future__ import annotations

import argparse
import csv
import gc
import hashlib
import multiprocessing as mp
import sys
import time
from pathlib import Path

# ============================================================
# BACKEND IMPORT
# ============================================================

BACKEND_DIR = Path(__file__).resolve().parents[1]

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


from modules.behavioral_dna import (
    CLASS_WEIGHT,
    PACKAGE_WEIGHT,
    REFERENCE_FILE,
    CACHE_FILE,
    class_idf_similarity,
    class_to_package,
    extract_target_transitions,
    flatten_counts,
    load_models,
    map_counts,
    normalize_transition_counts,
    package_markov_similarity,
)


# ============================================================
# PATHS
# ============================================================

ROOT = Path(
    r"D:\Spectre_BOI_project\SPECTRE"
)

VALIDATION_DIR = (
    ROOT / "data" / "validation"
)

PRIMARY_MANIFEST = (
    VALIDATION_DIR
    / "module2_validation_manifest.csv"
)

PRIMARY_DIR = (
    VALIDATION_DIR / "apks"
)

BANKING_MANIFEST = (
    VALIDATION_DIR
    / "legitimate_banking_manifest.csv"
)

BANKING_DIR = (
    VALIDATION_DIR / "banking_apks"
)

RESULTS_CSV = (
    VALIDATION_DIR
    / "module2_validation_results.csv"
)

RANKINGS_CSV = (
    VALIDATION_DIR
    / "module2_validation_rankings_top10.csv"
)

METRICS_TXT = (
    VALIDATION_DIR
    / "module2_validation_metrics.txt"
)

CHUNK_SIZE = 1024 * 1024


# ============================================================
# SHA256
# ============================================================

def sha256_file(
    path: Path,
) -> str:

    h = hashlib.sha256()

    with path.open("rb") as f:

        while True:

            chunk = f.read(CHUNK_SIZE)

            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


# ============================================================
# LOAD 170-APK MANIFEST
# ============================================================

def load_validation_manifest():

    all_rows = []

    # --------------------------------------------------------
    # Primary 150
    # --------------------------------------------------------

    with PRIMARY_MANIFEST.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as f:

        rows = list(
            csv.DictReader(f)
        )

    for row in rows:

        sha = (
            row["sha256"]
            .strip()
            .lower()
        )

        apk_path = (
            PRIMARY_DIR
            / f"{sha}.apk"
        )

        if not apk_path.exists():

            raise FileNotFoundError(
                f"Missing APK:\n{apk_path}"
            )

        row["_sha256"] = sha
        row["_apk_path"] = str(
            apk_path
        )

        all_rows.append(row)

    # --------------------------------------------------------
    # Banking 20
    # --------------------------------------------------------

    with BANKING_MANIFEST.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as f:

        rows = list(
            csv.DictReader(f)
        )

    for row in rows:

        sha = (
            row["sha256"]
            .strip()
            .lower()
        )

        apk_path = (
            BANKING_DIR
            / f"{sha}.apk"
        )

        if not apk_path.exists():

            raise FileNotFoundError(
                f"Missing APK:\n{apk_path}"
            )

        row["_sha256"] = sha
        row["_apk_path"] = str(
            apk_path
        )

        all_rows.append(row)

    # --------------------------------------------------------
    # Cohort checks
    # --------------------------------------------------------

    counts = {}

    for row in all_rows:

        cohort = row["cohort"]

        counts[cohort] = (
            counts.get(cohort, 0) + 1
        )

    expected = {
        "malicious": 75,
        "benign": 75,
        "legitimate_banking": 20,
    }

    for cohort, expected_count in expected.items():

        actual = counts.get(
            cohort,
            0,
        )

        if actual != expected_count:

            raise RuntimeError(
                f"{cohort}: expected "
                f"{expected_count}, got {actual}"
            )

    if len(all_rows) != 170:

        raise RuntimeError(
            f"Expected 170 APKs, "
            f"found {len(all_rows)}"
        )

    # --------------------------------------------------------
    # SHA uniqueness
    # --------------------------------------------------------

    shas = [
        row["_sha256"]
        for row in all_rows
    ]

    if len(shas) != len(set(shas)):

        raise RuntimeError(
            "Duplicate SHA256 values "
            "across validation manifests."
        )

    return all_rows


# ============================================================
# REFERENCE PREPARATION
# ============================================================

def prepare_reference_counts(
    family_models,
    cache,
):
    """
    Prepare each Drebin family's sample transition counts once.

    This is used for external/OOD targets so that we don't repeat
    cache normalization for every validation APK.
    """

    prepared = {}

    for family, model in (
        family_models.items()
    ):

        samples = []

        for sha in model.get(
            "sha256s",
            [],
        ):

            record = cache.get(
                sha
            )

            if not isinstance(
                record,
                dict,
            ):
                continue

            dna = record.get(
                "dna",
                {},
            )

            if not isinstance(
                dna,
                dict,
            ):
                continue

            counts = (
                normalize_transition_counts(
                    dna.get(
                        "class_transition_counts",
                        {},
                    )
                )
            )

            if counts:

                samples.append(
                    counts
                )

        prepared[family] = samples

    return prepared


# ============================================================
# REFERENCE MEMBERSHIP
# ============================================================

def detect_reference_family(
    family_models,
    target_sha,
):

    target_sha = target_sha.lower()

    for family, model in (
        family_models.items()
    ):

        for sha in model.get(
            "sha256s",
            [],
        ):

            if (
                str(sha).lower()
                == target_sha
            ):

                return family

    return None


# ============================================================
# FAST EXTERNAL TARGET SCORER
# ============================================================

def score_external_target(
    target_counts,
    family_models,
    stored_idf,
    prepared_refs,
):

    target_package = map_counts(
        target_counts,
        class_to_package,
    )

    results = []

    for family, model in (
        family_models.items()
    ):

        # ----------------------------------------------------
        # Class-IDF
        # V7/V8 family score = MAX over reference samples
        # ----------------------------------------------------

        best_class = 0.0

        for reference_counts in (
            prepared_refs[family]
        ):

            score = (
                class_idf_similarity(
                    target_counts,
                    reference_counts,
                    stored_idf,
                )
            )

            if score > best_class:

                best_class = score

        # ----------------------------------------------------
        # Package Markov
        # ----------------------------------------------------

        package_score = (
            package_markov_similarity(
                target_package,
                model.get(
                    "package_graph",
                    {},
                ),
            )
        )

        # ----------------------------------------------------
        # Frozen fusion
        # ----------------------------------------------------

        behavioral_score = (
            CLASS_WEIGHT
            * best_class
            + PACKAGE_WEIGHT
            * package_score
        )

        results.append(
            {
                "family": family,
                "class_idf_score": best_class,
                "package_markov_score": package_score,
                "behavioral_score": behavioral_score,
                "target_excluded_from_family": 0,
                "reference_samples_used": len(
                    prepared_refs[family]
                ),
            }
        )

    results.sort(
        key=lambda x: (
            -x["behavioral_score"],
            x["family"],
        )
    )

    for rank, row in enumerate(
        results,
        start=1,
    ):

        row["rank"] = rank

    return results


# ============================================================
# RESULT CSV
# ============================================================

RESULT_FIELDS = [
    "index",
    "cohort",
    "bank",
    "app_name",
    "package_name",
    "sha256",
    "apk_path",
    "file_size",
    "behavioral_score",
    "behavioral_similarity",
    "class_idf_score",
    "package_markov_score",
    "closest_family",
    "top1_margin",
    "top1_margin_percent",
    "top_match_rank",
    "target_in_reference",
    "reference_family",
    "loo_enabled",
    "loo_idf_entries",
    "reference_family_count",
    "reference_sample_count",
    "dex_files",
    "application_classes",
    "framework_classes",
    "unique_api_classes",
    "methods_with_api_calls",
    "api_calls",
    "unique_class_transitions",
    "transition_occurrences",
    "status",
    "error",
    "runtime_seconds",
]


def append_result(
    result,
):

    new_file = (
        not RESULTS_CSV.exists()
    )

    RESULTS_CSV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with RESULTS_CSV.open(
        "a",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=RESULT_FIELDS,
        )

        if new_file:

            writer.writeheader()

        writer.writerow(
            {
                field: result.get(
                    field,
                    "",
                )
                for field in RESULT_FIELDS
            }
        )


# ============================================================
# RANKINGS CSV
# ============================================================

RANKING_FIELDS = [
    "index",
    "cohort",
    "bank",
    "app_name",
    "package_name",
    "sha256",
    "rank",
    "family",
    "behavioral_score",
    "class_idf_score",
    "package_markov_score",
]


def append_rankings(
    rows,
):

    new_file = (
        not RANKINGS_CSV.exists()
    )

    RANKINGS_CSV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with RANKINGS_CSV.open(
        "a",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=RANKING_FIELDS,
        )

        if new_file:

            writer.writeheader()

        writer.writerows(
            {
                field: row.get(
                    field,
                    "",
                )
                for field in RANKING_FIELDS
            }
            for row in rows
        )


# ============================================================
# RESUME SUPPORT
# ============================================================

def load_completed():

    if not RESULTS_CSV.exists():

        return set()

    completed = set()

    with RESULTS_CSV.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as f:

        reader = csv.DictReader(f)

        for row in reader:

            if (
                row.get("status")
                == "complete"
            ):

                sha = (
                    row.get(
                        "sha256",
                        "",
                    )
                    .strip()
                    .lower()
                )

                if sha:

                    completed.add(
                        sha
                    )

    return completed


# ============================================================
# METRICS
# ============================================================

def calculate_auc(
    labels,
    scores,
):

    positive = [
        score
        for label, score
        in zip(
            labels,
            scores,
        )
        if label == 1
    ]

    negative = [
        score
        for label, score
        in zip(
            labels,
            scores,
        )
        if label == 0
    ]

    if not positive or not negative:

        return None

    wins = 0.0
    ties = 0.0

    for p in positive:

        for n in negative:

            if p > n:

                wins += 1

            elif p == n:

                ties += 1

    return (
        wins
        + 0.5 * ties
    ) / (
        len(positive)
        * len(negative)
    )


def calculate_binary_metrics(
    rows,
    threshold=85.0,
):

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for row in rows:

        if (
            row.get("status")
            != "complete"
        ):

            continue

        if row.get(
            "cohort"
        ) not in (
            "malicious",
            "benign",
        ):

            continue

        score = float(
            row["behavioral_score"]
        )

        prediction = (
            score > threshold
        )

        actual = (
            row["cohort"]
            == "malicious"
        )

        if actual and prediction:

            tp += 1

        elif (
            not actual
            and prediction
        ):

            fp += 1

        elif (
            not actual
            and not prediction
        ):

            tn += 1

        else:

            fn += 1

    total = (
        tp + fp + tn + fn
    )

    accuracy = (
        (tp + tn) / total
        if total
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if tp + fp
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn
        else 0.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if precision + recall
        else 0.0
    )

    fpr = (
        fp / (fp + tn)
        if fp + tn
        else 0.0
    )

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def write_metrics():

    if not RESULTS_CSV.exists():

        return

    with RESULTS_CSV.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as f:

        rows = list(
            csv.DictReader(f)
        )

    complete = [
        row
        for row in rows
        if row.get("status")
        == "complete"
    ]

    malicious = [
        row
        for row in complete
        if row.get("cohort")
        == "malicious"
    ]

    benign = [
        row
        for row in complete
        if row.get("cohort")
        == "benign"
    ]

    banking = [
        row
        for row in complete
        if row.get("cohort")
        == "legitimate_banking"
    ]

    lines = []

    lines.append("=" * 90)
    lines.append(
        "SPECTRE MODULE 2 — "
        "FORMAL 170-APK VALIDATION"
    )
    lines.append("=" * 90)
    lines.append("")

    lines.append(
        "Frozen fusion:"
    )

    lines.append(
        f"Behavioral = "
        f"{CLASS_WEIGHT:.2f} * Class-IDF + "
        f"{PACKAGE_WEIGHT:.2f} * Package Markov"
    )

    lines.append("")

    lines.append(
        "Important:"
    )

    lines.append(
        "Module 2 reports closest behavioral "
        "match/similarity, not malware probability."
    )

    lines.append(
        "The 85% binary metrics are an "
        "operational experiment using cohort labels."
    )

    lines.append("")

    lines.append("COHORT COUNTS")
    lines.append("-" * 90)

    lines.append(
        f"Malicious          : {len(malicious)}"
    )

    lines.append(
        f"Benign             : {len(benign)}"
    )

    lines.append(
        f"Legitimate banking : {len(banking)}"
    )

    lines.append(
        f"Complete total     : {len(complete)}"
    )

    lines.append("")

    # --------------------------------------------------------
    # Distribution helper
    # --------------------------------------------------------

    for title, group in (
        ("MALICIOUS", malicious),
        ("BENIGN", benign),
        ("LEGITIMATE BANKING", banking),
    ):

        if not group:

            continue

        scores = sorted(
            float(
                row["behavioral_score"]
            )
            for row in group
        )

        mean = (
            sum(scores)
            / len(scores)
        )

        median = scores[
            len(scores) // 2
        ]

        high = sum(
            score > 85.0
            for score in scores
        )

        lines.append(title)
        lines.append("-" * 90)

        lines.append(
            f"Mean   : {mean:.6f}%"
        )

        lines.append(
            f"Median : {median:.6f}%"
        )

        lines.append(
            f"Min    : {min(scores):.6f}%"
        )

        lines.append(
            f"Max    : {max(scores):.6f}%"
        )

        lines.append(
            f">85%   : {high}/{len(scores)} "
            f"({100 * high / len(scores):.2f}%)"
        )

        lines.append("")

    # --------------------------------------------------------
    # Primary binary metrics
    # --------------------------------------------------------

    metrics = (
        calculate_binary_metrics(
            complete,
            85.0,
        )
    )

    lines.append(
        "PRIMARY 75 MALICIOUS vs 75 BENIGN"
    )

    lines.append("-" * 90)

    lines.append(
        "Threshold: behavioral_score > 85%"
    )

    lines.append(
        f"TP={metrics['tp']} "
        f"FP={metrics['fp']} "
        f"TN={metrics['tn']} "
        f"FN={metrics['fn']}"
    )

    lines.append(
        f"Accuracy  : "
        f"{metrics['accuracy'] * 100:.2f}%"
    )

    lines.append(
        f"Precision : "
        f"{metrics['precision'] * 100:.2f}%"
    )

    lines.append(
        f"Recall    : "
        f"{metrics['recall'] * 100:.2f}%"
    )

    lines.append(
        f"F1        : "
        f"{metrics['f1'] * 100:.2f}%"
    )

    lines.append(
        f"FPR       : "
        f"{metrics['fpr'] * 100:.2f}%"
    )

    lines.append("")

    # --------------------------------------------------------
    # ROC-AUC
    # --------------------------------------------------------

    binary_rows = [
        row
        for row in complete
        if row.get("cohort")
        in (
            "malicious",
            "benign",
        )
    ]

    labels = [
        1
        if row["cohort"]
        == "malicious"
        else 0
        for row in binary_rows
    ]

    scores = [
        float(
            row["behavioral_score"]
        ) / 100.0
        for row in binary_rows
    ]

    auc_value = calculate_auc(
        labels,
        scores,
    )

    lines.append(
        "DISCRIMINATION"
    )

    lines.append("-" * 90)

    if auc_value is None:

        lines.append(
            "ROC-AUC: N/A"
        )

    else:

        lines.append(
            f"ROC-AUC: "
            f"{auc_value:.6f}"
        )

    lines.append("")

    # --------------------------------------------------------
    # Banking false-positive check
    # --------------------------------------------------------

    banking_high = [
        row
        for row in banking
        if float(
            row["behavioral_score"]
        ) > 85.0
    ]

    lines.append(
        "LEGITIMATE BANKING "
        "FALSE-POSITIVE CHECK"
    )

    lines.append("-" * 90)

    if banking:
        banking_rate = (
            100.0 * len(banking_high) / len(banking)
        )
        banking_summary = (
            f"{len(banking_high)}/{len(banking)} "
            f"({banking_rate:.2f}%)"
        )
    else:
        banking_summary = "N/A (banking cohort not included in this run)"

    lines.append(
        f"Banking apps >85%: {banking_summary}"
    )

    lines.append("")

    for row in sorted(
        banking,
        key=lambda x:
            -float(
                x["behavioral_score"]
            ),
    ):

        lines.append(
            f"{float(row['behavioral_score']):8.3f}% | "
            f"{row['closest_family']:<25} | "
            f"{row['app_name']} | "
            f"{row['package_name']}"
        )

    lines.append("")

    # --------------------------------------------------------
    # Closest family distribution
    # --------------------------------------------------------

    family_counts = {}

    for row in complete:

        family = row.get(
            "closest_family",
            "",
        )

        family_counts[family] = (
            family_counts.get(
                family,
                0,
            )
            + 1
        )

    lines.append(
        "CLOSEST FAMILY DISTRIBUTION"
    )

    lines.append("-" * 90)

    for family, count in sorted(
        family_counts.items(),
        key=lambda x: (
            -x[1],
            x[0],
        ),
    ):

        lines.append(
            f"{family:<30} {count:>4}"
        )

    lines.append("")

    lines.append(
        f"Results  : {RESULTS_CSV}"
    )

    lines.append(
        f"Top-10   : {RANKINGS_CSV}"
    )

    lines.append(
        f"Metrics  : {METRICS_TXT}"
    )

    METRICS_TXT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


# ============================================================
# ISOLATED ANDROGUARD EXTRACTION
# ============================================================

EXTRACTION_TIMEOUT_SECONDS = 180  # default; CLI --timeout can override


def _extract_worker(apk_path_str, connection):
    """Run Androguard extraction in a short-lived child process."""

    try:
        extracted = extract_target_transitions(Path(apk_path_str))
        connection.send(("ok", extracted))
    except BaseException as exc:
        try:
            connection.send(("error", type(exc).__name__, str(exc)))
        except Exception:
            pass
    finally:
        try:
            connection.close()
        except Exception:
            pass


def extract_target_transitions_isolated(apk_path, timeout_seconds=180):
    """Extract one APK in an isolated Windows spawn process."""

    ctx = mp.get_context("spawn")
    parent_conn, child_conn = ctx.Pipe(duplex=False)

    process = ctx.Process(
        target=_extract_worker,
        args=(str(apk_path), child_conn),
    )
    process.start()
    child_conn.close()

    try:
        deadline = time.monotonic() + timeout_seconds
        payload = None

        while True:
            if parent_conn.poll(0.5):
                payload = parent_conn.recv()
                break

            if not process.is_alive():
                process.join()
                raise RuntimeError(
                    f"Extraction worker exited without a result "
                    f"(exitcode={process.exitcode}): {apk_path}"
                )

            if time.monotonic() >= deadline:
                process.terminate()
                process.join(10)
                raise TimeoutError(
                    f"Androguard extraction exceeded {timeout_seconds}s: {apk_path}"
                )
    finally:
        parent_conn.close()

    process.join(timeout=5)

    if process.is_alive():
        process.terminate()
        process.join(5)

    if not payload:
        raise RuntimeError(
            f"Extraction worker exited without a result (exitcode={process.exitcode}): {apk_path}"
        )

    if payload[0] == "error":
        raise RuntimeError(f"{payload[1]}: {payload[2]}")

    if payload[0] != "ok":
        raise RuntimeError(f"Unknown extraction worker status: {payload[0]}")

    return payload[1]


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Run SPECTRE Module 2 Behavioral DNA "
            "validation over the 170 APK corpus."
        )
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=(
            "Run only the first N samples. "
            "Use --limit 1 for the first test."
        ),
    )

    parser.add_argument(
        "--cohort",
        choices=[
            "malicious",
            "benign",
            "legitimate_banking",
        ],
        default=None,
        help="Run one cohort only.",
    )

    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Skip samples already marked complete "
            "in module2_validation_results.csv."
        ),
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help=(
            "Maximum seconds allowed for one APK behavioral extraction. "
            "Timed-out samples are recorded as errors and validation continues. "
            "Default: 180 seconds."
        ),
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        raise ValueError("--timeout must be > 0")

    if (
        args.limit is not None
        and args.limit <= 0
    ):

        raise ValueError(
            "--limit must be > 0"
        )

    rows = load_validation_manifest()

    if args.cohort:

        rows = [
            row
            for row in rows
            if row["cohort"]
            == args.cohort
        ]

    if args.limit:

        rows = rows[
            :args.limit
        ]

    print()
    print("=" * 90)
    print(
        "SPECTRE MODULE 2 — "
        "170 APK VALIDATION RUNNER"
    )
    print("=" * 90)
    print()

    print(
        f"Reference file : "
        f"{REFERENCE_FILE}"
    )

    print(
        f"Cache file     : "
        f"{CACHE_FILE}"
    )

    print(
        f"Samples queued : "
        f"{len(rows)}"
    )

    print()

    print(
        "Loading Drebin reference model/cache..."
    )

    family_models, stored_idf, metadata, cache = (
        load_models()
    )

    if len(family_models) != 179:

        raise RuntimeError(
            f"Expected 179 families, "
            f"found {len(family_models)}"
        )

    print(
        f"Families available : "
        f"{len(family_models)}"
    )

    print(
        f"Reference samples  : "
        f"{metadata.get('sample_count', len(cache))}"
    )

    print(
        f"Stored IDF entries : "
        f"{len(stored_idf)}"
    )

    print()

    print(
        "Preparing reference transition counts once..."
    )

    prepared_refs = (
        prepare_reference_counts(
            family_models,
            cache,
        )
    )

    # Raw per-sample cache is no longer needed after preparation.
    del cache
    gc.collect()

    print(
        "Reference preparation complete."
    )

    completed = (
        load_completed()
        if args.resume
        else set()
    )

    if not args.resume:

        # Fresh experiment.
        # Remove previous result files only if they exist,
        # so the run cannot accidentally append to an old run.
        if RESULTS_CSV.exists():

            RESULTS_CSV.unlink()

        if RANKINGS_CSV.exists():

            RANKINGS_CSV.unlink()

    print()

    for number, row in enumerate(
        rows,
        start=1,
    ):

        sha = row["_sha256"]

        apk_path = Path(
            row["_apk_path"]
        )

        display_name = (
            row.get("app_name")
            or row.get("package_name")
            or row.get("pkg_name")
            or sha
        )

        if (
            args.resume
            and sha in completed
        ):

            print(
                f"[{number:03d}/{len(rows):03d}] "
                f"SKIP complete | "
                f"{row['cohort']} | "
                f"{display_name}"
            )

            continue

        started = time.perf_counter()

        print(
            f"[{number:03d}/{len(rows):03d}] "
            f"ANALYZING | "
            f"{row['cohort']:<19} | "
            f"{display_name}"
        )

        try:

            # ------------------------------------------------
            # Verify APK against manifest SHA
            # ------------------------------------------------

            actual_sha = sha256_file(
                apk_path
            )

            if (
                actual_sha.lower()
                != sha.lower()
            ):

                raise RuntimeError(
                    "SHA256 mismatch: "
                    f"manifest={sha}, "
                    f"actual={actual_sha}"
                )

            # ------------------------------------------------
            # Behavioral extraction
            # ------------------------------------------------

            extracted = extract_target_transitions_isolated(
                apk_path,
                timeout_seconds=args.timeout,
            )

            target_counts = (
                normalize_transition_counts(
                    extracted[
                        "class_transition_counts"
                    ]
                )
            )

            flat = flatten_counts(
                target_counts
            )

            if not target_counts:

                raise RuntimeError(
                    "Target produced no usable "
                    "class transitions."
                )

            # ------------------------------------------------
            # Reference membership
            # ------------------------------------------------

            reference_family = (
                detect_reference_family(
                    family_models,
                    sha,
                )
            )

            # ------------------------------------------------
            # External target = optimized path
            # In-reference target = exact production V9.1 path
            # ------------------------------------------------

            loo_enabled = False
            loo_idf_entries = 0

            # ============================================================
# ALL 170 VALIDATION APKs ARE EXTERNAL TEST SAMPLES
# ============================================================
#
# The validation manifests were constructed with Drebin
# SHA256 overlaps excluded. Therefore these APKs should be
# scored as independent/out-of-reference targets.
#
# We deliberately do NOT modify the Drebin reference corpus.
# ============================================================

            reference_family = detect_reference_family(
                family_models,
                sha,
            )

            if reference_family is not None:
                raise RuntimeError(
                    f"VALIDATION LEAKAGE DETECTED: "
                    f"{sha} is already present in Drebin "
                    f"family '{reference_family}'. "
                    f"Do not continue until this is investigated."
                )

            rankings = score_external_target(
                target_counts,
                family_models,
                stored_idf,
                prepared_refs,
            )

            target_in_reference = False
            loo_family = ""
            loo_enabled = False
            loo_idf_entries = 0

            if len(rankings) != 179:

                raise RuntimeError(
                    f"Expected 179 family scores, "
                    f"got {len(rankings)}"
                )

            # ------------------------------------------------
            # Top result
            # ------------------------------------------------

            top = rankings[0]
            second = rankings[1]

            behavior = float(
                top["behavioral_score"]
            )

            margin = (
                behavior
                - float(
                    second["behavioral_score"]
                )
            )

            runtime = (
                time.perf_counter()
                - started
            )

            result = {
                "index":
                    number,

                "cohort":
                    row["cohort"],

                "bank":
                    row.get(
                        "bank",
                        "",
                    ),

                "app_name":
                    row.get(
                        "app_name",
                        "",
                    ),

                "package_name":
                    row.get(
                        "package_name",
                        row.get(
                            "pkg_name",
                            "",
                        ),
                    ),

                "sha256":
                    sha,

                "apk_path":
                    str(apk_path),

                "file_size":
                    apk_path.stat().st_size,

                # Human-readable 0-100 score.
                "behavioral_score":
                    behavior * 100.0,

                # Core 0-1 score.
                "behavioral_similarity":
                    behavior,

                "class_idf_score":
                    float(
                        top[
                            "class_idf_score"
                        ]
                    ),

                "package_markov_score":
                    float(
                        top[
                            "package_markov_score"
                        ]
                    ),

                "closest_family":
                    top["family"],

                "top1_margin":
                    margin,

                "top1_margin_percent":
                    margin * 100.0,

                "top_match_rank":
                    top["rank"],

                "target_in_reference":
                    target_in_reference,

                "reference_family":
                    loo_family,

                "loo_enabled":
                    loo_enabled,

                "loo_idf_entries":
                    loo_idf_entries,

                "reference_family_count":
                    len(
                        family_models
                    ),

                "reference_sample_count":
                    int(
                        metadata.get(
                            "sample_count",
                            0,
                        )
                    ),

                "dex_files":
                    extracted[
                        "dex_files"
                    ],

                "application_classes":
                    len(
                        extracted[
                            "application_classes"
                        ]
                    ),

                "framework_classes":
                    len(
                        extracted[
                            "framework_classes"
                        ]
                    ),

                "unique_api_classes":
                    len(
                        extracted[
                            "framework_classes"
                        ]
                    ),

                "methods_with_api_calls":
                    extracted[
                        "methods"
                    ],

                "api_calls":
                    extracted[
                        "api_calls"
                    ],

                "unique_class_transitions":
                    len(flat),

                "transition_occurrences":
                    sum(flat.values()),

                "status":
                    "complete",

                "error":
                    "",

                "runtime_seconds":
                    runtime,
            }

            append_result(
                result
            )

            # ------------------------------------------------
            # Save top 10
            # ------------------------------------------------

            ranking_output = []

            for ranking in rankings[:10]:

                ranking_output.append(
                    {
                        "index":
                            number,

                        "cohort":
                            row["cohort"],

                        "bank":
                            row.get(
                                "bank",
                                "",
                            ),

                        "app_name":
                            row.get(
                                "app_name",
                                "",
                            ),

                        "package_name":
                            row.get(
                                "package_name",
                                row.get(
                                    "pkg_name",
                                    "",
                                ),
                            ),

                        "sha256":
                            sha,

                        "rank":
                            ranking[
                                "rank"
                            ],

                        "family":
                            ranking[
                                "family"
                            ],

                        "behavioral_score":
                            ranking[
                                "behavioral_score"
                            ],

                        "class_idf_score":
                            ranking[
                                "class_idf_score"
                            ],

                        "package_markov_score":
                            ranking[
                                "package_markov_score"
                            ],
                    }
                )

            append_rankings(
                ranking_output
            )

            print(
                f"          "
                f"MATCH={top['family']} | "
                f"Behavioral="
                f"{behavior * 100:.3f}% | "
                f"Class-IDF="
                f"{float(top['class_idf_score']) * 100:.3f}% | "
                f"Package="
                f"{float(top['package_markov_score']) * 100:.3f}% | "
                f"Margin="
                f"{margin * 100:.3f} pp | "
                f"{runtime:.1f}s"
            )

        except Exception as exc:

            runtime = (
                time.perf_counter()
                - started
            )

            error_result = {
                "index":
                    number,

                "cohort":
                    row["cohort"],

                "bank":
                    row.get(
                        "bank",
                        "",
                    ),

                "app_name":
                    row.get(
                        "app_name",
                        "",
                    ),

                "package_name":
                    row.get(
                        "package_name",
                        row.get(
                            "pkg_name",
                            "",
                        ),
                    ),

                "sha256":
                    sha,

                "apk_path":
                    str(apk_path),

                "file_size":
                    (
                        apk_path.stat().st_size
                        if apk_path.exists()
                        else ""
                    ),

                "status":
                    "error",

                "error":
                    (
                        f"{type(exc).__name__}: "
                        f"{exc}"
                    ),

                "runtime_seconds":
                    runtime,
            }

            append_result(
                error_result
            )

            print(
                f"          ERROR: "
                f"{type(exc).__name__}: "
                f"{exc}"
            )

        # Release parent-side temporary objects between samples.
        gc.collect()

    # --------------------------------------------------------
    # Final metrics
    # --------------------------------------------------------

    write_metrics()

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    if RESULTS_CSV.exists():

        with RESULTS_CSV.open(
            "r",
            encoding="utf-8",
            newline="",
        ) as f:

            final_rows = list(
                csv.DictReader(f)
            )

        complete = sum(
            row.get("status")
            == "complete"
            for row in final_rows
        )

        errors = sum(
            row.get("status")
            == "error"
            for row in final_rows
        )

    else:

        complete = 0
        errors = 0

    print()
    print("=" * 90)
    print(
        "MODULE 2 VALIDATION RUN COMPLETE"
    )
    print("=" * 90)

    print(
        f"Complete results : "
        f"{complete}"
    )

    print(
        f"Errors           : "
        f"{errors}"
    )

    print()
    print(
        f"Results CSV  : "
        f"{RESULTS_CSV}"
    )

    print(
        f"Top-10 CSV   : "
        f"{RANKINGS_CSV}"
    )

    print(
        f"Metrics TXT  : "
        f"{METRICS_TXT}"
    )


if __name__ == "__main__":
    main()