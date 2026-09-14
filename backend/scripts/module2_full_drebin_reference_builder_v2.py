
"""
SPECTRE MODULE 2
FULL DREBIN FAMILY REFERENCE BUILDER - V2

Fixes versus the previous builder:
1. Safely ignores zero-byte/corrupt full cache files instead of crashing.
2. DOES NOT infer Drebin family from folders such as drebin-4.
   Drebin batch folders are not malware-family labels.
3. Attempts to discover an external SHA256 -> family mapping file under
   the Drebin dataset directory.
4. Reuses the already validated pilot cache.
5. Checkpoints the sample cache atomically so interruption does not leave
   a zero-byte pickle.
6. Builds full-family package/function/class references only after a valid
   SHA256 -> family mapping has been found.

The builder stops with a clear error if it cannot find a trustworthy family
mapping. It will NOT silently label samples as drebin-0/drebin-1/etc.

Expected root:
    D:\Spectre_BOI_project\SPECTRE\data\drebin\drebin-share

Outputs:
    models\drebin_graphs_v2\full_drebin_sample_dna_cache.pkl
    models\drebin_graphs_v2\full_drebin_family_references.pkl
    models\drebin_graphs_v2\full_drebin_family_inventory.csv
    models\drebin_graphs_v2\full_drebin_build_log.csv
"""

from __future__ import annotations

import csv
import math
import os
import pickle
import re
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

import networkx as nx


# =============================================================================
# PATHS
# =============================================================================

PROJECT_ROOT = Path(r"D:\Spectre_BOI_project\SPECTRE")

DREBIN_ROOT = (
    PROJECT_ROOT
    / "data"
    / "drebin"
    / "drebin-share"
)

APK_ROOT = DREBIN_ROOT / "apks"

OLD_PILOT_CACHE = (
    PROJECT_ROOT
    / "models"
    / "drebin_graphs_v2"
    / "sample_dna_cache.pkl"
)

FULL_CACHE = (
    PROJECT_ROOT
    / "models"
    / "drebin_graphs_v2"
    / "full_drebin_sample_dna_cache.pkl"
)

FAMILY_REFERENCE_CACHE = (
    PROJECT_ROOT
    / "models"
    / "drebin_graphs_v2"
    / "full_drebin_family_references.pkl"
)

INVENTORY_CSV = (
    PROJECT_ROOT
    / "models"
    / "drebin_graphs_v2"
    / "full_drebin_family_inventory.csv"
)

BUILD_LOG_CSV = (
    PROJECT_ROOT
    / "models"
    / "drebin_graphs_v2"
    / "full_drebin_build_log.csv"
)


# =============================================================================
# SETTINGS
# =============================================================================

INVOKE_PREFIXES = (
    "invoke-virtual",
    "invoke-super",
    "invoke-direct",
    "invoke-static",
    "invoke-interface",
)

FRAMEWORK_PREFIXES = (
    "android.",
    "java.",
    "javax.",
    "dalvik.",
    "com.google.",
    "okhttp3.",
    "retrofit2.",
)

SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Common candidate family-column names.
SHA_COLUMNS = (
    "sha256",
    "sha",
    "hash",
    "sha-256",
    "sha_256",
)

FAMILY_COLUMNS = (
    "family",
    "malware_family",
    "malware family",
    "class",
    "label",
    "category",
)


# =============================================================================
# FUNCTIONAL TAXONOMY
# =============================================================================

FAMILY_RULES = {
    "android.telephony": "TELEPHONY",
    "android.telecom": "TELEPHONY",
    "android.provider": "DATA_PROVIDER",
    "android.sms": "SMS_MESSAGING",
    "android.mms": "SMS_MESSAGING",
    "android.net.wifi.p2p": "NETWORK",
    "android.net.wifi": "NETWORK",
    "android.net.http": "NETWORK",
    "android.net": "NETWORK",
    "okhttp3": "NETWORK",
    "retrofit2": "NETWORK",
    "java.net": "NETWORK",
    "javax.net.ssl": "NETWORK_SECURITY",
    "javax.net": "NETWORK_SECURITY",
    "android.inputmethodservice": "UI",
    "android.webkit": "UI",
    "android.widget": "UI",
    "android.view": "UI",
    "android.appwidget": "APP_COMPONENT",
    "android.app": "APP_COMPONENT",
    "android.content.res": "RESOURCE_CONFIG",
    "android.content": "CONTENT_IPC",
    "dalvik.system": "SYSTEM_RUNTIME",
    "android.system": "SYSTEM_RUNTIME",
    "android.os": "SYSTEM_RUNTIME",
    "android.database.sqlite": "DATABASE_STORAGE",
    "android.database": "DATABASE_STORAGE",
    "android.preference": "DATABASE_STORAGE",
    "java.sql": "DATABASE_STORAGE",
    "java.nio": "FILE_IO",
    "java.io": "FILE_IO",
    "android.graphics": "MEDIA_GRAPHICS",
    "android.media": "MEDIA",
    "android.hardware.camera": "HARDWARE_SENSOR",
    "android.hardware": "HARDWARE_SENSOR",
    "android.location": "LOCATION",
    "android.bluetooth": "BLUETOOTH",
    "android.nfc": "NFC",
    "android.security.keystore": "CRYPTO_SECURITY",
    "javax.crypto": "CRYPTO_SECURITY",
    "android.security": "SECURITY",
    "java.security": "SECURITY",
    "android.accounts": "ACCOUNT_AUTH",
    "android.accessibilityservice": "ACCESSIBILITY",
    "android.text": "TEXT_PROCESSING",
    "java.text": "TEXT_PROCESSING",
    "javax.xml": "XML_PROCESSING",
    "java.lang": "CORE_RUNTIME",
    "android.util": "UTILITY",
    "java.util": "UTILITY",
    "java.math": "MATH",
    "com.google": "GOOGLE_SERVICES",
}


# =============================================================================
# NORMALIZATION
# =============================================================================

def normalize_class_name(name: str) -> str:
    if not isinstance(name, str):
        return ""

    name = name.strip()

    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]

    return name.replace("/", ".")


def class_to_package(class_name: str) -> str:
    class_name = normalize_class_name(class_name)
    parts = class_name.split(".")

    if len(parts) <= 1:
        return class_name

    return ".".join(parts[:-1])


def package_to_family(package_name: str) -> str:
    package_name = package_name.strip()

    best_prefix = None
    best_family = None

    for prefix, family in FAMILY_RULES.items():
        if (
            package_name == prefix
            or package_name.startswith(prefix + ".")
        ):
            if (
                best_prefix is None
                or len(prefix) > len(best_prefix)
            ):
                best_prefix = prefix
                best_family = family

    if best_family is not None:
        return best_family

    if package_name.startswith("android."):
        return "ANDROID_OTHER"
    if package_name.startswith("java."):
        return "JAVA_OTHER"
    if package_name.startswith("javax."):
        return "JAVAX_OTHER"
    if package_name.startswith("dalvik."):
        return "DALVIK_OTHER"
    if package_name.startswith("com."):
        return "THIRD_PARTY_OTHER"

    return "OTHER"


# =============================================================================
# COUNTS
# =============================================================================

def normalize_transition_counts(raw_counts):
    if not isinstance(raw_counts, dict):
        return {}

    result = defaultdict(dict)

    tuple_format = any(
        isinstance(key, tuple) and len(key) == 2
        for key in raw_counts
    )

    if tuple_format:
        for key, value in raw_counts.items():
            if not (
                isinstance(key, tuple)
                and len(key) == 2
            ):
                continue

            src, dst = key

            try:
                count = int(value)
            except Exception:
                continue

            if count <= 0:
                continue

            src = normalize_class_name(str(src))
            dst = normalize_class_name(str(dst))

            if src and dst:
                result[src][dst] = count

    else:
        for src, destinations in raw_counts.items():
            if not isinstance(destinations, dict):
                continue

            src = normalize_class_name(str(src))

            if not src:
                continue

            for dst, value in destinations.items():
                try:
                    count = int(value)
                except Exception:
                    continue

                if count <= 0:
                    continue

                dst = normalize_class_name(str(dst))

                if dst:
                    result[src][dst] = count

    return {
        src: dict(destinations)
        for src, destinations in result.items()
    }


def flatten_counts(nested):
    flat = {}

    for src, destinations in nested.items():
        for dst, count in destinations.items():
            flat[(src, dst)] = int(count)

    return flat


def map_counts(class_counts, mapper):
    mapped = defaultdict(lambda: defaultdict(int))

    for src, destinations in class_counts.items():
        mapped_src = mapper(src)

        for dst, count in destinations.items():
            mapped_dst = mapper(dst)
            mapped[mapped_src][mapped_dst] += count

    return {
        src: dict(destinations)
        for src, destinations in mapped.items()
    }


def package_mapper(name):
    return class_to_package(name)


def family_mapper(name):
    return package_to_family(
        class_to_package(name)
    )


# =============================================================================
# MARKOV / IDF
# =============================================================================

def build_equal_sample_markov(sample_counts_list):
    if not sample_counts_list:
        return nx.DiGraph()

    source_distributions = defaultdict(list)

    for counts in sample_counts_list:
        for src, destinations in counts.items():
            total = sum(destinations.values())

            if total <= 0:
                continue

            distribution = {
                dst: count / total
                for dst, count in destinations.items()
            }

            source_distributions[src].append(
                distribution
            )

    graph = nx.DiGraph()

    for src, distributions in source_distributions.items():
        destination_set = set()

        for distribution in distributions:
            destination_set.update(distribution.keys())

        n = len(distributions)

        for dst in destination_set:
            probability = (
                sum(
                    distribution.get(dst, 0.0)
                    for distribution in distributions
                )
                / n
            )

            if probability > 0:
                graph.add_edge(
                    src,
                    dst,
                    weight=probability,
                )

    return graph


def build_transition_idf(references):
    family_df = Counter()

    for family, samples in references.items():
        family_transitions = set()

        for sample in samples:
            family_transitions.update(
                flatten_counts(
                    sample["class_counts"]
                ).keys()
            )

        for transition in family_transitions:
            family_df[transition] += 1

    n_families = len(references)

    idf = {}

    for transition, df in family_df.items():
        idf[transition] = (
            math.log(
                (n_families + 1)
                / (df + 1)
            )
            + 1.0
        )

    return idf


# =============================================================================
# ATOMIC PICKLE
# =============================================================================

def atomic_pickle_dump(obj, destination: Path):
    destination.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    fd, temp_name = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=str(destination.parent),
    )

    try:
        with os.fdopen(fd, "wb") as f:
            pickle.dump(
                obj,
                f,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
            f.flush()
            os.fsync(f.fileno())

        os.replace(
            temp_name,
            destination,
        )

    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def safe_load_pickle(path: Path):
    if not path.exists():
        return None

    size = path.stat().st_size

    if size == 0:
        print(
            f"Ignoring zero-byte cache: {path}"
        )
        return None

    try:
        with path.open("rb") as f:
            return pickle.load(f)
    except (
        EOFError,
        pickle.UnpicklingError,
        AttributeError,
        ValueError,
        TypeError,
    ) as exc:
        print(
            f"Ignoring unreadable cache: {path}"
        )
        print(
            f"    {type(exc).__name__}: {exc}"
        )
        return None


# =============================================================================
# FAMILY MAPPING DISCOVERY
# =============================================================================

def normalize_header(value):
    return (
        str(value)
        .strip()
        .lower()
        .replace("\ufeff", "")
    )


def find_mapping_columns(fieldnames):
    normalized = {
        normalize_header(name): name
        for name in fieldnames
    }

    sha_col = None
    family_col = None

    for candidate in SHA_COLUMNS:
        if candidate in normalized:
            sha_col = normalized[candidate]
            break

    for candidate in FAMILY_COLUMNS:
        if candidate in normalized:
            family_col = normalized[candidate]
            break

    return sha_col, family_col


def load_family_mapping_file(path: Path):
    try:
        with path.open(
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as f:
            reader = csv.DictReader(f)

            if not reader.fieldnames:
                return None

            sha_col, family_col = find_mapping_columns(
                reader.fieldnames
            )

            if not sha_col or not family_col:
                return None

            mapping = {}

            for row in reader:
                raw_sha = str(
                    row.get(sha_col, "")
                ).strip().lower()

                family = str(
                    row.get(family_col, "")
                ).strip()

                if not SHA256_RE.fullmatch(raw_sha):
                    continue

                if not family:
                    continue

                mapping[raw_sha] = family

            if not mapping:
                return None

            return mapping

    except (
        UnicodeDecodeError,
        csv.Error,
        OSError,
    ):
        return None


def discover_family_mapping():
    """
    Search only metadata-style CSV/TSV files under the Drebin share root.

    Folder names like drebin-0/drebin-4 are deliberately ignored because
    they are dataset batches, not reliable malware-family labels.
    """
    candidates = []

    for pattern in (
        "*.csv",
        "*.CSV",
        "*.tsv",
        "*.TSV",
    ):
        candidates.extend(
            DREBIN_ROOT.rglob(pattern)
        )

    # Prefer filenames that look like labels/mappings.
    candidates = sorted(
        set(candidates),
        key=lambda p: (
            0 if any(
                token in p.name.lower()
                for token in (
                    "family",
                    "label",
                    "class",
                    "sha256",
                    "metadata",
                    "malware",
                )
            ) else 1,
            str(p).lower(),
        ),
    )

    print()
    print("SEARCHING FOR SHA256 -> FAMILY METADATA")

    for path in candidates:
        mapping = load_family_mapping_file(path)

        if mapping:
            print(
                f"Found family mapping: {path}"
            )
            print(
                f"Mapped SHA256 values: {len(mapping)}"
            )
            return mapping, path

    return None, None


# =============================================================================
# APK DISCOVERY
# =============================================================================

def discover_apks():
    if not APK_ROOT.exists():
        raise FileNotFoundError(
            f"APK root does not exist:\n{APK_ROOT}"
        )

    apks = []

    for path in APK_ROOT.rglob("*"):
        if not path.is_file():
            continue

        if path.suffix.lower() == ".apk":
            stem = path.stem
            if SHA256_RE.fullmatch(stem):
                apks.append(path)
            continue

        if SHA256_RE.fullmatch(path.name):
            apks.append(path)

    return sorted(
        set(apks),
        key=lambda p: str(p).lower(),
    )


# =============================================================================
# ANDROGUARD EXTRACTION
# =============================================================================

def extract_class_transitions(apk_path):
    from androguard.misc import AnalyzeAPK

    apk, dex_list, analysis = AnalyzeAPK(
        str(apk_path)
    )

    transitions = defaultdict(int)
    application_classes = set()
    framework_classes = set()

    methods_with_api_calls = 0
    api_calls = 0

    for dex in dex_list:
        for cls in dex.get_classes():
            class_name = normalize_class_name(
                cls.get_name()
            )

            if not class_name:
                continue

            if class_name.startswith(
                FRAMEWORK_PREFIXES
            ):
                framework_classes.add(
                    class_name
                )
            else:
                application_classes.add(
                    class_name
                )

            for method in cls.get_methods():
                instructions = (
                    method.get_instructions()
                )

                if instructions is None:
                    continue

                previous_api_class = None
                method_api_count = 0

                for instruction in instructions:
                    opcode_name = (
                        instruction.get_name()
                        or ""
                    )

                    if not any(
                        opcode_name.startswith(prefix)
                        for prefix in INVOKE_PREFIXES
                    ):
                        continue

                    output = instruction.get_output()

                    if not output:
                        continue

                    api_class = ""

                    for part in output.split(","):
                        part = part.strip()

                        if (
                            part.startswith("L")
                            and ";" in part
                        ):
                            candidate = (
                                part.split("->")[0]
                            )

                            if candidate.endswith(";"):
                                api_class = (
                                    normalize_class_name(
                                        candidate
                                    )
                                )
                                break

                    if not api_class:
                        continue

                    if not api_class.startswith(
                        FRAMEWORK_PREFIXES
                    ):
                        continue

                    framework_classes.add(
                        api_class
                    )

                    api_calls += 1
                    method_api_count += 1

                    if previous_api_class is not None:
                        transitions[
                            (
                                previous_api_class,
                                api_class,
                            )
                        ] += 1

                    previous_api_class = api_class

                if method_api_count > 0:
                    methods_with_api_calls += 1

    return {
        "class_transition_counts": dict(
            transitions
        ),
        "application_classes": application_classes,
        "framework_classes": framework_classes,
        "methods": methods_with_api_calls,
        "api_calls": api_calls,
    }


# =============================================================================
# CACHE
# =============================================================================

def load_existing_cache():
    merged = {}

    pilot = safe_load_pickle(
        OLD_PILOT_CACHE
    )

    if isinstance(pilot, dict):
        print(
            f"Loaded pilot cache: {len(pilot)} records"
        )
        merged.update(pilot)

    full = safe_load_pickle(
        FULL_CACHE
    )

    if isinstance(full, dict):
        print(
            f"Loaded existing full cache: {len(full)} records"
        )
        merged.update(full)

    print(
        f"Combined usable cached records: {len(merged)}"
    )

    return merged


# =============================================================================
# BUILD REFERENCES
# =============================================================================

def build_family_references(
    cache,
    sha_to_family,
):
    references = defaultdict(list)

    unknown_family = 0

    for sha256, record in cache.items():
        if not isinstance(record, dict):
            continue

        dna = record.get("dna")

        if not isinstance(dna, dict):
            continue

        counts = normalize_transition_counts(
            dna.get(
                "class_transition_counts"
            )
        )

        if not counts:
            continue

        family = (
            sha_to_family.get(
                str(sha256).lower()
            )
            or record.get("family")
        )

        if not family:
            unknown_family += 1
            continue

        # Prefer trusted metadata mapping over stale cache family if present.
        if str(sha256).lower() in sha_to_family:
            family = sha_to_family[
                str(sha256).lower()
            ]

        references[family].append(
            {
                "sha256": sha256,
                "class_counts": counts,
            }
        )

    if unknown_family:
        print(
            f"Samples without resolvable family: {unknown_family}"
        )

    references = {
        family: samples
        for family, samples in references.items()
        if samples
    }

    if not references:
        raise RuntimeError(
            "No family references could be constructed."
        )

    transition_idf = build_transition_idf(
        references
    )

    family_models = {}

    for family, samples in references.items():
        package_samples = []
        functional_family_samples = []
        transition_union = set()

        for sample in samples:
            counts = sample["class_counts"]

            package_samples.append(
                map_counts(
                    counts,
                    package_mapper,
                )
            )

            functional_family_samples.append(
                map_counts(
                    counts,
                    family_mapper,
                )
            )

            transition_union.update(
                flatten_counts(counts).keys()
            )

        package_graph = (
            build_equal_sample_markov(
                package_samples
            )
        )

        functional_family_graph = (
            build_equal_sample_markov(
                functional_family_samples
            )
        )

        family_models[family] = {
            "sample_count": len(samples),
            "sha256s": [
                sample["sha256"]
                for sample in samples
            ],
            "package_graph": package_graph,
            "family_graph": functional_family_graph,
            "class_transition_union": transition_union,
        }

    return family_models, transition_idf


# =============================================================================
# MAIN
# =============================================================================

def main():
    started = time.time()

    print("=" * 100)
    print("SPECTRE MODULE 2")
    print("FULL DREBIN FAMILY REFERENCE BUILDER - V2")
    print("=" * 100)
    print()

    print(
        f"Drebin root: {DREBIN_ROOT}"
    )
    print(
        f"APK root:    {APK_ROOT}"
    )
    print()

    apks = discover_apks()

    print(
        f"Drebin APK/sample files discovered: {len(apks)}"
    )

    if len(apks) == 0:
        raise RuntimeError(
            "No SHA256-named/APK samples found."
        )

    # -------------------------------------------------------------------------
    # TRUSTED FAMILY METADATA FIRST.
    # -------------------------------------------------------------------------

    sha_to_family, mapping_path = (
        discover_family_mapping()
    )

    if not sha_to_family:
        raise RuntimeError(
            "\n"
            "STOP: No trustworthy SHA256 -> family metadata file was found.\n"
            "The previous builder must not infer family from directories such as\n"
            "'drebin-4', because those folders are dataset batches rather than\n"
            "malware-family labels.\n"
            "\n"
            "Please locate the Drebin family-label CSV/metadata file under:\n"
            f"    {DREBIN_ROOT}\n"
            "\n"
            "It must contain one SHA256/hash column and one family/label column."
        )

    print()
    print(
        f"Family mapping source: {mapping_path}"
    )
    print(
        f"Mapped SHA256 values:  {len(sha_to_family)}"
    )

    cache = load_existing_cache()

    log_rows = []

    new_count = 0
    reused_count = 0
    failed_count = 0
    skipped_count = 0
    mapping_missing = 0

    total = len(apks)

    for index, apk_path in enumerate(
        apks,
        start=1,
    ):
        sha256 = apk_path.stem.lower()

        if not SHA256_RE.fullmatch(
            sha256
        ):
            sha256 = apk_path.name.lower()

        family = sha_to_family.get(
            sha256
        )

        if not family:
            mapping_missing += 1

            log_rows.append(
                {
                    "sha256": sha256,
                    "family": "",
                    "path": str(apk_path),
                    "status": "SKIPPED_NO_FAMILY_METADATA",
                    "api_calls": 0,
                    "transitions": 0,
                }
            )
            continue

        # Reuse only if there is a usable DNA record.
        if sha256 in cache:
            record = cache[sha256]

            if (
                isinstance(record, dict)
                and isinstance(
                    record.get("dna"),
                    dict,
                )
                and normalize_transition_counts(
                    record["dna"].get(
                        "class_transition_counts",
                        {},
                    )
                )
            ):
                # Metadata mapping is authoritative.
                record["family"] = family

                dna = record["dna"]

                transitions = normalize_transition_counts(
                    dna.get(
                        "class_transition_counts",
                        {},
                    )
                )

                dna["class_transition_counts"] = transitions

                reused_count += 1

                log_rows.append(
                    {
                        "sha256": sha256,
                        "family": family,
                        "path": str(apk_path),
                        "status": "REUSED_CACHE",
                        "api_calls": dna.get(
                            "api_calls",
                            0,
                        ),
                        "transitions": sum(
                            flatten_counts(
                                transitions
                            ).values()
                        ),
                    }
                )
                continue

        print(
            f"[{index}/{total}] "
            f"{family:<24} "
            f"{sha256[:16]}..."
        )

        try:
            extracted = (
                extract_class_transitions(
                    apk_path
                )
            )

            transitions = extracted[
                "class_transition_counts"
            ]

            if not transitions:
                skipped_count += 1

                log_rows.append(
                    {
                        "sha256": sha256,
                        "family": family,
                        "path": str(apk_path),
                        "status": "SKIPPED_NO_TRANSITIONS",
                        "api_calls": extracted[
                            "api_calls"
                        ],
                        "transitions": 0,
                    }
                )

                continue

            cache[sha256] = {
                "family": family,
                "dna": {
                    "api_features": set(),
                    "class_transition_counts": transitions,
                    "package_transition_counts": {},
                    "family_transition_counts": {},
                    "package_nodes": set(),
                    "family_nodes": set(),
                    "api_calls": extracted[
                        "api_calls"
                    ],
                    "methods": extracted[
                        "methods"
                    ],
                    "application_classes": extracted[
                        "application_classes"
                    ],
                    "framework_classes": extracted[
                        "framework_classes"
                    ],
                },
            }

            new_count += 1

            log_rows.append(
                {
                    "sha256": sha256,
                    "family": family,
                    "path": str(apk_path),
                    "status": "EXTRACTED",
                    "api_calls": extracted[
                        "api_calls"
                    ],
                    "transitions": sum(
                        transitions.values()
                    ),
                }
            )

        except Exception as exc:
            failed_count += 1

            print(
                f"    ERROR: {type(exc).__name__}: {exc}"
            )

            log_rows.append(
                {
                    "sha256": sha256,
                    "family": family,
                    "path": str(apk_path),
                    "status": "FAILED",
                    "api_calls": 0,
                    "transitions": 0,
                    "error": str(exc)[:500],
                }
            )

        if (
            index % 25 == 0
            or index == total
        ):
            atomic_pickle_dump(
                cache,
                FULL_CACHE,
            )

            print(
                f"    Atomic checkpoint saved: "
                f"{len(cache)} cache records"
            )

    atomic_pickle_dump(
        cache,
        FULL_CACHE,
    )

    print()
    print("=" * 100)
    print("REFERENCE MODEL CONSTRUCTION")
    print("=" * 100)

    family_models, transition_idf = (
        build_family_references(
            cache,
            sha_to_family,
        )
    )

    atomic_pickle_dump(
        {
            "family_models": family_models,
            "transition_idf": transition_idf,
            "family_count": len(
                family_models
            ),
            "sample_count": sum(
                model["sample_count"]
                for model in family_models.values()
            ),
            "family_mapping_source": str(
                mapping_path
            ),
        },
        FAMILY_REFERENCE_CACHE,
    )

    inventory_rows = []

    for family in sorted(
        family_models
    ):
        model = family_models[family]

        inventory_rows.append(
            {
                "family": family,
                "samples": model[
                    "sample_count"
                ],
                "package_nodes": model[
                    "package_graph"
                ].number_of_nodes(),
                "package_edges": model[
                    "package_graph"
                ].number_of_edges(),
                "functional_family_nodes": model[
                    "family_graph"
                ].number_of_nodes(),
                "functional_family_edges": model[
                    "family_graph"
                ].number_of_edges(),
                "class_transition_types": len(
                    model[
                        "class_transition_union"
                    ]
                ),
            }
        )

    with INVENTORY_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(
                inventory_rows[0].keys()
            ),
        )
        writer.writeheader()
        writer.writerows(
            inventory_rows
        )

    with BUILD_LOG_CSV.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        fieldnames = sorted(
            {
                key
                for row in log_rows
                for key in row
            }
        )

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(
            log_rows
        )

    elapsed = time.time() - started

    print()
    print("=" * 100)
    print("BUILD SUMMARY")
    print("=" * 100)

    print(
        f"Drebin APK/sample files discovered: {len(apks)}"
    )
    print(
        f"Unique cache records:                {len(cache)}"
    )
    print(
        f"Families represented:                {len(family_models)}"
    )
    print(
        f"Newly extracted:                      {new_count}"
    )
    print(
        f"Reused from cache:                   {reused_count}"
    )
    print(
        f"Skipped:                              {skipped_count}"
    )
    print(
        f"Failed extraction:                   {failed_count}"
    )
    print(
        f"Missing family metadata:             {mapping_missing}"
    )
    print(
        f"Transition-IDF entries:               {len(transition_idf)}"
    )

    print()
    print("Outputs:")
    print(FULL_CACHE)
    print(FAMILY_REFERENCE_CACHE)
    print(INVENTORY_CSV)
    print(BUILD_LOG_CSV)

    print()
    print(
        f"Elapsed: {elapsed / 60.0:.2f} minutes"
    )

    print()
    print("=" * 100)
    print("FULL DREBIN REFERENCE BUILD COMPLETE")
    print("=" * 100)


if __name__ == "__main__":
    main()
