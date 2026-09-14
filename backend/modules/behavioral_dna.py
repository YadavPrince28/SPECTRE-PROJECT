"""
SPECTRE MODULE 2 — BEHAVIORAL DNA
=================================

Production implementation of the validated V9.1 scorer.

Frozen behavioral score
-----------------------
    Behavioral Similarity
        = 0.90 * Class Transition-IDF
        + 0.10 * Package Markov

Pipeline-facing score
---------------------
    behavioral_score = Behavioral Similarity * 100

The module reports:
    - closest behavioral family
    - behavioral similarity
    - Class Transition-IDF score
    - Package Markov score
    - Top-1 margin
    - extraction telemetry
    - leakage / true-LOO metadata

It does NOT claim:
    - definitive malware attribution
    - malware probability

Expected public entry point
---------------------------
    analyze_behavioral_dna(apk_path: str) -> dict
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import pickle
import re
import zipfile

from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from androguard.misc import AnalyzeDex
from androguard.util import set_log


# =============================================================================
# ANDROGUARD LOGGING
# =============================================================================

set_log("WARNING")


# =============================================================================
# PROJECT PATHS
# =============================================================================

PROJECT_ROOT = Path(
    r"D:\Spectre_BOI_project\SPECTRE"
)

MODEL_DIR = (
    PROJECT_ROOT
    / "models"
    / "drebin_graphs_v2"
)

REFERENCE_FILE = (
    MODEL_DIR
    / "full_drebin_family_references.pkl"
)

CACHE_FILE = (
    MODEL_DIR
    / "full_drebin_sample_dna_cache.pkl"
)


# =============================================================================
# FROZEN VALIDATED CONFIGURATION
# =============================================================================

EXPECTED_FAMILIES = 179

CLASS_WEIGHT = 0.90
PACKAGE_WEIGHT = 0.10

# behavioral_similarity is 0.0–1.0.
# behavioral_score is 0–100.
SCORE_SCALE = 100.0


# =============================================================================
# DEX INVOKE INSTRUCTIONS
# =============================================================================

INVOKE_PREFIXES = (
    "invoke-virtual",
    "invoke-super",
    "invoke-direct",
    "invoke-static",
    "invoke-interface",
)


# =============================================================================
# FRAMEWORK / LIBRARY PREFIXES
# =============================================================================
#
# Keep this aligned with the validated V9.1 extractor.
#
# Application-specific classes are not used as Behavioral DNA nodes.
# Only framework/library API classes are retained.
# =============================================================================

FRAMEWORK_PREFIXES = (
    "android.",
    "java.",
    "javax.",
    "dalvik.",
    "com.google.",
    "okhttp3.",
    "retrofit2.",
)


# =============================================================================
# OPTIONAL FUNCTIONAL TAXONOMY
# =============================================================================
#
# Functional-family representation was validated during development.
# It is retained here for analysis/explainability but is NOT part of the
# frozen 90% Class-IDF + 10% Package-Markov production score.
# =============================================================================

FAMILY_RULES = {

    # Telephony
    "android.telephony": "TELEPHONY",
    "android.telecom": "TELEPHONY",

    # Providers
    "android.provider": "DATA_PROVIDER",

    # Messaging
    "android.sms": "SMS_MESSAGING",
    "android.mms": "SMS_MESSAGING",

    # Networking
    "android.net.wifi.p2p": "NETWORK",
    "android.net.wifi": "NETWORK",
    "android.net.http": "NETWORK",
    "android.net": "NETWORK",
    "okhttp3": "NETWORK",
    "retrofit2": "NETWORK",
    "java.net": "NETWORK",

    # Network security
    "javax.net.ssl": "NETWORK_SECURITY",
    "javax.net": "NETWORK_SECURITY",

    # UI
    "android.inputmethodservice": "UI",
    "android.webkit": "UI",
    "android.widget": "UI",
    "android.view": "UI",

    # App components
    "android.appwidget": "APP_COMPONENT",
    "android.app": "APP_COMPONENT",

    # Content / IPC
    "android.content.res": "RESOURCE_CONFIG",
    "android.content": "CONTENT_IPC",

    # System
    "dalvik.system": "SYSTEM_RUNTIME",
    "android.system": "SYSTEM_RUNTIME",
    "android.os": "SYSTEM_RUNTIME",

    # Database
    "android.database.sqlite": "DATABASE_STORAGE",
    "android.database": "DATABASE_STORAGE",
    "android.preference": "DATABASE_STORAGE",
    "java.sql": "DATABASE_STORAGE",

    # File I/O
    "java.nio": "FILE_IO",
    "java.io": "FILE_IO",

    # Media
    "android.graphics": "MEDIA_GRAPHICS",
    "android.media": "MEDIA",

    # Hardware
    "android.hardware": "HARDWARE_SENSOR",

    # Location / wireless
    "android.location": "LOCATION",
    "android.bluetooth": "BLUETOOTH",
    "android.nfc": "NFC",

    # Security
    "android.security": "SECURITY",
    "android.accounts": "ACCOUNT_AUTH",
    "javax.crypto": "CRYPTO_SECURITY",
    "android.accessibilityservice": "ACCESSIBILITY",

    # Text / XML
    "android.text": "TEXT_PROCESSING",
    "java.text": "TEXT_PROCESSING",
    "org.xml": "XML_PROCESSING",
    "javax.xml": "XML_PROCESSING",

    # Core Java
    "java.lang": "CORE_RUNTIME",
    "java.util": "UTILITY",
    "java.math": "MATH",

    # Google services
    "com.google.android": "GOOGLE_SERVICES",
}


def classify_functional_family(class_name: str) -> str:
    """
    Map a normalized API class to the configured functional family.

    Longest-prefix matching is used so specific rules win over broad
    parent-package rules.
    """
    name = normalize_class_name(class_name)

    best_prefix = ""
    best_family = None

    for prefix, family in FAMILY_RULES.items():

        if name == prefix or name.startswith(prefix + "."):

            if len(prefix) > len(best_prefix):
                best_prefix = prefix
                best_family = family

    if best_family is not None:
        return best_family

    if name.startswith("android."):
        return "ANDROID_OTHER"

    if name.startswith("java."):
        return "JAVA_OTHER"

    if name.startswith("javax."):
        return "JAVAX_OTHER"

    if name.startswith("dalvik."):
        return "DALVIK_OTHER"

    if name.startswith(
        (
            "com.",
            "org.",
            "okhttp3.",
            "retrofit2.",
        )
    ):
        return "THIRD_PARTY_OTHER"

    return "OTHER"


# =============================================================================
# NORMALIZATION
# =============================================================================

def normalize_class_name(name: str) -> str:
    """
    Normalize Android/Dalvik class names.

    Examples:

        Landroid/telephony/SmsManager;
            ->
        android.telephony.SmsManager

    """
    if not isinstance(name, str):
        return ""

    name = name.strip()

    if (
        name.startswith("L")
        and name.endswith(";")
    ):
        name = name[1:-1]

    return name.replace("/", ".")


def class_to_package(class_name: str) -> str:
    """
    Convert normalized class name to package.

    Example:

        android.telephony.SmsManager
            ->
        android.telephony
    """
    class_name = normalize_class_name(
        class_name
    )

    parts = class_name.split(".")

    if len(parts) <= 1:
        return class_name

    return ".".join(parts[:-1])


# =============================================================================
# TRANSITION COUNT NORMALIZATION
# =============================================================================

def normalize_transition_counts(
    raw_counts: Any,
) -> dict[str, dict[str, int]]:
    """
    Convert supported transition representations into:

        {
            source_class: {
                destination_class: count
            }
        }

    Supported input formats:

        {(src, dst): count}

    and:

        {
            src: {
                dst: count
            }
        }
    """

    if not isinstance(raw_counts, dict):
        return {}

    result = defaultdict(dict)

    tuple_format = any(
        isinstance(key, tuple)
        and len(key) == 2
        for key in raw_counts
    )

    # -------------------------------------------------------------------------
    # Flat tuple-key format
    # -------------------------------------------------------------------------

    if tuple_format:

        for key, value in raw_counts.items():

            if not (
                isinstance(key, tuple)
                and len(key) == 2
            ):
                continue

            try:
                count = int(value)
            except Exception:
                continue

            if count <= 0:
                continue

            src = normalize_class_name(
                str(key[0])
            )

            dst = normalize_class_name(
                str(key[1])
            )

            if src and dst:
                result[src][dst] = count

    # -------------------------------------------------------------------------
    # Nested dictionary format
    # -------------------------------------------------------------------------

    else:

        for raw_src, destinations in raw_counts.items():

            if not isinstance(
                destinations,
                dict,
            ):
                continue

            src = normalize_class_name(
                str(raw_src)
            )

            if not src:
                continue

            for raw_dst, value in destinations.items():

                try:
                    count = int(value)
                except Exception:
                    continue

                if count <= 0:
                    continue

                dst = normalize_class_name(
                    str(raw_dst)
                )

                if dst:
                    result[src][dst] = count

    return {
        src: dict(destinations)
        for src, destinations in result.items()
    }


def flatten_counts(
    nested: dict[str, dict[str, int]],
) -> dict[tuple[str, str], int]:
    """
    Convert nested transition counts into tuple-key format.
    """

    return {
        (src, dst): int(count)
        for src, destinations in nested.items()
        for dst, count in destinations.items()
    }


def map_counts(
    class_counts: dict[str, dict[str, int]],
    mapper: Callable[[str], str],
) -> dict[str, dict[str, int]]:
    """
    Map source/destination nodes through a mapper and aggregate collisions.
    """

    mapped = defaultdict(
        lambda: defaultdict(int)
    )

    for src, destinations in class_counts.items():

        mapped_src = mapper(src)

        if not mapped_src:
            continue

        for dst, count in destinations.items():

            mapped_dst = mapper(dst)

            if not mapped_dst:
                continue

            mapped[mapped_src][mapped_dst] += int(
                count
            )

    return {
        src: dict(destinations)
        for src, destinations in mapped.items()
    }


# =============================================================================
# EQUAL-SAMPLE MARKOV REFERENCE
# =============================================================================

def build_equal_sample_markov(
    sample_counts_list: list[
        dict[str, dict[str, int]]
    ],
) -> dict[str, dict[str, float]]:
    """
    Exact equal-sample conditional-distribution construction used by the
    validated V7/V9 pipeline.

    Each sample contributes equally to the source-state distribution.
    """

    if not sample_counts_list:
        return {}

    source_distributions = defaultdict(list)

    for counts in sample_counts_list:

        for src, destinations in counts.items():

            total = sum(
                destinations.values()
            )

            if total <= 0:
                continue

            source_distributions[src].append(
                {
                    dst: count / total
                    for dst, count
                    in destinations.items()
                }
            )

    graph = {}

    for src, distributions in (
        source_distributions.items()
    ):

        destination_set = set()

        for distribution in distributions:
            destination_set.update(
                distribution.keys()
            )

        sample_count = len(
            distributions
        )

        if sample_count <= 0:
            continue

        graph[src] = {
            dst: (
                sum(
                    distribution.get(
                        dst,
                        0.0,
                    )
                    for distribution
                    in distributions
                )
                / sample_count
            )
            for dst in destination_set
        }

    return graph


# =============================================================================
# TRUE LEAVE-ONE-OUT TRANSITION-IDF
# =============================================================================

def build_transition_idf_from_cache(
    cache: dict[str, Any],
    family_models: dict[str, Any],
    exclude_sha256: str | None = None,
) -> dict[
    tuple[str, str],
    float,
]:
    """
    Build FAMILY document-frequency IDF.

    A transition is counted at most once per family.

    Important:
        denominator = number of families represented
                     after exclusion

    This is the true LOO behavior used by V9.1.
    """

    family_df = Counter()

    participating_families = set()

    normalized_exclude = (
        exclude_sha256.lower()
        if exclude_sha256
        else None
    )

    for family, model in family_models.items():

        family_transitions = set()

        for sha256 in model.get(
            "sha256s",
            [],
        ):

            if (
                normalized_exclude
                and str(sha256).lower()
                == normalized_exclude
            ):
                continue

            record = cache.get(
                sha256
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

            counts = normalize_transition_counts(
                dna.get(
                    "class_transition_counts",
                    {},
                )
            )

            if counts:

                family_transitions.update(
                    flatten_counts(
                        counts
                    ).keys()
                )

        if family_transitions:

            participating_families.add(
                family
            )

            for transition in (
                family_transitions
            ):
                family_df[transition] += 1

    n_families = len(
        participating_families
    )

    if n_families <= 0:
        return {}

    return {
        transition: (
            math.log(
                (n_families + 1)
                / (df + 1)
            )
            + 1.0
        )
        for transition, df
        in family_df.items()
    }


# =============================================================================
# TARGET APK → DEX
# =============================================================================

def extract_target_dex(
    apk_path: Path,
) -> list[bytes]:
    """
    Extract classes.dex, classes2.dex, ...

    DEX files are sorted deterministically.
    """

    if not apk_path.exists():

        raise FileNotFoundError(
            f"Target APK does not exist:\n{apk_path}"
        )

    try:

        with zipfile.ZipFile(
            apk_path,
            "r",
        ) as zf:

            entries = []

            for info in zf.infolist():

                base = Path(
                    info.filename
                ).name.lower()

                if re.fullmatch(
                    r"classes(?:\d+)?\.dex",
                    base,
                ):
                    entries.append(info)

            def dex_number(info: Any) -> int:

                base = Path(
                    info.filename
                ).name.lower()

                if base == "classes.dex":
                    return 1

                match = re.fullmatch(
                    r"classes(\d+)\.dex",
                    base,
                )

                if match:
                    return (
                        int(match.group(1))
                        + 1
                    )

                return 999999

            entries.sort(
                key=dex_number
            )

            if not entries:

                raise RuntimeError(
                    "Target APK contains no classes*.dex."
                )

            return [
                zf.read(info)
                for info in entries
            ]

    except zipfile.BadZipFile as exc:

        raise RuntimeError(
            f"Target APK is not a valid APK/ZIP:\n"
            f"{apk_path}"
        ) from exc


# =============================================================================
# TARGET DEX → ORDERED API TRANSITIONS
# =============================================================================

def extract_target_transitions(
    apk_path: Path,
) -> dict[str, Any]:
    """
    Extract ordered framework/API-class transitions from Dalvik invoke
    instructions.

    Important:
        transitions reset at each method boundary.

    This prevents creating artificial transitions between two unrelated
    methods.
    """

    dex_blobs = extract_target_dex(
        apk_path
    )

    transitions = defaultdict(int)

    application_classes = set()

    framework_classes = set()

    methods = 0

    api_calls = 0

    for dex_index, dex_bytes in enumerate(
        dex_blobs,
        start=1,
    ):

        try:

            result = AnalyzeDex(
                dex_bytes,
                raw=True,
            )

        except Exception as exc:

            raise RuntimeError(
                f"Androguard failed to parse "
                f"DEX #{dex_index}: {exc}"
            ) from exc

        if not isinstance(
            result,
            tuple,
        ):

            raise RuntimeError(
                "Unexpected AnalyzeDex() result."
            )

        # Androguard variants may return either:
        #
        #   (apk, dex, dx)
        #
        # or:
        #
        #   (dex, dx)

        if len(result) == 3:

            _, dex, _ = result

        elif len(result) == 2:

            dex, _ = result

        else:

            raise RuntimeError(
                "Unexpected AnalyzeDex() "
                f"tuple length: {len(result)}"
            )

        if not hasattr(
            dex,
            "get_classes",
        ):

            raise RuntimeError(
                "AnalyzeDex() did not return "
                "a usable DEX object."
            )

        # ---------------------------------------------------------------------
        # Classes
        # ---------------------------------------------------------------------

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

            # -----------------------------------------------------------------
            # Methods
            # -----------------------------------------------------------------

            for method in cls.get_methods():

                try:
                    instructions = (
                        method.get_instructions()
                    )

                except Exception:
                    continue

                if instructions is None:
                    continue

                # Method-local transition chain.
                previous_api_class = None

                method_api_count = 0

                # -------------------------------------------------------------
                # Instructions in execution order
                # -------------------------------------------------------------

                for instruction in instructions:

                    try:

                        opcode_name = (
                            instruction.get_name()
                            or ""
                        )

                    except Exception:

                        continue

                    if not any(
                        opcode_name.startswith(
                            prefix
                        )
                        for prefix
                        in INVOKE_PREFIXES
                    ):

                        continue

                    try:

                        output = (
                            instruction.get_output()
                            or ""
                        )

                    except Exception:

                        continue

                    api_class = ""

                    # ---------------------------------------------------------
                    # Parse descriptor from invoke output.
                    #
                    # Example:
                    #
                    #   v0, Landroid/telephony/SmsManager;->sendTextMessage(...)
                    #
                    # We retain:
                    #
                    #   android.telephony.SmsManager
                    # ---------------------------------------------------------

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

                    # Only framework/library APIs enter the DNA.
                    if not api_class.startswith(
                        FRAMEWORK_PREFIXES
                    ):
                        continue

                    framework_classes.add(
                        api_class
                    )

                    api_calls += 1

                    method_api_count += 1

                    # ---------------------------------------------------------
                    # Ordered transition
                    # ---------------------------------------------------------

                    if (
                        previous_api_class
                        is not None
                    ):

                        transitions[
                            (
                                previous_api_class,
                                api_class,
                            )
                        ] += 1

                    previous_api_class = (
                        api_class
                    )

                if method_api_count > 0:
                    methods += 1

    return {
        "class_transition_counts": dict(
            transitions
        ),

        "application_classes": (
            application_classes
        ),

        "framework_classes": (
            framework_classes
        ),

        "methods": methods,

        "api_calls": api_calls,

        "dex_files": len(
            dex_blobs
        ),
    }


# =============================================================================
# CLASS-LEVEL TRANSITION-IDF SIMILARITY
# =============================================================================

def class_idf_similarity(
    target_counts: dict[str, dict[str, int]],
    reference_counts: dict[str, dict[str, int]],
    idf: dict[
        tuple[str, str],
        float,
    ],
) -> float:
    """
    Exact validated Class Transition-IDF similarity.

    Transition occurrence counts are converted into normalized transition
    mass.

    Weighted overlap:
        min(target_mass, reference_mass) * IDF

    Denominator:
        all weighted target mass
    """

    target = flatten_counts(
        target_counts
    )

    reference = flatten_counts(
        reference_counts
    )

    if not target or not reference:
        return 0.0

    target_total = sum(
        target.values()
    )

    reference_total = sum(
        reference.values()
    )

    if (
        target_total <= 0
        or reference_total <= 0
    ):

        return 0.0

    matched = 0.0

    maximum = 0.0

    for transition, count in (
        target.items()
    ):

        target_mass = (
            count / target_total
        )

        reference_mass = (
            reference.get(
                transition,
                0,
            )
            / reference_total
        )

        weight = idf.get(
            transition,
            1.0,
        )

        matched += (
            min(
                target_mass,
                reference_mass,
            )
            * weight
        )

        maximum += (
            target_mass
            * weight
        )

    if maximum <= 0:
        return 0.0

    return matched / maximum


# =============================================================================
# PACKAGE MARKOV SIMILARITY
# =============================================================================

def package_markov_similarity(
    target_counts: dict[str, dict[str, int]],
    reference_graph: dict[
        str,
        dict[str, float],
    ],
) -> float:
    """
    Compare target Package Markov transition distributions against the
    reference family Package Markov graph.
    """

    target_graph = {}

    # -------------------------------------------------------------------------
    # Target class transitions → packages
    # -------------------------------------------------------------------------

    for src, destinations in (
        target_counts.items()
    ):

        total = sum(
            destinations.values()
        )

        if total <= 0:
            continue

        target_graph[src] = {
            dst: count / total
            for dst, count
            in destinations.items()
        }

    if (
        not target_graph
        or not reference_graph
    ):

        return 0.0

    total = 0.0

    weighted = 0.0

    # -------------------------------------------------------------------------
    # Conditional-distribution overlap
    # -------------------------------------------------------------------------

    for src, target_distribution in (
        target_graph.items()
    ):

        reference_distribution = (
            reference_graph.get(
                src,
                {},
            )
        )

        source_mass = sum(
            target_distribution.values()
        )

        if source_mass <= 0:
            continue

        overlap = sum(
            min(
                probability,
                reference_distribution.get(
                    dst,
                    0.0,
                ),
            )
            for dst, probability
            in target_distribution.items()
        )

        weighted += (
            source_mass
            * overlap
        )

        total += source_mass

    if total <= 0:
        return 0.0

    return weighted / total


# =============================================================================
# LOAD REFERENCE MODELS
# =============================================================================

@lru_cache(maxsize=1)
def load_models():
    """
    Load the full 179-family reference model and sample cache.

    lru_cache prevents re-reading the large pickle files for every request
    within the same backend process.
    """

    if not REFERENCE_FILE.exists():

        raise FileNotFoundError(
            "Module 2 reference model not found:\n"
            f"{REFERENCE_FILE}"
        )

    if not CACHE_FILE.exists():

        raise FileNotFoundError(
            "Module 2 sample cache not found:\n"
            f"{CACHE_FILE}"
        )

    try:

        with REFERENCE_FILE.open(
            "rb"
        ) as f:

            reference_data = (
                pickle.load(f)
            )

        with CACHE_FILE.open(
            "rb"
        ) as f:

            cache = pickle.load(f)

    except Exception as exc:

        raise RuntimeError(
            "Failed to load Module 2 "
            f"reference/cache files: {exc}"
        ) from exc

    if not isinstance(
        reference_data,
        dict,
    ):

        raise RuntimeError(
            "Unexpected reference model format."
        )

    if not isinstance(
        cache,
        dict,
    ):

        raise RuntimeError(
            "Unexpected sample cache format."
        )

    family_models = (
        reference_data.get(
            "family_models"
        )
    )

    stored_idf = (
        reference_data.get(
            "transition_idf"
        )
    )

    if not isinstance(
        family_models,
        dict,
    ):

        raise RuntimeError(
            "family_models missing from "
            "reference model."
        )

    if not isinstance(
        stored_idf,
        dict,
    ):

        raise RuntimeError(
            "transition_idf missing from "
            "reference model."
        )

    if len(family_models) != (
        EXPECTED_FAMILIES
    ):

        raise RuntimeError(
            f"Expected {EXPECTED_FAMILIES} "
            f"Drebin families, found "
            f"{len(family_models)}."
        )

    return (
        family_models,
        stored_idf,
        reference_data,
        cache,
    )


# =============================================================================
# REFERENCE MEMBERSHIP
# =============================================================================

def find_reference_family(
    target_sha256: str,
    family_models: dict[str, Any],
) -> str | None:
    """
    Determine whether the target SHA already exists in the Drebin reference
    corpus.
    """

    target = target_sha256.lower()

    for family, model in (
        family_models.items()
    ):

        for sha256 in model.get(
            "sha256s",
            [],
        ):

            if (
                str(sha256).lower()
                == target
            ):

                return family

    return None


# =============================================================================
# SCORE ALL 179 FAMILIES
# =============================================================================

def score_all_families(
    target_counts: dict[str, dict[str, int]],
    family_models: dict[str, Any],
    stored_idf: dict[
        tuple[str, str],
        float,
    ],
    cache: dict[str, Any],
    target_sha256: str,
):
    """
    Score the target against all 179 Drebin families.

    True LOO behavior:
        if target belongs to the reference corpus:
            - remove target from its family
            - remove target from global family DF/IDF
            - rebuild target family's package graph
    """

    target_family = find_reference_family(
        target_sha256,
        family_models,
    )

    # -------------------------------------------------------------------------
    # IDF
    # -------------------------------------------------------------------------

    if target_family is not None:

        scoring_idf = (
            build_transition_idf_from_cache(
                cache,
                family_models,
                exclude_sha256=target_sha256,
            )
        )

    else:

        scoring_idf = stored_idf

    # -------------------------------------------------------------------------
    # Target package transitions
    # -------------------------------------------------------------------------

    target_package = map_counts(
        target_counts,
        class_to_package,
    )

    results = []

    # -------------------------------------------------------------------------
    # Score every family
    # -------------------------------------------------------------------------

    for family, model in (
        family_models.items()
    ):

        exclude_target = (
            family == target_family
        )

        reference_samples = []

        # -------------------------------------------------------------
        # Collect reference samples
        # -------------------------------------------------------------

        for sha256 in model.get(
            "sha256s",
            [],
        ):

            if (
                exclude_target
                and str(sha256).lower()
                == target_sha256.lower()
            ):
                continue

            record = cache.get(
                sha256
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

            counts = normalize_transition_counts(
                dna.get(
                    "class_transition_counts",
                    {},
                )
            )

            if counts:
                reference_samples.append(
                    counts
                )

        # -------------------------------------------------------------
        # Class Transition-IDF
        #
        # Validated family aggregation:
        # MAX similarity over reference samples.
        # -------------------------------------------------------------

        best_class = 0.0

        for reference_counts in (
            reference_samples
        ):

            score = class_idf_similarity(
                target_counts,
                reference_counts,
                scoring_idf,
            )

            if score > best_class:
                best_class = score

        # -------------------------------------------------------------
        # Package Markov
        # -------------------------------------------------------------

        if family == target_family:

            # Rebuild own family graph without the target.
            package_graph = (
                build_equal_sample_markov(
                    [
                        map_counts(
                            counts,
                            class_to_package,
                        )
                        for counts
                        in reference_samples
                    ]
                )
            )

        else:

            # Use prebuilt family graph.
            package_graph = model.get(
                "package_graph",
                {},
            )

        package_score = (
            package_markov_similarity(
                target_package,
                package_graph,
            )
        )

        # -------------------------------------------------------------
        # Frozen fusion
        # -------------------------------------------------------------

        behavioral_similarity = (
            CLASS_WEIGHT * best_class
            + PACKAGE_WEIGHT * package_score
        )

        behavioral_score = (
            behavioral_similarity
            * SCORE_SCALE
        )

        results.append(
            {
                "family": family,

                "class_idf_score": (
                    best_class
                ),

                "package_markov_score": (
                    package_score
                ),

                "behavioral_similarity": (
                    behavioral_similarity
                ),

                "behavioral_score": (
                    behavioral_score
                ),

                "target_excluded_from_family": (
                    family == target_family
                ),

                "reference_samples_used": (
                    len(reference_samples)
                ),
            }
        )

    # -------------------------------------------------------------------------
    # Sort highest similarity first
    # -------------------------------------------------------------------------

    results.sort(
        key=lambda row: (
            -row["behavioral_similarity"],
            row["family"],
        )
    )

    # -------------------------------------------------------------------------
    # Assign ranks
    # -------------------------------------------------------------------------

    for rank, row in enumerate(
        results,
        start=1,
    ):

        row["rank"] = rank

    return (
        results,
        target_family,
        scoring_idf,
    )


# =============================================================================
# PUBLIC PIPELINE FUNCTION
# =============================================================================

def analyze_behavioral_dna(
    apk_path: str,
) -> dict[str, Any]:
    """
    Main Module 2 function.

    This is the function imported by:

        backend/pipeline.py

    through:

        from modules.behavioral_dna import analyze_behavioral_dna

    Returned behavioral_score is 0–100 for compatibility with the SPECTRE
    risk-scoring and override layers.
    """

    path = Path(apk_path)

    if not path.exists():

        raise FileNotFoundError(
            "Behavioral DNA target APK not found:\n"
            f"{path}"
        )

    # -------------------------------------------------------------------------
    # SHA256
    # -------------------------------------------------------------------------

    target_sha256 = hashlib.sha256(
        path.read_bytes()
    ).hexdigest()

    # -------------------------------------------------------------------------
    # Load reference system
    # -------------------------------------------------------------------------

    (
        family_models,
        stored_idf,
        metadata,
        cache,
    ) = load_models()

    # -------------------------------------------------------------------------
    # Extract Behavioral DNA
    # -------------------------------------------------------------------------

    extracted = (
        extract_target_transitions(
            path
        )
    )

    target_counts = (
        normalize_transition_counts(
            extracted[
                "class_transition_counts"
            ]
        )
    )

    flattened = flatten_counts(
        target_counts
    )

    if not flattened:

        raise RuntimeError(
            "Target produced no usable "
            "framework/API class transitions."
        )

    # -------------------------------------------------------------------------
    # Score target against all 179 families
    # -------------------------------------------------------------------------

    (
        results,
        target_family,
        scoring_idf,
    ) = score_all_families(
        target_counts=target_counts,
        family_models=family_models,
        stored_idf=stored_idf,
        cache=cache,
        target_sha256=target_sha256,
    )

    if len(results) != EXPECTED_FAMILIES:

        raise RuntimeError(
            f"Expected {EXPECTED_FAMILIES} "
            f"family scores, got {len(results)}."
        )

    # -------------------------------------------------------------------------
    # Top result
    # -------------------------------------------------------------------------

    top = results[0]

    if len(results) >= 2:

        second = results[1]

        margin = (
            top["behavioral_similarity"]
            - second[
                "behavioral_similarity"
            ]
        )

    else:

        margin = (
            top["behavioral_similarity"]
        )

    # -------------------------------------------------------------------------
    # Compact ranking for UI / GenAI
    # -------------------------------------------------------------------------

    top_matches = []

    for row in results[:10]:

        top_matches.append(
            {
                "rank": row["rank"],

                "family": row["family"],

                "behavioral_score": (
                    row["behavioral_score"]
                ),

                "behavioral_similarity": (
                    row[
                        "behavioral_similarity"
                    ]
                ),

                "class_idf_score": (
                    row[
                        "class_idf_score"
                    ]
                ),

                "package_markov_score": (
                    row[
                        "package_markov_score"
                    ]
                ),

                "reference_samples_used": (
                    row[
                        "reference_samples_used"
                    ]
                ),
            }
        )

    # -------------------------------------------------------------------------
    # Final Module 2 result
    # -------------------------------------------------------------------------

    result = {

        # ---------------------------------------------------------------------
        # Generic module information
        # ---------------------------------------------------------------------

        "module": "behavioral_dna",

        "status": "complete",

        # ---------------------------------------------------------------------
        # Pipeline-facing score
        # ---------------------------------------------------------------------

        # 0–100
        "behavioral_score": round(
            top[
                "behavioral_score"
            ],
            6,
        ),

        # ---------------------------------------------------------------------
        # Raw mathematical score
        # ---------------------------------------------------------------------

        # 0–1
        "behavioral_similarity": round(
            top[
                "behavioral_similarity"
            ],
            9,
        ),

        # ---------------------------------------------------------------------
        # Score components
        # ---------------------------------------------------------------------

        "class_idf_score": round(
            top[
                "class_idf_score"
            ],
            9,
        ),

        "package_markov_score": round(
            top[
                "package_markov_score"
            ],
            9,
        ),

        # ---------------------------------------------------------------------
        # Family result
        # ---------------------------------------------------------------------

        "closest_family": (
            top["family"]
        ),

        "top1_margin": round(
            margin,
            9,
        ),

        "top1_margin_percent": round(
            margin * 100.0,
            6,
        ),

        "top_match_rank": int(
            top["rank"]
        ),

        "top_matches": top_matches,

        # ---------------------------------------------------------------------
        # Leakage / LOO metadata
        # ---------------------------------------------------------------------

        "target_sha256": (
            target_sha256
        ),

        "target_in_reference": (
            target_family
            is not None
        ),

        "reference_family": (
            target_family
        ),

        "loo_enabled": (
            target_family
            is not None
        ),

        "loo_idf_entries": (
            len(scoring_idf)
            if target_family is not None
            else None
        ),

        # ---------------------------------------------------------------------
        # Reference metadata
        # ---------------------------------------------------------------------

        "reference_family_count": (
            len(family_models)
        ),

        "reference_sample_count": int(
            metadata.get(
                "sample_count",
                len(cache),
            )
        ),

        # ---------------------------------------------------------------------
        # Extraction telemetry
        # ---------------------------------------------------------------------

        "dex_files": int(
            extracted["dex_files"]
        ),

        "application_classes": len(
            extracted[
                "application_classes"
            ]
        ),

        "framework_classes": len(
            extracted[
                "framework_classes"
            ]
        ),

        "unique_api_classes": len(
            extracted[
                "framework_classes"
            ]
        ),

        "methods_with_api_calls": int(
            extracted["methods"]
        ),

        "api_calls": int(
            extracted["api_calls"]
        ),

        "unique_class_transitions": len(
            flattened
        ),

        "transition_occurrences": int(
            sum(flattened.values())
        ),

        # ---------------------------------------------------------------------
        # Explicit interpretation
        # ---------------------------------------------------------------------

        "interpretation": (
            "Closest behavioral match; "
            "not definitive malware attribution "
            "and not a malware probability."
        ),
    }

    return result


# =============================================================================
# DIRECT COMMAND-LINE TEST
# =============================================================================

def main() -> None:
    """
    Optional development/test interface.

    Example:

        python behavioral_dna.py ^
            "D:\\path\\sample.apk"
    """

    parser = argparse.ArgumentParser(
        description=(
            "SPECTRE Module 2 - "
            "Behavioral DNA"
        )
    )

    parser.add_argument(
        "apk",
        type=Path,
        help="Target APK path",
    )

    parser.add_argument(
        "--top",
        type=int,
        default=10,
        help="Number of family matches to print",
    )

    args = parser.parse_args()

    if args.top <= 0:

        raise ValueError(
            "--top must be greater than zero."
        )

    result = analyze_behavioral_dna(
        str(args.apk)
    )

    print("=" * 100)
    print(
        "SPECTRE MODULE 2 - BEHAVIORAL DNA"
    )
    print("=" * 100)

    print(
        f"APK:                    "
        f"{args.apk}"
    )

    print(
        f"SHA256:                 "
        f"{result['target_sha256']}"
    )

    print(
        f"Families:               "
        f"{result['reference_family_count']}"
    )

    print(
        f"Reference samples:      "
        f"{result['reference_sample_count']}"
    )

    print(
        f"Target in reference:    "
        f"{result['target_in_reference']}"
    )

    print(
        f"True LOO enabled:       "
        f"{result['loo_enabled']}"
    )

    print()

    print(
        "TARGET EXTRACTION"
    )

    print("-" * 100)

    print(
        f"DEX files:              "
        f"{result['dex_files']}"
    )

    print(
        f"Application classes:    "
        f"{result['application_classes']}"
    )

    print(
        f"Framework classes:     "
        f"{result['framework_classes']}"
    )

    print(
        f"Unique API classes:     "
        f"{result['unique_api_classes']}"
    )

    print(
        f"Methods with API calls: "
        f"{result['methods_with_api_calls']}"
    )

    print(
        f"API calls:              "
        f"{result['api_calls']}"
    )

    print(
        f"Unique transitions:     "
        f"{result['unique_class_transitions']}"
    )

    print(
        f"Transition occurrences: "
        f"{result['transition_occurrences']}"
    )

    print()

    print(
        "CLOSEST BEHAVIORAL MATCH"
    )

    print("-" * 100)

    print(
        f"Family:                 "
        f"{result['closest_family']}"
    )

    print(
        f"Behavioral score:       "
        f"{result['behavioral_score']:.6f} / 100"
    )

    print(
        f"Raw similarity:         "
        f"{result['behavioral_similarity']:.9f}"
    )

    print(
        f"Class-IDF score:        "
        f"{result['class_idf_score']:.9f}"
    )

    print(
        f"Package Markov score:   "
        f"{result['package_markov_score']:.9f}"
    )

    print(
        f"Top-1 margin:           "
        f"{result['top1_margin']:.9f}"
    )

    print()

    print(
        f"TOP {min(args.top, len(result['top_matches']))}"
    )

    print("-" * 100)

    for row in result[
        "top_matches"
    ][:args.top]:

        print(
            f"{row['rank']:>3}. "
            f"{row['family']:<28} "
            f"{row['behavioral_score']:>10.4f}"
        )

    print()

    print(
        "MODULE RESULT JSON"
    )

    print("-" * 100)

    print(
        json.dumps(
            result,
            indent=2,
            default=str,
        )
    )


# =============================================================================
# ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    main()