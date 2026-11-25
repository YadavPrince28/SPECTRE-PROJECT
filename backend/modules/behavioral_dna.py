from __future__ import annotations

import argparse
import hashlib
import json
import math
import pickle
import re
import sys
import zipfile
from collections import Counter, defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

import numpy as np
from androguard.misc import AnalyzeDex
from androguard.util import set_log

try:
    set_log("WARNING")
except (ValueError, AttributeError, TypeError):
    pass

# =============================================================================
# PROJECT PATHS (SPECTRE v3)
# =============================================================================

PROJECT_ROOT = Path(r"D:\Spectre_BOI_project\SPECTRE")
MODEL_DIR = PROJECT_ROOT / "models" / "drebin_graphs_v3"
REFERENCE_FILE = MODEL_DIR / "full_drebin_family_references.pkl"
CACHE_FILE = MODEL_DIR / "full_drebin_sample_dna_cache.pkl"

CLASS_WEIGHT = 0.90
PACKAGE_WEIGHT = 0.10
SCORE_SCALE = 100.0

MODERN_FAMILIES = frozenset({
    "Anubis", "Cerberus", "Alien", "Ermac", "Hook", "Hydra", "FluBot",
    "TeaBot", "SharkBot", "BRATA", "Octo", "Xenomorph", "MaliBot",
    "GodFather", "Chameleon", "Joker", "Harly", "Fleckpe", "SpinOk",
    "Triada", "HiddenAds", "FakeApp", "Hiddad", "SpyNote", "AhMyth",
    "CraxsRat", "CypherRat", "Dendroid", "DroidJack", "AndroRAT",
    "BianLian", "BlackRock", "Cabassous", "EventBot", "Ginp", "Gustuff",
    "Medusa", "Oscorp", "Sova", "Vultur", "ZBot", "BankBot", "Marcher",
    "Svpeng", "Asacub", "Fakecalls", "PixPirate", "Goldoson", "Necro",
    "AgentSmith", "xHelper", "Dvmap", "GhostPush", "Guerrilla", "Triout",
    "Gooligan", "HummingBad", "CopyCat", "Judy", "RottenSys", "ExpensiveWall",
    "mandrake", "mamont", "SMSSpy", "RatHat", "Koktevrat", "androzoo_vt5plus",
})

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


def normalize_transition_counts(raw_counts: Any) -> dict[str, dict[str, int]]:
    if not isinstance(raw_counts, dict):
        return {}
    result = defaultdict(dict)
    tuple_format = any(isinstance(key, tuple) and len(key) == 2 for key in raw_counts)
    if tuple_format:
        for key, value in raw_counts.items():
            if not (isinstance(key, tuple) and len(key) == 2):
                continue
            try:
                count = int(value)
            except Exception:
                continue
            if count <= 0:
                continue
            src = normalize_class_name(str(key[0]))
            dst = normalize_class_name(str(key[1]))
            if src and dst:
                result[src][dst] = count
    else:
        for raw_src, destinations in raw_counts.items():
            if not isinstance(destinations, dict):
                continue
            src = normalize_class_name(str(raw_src))
            if not src:
                continue
            for raw_dst, value in destinations.items():
                try:
                    count = int(value)
                except Exception:
                    continue
                if count <= 0:
                    continue
                dst = normalize_class_name(str(raw_dst))
                if dst:
                    result[src][dst] = count
    return {src: dict(destinations) for src, destinations in result.items()}


def flatten_counts(nested: dict[str, dict[str, int]]) -> dict[tuple[str, str], int]:
    return {
        (src, dst): int(count)
        for src, destinations in nested.items()
        for dst, count in destinations.items()
    }


def map_counts(
    class_counts: dict[str, dict[str, int]],
    mapper: Callable[[str], str],
) -> dict[str, dict[str, int]]:
    mapped = defaultdict(lambda: defaultdict(int))
    for src, destinations in class_counts.items():
        mapped_src = mapper(src)
        if not mapped_src:
            continue
        for dst, count in destinations.items():
            mapped_dst = mapper(dst)
            if not mapped_dst:
                continue
            mapped[mapped_src][mapped_dst] += int(count)
    return {src: dict(destinations) for src, destinations in mapped.items()}


def build_equal_sample_markov(
    sample_counts_list: list[dict[str, dict[str, int]]],
) -> dict[str, dict[str, float]]:
    if not sample_counts_list:
        return {}
    source_distributions = defaultdict(list)
    for counts in sample_counts_list:
        for src, destinations in counts.items():
            total = sum(destinations.values())
            if total <= 0:
                continue
            source_distributions[src].append(
                {dst: count / total for dst, count in destinations.items()}
            )
    graph = {}
    for src, distributions in source_distributions.items():
        destination_set = set()
        for distribution in distributions:
            destination_set.update(distribution.keys())
        sample_count = len(distributions)
        if sample_count <= 0:
            continue
        graph[src] = {
            dst: sum(distribution.get(dst, 0.0) for distribution in distributions) / sample_count
            for dst in destination_set
        }
    return graph


def extract_target_dex(apk_path: Path) -> list[bytes]:
    if not apk_path.exists():
        raise FileNotFoundError(f"Target APK does not exist:\n{apk_path}")
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            entries = [
                info for info in zf.infolist()
                if re.fullmatch(r"classes(?:\d+)?\.dex", Path(info.filename).name.lower())
            ]

            def dex_number(info: Any) -> int:
                base = Path(info.filename).name.lower()
                if base == "classes.dex":
                    return 1
                match = re.fullmatch(r"classes(\d+)\.dex", base)
                return int(match.group(1)) + 1 if match else 999999

            entries.sort(key=dex_number)
            if not entries:
                raise RuntimeError("Target APK contains no classes*.dex.")
            return [zf.read(info) for info in entries]
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Target APK is not a valid APK/ZIP:\n{apk_path}") from exc


def extract_target_transitions(apk_path: Path) -> dict[str, Any]:
    """Fast binary DEX transition extraction with automatic Androguard fallback."""
    try:
        from modules.fast_dex_extractor import fast_extract_target_transitions
        return fast_extract_target_transitions(apk_path, sys.modules[__name__])
    except Exception:
        pass

    dex_blobs = extract_target_dex(apk_path)
    transitions = defaultdict(int)
    application_classes = set()
    framework_classes = set()
    methods = 0
    api_calls = 0

    for dex_index, dex_bytes in enumerate(dex_blobs, start=1):
        result = AnalyzeDex(dex_bytes, raw=True)
        dex = result[1] if len(result) == 3 else result[0]
        for cls in dex.get_classes():
            class_name = normalize_class_name(cls.get_name())
            if not class_name:
                continue
            if class_name.startswith(FRAMEWORK_PREFIXES):
                framework_classes.add(class_name)
            else:
                application_classes.add(class_name)

            for method in cls.get_methods():
                try:
                    instructions = method.get_instructions()
                except Exception:
                    continue
                if instructions is None:
                    continue
                previous_api_class = None
                method_api_count = 0
                for instruction in instructions:
                    try:
                        opcode_name = instruction.get_name() or ""
                    except Exception:
                        continue
                    if not any(opcode_name.startswith(p) for p in INVOKE_PREFIXES):
                        continue
                    try:
                        output = instruction.get_output() or ""
                    except Exception:
                        continue
                    api_class = ""
                    for part in output.split(","):
                        part = part.strip()
                        if part.startswith("L") and ";" in part:
                            candidate = part.split("->")[0]
                            if candidate.endswith(";"):
                                api_class = normalize_class_name(candidate)
                                break
                    if not api_class or not api_class.startswith(FRAMEWORK_PREFIXES):
                        continue
                    framework_classes.add(api_class)
                    api_calls += 1
                    method_api_count += 1
                    if previous_api_class is not None:
                        transitions[(previous_api_class, api_class)] += 1
                    previous_api_class = api_class
                if method_api_count > 0:
                    methods += 1

    return {
        "class_transition_counts": dict(transitions),
        "application_classes": application_classes,
        "framework_classes": framework_classes,
        "methods": methods,
        "api_calls": api_calls,
        "dex_files": len(dex_blobs),
    }


def package_markov_similarity(
    target_counts: dict[str, dict[str, int]],
    reference_graph: dict[str, dict[str, float]],
) -> float:
    target_graph = {}
    for src, destinations in target_counts.items():
        total = sum(destinations.values())
        if total > 0:
            target_graph[src] = {dst: count / total for dst, count in destinations.items()}
    if not target_graph or not reference_graph:
        return 0.0
    total = 0.0
    weighted = 0.0
    for src, target_distribution in target_graph.items():
        reference_distribution = reference_graph.get(src, {})
        source_mass = sum(target_distribution.values())
        if source_mass <= 0:
            continue
        overlap = sum(
            min(prob, reference_distribution.get(dst, 0.0))
            for dst, prob in target_distribution.items()
        )
        weighted += source_mass * overlap
        total += source_mass
    return weighted / total if total > 0 else 0.0


class VectorizedM2Scorer:
    """Inverted-index NumPy scorer for 195-family Behavioral DNA (~0.02s/APK)."""

    def __init__(self, family_models: dict[str, Any], stored_idf: dict[tuple[str, str], float], cache: dict[str, Any]):
        self.family_models = family_models
        self.stored_idf = stored_idf
        self.families = sorted(family_models.keys())
        self.fam_to_idx = {f: i for i, f in enumerate(self.families)}
        self.n_families = len(self.families)

        self.sample_shas: list[str] = []
        self.sample_fam_idx: list[int] = []
        self.sha_to_sample_idx: dict[str, int] = {}
        self.sha_to_family: dict[str, str] = {}

        edge_to_entries: dict[tuple[str, str], list[tuple[int, float]]] = defaultdict(list)

        for fam_i, fam in enumerate(self.families):
            for sha in family_models[fam].get("sha256s", []):
                sha_low = str(sha).lower()
                self.sha_to_family[sha_low] = fam
                rec = cache.get(sha) or cache.get(sha_low)
                if not isinstance(rec, dict):
                    continue
                dna = rec.get("dna", {})
                if not isinstance(dna, dict):
                    continue
                nested = normalize_transition_counts(dna.get("class_transition_counts", {}))
                flat = flatten_counts(nested)
                total = sum(flat.values())
                if total <= 0:
                    continue

                s_idx = len(self.sample_shas)
                self.sample_shas.append(sha_low)
                self.sample_fam_idx.append(fam_i)
                self.sha_to_sample_idx[sha_low] = s_idx

                inv_total = 1.0 / float(total)
                for edge, cnt in flat.items():
                    edge_to_entries[edge].append((s_idx, cnt * inv_total))

        self.n_samples = len(self.sample_shas)
        self.sample_fam_arr = np.array(self.sample_fam_idx, dtype=np.int32)
        self.inv_index: dict[tuple[str, str], tuple[np.ndarray, np.ndarray]] = {}
        for edge, pairs in edge_to_entries.items():
            s_arr = np.fromiter((p[0] for p in pairs), dtype=np.int32, count=len(pairs))
            m_arr = np.fromiter((p[1] for p in pairs), dtype=np.float32, count=len(pairs))
            self.inv_index[edge] = (s_arr, m_arr)

    def score(self, target_counts: dict[str, dict[str, int]], target_sha256: str) -> tuple[list[dict[str, Any]], str | None]:
        sha_low = target_sha256.lower()
        target_family = self.sha_to_family.get(sha_low)
        exclude_s_idx = self.sha_to_sample_idx.get(sha_low)

        flat = flatten_counts(target_counts)
        target_total = sum(flat.values())

        sample_matched = np.zeros(self.n_samples, dtype=np.float64)
        maximum = 0.0

        if target_total > 0:
            inv_t = 1.0 / float(target_total)
            for edge, cnt in flat.items():
                t_mass = cnt * inv_t
                w = float(self.stored_idf.get(edge, 1.0))
                maximum += t_mass * w
                inv_entry = self.inv_index.get(edge)
                if inv_entry is not None:
                    s_arr, m_arr = inv_entry
                    overlap = np.minimum(t_mass, m_arr) * w
                    np.add.at(sample_matched, s_arr, overlap)

        if exclude_s_idx is not None:
            sample_matched[exclude_s_idx] = -1.0

        sample_sims = sample_matched / maximum if maximum > 0 else np.zeros(self.n_samples, dtype=np.float64)

        best_class_per_fam = np.zeros(self.n_families, dtype=np.float64)
        valid_mask = sample_sims > 0.0
        if np.any(valid_mask):
            np.maximum.at(best_class_per_fam, self.sample_fam_arr[valid_mask], sample_sims[valid_mask])

        target_package = map_counts(target_counts, class_to_package)
        results = []

        for fam_i, fam in enumerate(self.families):
            model = self.family_models[fam]
            best_class = float(best_class_per_fam[fam_i])
            pkg_graph = model.get("package_graph", {})
            pkg_score = package_markov_similarity(target_package, pkg_graph)
            beh_sim = CLASS_WEIGHT * best_class + PACKAGE_WEIGHT * pkg_score
            beh_score = beh_sim * SCORE_SCALE

            results.append({
                "family": fam,
                "class_idf_score": best_class,
                "package_markov_score": pkg_score,
                "behavioral_similarity": beh_sim,
                "behavioral_score": beh_score,
                "target_excluded_from_family": fam == target_family,
                "reference_samples_used": len(model.get("sha256s", [])),
            })

        results.sort(key=lambda row: (-row["behavioral_similarity"], row["family"]))
        for rank, row in enumerate(results, start=1):
            row["rank"] = rank
        return results, target_family


@lru_cache(maxsize=1)
def load_models():
    if not REFERENCE_FILE.exists():
        raise FileNotFoundError(f"Module 2 reference model not found:\n{REFERENCE_FILE}")
    if not CACHE_FILE.exists():
        raise FileNotFoundError(f"Module 2 sample cache not found:\n{CACHE_FILE}")

    with REFERENCE_FILE.open("rb") as f:
        reference_data = pickle.load(f)
    with CACHE_FILE.open("rb") as f:
        cache = pickle.load(f)

    family_models = reference_data.get("family_models")
    stored_idf = reference_data.get("transition_idf")
    if not isinstance(family_models, dict) or not isinstance(stored_idf, dict):
        raise RuntimeError("Invalid Module 2 reference model format.")

    scorer = VectorizedM2Scorer(family_models, stored_idf, cache)
    return family_models, stored_idf, reference_data, cache, scorer


def analyze_behavioral_dna(apk_path: str) -> dict[str, Any]:
    """Main Module 2 entry point imported by backend/pipeline.py."""
    path = Path(apk_path)
    if not path.exists():
        raise FileNotFoundError(f"Behavioral DNA target APK not found:\n{path}")

    target_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    family_models, stored_idf, metadata, cache, scorer = load_models()

    extracted = extract_target_transitions(path)
    target_counts = normalize_transition_counts(extracted["class_transition_counts"])
    flattened = flatten_counts(target_counts)

    if not flattened:
        return {
            "module": "behavioral_dna",
            "status": "complete",
            "behavioral_score": 0.0,
            "similarity_score": 0.0,
            "behavioral_similarity": 0.0,
            "similarity": 0.0,
            "class_idf_score": 0.0,
            "package_markov_score": 0.0,
            "closest_family": "unknown",
            "closest_modern_family": 0,
            "top1_margin": 0.0,
            "top1_margin_percent": 0.0,
            "top_match_rank": 0,
            "top_matches": [],
            "target_sha256": target_sha256,
            "target_in_reference": False,
            "reference_family": None,
            "loo_enabled": False,
            "reference_family_count": len(family_models),
            "reference_sample_count": int(metadata.get("sample_count", len(cache))),
            "dex_files": int(extracted.get("dex_files", 0)),
            "application_classes": len(extracted.get("application_classes", set())),
            "framework_classes": len(extracted.get("framework_classes", set())),
            "unique_api_classes": len(extracted.get("framework_classes", set())),
            "methods_with_api_calls": int(extracted.get("methods", 0)),
            "api_calls": int(extracted.get("api_calls", 0)),
            "unique_class_transitions": 0,
            "transition_occurrences": 0,
            "interpretation": "No usable framework/API class transitions extracted.",
        }

    results, target_family = scorer.score(target_counts=target_counts, target_sha256=target_sha256)
    top = results[0]
    margin = (
        top["behavioral_similarity"] - results[1]["behavioral_similarity"]
        if len(results) >= 2
        else top["behavioral_similarity"]
    )
    closest_fam = str(top["family"])

    top_matches = [
        {
            "rank": row["rank"],
            "family": row["family"],
            "behavioral_score": row["behavioral_score"],
            "similarity_score": row["behavioral_score"],
            "behavioral_similarity": row["behavioral_similarity"],
            "similarity": row["behavioral_similarity"],
            "class_idf_score": row["class_idf_score"],
            "package_markov_score": row["package_markov_score"],
            "reference_samples_used": row["reference_samples_used"],
        }
        for row in results[:10]
    ]

    return {
        "module": "behavioral_dna",
        "status": "complete",
        "behavioral_score": round(top["behavioral_score"], 6),
        "similarity_score": round(top["behavioral_score"], 6),
        "behavioral_similarity": round(top["behavioral_similarity"], 9),
        "similarity": round(top["behavioral_similarity"], 9),
        "class_idf_score": round(top["class_idf_score"], 9),
        "package_markov_score": round(top["package_markov_score"], 9),
        "closest_family": closest_fam,
        "closest_modern_family": 1 if closest_fam in MODERN_FAMILIES else 0,
        "top1_margin": round(margin, 9),
        "top1_margin_percent": round(margin * 100.0, 6),
        "top_match_rank": int(top["rank"]),
        "top_matches": top_matches,
        "target_sha256": target_sha256,
        "target_in_reference": target_family is not None,
        "reference_family": target_family,
        "loo_enabled": target_family is not None,
        "loo_idf_entries": len(stored_idf) if target_family is not None else None,
        "reference_family_count": len(family_models),
        "reference_sample_count": int(metadata.get("sample_count", len(cache))),
        "dex_files": int(extracted["dex_files"]),
        "application_classes": len(extracted["application_classes"]),
        "framework_classes": len(extracted["framework_classes"]),
        "unique_api_classes": len(extracted["framework_classes"]),
        "methods_with_api_calls": int(extracted["methods"]),
        "api_calls": int(extracted["api_calls"]),
        "unique_class_transitions": len(flattened),
        "transition_occurrences": int(sum(flattened.values())),
        "interpretation": (
            "Closest behavioral match across 195 malware families; "
            "not definitive malware attribution and not a malware probability."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="SPECTRE Module 2 - Behavioral DNA v3")
    parser.add_argument("apk", type=Path, help="Target APK path")
    parser.add_argument("--top", type=int, default=10, help="Number of family matches to print")
    args = parser.parse_args()
    result = analyze_behavioral_dna(str(args.apk))
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()