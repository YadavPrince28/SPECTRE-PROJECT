from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

RULE_DIR = (
    PROJECT_ROOT
    / "backend"
    / "config"
    / "quark_rules_selected"
)


HIGH_SIGNAL_PATTERNS = (
    r"\botp\b",
    r"\bm?t[aA]n\b",
    r"\bbanking\b",
    r"\bcredential",
    r"\bphish",
    r"\boverlay\b",
    r"\baccessibility service\b",
    r"\bintercept",
    r"\bsms\b.*\b(http|internet|forward|send)\b",
    r"\b(http|internet|network)\b.*\bsms\b",
    r"\bimei\b.*\b(http|internet|network)\b",
    r"\bimsi\b.*\b(http|internet|network)\b",
    r"\bphone number\b.*\b(http|internet|network)\b",
    r"\bsensitive data\b.*\b(http|internet|network)\b",
    r"\binstall other apks?\b",
    r"\bload .*dex\b",
    r"\bclassloader\b",
    r"\bunpack .*dex\b",
    r"\bpayment data\b",
    r"\bnfc\b.*\b(card|payment|relay)\b",
    r"\bkeylogging\b",
    r"\bclipboard\b",
    r"\bexecute .*shell\b",
    r"\bprocessbuilder\b",
)


def _parse_confidence(value: Any) -> float:
    try:
        return (
            float(
                str(value).rstrip("%")
            )
            / 100.0
        )
    except (TypeError, ValueError):
        return 0.0


def _is_high_signal(
    crime: dict[str, Any]
) -> bool:
    text = " ".join(
        [
            str(crime.get("crime", "")),
            " ".join(
                map(
                    str,
                    crime.get("label", []),
                )
            ),
        ]
    )

    return any(
        re.search(
            pattern,
            text,
            re.IGNORECASE,
        )
        for pattern in HIGH_SIGNAL_PATTERNS
    )


def _run_quark(
    apk_path: str,
    timeout_seconds: int,
) -> dict[str, Any]:

    if (
        not RULE_DIR.is_dir()
        or not any(RULE_DIR.glob("*.json"))
    ):
        return {
            "available": False,
            "error": (
                f"SPECTRE Quark rule subset "
                f"not found: {RULE_DIR}"
            ),
        }

    output_path = None

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".json",
            prefix="spectre_quark_",
            delete=False,
        ) as tmp:
            output_path = Path(tmp.name)

        command = [
            "quark",
            "-a",
            str(apk_path),
            "-r",
            str(RULE_DIR),
            "-o",
            str(output_path),
        ]

        # Optional runtime benchmark override.
        core = os.environ.get(
            "SPECTRE_QUARK_CORE_LIBRARY",
            ""
        ).strip()

        if core:
            command.extend(
                [
                    "--core-library",
                    core,
                ]
            )

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

        if completed.returncode != 0:
            return {
                "available": True,
                "error": (
                    f"Quark exited with code "
                    f"{completed.returncode}: "
                    f"{completed.stderr[-2000:]}"
                ),
            }

        if not output_path.exists():
            return {
                "available": True,
                "error": (
                    "Quark completed but "
                    "produced no JSON output."
                ),
            }

        report = json.loads(
            output_path.read_text(
                encoding="utf-8"
            )
        )

        return {
            "available": True,
            "report": report,
        }

    except FileNotFoundError:
        return {
            "available": False,
            "error": (
                "Quark executable was not "
                "found on PATH."
            ),
        }

    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "error": (
                f"Quark timed out after "
                f"{timeout_seconds}s."
            ),
            "timed_out": True,
        }

    except json.JSONDecodeError as exc:
        return {
            "available": True,
            "error": (
                f"Invalid Quark JSON output: {exc}"
            ),
        }

    except Exception as exc:
        return {
            "available": True,
            "error": (
                f"{type(exc).__name__}: {exc}"
            ),
        }

    finally:
        if output_path:
            try:
                output_path.unlink(
                    missing_ok=True
                )
            except Exception:
                pass


def analyze_quark(
    apk_path: str,
    timeout_seconds: int = 360,
) -> dict[str, Any]:

    raw = _run_quark(
        apk_path,
        timeout_seconds,
    )

    base = {
        "available": bool(
            raw.get("available")
        ),
        "rule_directory": str(
            RULE_DIR
        ),
        "rules_used": (
            len(
                list(
                    RULE_DIR.glob("*.json")
                )
            )
            if RULE_DIR.is_dir()
            else 0
        ),
        "evaluated_rules": 0,
        "positive_rules": 0,
        "high_confidence_positive_rules": 0,
        "high_signal_rules": 0,
        "sequence_matches": 0,
        "combination_matches": 0,
        "high_signal_sequence_matches": 0,
        "high_signal_combination_matches": 0,
        "high_signal_positive_rules": [],
        "quark_total_score": None,
        "quark_threat_level": None,
        "error": raw.get("error"),
        "timed_out": bool(
            raw.get("timed_out")
        ),
    }

    if "report" not in raw:
        return base

    report = raw["report"]
    crimes = report.get(
        "crimes",
        []
    ) or []

    base["evaluated_rules"] = len(
        crimes
    )

    # Kept for telemetry only.
    base["quark_total_score"] = (
        report.get("total_score")
    )

    base["quark_threat_level"] = (
        report.get("threat_level")
    )

    relevant = []

    for crime in crimes:
        confidence = _parse_confidence(
            crime.get("confidence")
        )

        weight = float(
            crime.get("weight", 0)
            or 0
        )

        if weight > 0:
            base["positive_rules"] += 1

        if (
            confidence >= 0.80
            and weight > 0
        ):
            base[
                "high_confidence_positive_rules"
            ] += 1

        if (
            weight <= 0
            or confidence < 0.60
            or not _is_high_signal(crime)
        ):
            continue

        sequence = bool(
            crime.get("sequence")
        )

        combination = bool(
            crime.get("combination")
        )

        base[
            "high_signal_rules"
        ] += 1

        if sequence:
            base[
                "high_signal_sequence_matches"
            ] += 1

        if combination:
            base[
                "high_signal_combination_matches"
            ] += 1

        relevant.append(
            {
                "rule": crime.get("rule"),
                "crime": crime.get("crime"),
                "labels": crime.get(
                    "label",
                    []
                ),
                "confidence": confidence,
                "score": crime.get("score"),
                "weight": crime.get("weight"),
                "sequence": crime.get(
                    "sequence",
                    []
                ),
                "combination": crime.get(
                    "combination",
                    []
                ),
                "native_api": crime.get(
                    "native_api",
                    []
                ),
            }
        )

    # Positive matches with actual sequence/combination evidence.
    base["sequence_matches"] = sum(
        1
        for crime in crimes
        if float(
            crime.get("weight", 0)
            or 0
        ) > 0
        and bool(
            crime.get("sequence")
        )
    )

    base["combination_matches"] = sum(
        1
        for crime in crimes
        if float(
            crime.get("weight", 0)
            or 0
        ) > 0
        and bool(
            crime.get("combination")
        )
    )

    relevant.sort(
        key=lambda x: (
            bool(x.get("sequence")),
            bool(x.get("combination")),
            x.get(
                "confidence",
                0.0
            ),
            float(
                x.get("weight", 0)
                or 0
            ),
        ),
        reverse=True,
    )

    base[
        "high_signal_positive_rules"
    ] = relevant[:100]

    return base