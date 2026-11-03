from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_DIR = (
    PROJECT_ROOT
    / "backend"
    / "config"
    / "quark_rules_selected"
)

MANIFEST_FILE = (
    PROJECT_ROOT
    / "backend"
    / "config"
    / "spectre_quark_rules_manifest.json"
)


RULE_ROOT_CANDIDATES = (
    Path.home() / ".quark-engine" / "quark-rules" / "rules",
    Path.home() / ".quark" / "quark-rules" / "rules",
)


# High-value behaviors for SPECTRE's banking-malware objective.
HIGH_SIGNAL_PHRASES = (
    r"\botp\b",
    r"\bm?t[aA]n\b",
    r"\bbanking\b",
    r"\bcredential",
    r"\bphish",
    r"\boverlay\b",
    r"\baccessibility service\b",
    r"\bintercept",
    r"\bsms\b.*\bforward\b",
    r"\bforward\b.*\bsms\b",
    r"\bsms\b.*\bhttp\b",
    r"\bsms\b.*\binternet\b",
    r"\bimei\b.*\b(http|internet|network)\b",
    r"\bimsi\b.*\b(http|internet|network)\b",
    r"\bphone number\b.*\b(http|internet|network)\b",
    r"\bsensitive data\b.*\b(http|internet|network)\b",
    r"\bsensitive data\b.*\bhttp\b",
    r"\bsend .* over internet\b",
    r"\bsend .* over http\b",
    r"\binstall other apks?\b",
    r"\bload additional dex\b",
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


HIGH_SIGNAL_LABELS = {
    "sms",
    "calllog",
    "otp",
    "credential",
    "banking",
    "phish",
    "overlay",
    "accessibility service",
    "payment",
    "nfc",
    "relay",
    "keylogging",
    "dexclassloader",
    "packer",
    "privacy",
    "evasion",
}


GENERIC_ONLY_PHRASES = (
    r"\bcheck if the network is connected\b",
    r"\bcheck the network capabilities\b",
    r"\bcheck the current (active )?network type\b",
    r"\bopen camera\b",
    r"\bconfigure video source\b",
    r"\bcreate a ui layout\b",
    r"\bnavigation bar height\b",
    r"\bstatus bar height\b",
    r"\bdefault ringtone\b",
    r"\bcreate a directory\b",
    r"\bstart a background service\b",
    r"\bretrieve the application context\b",
    r"\bmodify voice volume\b",
)


def locate_rules() -> Path:
    for candidate in RULE_ROOT_CANDIDATES:
        if candidate.is_dir() and any(candidate.glob("*.json")):
            return candidate

    raise FileNotFoundError(
        "Quark rules not found. Run freshquark first."
    )


def score_rule(data: dict[str, Any]) -> tuple[int, list[str]]:
    crime = str(data.get("crime", ""))
    labels = [
        str(x)
        for x in data.get("label", [])
    ]

    text = (
        crime
        + " "
        + " ".join(labels)
    ).lower()

    score = 0
    reasons: list[str] = []

    phrase_hits = [
        p
        for p in HIGH_SIGNAL_PHRASES
        if re.search(p, text, re.IGNORECASE)
    ]

    if phrase_hits:
        score += min(12, 4 * len(phrase_hits))
        reasons.append(
            f"high_signal_phrases={len(phrase_hits)}"
        )

    label_hits = [
        x
        for x in labels
        if x.strip().lower() in HIGH_SIGNAL_LABELS
    ]

    if label_hits:
        score += min(
            8,
            2 * len(set(x.lower() for x in label_hits))
        )
        reasons.append(
            "high_signal_labels="
            + ",".join(sorted(set(label_hits)))
        )

    # Reflection alone is too generic.
    # Reflection becomes useful when tied to loading/install/evasion.
    if "reflection" in text:
        if any(
            k in text
            for k in (
                "dex",
                "install",
                "overlay",
                "credential",
                "phish",
            )
        ):
            score += 3
            reasons.append("contextual_reflection")
        elif not phrase_hits:
            score -= 3

    generic_hits = [
        p
        for p in GENERIC_ONLY_PHRASES
        if re.search(p, text, re.IGNORECASE)
    ]

    if (
        generic_hits
        and not phrase_hits
        and not label_hits
    ):
        score -= 8
        reasons.append("generic_only")

    return score, reasons


def main() -> None:
    source_dir = locate_rules()

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Remove only our previously generated subset.
    for old in OUTPUT_DIR.glob("*.json"):
        old.unlink()

    selected = []
    total_rules = 0

    for source in sorted(source_dir.glob("*.json")):
        total_rules += 1

        try:
            data = json.loads(
                source.read_text(
                    encoding="utf-8"
                )
            )
        except Exception:
            continue

        selection_score, reasons = score_rule(data)

        if selection_score < 5:
            continue

        shutil.copy2(
            source,
            OUTPUT_DIR / source.name
        )

        selected.append(
            {
                "rule": source.name,
                "crime": data.get("crime", ""),
                "labels": data.get("label", []),
                "selection_score": selection_score,
                "selection_reasons": reasons,
            }
        )

    manifest = {
        "source_rule_directory": str(source_dir),
        "source_rule_count": total_rules,
        "selected_rule_count": len(selected),
        "purpose": (
            "SPECTRE Phase-1 Quark candidate subset"
        ),
        "not_for_final_scoring": True,
        "rules": selected,
    }

    MANIFEST_FILE.write_text(
        json.dumps(
            manifest,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    print()
    print("=" * 70)
    print("SPECTRE QUARK RULE SELECTION")
    print("=" * 70)
    print(f"Source rules      : {source_dir}")
    print(f"Total rules       : {total_rules}")
    print(f"Selected rules    : {len(selected)}")
    print(f"Output directory  : {OUTPUT_DIR}")
    print(f"Manifest          : {MANIFEST_FILE}")
    print("=" * 70)

    for item in selected:
        print(
            f"{item['rule']:>10} | "
            f"{item['selection_score']:>2} | "
            f"{','.join(item['labels'])[:30]:30} | "
            f"{item['crime']}"
        )


if __name__ == "__main__":
    main()