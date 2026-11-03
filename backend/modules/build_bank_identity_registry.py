

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from androguard.core.apk import APK
from androguard.util import set_log


# Keep Androguard output reasonably quiet during normal SPECTRE operation.
set_log("WARNING")


def normalize_fp(value: str) -> str:
    return value.replace(":", "").replace(" ", "").lower()


def extract_one(apk_path: Path) -> dict[str, Any]:
    apk = APK(str(apk_path))

    package = str(apk.get_package() or "").strip()
    label = ""
    try:
        label = str(apk.get_app_name() or "").strip()
    except Exception:
        pass

    certs = []
    try:
        for cert in apk.get_certificates() or []:
            try:
                certs.append(normalize_fp(cert.sha256.hex()))
            except Exception:
                continue
    except Exception:
        pass

    return {
        "package": package,
        "app_name": label,
        "cert_sha256": sorted(set(certs)),
        "source_apk": apk_path.name,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build SPECTRE bank identity registry from official APKs."
    )
    parser.add_argument(
        "--apk-dir",
        default=r"D:\Spectre_BOI_project\SPECTRE\data\validation\banking_apks",
        help="Directory containing verified official bank APKs.",
    )
    parser.add_argument(
        "--output",
        default=(
            r"D:\Spectre_BOI_project\SPECTRE\backend\config"
            r"\bank_identity_registry.json"
        ),
        help="Output registry JSON path.",
    )
    args = parser.parse_args()

    apk_dir = Path(args.apk_dir)
    output = Path(args.output)

    if not apk_dir.exists():
        raise FileNotFoundError(f"APK directory not found: {apk_dir}")

    output.parent.mkdir(parents=True, exist_ok=True)

    records: dict[str, dict[str, Any]] = {}

    apk_files = sorted(apk_dir.glob("*.apk"))
    if not apk_files:
        raise RuntimeError(f"No APK files found in {apk_dir}")

    print("=" * 90)
    print("SPECTRE BANK IDENTITY REGISTRY BUILDER")
    print("=" * 90)

    for apk_path in apk_files:
        print(f"[+] {apk_path.name}")
        try:
            item = extract_one(apk_path)
        except Exception as exc:
            print(f"    ERROR: {type(exc).__name__}: {exc}")
            continue

        package = item["package"]
        if not package:
            print("    ERROR: package name unavailable")
            continue

        record = records.setdefault(
            package,
            {
                "app_name": item["app_name"],
                "cert_sha256": [],
                "source_apks": [],
                "notes": (
                    "Populate only from independently verified official "
                    "bank APKs. Multiple fingerprints may be valid across "
                    "versions/signing rotations."
                ),
            },
        )

        if item["app_name"] and not record["app_name"]:
            record["app_name"] = item["app_name"]

        record["cert_sha256"] = sorted(
            set(record["cert_sha256"]) | set(item["cert_sha256"])
        )
        record["source_apks"].append(item["source_apk"])

        print(f"    package : {package}")
        print(f"    label   : {item['app_name']}")
        print(f"    certs   : {len(item['cert_sha256'])}")

    output.write_text(
        json.dumps(records, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print()
    print(f"Registry entries : {len(records)}")
    print(f"Output            : {output}")


if __name__ == "__main__":
    main()
