from __future__ import annotations

import csv
import hashlib
from pathlib import Path


PROJECT_ROOT = Path(r"D:\Spectre_BOI_project\SPECTRE")

PRIMARY_MANIFEST = (
    PROJECT_ROOT
    / "data"
    / "validation"
    / "module2_validation_manifest.csv"
)

PRIMARY_DIR = (
    PROJECT_ROOT
    / "data"
    / "validation"
    / "apks"
)

BANKING_MANIFEST = (
    PROJECT_ROOT
    / "data"
    / "validation"
    / "legitimate_banking_manifest.csv"
)

BANKING_DIR = (
    PROJECT_ROOT
    / "data"
    / "validation"
    / "banking_apks"
)

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()

    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()


def check_manifest(
    manifest: Path,
    apk_dir: Path,
) -> tuple[int, int, list[str]]:

    with manifest.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as f:
        rows = list(csv.DictReader(f))

    verified = 0
    failed = 0
    problems = []

    for row in rows:

        sha = (
            row["sha256"]
            .strip()
            .lower()
        )

        apk = apk_dir / f"{sha}.apk"

        if not apk.exists():

            failed += 1

            problems.append(
                f"MISSING: {sha}"
            )

            continue

        try:

            actual = sha256_file(apk)

        except Exception as exc:

            failed += 1

            problems.append(
                f"READ ERROR: {sha} | {exc}"
            )

            continue

        if actual != sha:

            failed += 1

            problems.append(
                f"SHA256 MISMATCH: {sha} | "
                f"actual={actual}"
            )

        else:

            verified += 1

    return verified, failed, problems


def main():

    print()
    print("=" * 90)
    print("SPECTRE MODULE 2 — 170 APK RECONCILIATION")
    print("=" * 90)
    print()

    m_verified, m_failed, m_problems = check_manifest(
        PRIMARY_MANIFEST,
        PRIMARY_DIR,
    )

    b_verified, b_failed, b_problems = check_manifest(
        BANKING_MANIFEST,
        BANKING_DIR,
    )

    print("PRIMARY VALIDATION")
    print("-" * 90)
    print(f"Expected : 150")
    print(f"Verified : {m_verified}")
    print(f"Failed   : {m_failed}")
    print()

    print("LEGITIMATE BANKING")
    print("-" * 90)
    print(f"Expected : 20")
    print(f"Verified : {b_verified}")
    print(f"Failed   : {b_failed}")
    print()

    total_verified = (
        m_verified + b_verified
    )

    total_failed = (
        m_failed + b_failed
    )

    print("=" * 90)
    print("TOTAL")
    print("=" * 90)
    print(f"Expected : 170")
    print(f"Verified : {total_verified}")
    print(f"Failed   : {total_failed}")

    problems = (
        m_problems
        + b_problems
    )

    if problems:

        print()
        print("PROBLEMS")

        for problem in problems:
            print(problem)

        raise SystemExit(1)

    print()
    print(
        "ALL 170 APKs ARE PRESENT AND "
        "SHA256-VERIFIED."
    )


if __name__ == "__main__":
    main()