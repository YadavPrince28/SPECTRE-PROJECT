"""
SPECTRE Module 2 — Validation APK Downloader

Downloads ONLY SHA256 values listed in:
data/validation/module2_validation_manifest.csv

API key:
    ANDROZOO_API_KEY environment variable

Safe behavior:
- Skips already SHA256-verified APKs.
- Uses .part files for incomplete downloads.
- Streams downloads in 1 MiB chunks.
- Verifies SHA256 before finalizing an APK.
- Retries transient errors.
- Logs each result incrementally.
- Never reads the huge AndroZoo metadata CSV.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


PROJECT_ROOT = Path(r"D:\Spectre_BOI_project\SPECTRE")
MANIFEST_PATH = PROJECT_ROOT / "data" / "validation" / "module2_validation_manifest.csv"
DOWNLOAD_DIR = PROJECT_ROOT / "data" / "validation" / "apks"
LOG_PATH = PROJECT_ROOT / "data" / "validation" / "module2_apk_download_log.csv"

ANDROZOO_URL = "https://androzoo.uni.lu/api/download"

CHUNK_SIZE = 1024 * 1024
CONNECT_TIMEOUT = 30
READ_TIMEOUT = 120
MAX_RETRIES = 4
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}

LOG_FIELDS = [
    "timestamp_utc",
    "cohort",
    "sha256",
    "pkg_name",
    "vt_detection",
    "status",
    "http_status",
    "file_size",
    "sha256_verified",
    "attempts",
    "error",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def load_manifest() -> list[dict[str, str]]:
    if not MANIFEST_PATH.exists():
        raise FileNotFoundError(f"Manifest not found:\n{MANIFEST_PATH}")

    with MANIFEST_PATH.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    if len(rows) != 150:
        raise RuntimeError(
            f"Expected exactly 150 manifest rows, found {len(rows)}."
        )

    required = {"cohort", "sha256", "pkg_name", "vt_detection"}
    missing = required - set(rows[0].keys())
    if missing:
        raise RuntimeError(f"Manifest missing columns: {sorted(missing)}")

    shas = []
    for row in rows:
        sha = row["sha256"].strip().lower()
        if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
            raise RuntimeError(f"Invalid SHA256: {sha}")
        shas.append(sha)

    if len(shas) != len(set(shas)):
        raise RuntimeError("Manifest contains duplicate SHA256 values.")

    return rows


def ensure_log() -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not LOG_PATH.exists():
        with LOG_PATH.open("w", encoding="utf-8", newline="") as f:
            csv.DictWriter(f, fieldnames=LOG_FIELDS).writeheader()


def append_log(record: dict) -> None:
    with LOG_PATH.open("a", encoding="utf-8", newline="") as f:
        csv.DictWriter(f, fieldnames=LOG_FIELDS).writerow(record)


def download_one(
    session: requests.Session,
    sha256: str,
    destination: Path,
) -> tuple[bool, int | None, int, str]:
    part_path = Path(str(destination) + ".part")
    last_error = ""
    last_status: int | None = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = session.get(
                ANDROZOO_URL,
                params={
                    "apikey": os.environ["ANDROZOO_API_KEY"],
                    "sha256": sha256,
                },
                stream=True,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )

            last_status = response.status_code

            if response.status_code != 200:
                try:
                    body = response.text[:500].replace("\n", " ")
                except Exception:
                    body = ""

                last_error = f"HTTP {response.status_code}"
                if body:
                    last_error += f": {body}"

                response.close()

                if response.status_code not in RETRYABLE_STATUS:
                    return False, last_status, attempt, last_error

                time.sleep(min(2 ** attempt, 20))
                continue

            with part_path.open("wb") as f:
                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    if chunk:
                        f.write(chunk)

            response.close()

            actual = sha256_file(part_path)
            if actual != sha256:
                part_path.unlink(missing_ok=True)
                last_error = (
                    f"SHA256 mismatch: expected={sha256}, actual={actual}"
                )
                if attempt < MAX_RETRIES:
                    time.sleep(min(2 ** attempt, 20))
                    continue
                return False, last_status, attempt, last_error

            part_path.replace(destination)
            return True, last_status, attempt, ""

        except (requests.RequestException, OSError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
            if attempt < MAX_RETRIES:
                time.sleep(min(2 ** attempt, 20))
                continue
            return False, last_status, attempt, last_error

    return False, last_status, MAX_RETRIES, last_error


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--sleep",
        type=float,
        default=0.5,
        help="Delay in seconds between successful downloads.",
    )
    args = parser.parse_args()

    if not os.environ.get("ANDROZOO_API_KEY", "").strip():
        print("ERROR: ANDROZOO_API_KEY is not set.", file=sys.stderr)
        print(
            'Set it in PowerShell with your current/new key, e.g.:',
            file=sys.stderr,
        )
        print('$env:ANDROZOO_API_KEY="YOUR_KEY"', file=sys.stderr)
        return 2

    rows = load_manifest()
    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    ensure_log()

    print("=" * 90)
    print("SPECTRE MODULE 2 — VALIDATION APK DOWNLOADER")
    print("=" * 90)
    print(f"Manifest : {MANIFEST_PATH}")
    print(f"Output   : {DOWNLOAD_DIR}")
    print(f"Entries  : {len(rows)}")
    print(f"Log      : {LOG_PATH}")
    print()

    session = requests.Session()
    session.headers["User-Agent"] = "SPECTRE-Module2-Validation/1.0"

    verified = 0
    failures = 0
    already_verified = 0

    for index, row in enumerate(rows, start=1):
        sha256 = row["sha256"].strip().lower()
        cohort = row["cohort"].strip().lower()
        pkg = row.get("pkg_name", "").strip()
        vt = row.get("vt_detection", "").strip()

        destination = DOWNLOAD_DIR / f"{sha256}.apk"

        if destination.exists():
            try:
                actual = sha256_file(destination)
                if actual == sha256:
                    verified += 1
                    already_verified += 1
                    print(
                        f"[{index:03d}/150] EXISTS+VERIFIED | "
                        f"{cohort:9s} | {sha256}"
                    )
                    append_log({
                        "timestamp_utc": utc_now(),
                        "cohort": cohort,
                        "sha256": sha256,
                        "pkg_name": pkg,
                        "vt_detection": vt,
                        "status": "already_verified",
                        "http_status": "",
                        "file_size": destination.stat().st_size,
                        "sha256_verified": "true",
                        "attempts": 0,
                        "error": "",
                    })
                    continue

                destination.unlink()
                print(
                    f"[{index:03d}/150] BAD EXISTING FILE — redownloading | "
                    f"{sha256}"
                )
            except OSError as exc:
                failures += 1
                append_log({
                    "timestamp_utc": utc_now(),
                    "cohort": cohort,
                    "sha256": sha256,
                    "pkg_name": pkg,
                    "vt_detection": vt,
                    "status": "existing_file_error",
                    "http_status": "",
                    "file_size": "",
                    "sha256_verified": "false",
                    "attempts": 0,
                    "error": str(exc),
                })
                continue

        print(
            f"[{index:03d}/150] DOWNLOADING | "
            f"{cohort:9s} | {sha256} | {pkg}"
        )

        success, http_status, attempts, error = download_one(
            session, sha256, destination
        )

        if success:
            size = destination.stat().st_size
            verified += 1
            print(
                f"              VERIFIED | {size:,} bytes | "
                f"attempts={attempts}"
            )
            append_log({
                "timestamp_utc": utc_now(),
                "cohort": cohort,
                "sha256": sha256,
                "pkg_name": pkg,
                "vt_detection": vt,
                "status": "downloaded",
                "http_status": http_status or "",
                "file_size": size,
                "sha256_verified": "true",
                "attempts": attempts,
                "error": "",
            })
            if args.sleep > 0:
                time.sleep(args.sleep)
        else:
            failures += 1
            print(
                f"              FAILED | HTTP={http_status} | "
                f"attempts={attempts} | {error}"
            )
            append_log({
                "timestamp_utc": utc_now(),
                "cohort": cohort,
                "sha256": sha256,
                "pkg_name": pkg,
                "vt_detection": vt,
                "status": "failed",
                "http_status": http_status or "",
                "file_size": "",
                "sha256_verified": "false",
                "attempts": attempts,
                "error": error,
            })

    print()
    print("=" * 90)
    print("DOWNLOAD SUMMARY")
    print("=" * 90)
    print(f"Verified APKs    : {verified}")
    print(f"Already verified : {already_verified}")
    print(f"Failures         : {failures}")
    print(f"APK directory    : {DOWNLOAD_DIR}")
    print(f"Download log     : {LOG_PATH}")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
