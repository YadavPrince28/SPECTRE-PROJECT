from __future__ import annotations

import csv
import hashlib
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(r"D:\Spectre_BOI_project\SPECTRE")

MANIFEST_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation"
    / "legitimate_banking_manifest.csv"
)

DOWNLOAD_DIR = (
    PROJECT_ROOT
    / "data"
    / "validation"
    / "banking_apks"
)

LOG_PATH = (
    PROJECT_ROOT
    / "data"
    / "validation"
    / "legitimate_banking_download_log.csv"
)

ANDROZOO_URL = "https://androzoo.uni.lu/api/download"

CHUNK_SIZE = 1024 * 1024  # 1 MiB

CONNECT_TIMEOUT = 30
READ_TIMEOUT = 120

MAX_RETRIES = 4

RETRYABLE_STATUS = {
    408,
    425,
    429,
    500,
    502,
    503,
    504,
}

LOG_FIELDS = [
    "timestamp_utc",
    "bank",
    "app_name",
    "package_name",
    "sha256",
    "vercode",
    "vt_detection",
    "status",
    "http_status",
    "file_size",
    "sha256_verified",
    "attempts",
    "error",
]


# ============================================================
# HELPERS
# ============================================================

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

        raise FileNotFoundError(
            f"Banking manifest not found:\n{MANIFEST_PATH}"
        )

    with MANIFEST_PATH.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as f:

        rows = list(csv.DictReader(f))

    if len(rows) != 20:

        raise RuntimeError(
            f"Expected exactly 20 banking APK records, "
            f"found {len(rows)}."
        )

    required = {
        "bank",
        "app_name",
        "package_name",
        "sha256",
        "vercode",
        "vt_detection",
    }

    missing = (
        required
        - set(rows[0].keys())
    )

    if missing:

        raise RuntimeError(
            f"Manifest is missing columns: "
            f"{sorted(missing)}"
        )

    shas = []

    for row in rows:

        sha = (
            row["sha256"]
            .strip()
            .lower()
        )

        if (
            len(sha) != 64
            or any(
                c not in "0123456789abcdef"
                for c in sha
            )
        ):

            raise RuntimeError(
                f"Invalid SHA256: {sha}"
            )

        shas.append(sha)

    if len(shas) != len(set(shas)):

        raise RuntimeError(
            "Duplicate SHA256 values found "
            "in banking manifest."
        )

    return rows


def ensure_log() -> None:

    LOG_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if not LOG_PATH.exists():

        with LOG_PATH.open(
            "w",
            encoding="utf-8",
            newline="",
        ) as f:

            writer = csv.DictWriter(
                f,
                fieldnames=LOG_FIELDS,
            )

            writer.writeheader()


def append_log(record: dict) -> None:

    with LOG_PATH.open(
        "a",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=LOG_FIELDS,
        )

        writer.writerow(record)


# ============================================================
# DOWNLOAD ONE APK
# ============================================================

def download_one(
    session: requests.Session,
    sha256: str,
    destination: Path,
) -> tuple[
    bool,
    int | None,
    int,
    str,
]:

    part_path = Path(
        str(destination) + ".part"
    )

    last_error = ""
    last_status = None

    for attempt in range(
        1,
        MAX_RETRIES + 1,
    ):

        try:

            response = session.get(
                ANDROZOO_URL,
                params={
                    "apikey": os.environ[
                        "ANDROZOO_API_KEY"
                    ],
                    "sha256": sha256,
                },
                stream=True,
                timeout=(
                    CONNECT_TIMEOUT,
                    READ_TIMEOUT,
                ),
            )

            last_status = (
                response.status_code
            )

            # ------------------------------------------------
            # HTTP ERROR
            # ------------------------------------------------

            if response.status_code != 200:

                try:

                    body = (
                        response.text[:500]
                        .replace("\n", " ")
                    )

                except Exception:

                    body = ""

                last_error = (
                    f"HTTP {response.status_code}"
                )

                if body:

                    last_error += (
                        f": {body}"
                    )

                response.close()

                if (
                    response.status_code
                    not in RETRYABLE_STATUS
                ):

                    return (
                        False,
                        last_status,
                        attempt,
                        last_error,
                    )

                time.sleep(
                    min(
                        2 ** attempt,
                        20,
                    )
                )

                continue

            # ------------------------------------------------
            # STREAM APK
            # ------------------------------------------------

            with part_path.open(
                "wb"
            ) as f:

                for chunk in response.iter_content(
                    chunk_size=CHUNK_SIZE
                ):

                    if chunk:

                        f.write(chunk)

            response.close()

            # ------------------------------------------------
            # VERIFY SHA256
            # ------------------------------------------------

            actual_sha256 = sha256_file(
                part_path
            )

            if actual_sha256 != sha256:

                part_path.unlink(
                    missing_ok=True
                )

                last_error = (
                    "SHA256 mismatch: "
                    f"expected={sha256}, "
                    f"actual={actual_sha256}"
                )

                if attempt < MAX_RETRIES:

                    time.sleep(
                        min(
                            2 ** attempt,
                            20,
                        )
                    )

                    continue

                return (
                    False,
                    last_status,
                    attempt,
                    last_error,
                )

            # ------------------------------------------------
            # FINALIZE
            # ------------------------------------------------

            part_path.replace(
                destination
            )

            return (
                True,
                last_status,
                attempt,
                "",
            )

        except (
            requests.RequestException,
            OSError,
        ) as exc:

            last_error = (
                f"{type(exc).__name__}: {exc}"
            )

            if attempt < MAX_RETRIES:

                time.sleep(
                    min(
                        2 ** attempt,
                        20,
                    )
                )

                continue

            return (
                False,
                last_status,
                attempt,
                last_error,
            )

    return (
        False,
        last_status,
        MAX_RETRIES,
        last_error,
    )


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    # --------------------------------------------------------
    # API KEY
    # --------------------------------------------------------

    api_key = (
        os.environ
        .get("ANDROZOO_API_KEY", "")
        .strip()
    )

    if not api_key:

        print(
            "ERROR: ANDROZOO_API_KEY is not set.",
            file=sys.stderr,
        )

        print(
            'Set it in PowerShell with:',
            file=sys.stderr,
        )

        print(
            '$env:ANDROZOO_API_KEY="YOUR_CURRENT_KEY"',
            file=sys.stderr,
        )

        return 2

    # --------------------------------------------------------
    # LOAD MANIFEST
    # --------------------------------------------------------

    rows = load_manifest()

    DOWNLOAD_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    ensure_log()

    print()
    print("=" * 90)
    print(
        "SPECTRE MODULE 2 — "
        "LEGITIMATE BANKING APK DOWNLOADER"
    )
    print("=" * 90)
    print()

    print(
        f"Manifest : {MANIFEST_PATH}"
    )

    print(
        f"Output   : {DOWNLOAD_DIR}"
    )

    print(
        f"Entries  : {len(rows)}"
    )

    print(
        f"Log      : {LOG_PATH}"
    )

    print()

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent":
                "SPECTRE-Module2-BankingValidation/1.0"
        }
    )

    verified = 0
    already_verified = 0
    failures = 0

    # ========================================================
    # PROCESS EACH BANKING APK
    # ========================================================

    for index, row in enumerate(
        rows,
        start=1,
    ):

        bank = (
            row["bank"]
            .strip()
        )

        app_name = (
            row["app_name"]
            .strip()
        )

        package_name = (
            row["package_name"]
            .strip()
        )

        sha256 = (
            row["sha256"]
            .strip()
            .lower()
        )

        vercode = (
            row.get("vercode", "")
            .strip()
        )

        vt_detection = (
            row.get("vt_detection", "")
            .strip()
        )

        destination = (
            DOWNLOAD_DIR
            / f"{sha256}.apk"
        )

        # ----------------------------------------------------
        # EXISTING VERIFIED APK
        # ----------------------------------------------------

        if destination.exists():

            try:

                actual = sha256_file(
                    destination
                )

                if actual == sha256:

                    verified += 1
                    already_verified += 1

                    print(
                        f"[{index:02d}/20] "
                        f"EXISTS+VERIFIED | "
                        f"{bank} | "
                        f"{app_name}"
                    )

                    append_log(
                        {
                            "timestamp_utc":
                                utc_now(),
                            "bank":
                                bank,
                            "app_name":
                                app_name,
                            "package_name":
                                package_name,
                            "sha256":
                                sha256,
                            "vercode":
                                vercode,
                            "vt_detection":
                                vt_detection,
                            "status":
                                "already_verified",
                            "http_status":
                                "",
                            "file_size":
                                destination.stat().st_size,
                            "sha256_verified":
                                "true",
                            "attempts":
                                0,
                            "error":
                                "",
                        }
                    )

                    continue

                # Bad existing file.
                destination.unlink()

                print(
                    f"[{index:02d}/20] "
                    f"BAD EXISTING FILE — "
                    f"redownloading"
                )

            except OSError as exc:

                failures += 1

                print(
                    f"[{index:02d}/20] "
                    f"ERROR checking existing APK: "
                    f"{exc}"
                )

                append_log(
                    {
                        "timestamp_utc":
                            utc_now(),
                        "bank":
                            bank,
                        "app_name":
                            app_name,
                        "package_name":
                            package_name,
                        "sha256":
                            sha256,
                        "vercode":
                            vercode,
                        "vt_detection":
                            vt_detection,
                        "status":
                            "existing_file_error",
                        "http_status":
                            "",
                        "file_size":
                            "",
                        "sha256_verified":
                            "false",
                        "attempts":
                            0,
                        "error":
                            str(exc),
                    }
                )

                continue

        # ----------------------------------------------------
        # DOWNLOAD
        # ----------------------------------------------------

        print(
            f"[{index:02d}/20] "
            f"DOWNLOADING | "
            f"{bank} | "
            f"{app_name} | "
            f"{package_name}"
        )

        success, http_status, attempts, error = (
            download_one(
                session,
                sha256,
                destination,
            )
        )

        if success:

            file_size = (
                destination.stat().st_size
            )

            verified += 1

            print(
                f"          VERIFIED | "
                f"{file_size:,} bytes | "
                f"attempts={attempts}"
            )

            append_log(
                {
                    "timestamp_utc":
                        utc_now(),
                    "bank":
                        bank,
                    "app_name":
                        app_name,
                    "package_name":
                        package_name,
                    "sha256":
                        sha256,
                    "vercode":
                        vercode,
                    "vt_detection":
                        vt_detection,
                    "status":
                        "downloaded",
                    "http_status":
                        http_status or "",
                    "file_size":
                        file_size,
                    "sha256_verified":
                        "true",
                    "attempts":
                        attempts,
                    "error":
                        "",
                }
            )

            time.sleep(0.5)

        else:

            failures += 1

            print(
                f"          FAILED | "
                f"HTTP={http_status} | "
                f"attempts={attempts} | "
                f"{error}"
            )

            append_log(
                {
                    "timestamp_utc":
                        utc_now(),
                    "bank":
                        bank,
                    "app_name":
                        app_name,
                    "package_name":
                        package_name,
                    "sha256":
                        sha256,
                    "vercode":
                        vercode,
                    "vt_detection":
                        vt_detection,
                    "status":
                        "failed",
                    "http_status":
                        http_status or "",
                    "file_size":
                        "",
                    "sha256_verified":
                        "false",
                    "attempts":
                        attempts,
                    "error":
                        error,
                }
            )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print()
    print("=" * 90)
    print("BANKING APK DOWNLOAD SUMMARY")
    print("=" * 90)

    print(
        f"Verified APKs    : {verified}"
    )

    print(
        f"Already verified : {already_verified}"
    )

    print(
        f"Failures         : {failures}"
    )

    print()

    print(
        "APK directory:"
    )

    print(DOWNLOAD_DIR)

    print()

    print(
        "Download log:"
    )

    print(LOG_PATH)

    print()

    if failures:

        print(
            "Some APKs failed. "
            "Run the same command again; "
            "verified APKs will be skipped."
        )

        return 1

    if verified != 20:

        print(
            f"WARNING: expected 20 verified APKs, "
            f"got {verified}."
        )

        return 1

    print(
        "ALL 20 LEGITIMATE BANKING APKs "
        "ARE SHA256-VERIFIED."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )