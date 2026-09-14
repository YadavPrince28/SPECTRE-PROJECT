from __future__ import annotations

import csv
import gzip
from datetime import datetime
from pathlib import Path


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(r"D:\Spectre_BOI_project\SPECTRE")

METADATA = (
    PROJECT_ROOT
    / "data"
    / "androzoo"
    / "latest_with-added-date.csv.gz"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "validation"
)

MANIFEST = (
    OUTPUT_DIR
    / "legitimate_banking_manifest.csv"
)

SUMMARY = (
    OUTPUT_DIR
    / "legitimate_banking_selection_summary.txt"
)


# ============================================================
# BANKING APPLICATIONS
#
# Package IDs correspond to the official apps we want to test.
# The script will NOT assume that an APK exists in AndroZoo.
# It will scan your metadata and report FOUND/MISSING.
# ============================================================

BANKING_APPS = [
    (
        "Bank of India",
        "BOI Mobile",
        "com.boi.ua.android",
    ),
    (
        "State Bank of India",
        "YONO SBI",
        "com.sbi.lotusintouch",
    ),
    (
        "State Bank of India",
        "YONO Lite SBI",
        "com.sbi.SBIFreedomPlus",
    ),
    (
        "Punjab National Bank",
        "PNB ONE",
        "com.Version1",
    ),
    (
        "Axis Bank",
        "Axis Mobile",
        "com.axis.mobile",
    ),
    (
        "ICICI Bank",
        "iMobile",
        "com.csam.icici.bank.imobile",
    ),
    (
        "HDFC Bank",
        "HDFC Bank MobileBanking",
        "com.snapwork.hdfc",
    ),
    (
        "Kotak Mahindra Bank",
        "Kotak 811 & Mobile Banking",
        "com.msf.kbank.mobile",
    ),
    (
        "Canara Bank",
        "Canara ai1",
        "com.canarabank.mobility",
    ),
    (
        "IDBI Bank",
        "IDBI Bank GO Mobile+",
        "com.snapwork.IDBI",
    ),
    (
        "AU Small Finance Bank",
        "AU 0101",
        "com.ausmallfinancebank.amb",
    ),
    (
        "Union Bank of India",
        "Union ease",
        "com.infrasoft.uboi",
    ),
    (
        "Bank of Baroda",
        "bob World",
        "com.bankofbaroda.mconnect",
    ),
    (
        "Indian Bank",
        "IndSMART",
        "com.iexceed.ib.digitalbankingprod",
    ),
    (
        "UCO Bank",
        "UCO mPassbook",
        "com.lcode.ucombook",
    ),
    (
        "Central Bank of India",
        "Cent Mobile",
        "com.infrasofttech.CentralBank",
    ),
    (
        "Federal Bank",
        "FedMobile",
        "com.fedmobile",
    ),
    (
        "IndusInd Bank",
        "IndusMobile",
        "com.fss.indus",
    ),
    (
        "IDFC FIRST Bank",
        "IDFC FIRST Bank: MobileBanking",
        "com.idfcfirstbank.optimus",
    ),
    (
        "Bandhan Bank",
        "mBandhan",
        "com.bandhan.mBandhan",
    ),
]


# ============================================================
# DATE PARSER
# ============================================================

def parse_added(value: str) -> datetime:
    value = (value or "").strip()

    formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(
                value,
                fmt,
            )
        except ValueError:
            pass

    return datetime.min


# ============================================================
# GOOGLE PLAY MARKET CHECK
# ============================================================

def is_google_play(markets: str) -> bool:
    return (
        "play.google.com"
        in (markets or "").lower()
    )


# ============================================================
# MAIN
# ============================================================

def main():

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # package -> (bank, app name)
    package_map = {
        package: (bank, app_name)
        for bank, app_name, package
        in BANKING_APPS
    }

    # Best qualifying record per package.
    #
    # We do NOT retain all matching rows.
    # Only one record per target package is kept.
    best = {}

    # Diagnostics.
    package_seen = {
        package: 0
        for package in package_map
    }

    play_seen = {
        package: 0
        for package in package_map
    }

    vt0_seen = {
        package: 0
        for package in package_map
    }

    processed = 0
    invalid_rows = 0

    print()
    print("=" * 90)
    print("SPECTRE MODULE 2")
    print("LEGITIMATE BANKING MANIFEST BUILDER")
    print("=" * 90)
    print()

    print("Metadata:")
    print(METADATA)
    print()

    print(
        f"Target banking applications: "
        f"{len(BANKING_APPS)}"
    )

    print()
    print(
        "Streaming AndroZoo metadata..."
    )
    print(
        "Only one candidate record per target package "
        "is retained in memory."
    )
    print()
    
    # ========================================================
    # STREAM 27.7M ROW METADATA
    # ========================================================

    with gzip.open(
        METADATA,
        "rt",
        encoding="utf-8",
        newline="",
    ) as gz:

        reader = csv.DictReader(gz)

        required_columns = {
            "sha256",
            "sha1",
            "md5",
            "pkg_name",
            "vercode",
            "apk_size",
            "dex_size",
            "vt_detection",
            "vt_scan_date",
            "added",
            "markets",
        }

        missing_columns = (
            required_columns
            - set(reader.fieldnames or [])
        )

        if missing_columns:
            raise RuntimeError(
                "Missing required metadata columns: "
                f"{sorted(missing_columns)}"
            )

        for row in reader:

            processed += 1

            package_name = (
                row.get("pkg_name") or ""
            ).strip()

            # Ignore everything that is not one of
            # our target banking packages.
            if package_name not in package_map:
                if processed % 5_000_000 == 0:
                    print(
                        f"Processed {processed:,} rows | "
                        f"qualifying packages="
                        f"{len(best)}/{len(package_map)}"
                    )
                continue

            package_seen[package_name] += 1

            # ----------------------------------------------
            # VT detection must be numeric.
            # ----------------------------------------------

            try:
                vt_detection = int(
                    (row.get("vt_detection") or "").strip()
                )

            except ValueError:
                invalid_rows += 1
                continue

            # ----------------------------------------------
            # Must have Google Play provenance.
            # ----------------------------------------------

            if not is_google_play(
                row.get("markets", "")
            ):
                continue

            play_seen[package_name] += 1

            # ----------------------------------------------
            # Legitimate cohort rule:
            # VT detection = 0
            # ----------------------------------------------

            if vt_detection != 0:
                continue

            vt0_seen[package_name] += 1

            sha256 = (
                row.get("sha256") or ""
            ).strip().lower()

            if (
                len(sha256) != 64
                or any(
                    c not in
                    "0123456789abcdef"
                    for c in sha256
                )
            ):
                invalid_rows += 1
                continue

            # ----------------------------------------------
            # Keep the latest "added" record.
            # ----------------------------------------------

            old = best.get(package_name)

            if old is None:

                best[package_name] = row

            else:

                new_date = parse_added(
                    row.get("added", "")
                )

                old_date = parse_added(
                    old.get("added", "")
                )

                if new_date > old_date:
                    best[package_name] = row

            if processed % 5_000_000 == 0:

                print(
                    f"Processed {processed:,} rows | "
                    f"qualifying packages="
                    f"{len(best)}/{len(package_map)}"
                )

    # ========================================================
    # BUILD RESULTS
    # ========================================================

    results = []
    missing_apps = []

    for bank, app_name, package_name in BANKING_APPS:

        if package_name not in best:

            missing_apps.append(
                (
                    bank,
                    app_name,
                    package_name,
                )
            )

            continue

        row = best[package_name]

        results.append(
            {
                "cohort": "legitimate_banking",
                "bank": bank,
                "app_name": app_name,
                "package_name": package_name,
                "sha256": (
                    row.get("sha256") or ""
                ).strip().lower(),
                "sha1": row.get("sha1", ""),
                "md5": row.get("md5", ""),
                "vercode": row.get("vercode", ""),
                "apk_size": row.get("apk_size", ""),
                "dex_size": row.get("dex_size", ""),
                "vt_detection": row.get(
                    "vt_detection",
                    "",
                ),
                "vt_scan_date": row.get(
                    "vt_scan_date",
                    "",
                ),
                "added": row.get("added", ""),
                "markets": row.get("markets", ""),
                "selection_rule": (
                    "package match + "
                    "play.google.com + "
                    "VT=0 + "
                    "latest added date"
                ),
                "source": (
                    "AndroZoo metadata; "
                    "official Google Play package verification"
                ),
            }
        )

    # ========================================================
    # SAFETY CHECKS
    # ========================================================

    sha_values = [
        row["sha256"]
        for row in results
    ]

    package_values = [
        row["package_name"]
        for row in results
    ]

    if len(sha_values) != len(set(sha_values)):

        raise RuntimeError(
            "Duplicate SHA256 values detected "
            "among selected banking applications."
        )

    if (
        len(package_values)
        != len(set(package_values))
    ):

        raise RuntimeError(
            "Duplicate package names detected."
        )

    # ========================================================
    # WRITE MANIFEST
    # ========================================================

    fieldnames = [
        "cohort",
        "bank",
        "app_name",
        "package_name",
        "sha256",
        "sha1",
        "md5",
        "vercode",
        "apk_size",
        "dex_size",
        "vt_detection",
        "vt_scan_date",
        "added",
        "markets",
        "selection_rule",
        "source",
    ]

    with MANIFEST.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()

        writer.writerows(results)

    # ========================================================
    # WRITE SUMMARY
    # ========================================================

    summary_lines = []

    summary_lines.append(
        "=" * 90
    )

    summary_lines.append(
        "SPECTRE MODULE 2 — "
        "LEGITIMATE BANKING MANIFEST"
    )

    summary_lines.append(
        "=" * 90
    )

    summary_lines.append("")

    summary_lines.append(
        f"Metadata rows processed: "
        f"{processed:,}"
    )

    summary_lines.append(
        f"Invalid rows encountered: "
        f"{invalid_rows:,}"
    )

    summary_lines.append("")

    summary_lines.append(
        f"Requested banking apps: "
        f"{len(BANKING_APPS)}"
    )

    summary_lines.append(
        f"Found with Play + VT=0: "
        f"{len(results)}"
    )

    summary_lines.append(
        f"Missing with required criteria: "
        f"{len(missing_apps)}"
    )

    summary_lines.append("")

    summary_lines.append(
        "Qualification rule:"
    )

    summary_lines.append(
        "  exact package match"
    )

    summary_lines.append(
        "  markets contains play.google.com"
    )

    summary_lines.append(
        "  vt_detection = 0"
    )

    summary_lines.append(
        "  latest added record selected"
    )

    summary_lines.append("")

    summary_lines.append(
        "FOUND:"
    )

    for row in results:

        summary_lines.append(
            f"{row['bank']} | "
            f"{row['app_name']} | "
            f"{row['package_name']} | "
            f"SHA256={row['sha256']} | "
            f"VT={row['vt_detection']} | "
            f"vercode={row['vercode']} | "
            f"added={row['added']}"
        )

    if missing_apps:

        summary_lines.append("")
        summary_lines.append(
            "MISSING:"
        )

        for (
            bank,
            app_name,
            package_name,
        ) in missing_apps:

            summary_lines.append(
                f"{bank} | "
                f"{app_name} | "
                f"{package_name} | "
                f"package_rows="
                f"{package_seen[package_name]:,} | "
                f"play_rows="
                f"{play_seen[package_name]:,} | "
                f"VT0_rows="
                f"{vt0_seen[package_name]:,}"
            )

    summary_lines.append("")
    summary_lines.append(
        f"Manifest: {MANIFEST}"
    )

    summary_lines.append("")
    summary_lines.append(
        "No APKs were downloaded by this script."
    )

    SUMMARY.write_text(
        "\n".join(summary_lines),
        encoding="utf-8",
    )

    # ========================================================
    # FINAL TERMINAL OUTPUT
    # ========================================================

    print()
    print("=" * 90)
    print("BANKING MANIFEST BUILD COMPLETE")
    print("=" * 90)
    print()

    print(
        f"Requested : {len(BANKING_APPS)}"
    )

    print(
        f"Found     : {len(results)}"
    )

    print(
        f"Missing   : {len(missing_apps)}"
    )

    print()

    print(
        "Manifest:"
    )

    print(MANIFEST)

    print()

    print(
        "Summary:"
    )

    print(SUMMARY)

    if missing_apps:

        print()
        print(
            "Some banking applications were not "
            "found with the required Play + VT=0 criteria."
        )

        print(
            "Review the MISSING diagnostics before "
            "we select replacements."
        )


if __name__ == "__main__":
    main()