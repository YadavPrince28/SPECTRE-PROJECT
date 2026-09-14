import csv
import gzip
from collections import Counter
from pathlib import Path

CSV_GZ = Path(
    r"D:\Spectre_BOI_project\SPECTRE\data\androzoo\latest_with-added-date.csv.gz"
)


def detection_bucket(value: str) -> str:
    try:
        n = int(value)
    except ValueError:
        return "invalid"

    if n == 0:
        return "0"
    if n == 1:
        return "1"
    if 2 <= n <= 4:
        return "2-4"
    if 5 <= n <= 9:
        return "5-9"
    if 10 <= n <= 19:
        return "10-19"
    if 20 <= n <= 49:
        return "20-49"
    if 50 <= n <= 69:
        return "50-69"
    if n >= 70:
        return "70+"

    return "other"


def main():
    if not CSV_GZ.exists():
        raise FileNotFoundError(
            f"File not found:\n{CSV_GZ}"
        )

    total = 0

    detection_counts = Counter()
    buckets = Counter()
    markets = Counter()

    android_play = 0
    with_play = 0

    print("=" * 90)
    print("ANDROZOO METADATA ANALYSIS")
    print("=" * 90)
    print(f"File: {CSV_GZ}")
    print()

    with gzip.open(
        CSV_GZ,
        "rt",
        encoding="utf-8",
        newline="",
        errors="replace",
    ) as f:

        reader = csv.DictReader(f)

        print("Columns:")
        print(reader.fieldnames)
        print()

        for row in reader:

            total += 1

            # ---------------------------------------------------------
            # VT detection
            # ---------------------------------------------------------

            vt = row.get(
                "vt_detection",
                "",
            ).strip()

            try:
                vt_value = int(vt)
                detection_counts[vt_value] += 1
                buckets[
                    detection_bucket(vt)
                ] += 1
            except ValueError:
                buckets["invalid"] += 1

            # ---------------------------------------------------------
            # Markets
            # ---------------------------------------------------------

            market_field = row.get(
                "markets",
                "",
            ).strip()

            if market_field:

                for market in market_field.split("|"):

                    market = market.strip()

                    if market:
                        markets[market] += 1

                if "play.google.com" in market_field:
                    with_play += 1

            # ---------------------------------------------------------
            # Package check
            # ---------------------------------------------------------

            pkg = row.get(
                "pkg_name",
                "",
            ).strip()

            if pkg.startswith("com.android."):
                android_play += 1

            # ---------------------------------------------------------
            # Progress
            # ---------------------------------------------------------

            if total % 5_000_000 == 0:
                print(
                    f"Processed {total:,} rows...",
                    flush=True,
                )

    print()
    print("=" * 90)
    print("RESULTS")
    print("=" * 90)

    print()
    print(
        f"Total metadata rows: {total:,}"
    )

    print()
    print("VT DETECTION BUCKETS")
    print("-" * 90)

    for bucket in (
        "0",
        "1",
        "2-4",
        "5-9",
        "10-19",
        "20-49",
        "50-69",
        "70+",
        "invalid",
    ):

        count = buckets[bucket]

        percentage = (
            count / total * 100
            if total
            else 0
        )

        print(
            f"{bucket:>8} : "
            f"{count:>12,} "
            f"({percentage:>7.3f}%)"
        )

    print()
    print("MOST COMMON EXACT VT DETECTION VALUES")
    print("-" * 90)

    for value, count in detection_counts.most_common(30):

        percentage = (
            count / total * 100
            if total
            else 0
        )

        print(
            f"{value:>4} detections : "
            f"{count:>12,} "
            f"({percentage:>7.3f}%)"
        )

    print()
    print("MARKET INFORMATION")
    print("-" * 90)

    print(
        f"Rows mentioning play.google.com: "
        f"{with_play:,}"
    )

    print()
    print("TOP 30 MARKETS")

    for market, count in markets.most_common(30):

        percentage = (
            count / total * 100
            if total
            else 0
        )

        print(
            f"{market:<30} "
            f"{count:>12,} "
            f"({percentage:>7.3f}%)"
        )

    print()
    print("=" * 90)
    print("ANALYSIS COMPLETE")
    print("=" * 90)


if __name__ == "__main__":
    main()