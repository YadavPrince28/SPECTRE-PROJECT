import argparse
import hashlib
import os
import sys
from pathlib import Path

import requests


# ============================================================
# CONFIG
# ============================================================

ANDROZOO_URL = "https://androzoo.uni.lu/api/download"

DEFAULT_OUTPUT_DIR = (
    Path(r"D:\Spectre_BOI_project\SPECTRE\data\androzoo\apks")
)


# ============================================================
# SHA256 VALIDATION
# ============================================================

def validate_sha256(sha256: str) -> str:

    sha256 = sha256.strip().lower()

    if len(sha256) != 64:

        raise ValueError(
            "SHA256 must contain exactly 64 hexadecimal characters."
        )

    try:
        int(sha256, 16)
    except ValueError as exc:
        raise ValueError(
            "SHA256 contains invalid hexadecimal characters."
        ) from exc

    return sha256


# ============================================================
# FILE SHA256
# ============================================================

def calculate_sha256(path: Path) -> str:

    digest = hashlib.sha256()

    with path.open("rb") as f:

        while True:

            chunk = f.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest().lower()


# ============================================================
# DOWNLOAD
# ============================================================

def download_apk(
    sha256: str,
    output_dir: Path,
    api_key: str,
):

    sha256 = validate_sha256(
        sha256
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path = (
        output_dir /
        f"{sha256}.apk"
    )

    # --------------------------------------------------------
    # Avoid downloading an APK that is already verified.
    # --------------------------------------------------------

    if output_path.exists():

        print(
            f"File already exists:\n"
            f"{output_path}"
        )

        print(
            "\nVerifying existing file..."
        )

        existing_hash = calculate_sha256(
            output_path
        )

        if existing_hash == sha256:

            print(
                "SHA256 verification: PASS"
            )

            return output_path

        print(
            "Existing file has wrong SHA256."
        )

        print(
            "Deleting corrupted/incomplete file..."
        )

        output_path.unlink()

    # --------------------------------------------------------
    # Temporary file
    # --------------------------------------------------------

    temp_path = output_dir / (
        f".{sha256}.part"
    )

    if temp_path.exists():

        temp_path.unlink()

    # --------------------------------------------------------
    # API request
    # --------------------------------------------------------

    print(
        "\nRequesting APK from AndroZoo..."
    )

    print(
        f"SHA256: {sha256}"
    )

    params = {
        "apikey": api_key,
        "sha256": sha256,
    }

    try:

        with requests.get(
            ANDROZOO_URL,
            params=params,
            stream=True,
            timeout=(30, 300),
            allow_redirects=True,
        ) as response:

            print(
                f"HTTP status: "
                f"{response.status_code}"
            )

            response.raise_for_status()

            content_length = response.headers.get(
                "Content-Length"
            )

            if content_length:

                print(
                    f"Download size: "
                    f"{int(content_length):,} bytes"
                )

            print(
                "\nDownloading..."
            )

            downloaded = 0

            with temp_path.open(
                "wb"
            ) as f:

                for chunk in response.iter_content(
                    chunk_size=1024 * 1024
                ):

                    if not chunk:
                        continue

                    f.write(chunk)

                    downloaded += len(chunk)

                    if (
                        content_length
                        and downloaded % (
                            10 * 1024 * 1024
                        ) < len(chunk)
                    ):

                        percent = (
                            downloaded
                            /
                            int(content_length)
                            * 100
                        )

                        print(
                            f"  {percent:6.2f}% "
                            f"({downloaded:,} bytes)",
                            flush=True
                        )

        print(
            f"\nDownloaded: "
            f"{downloaded:,} bytes"
        )

    except requests.RequestException as exc:

        if temp_path.exists():
            temp_path.unlink()

        raise RuntimeError(
            f"AndroZoo download request failed: {exc}"
        ) from exc

    # --------------------------------------------------------
    # Verify SHA256
    # --------------------------------------------------------

    print(
        "\nVerifying SHA256..."
    )

    actual_hash = calculate_sha256(
        temp_path
    )

    print(
        f"Expected: {sha256}"
    )

    print(
        f"Actual:   {actual_hash}"
    )

    if actual_hash != sha256:

        temp_path.unlink()

        raise RuntimeError(
            "\nSHA256 verification FAILED.\n"
            "The downloaded file was not saved."
        )

    # --------------------------------------------------------
    # Finalize
    # --------------------------------------------------------

    temp_path.replace(
        output_path
    )

    print(
        "\nSHA256 verification: PASS"
    )

    print(
        "APK saved:"
    )

    print(
        output_path
    )

    return output_path


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Download a specific APK from AndroZoo "
            "using its SHA256."
        )
    )

    parser.add_argument(
        "sha256",
        help="SHA256 hash of the APK to download."
    )

    parser.add_argument(
        "--output-dir",
        default=str(
            DEFAULT_OUTPUT_DIR
        ),
        help=(
            "Directory in which to save the APK."
        ),
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # API key
    # --------------------------------------------------------

    api_key = os.environ.get(
        "ANDROZOO_API_KEY"
    )

    if not api_key:

        print(
            "ERROR: ANDROZOO_API_KEY is not set."
        )

        print(
            "\nPowerShell:"
        )

        print(
            '  $env:ANDROZOO_API_KEY="YOUR_NEW_KEY"'
        )

        print(
            "\nDo not put your API key directly "
            "inside this Python file."
        )

        sys.exit(1)

    try:

        download_apk(
            sha256=args.sha256,
            output_dir=Path(
                args.output_dir
            ),
            api_key=api_key,
        )

    except Exception as exc:

        print(
            f"\nERROR:\n{exc}"
        )

        sys.exit(1)


if __name__ == "__main__":

    main()