import os
import sys
import json
import time
import subprocess
from pathlib import Path
from datetime import datetime

import requests

BASE = "http://127.0.0.1:8000"
API_KEY = os.environ.get("MOBSF_API_KEY")

DEVICE = "emulator-5554"
IDENTIFIER = "host.docker.internal:5555"
SCAN_HASH = "4cbdb154c9c0df17b912a8e3156ca7ac"
PACKAGE_FALLBACK = "com.tailoredapps"

OBSERVATION_SECONDS = 90
MONKEY_EVENTS = 30

OUT = Path("reports") / "mobsf_dynamic_test" / SCAN_HASH
OUT.mkdir(parents=True, exist_ok=True)

if not API_KEY:
    sys.exit("ERROR: MOBSF_API_KEY is not set.")

s = requests.Session()
s.trust_env = False
s.headers.update({"Authorization": API_KEY})

started = False
report_saved = False
package = PACKAGE_FALLBACK
error_message = None

def save_json(name, data):
    (OUT / name).write_text(
        json.dumps(data, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

def adb(args, timeout=60, check=True):
    result = subprocess.run(
        ["adb", "-s", DEVICE] + args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout
    )

    # Preserve arbitrary Android output without Windows cp1252 errors.
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")

    if stdout.strip():
        print(stdout[-1200:])
    if result.returncode != 0:
        print(stderr[-1200:])
        if check:
            raise RuntimeError(
                "ADB command failed: " + " ".join(args)
            )
    return result.returncode, stdout, stderr

def api_post(endpoint, data, timeout=180):
    r = s.post(BASE + endpoint, data=data, timeout=timeout)
    try:
        payload = r.json()
    except ValueError:
        payload = {"response_text": r.text[:3000]}

    save_json(endpoint.rsplit("/", 1)[-1] + "_response.json", payload)
    print(f"{endpoint}: HTTP {r.status_code}")

    if not r.ok or (
        isinstance(payload, dict) and "error" in payload
    ):
        raise RuntimeError(
            f"MobSF API error at {endpoint}: {payload}"
        )
    return payload

try:
    # Confirm the expected emulator is connected.
    rc, devices, _ = adb(["devices"], check=False)
    print("=== ADB devices ===")
    print(devices)

    if not any(
        line.startswith(DEVICE + "\tdevice")
        for line in devices.splitlines()
    ):
        raise RuntimeError(
            f"{DEVICE} is not connected/authorized. "
            "No dynamic session started."
        )

    # Start MobSF with explicit authorization for replacement.
    # WARNING: this can uninstall the existing app and erase its data.
    print("\n=== Starting MobSF dynamic analysis ===")
    start = api_post(
        "/api/v1/dynamic/start_analysis",
        {
            "hash": SCAN_HASH,
            "re_install": "1",
            "install": "1",
            "device_mode": "auto",
            "identifier": IDENTIFIER,
            "uninstall_existing": "1"
        },
        timeout=300
    )

    package = start.get("package") or PACKAGE_FALLBACK
    started = True
    save_json("start_analysis_result.json", start)
    print("Package:", package)
    print("MobSF response:", json.dumps(start, indent=2)[:2500])

    # Verify the app is installed after MobSF prepares it.
    rc, installed, _ = adb(
        ["shell", "pm", "path", package],
        timeout=30,
        check=False
    )
    if rc != 0 or "package:" not in installed:
        raise RuntimeError(
            f"{package} is not installed after MobSF preparation."
        )

    # Launch the app and produce a small number of UI events.
    print("\n=== Launching application ===")
    rc, monkey_out, monkey_err = adb(
        [
            "shell", "monkey",
            "-p", package,
            "--pct-syskeys", "0",
            str(MONKEY_EVENTS)
        ],
        timeout=120,
        check=False
    )
    (OUT / "monkey_output.txt").write_text(
        monkey_out + "\n" + monkey_err,
        encoding="utf-8"
    )
    if rc != 0:
        raise RuntimeError("Monkey launch/event generation failed.")

    print(f"\nObserving for {OBSERVATION_SECONDS} seconds...")
    time.sleep(OBSERVATION_SECONDS)

except Exception as exc:
    error_message = str(exc)
    print("\nRUN ERROR:", error_message)

finally:
    # Save logcat as raw bytes, avoiding Windows encoding failures.
    try:
        result = subprocess.run(
            ["adb", "-s", DEVICE, "logcat", "-d", "-v", "threadtime"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=90
        )
        (OUT / "logcat.txt").write_bytes(result.stdout)
        (OUT / "logcat_stderr.txt").write_bytes(result.stderr)
        print("\nSaved logcat:", OUT / "logcat.txt")
    except Exception as exc:
        print("WARNING: Logcat collection failed:", repr(exc))

    if started:
        try:
            print("\n=== Stopping MobSF dynamic session ===")
            api_post(
                "/api/v1/dynamic/stop_analysis",
                {"hash": SCAN_HASH},
                timeout=180
            )

            print("\n=== Requesting dynamic JSON report ===")
            r = s.post(
                BASE + "/api/v1/dynamic/report_json",
                data={"hash": SCAN_HASH},
                timeout=180
            )
            try:
                report = r.json()
            except ValueError:
                report = {"response_text": r.text[:5000]}

            if r.ok and not (
                isinstance(report, dict) and "error" in report
            ):
                save_json("dynamic_report.json", report)
                report_saved = True
                print("DYNAMIC REPORT SAVED:", OUT / "dynamic_report.json")
            else:
                save_json("report_error.json", report)
                print("Report retrieval failed:", r.status_code)
                print(json.dumps(report, indent=2)[:2500])

        except Exception as exc:
            message = "Stop/report error: " + str(exc)
            error_message = (
                error_message + " | " + message
                if error_message else message
            )
            print("WARNING:", repr(exc))

    summary = {
        "timestamp": datetime.now().isoformat(),
        "scan_hash": SCAN_HASH,
        "package": package,
        "device": DEVICE,
        "mobsf_identifier": IDENTIFIER,
        "observation_seconds": OBSERVATION_SECONDS,
        "monkey_events": MONKEY_EVENTS,
        "dynamic_session_started": started,
        "dynamic_report_saved": report_saved,
        "error": error_message,
        "output_directory": str(OUT.resolve())
    }
    save_json("run_summary.json", summary)
    print("\n=== RUN SUMMARY ===")
    print(json.dumps(summary, indent=2))
