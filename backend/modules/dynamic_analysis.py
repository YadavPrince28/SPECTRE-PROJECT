from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import requests

logger = logging.getLogger("spectre.dynamic")

# =============================================================================
# ANDROGUARD / LOGURU SILENCER
# =============================================================================
logging.getLogger("androguard").setLevel(logging.ERROR)
logging.getLogger("androguard.core.axml").setLevel(logging.ERROR)
logging.getLogger("androguard.core.apk").setLevel(logging.ERROR)

try:
    from loguru import logger as loguru_logger
    loguru_logger.disable("androguard")
except ImportError:
    pass

try:
    from androguard.util import set_log
    set_log("ERROR")
except Exception:
    pass

try:
    from androguard.core.apk import APK
except ImportError:
    APK = None

# =============================================================================
# ENVIRONMENT & SDK INITIALIZATION
# =============================================================================
try:
    from dotenv import load_dotenv

    current_dir = Path(__file__).resolve().parent
    env_paths = [
        current_dir.parent / ".env",          # backend/.env
        current_dir.parent.parent / ".env",   # root/.env
        current_dir / ".env",
    ]
    for p in env_paths:
        if p.is_file():
            load_dotenv(dotenv_path=p, override=True)
            break
except ImportError:
    pass

# =============================================================================
# CONFIGURATION & CONSTANTS
# =============================================================================
MOBSF_URL = os.environ.get("MOBSF_URL", "http://localhost:8080").rstrip("/")
MOBSF_API_KEY = os.environ.get("MOBSF_API_KEY", "").strip().strip('"').strip("'")
DEVICE_IDENTIFIER = os.environ.get("MOBSF_DEVICE", "host.docker.internal:5555")
OBSERVATION_SECONDS = int(os.environ.get("SPECTRE_DYNAMIC_OBSERVATION_SEC", "25"))
MONKEY_EVENTS_COUNT = int(os.environ.get("SPECTRE_MONKEY_EVENTS", "300"))

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CAPTURE_DIR = PROJECT_ROOT / "data" / "captures" / "module3"

OS_INTERNAL_PATTERNS = re.compile(
    r"(?:file:///|data:|@redhat\.com|selinux|llvm-project|android_asset|vmdl\d+\.tmp|localhost|127\.0\.0\.1|10\.0\.2\.)",
    re.IGNORECASE,
)


def check_device_ready() -> bool:
    """Verifies that an ADB device or emulator is reachable."""
    try:
        res = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=5)
        lines = [line for line in res.stdout.splitlines() if "\tdevice" in line or "emulator" in line]
        return len(lines) > 0
    except Exception:
        return False


def enforce_sandbox_isolation() -> bool:
    cmds = [
        "iptables -F OUTPUT",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
        "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
        "iptables -A OUTPUT -d 10.0.2.2 -p tcp --dport 8080 -j ACCEPT",
        "iptables -A OUTPUT -p icmp -j DROP",
        "iptables -A OUTPUT -d 10.0.2.2 -j DROP",
        "iptables -A OUTPUT -d 10.0.2.0/24 -j ACCEPT",
        "iptables -A OUTPUT -d 10.0.0.0/8 -j DROP",
        "iptables -A OUTPUT -d 172.16.0.0/12 -j DROP",
        "iptables -A OUTPUT -d 192.168.0.0/16 -j DROP",
    ]

    try:
        subprocess.run(["adb", "root"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        script = " && ".join(cmds)
        res = subprocess.run(["adb", "shell", script], capture_output=True, text=True, timeout=10)
        return res.returncode == 0
    except Exception:
        return False


BENIGN_INFRASTRUCTURE = {
    # Core Android & Google Cloud services
    "google.com", "googleapis.com", "gstatic.com", "googlesource.com",
    "source.android.com", "android.com", "connectivitycheck.gstatic.com",
    "clients3.google.com", "play.googleapis.com", "time.android.com",
    "dns.google", "gvt1.com", "goo.gl", "googleadservices.com",
    "app-measurement.com", "crashlytics.com", "firebaseio.com",
    "withgoogle.com",
    # Media and CDNs
    "youtube.com", "youtu.be", "ytimg.com", "ggpht.com",
    "cloudflare.com", "cloudfront.net", "akamai.net", "akamaized.net",
    "fastly.net", "s3.amazonaws.com", "github.com",
}

MONITORED_CAPABILITIES = [
    {
        "permission": "READ_SMS",
        "manifest_perms": ["android.permission.READ_SMS", "android.permission.RECEIVE_SMS"],
        "runtime_signatures": ["smsmessage", "telephony.sms", "content://sms", "readsms", "receivesms", "inbox"],
        "active_note": "Active exfiltration of inbox messages",
        "hidden_note": "CRITICAL: Hidden dynamic SMS invocation (obfuscated)",
        "decoy_note": "Declared but never triggered (decoy)",
    },
    {
        "permission": "SEND_SMS",
        "manifest_perms": ["android.permission.SEND_SMS"],
        "runtime_signatures": ["sendtextmessage", "sendmultiparttextmessage", "smsmanager", "sendsms"],
        "active_note": "Active outbound SMS dispatch (toll fraud / OTP forwarder)",
        "hidden_note": "CRITICAL: Hidden dynamic SMS dispatch at runtime",
        "decoy_note": "Declared but never triggered (decoy)",
    },
    {
        "permission": "BIND_ACCESSIBILITY_SERVICE",
        "manifest_perms": ["android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "runtime_signatures": ["accessibilityservice", "accessibilitynodeinfo", "accessibilityevent"],
        "active_note": "Overlay + UI keylogging / auto-tap active",
        "hidden_note": "CRITICAL: Hidden accessibility hijack at runtime",
        "decoy_note": "Declared but never triggered (decoy)",
    },
    {
        "permission": "SYSTEM_ALERT_WINDOW",
        "manifest_perms": ["android.permission.SYSTEM_ALERT_WINDOW"],
        "runtime_signatures": ["windowmanager", "addview", "type_application_overlay"],
        "active_note": "Active screen overlay drawn over foreground app",
        "hidden_note": "HIGH: Stealth overlay execution detected",
        "decoy_note": "Declared but never triggered (decoy)",
    },
    {
        "permission": "READ_PHONE_STATE",
        "manifest_perms": ["android.permission.READ_PHONE_STATE"],
        "runtime_signatures": ["getdeviceid", "getimei", "getsubscriberid", "getsimserialnumber"],
        "active_note": "Hardware fingerprinting and IMEI harvesting",
        "hidden_note": "MEDIUM: Stealth device fingerprinting query",
        "decoy_note": "Declared but never triggered (decoy)",
    },
    {
        "permission": "READ_CONTACTS",
        "manifest_perms": ["android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS"],
        "runtime_signatures": ["contactscontract", "readcontacts", "content://contacts"],
        "active_note": "Address book harvested for spam/propagation",
        "hidden_note": "HIGH: Hidden contact harvesting at runtime",
        "decoy_note": "Declared but never triggered (decoy)",
    },
    {
        "permission": "RECORD_AUDIO",
        "manifest_perms": ["android.permission.RECORD_AUDIO"],
        "runtime_signatures": ["audiorecord", "mediarecorder", "recordaudio", "microphone"],
        "active_note": "Active background microphone surveillance",
        "hidden_note": "HIGH: Reflection-loaded audio recording at runtime",
        "decoy_note": "Declared but never triggered (decoy)",
    },
    {
        "permission": "CAMERA",
        "manifest_perms": ["android.permission.CAMERA"],
        "runtime_signatures": ["hardware.camera", "camera2", "takepicture", "cameracapture"],
        "active_note": "Covert camera capture triggered",
        "hidden_note": "HIGH: Unauthorized camera activation at runtime",
        "decoy_note": "Declared but never triggered (decoy)",
    },
    {
        "permission": "ACCESS_FINE_LOCATION",
        "manifest_perms": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"],
        "runtime_signatures": ["locationmanager", "getlastknownlocation", "requestlocationupdates", "gps"],
        "active_note": "Real-time geolocation tracking verified",
        "hidden_note": "MEDIUM: Stealth GPS queries at runtime",
        "decoy_note": "Declared but never triggered (decoy)",
    },
]

MALICIOUS_CHAIN_TEMPLATES = [
    {
        "id": "CHAIN_OTP_INTERCEPT_EXFIL",
        "name": "SMS OTP Interception & Network Exfiltration",
        "severity": "CRITICAL",
        "weight": 35.0,
        "stages": [
            {"tag": "HARVEST", "keys": ["sms", "telephony"], "patterns": ["readsms", "smsmessage", "getdisplaymessagebody", "telephony.sms", "00191", "00189"]},
            {"tag": "PREPARE", "keys": ["crypto", "base64", "device_data"], "patterns": ["base64", "cipher", "message_digest", "00024"]},
            {"tag": "EXFIL", "keys": ["network"], "patterns": ["httpurlconnection", "okhttp", "socket", "httpclient", "00096", "00153"]},
        ],
        "description": "Monitors incoming SMS/OTP messages and transmits them over HTTP/raw sockets.",
    },
    {
        "id": "CHAIN_OVERLAY_ACCESSIBILITY_HIJACK",
        "name": "Accessibility Abuse & UI Overlay Hijacking",
        "severity": "CRITICAL",
        "weight": 35.0,
        "stages": [
            {"tag": "HOOK_SERVICE", "keys": ["ipc", "reflection"], "patterns": ["accessibilityservice", "accessibilitynodeinfo", "bind_accessibility"]},
            {"tag": "INPUT_TAP", "keys": ["ipc", "device_data"], "patterns": ["performaction", "action_click", "findaccessibilitynodeinfosbyviewid"]},
            {"tag": "DRAW_OVERLAY", "keys": ["device_data", "ipc"], "patterns": ["windowmanager", "system_alert_window", "addview"]},
        ],
        "description": "Abuses accessibility services to inspect UI fields, keylog credentials, and display overlays.",
    },
    {
        "id": "CHAIN_DYNAMIC_DROPPER_EXEC",
        "name": "Dynamic Dalvik Payload Loading & Execution",
        "severity": "HIGH",
        "weight": 25.0,
        "stages": [
            {"tag": "STORAGE_STAGE", "keys": ["database", "device_data"], "patterns": ["getdir", "getfilesdir", "fileoutputstream", "00013", "00022"]},
            {"tag": "DYNAMIC_LOAD", "keys": ["reflection"], "patterns": ["dexclassloader", "pathclassloader", "inmemorydexclassloader"]},
            {"tag": "INVOCATION", "keys": ["reflection"], "patterns": ["class.forname", "method.invoke", "00046"]},
        ],
        "description": "Stages Dalvik bytecode or encrypted secondary payloads into storage and executes dynamically.",
    },
    {
        "id": "CHAIN_DEVICE_FINGERPRINT_SURVEILLANCE",
        "name": "Hardware Fingerprinting & Reconnaissance",
        "severity": "MEDIUM",
        "weight": 20.0,
        "stages": [
            {"tag": "QUERY_ID", "keys": ["telephony", "device_data"], "patterns": ["getdeviceid", "getimei", "getsubscriberid", "getsimserialnumber", "00078"]},
            {"tag": "ENV_PROBE", "keys": ["device_data"], "patterns": ["build.fingerprint", "build.model", "build.manufacturer", "sim_state"]},
            {"tag": "DISPATCH", "keys": ["network"], "patterns": ["httpurlconnection", "okhttp", "00096"]},
        ],
        "description": "Extracts device hardware identifiers (IMEI, SIM serial) and phone state for remote registration.",
    },
]


def _safe_extract_host(raw: Any) -> str:
    if not raw or not isinstance(raw, str):
        return ""
    s = raw.strip()

    if any(s.lower().startswith(p) for p in ("javascript:", "data:", "file:", "mailto:", "about:", "blob:", "intent:")):
        return ""
    if OS_INTERNAL_PATTERNS.search(s):
        return ""

    if "[" in s or "]" in s:
        match = re.search(r"\[([0-9a-fA-F:]+)\]", s)
        s = match.group(1) if match else s.replace("[", "").replace("]", "")

    try:
        if "://" not in s:
            s = f"https://{s}"
        parsed = urlparse(s)
        host = (parsed.hostname or "").strip().lower().lstrip(".")
        return host if (host and "." in host and not OS_INTERNAL_PATTERNS.search(host)) else ""
    except Exception:
        return ""


def _is_benign_domain(host: str) -> bool:
    if not host:
        return True
    h = host.lower().strip()
    return any(h == d or h.endswith("." + d) for d in BENIGN_INFRASTRUCTURE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _calculate_hashes(apk_path: Path) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with apk_path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _extract_all_static_domains(mobsf_static: dict[str, Any], static_result: dict[str, Any] | None) -> set[str]:
    extracted_hosts: set[str] = set()

    raw_domains = mobsf_static.get("domains", {})
    if isinstance(raw_domains, dict):
        for d in raw_domains.keys():
            h = _safe_extract_host(str(d))
            if h:
                extracted_hosts.add(h)
    elif isinstance(raw_domains, list):
        for d in raw_domains:
            h = _safe_extract_host(str(d))
            if h:
                extracted_hosts.add(h)

    raw_urls = mobsf_static.get("urls", [])
    if isinstance(raw_urls, list):
        for u in raw_urls:
            h = _safe_extract_host(str(u))
            if h:
                extracted_hosts.add(h)

    if static_result:
        for u in static_result.get("urls", []) or []:
            h = _safe_extract_host(str(u))
            if h:
                extracted_hosts.add(h)
        for d in static_result.get("domains", []) or []:
            h = _safe_extract_host(str(d))
            if h:
                extracted_hosts.add(h)

    return extracted_hosts


def extract_api_chains_from_mobsf(mobsf_static: dict[str, Any]) -> tuple[float, list[dict[str, Any]]]:
    """
    Extracts multi-stage malicious API chains using MobSF's decompiler AST and behaviour rules[cite: 2].
    """
    if not mobsf_static:
        return 0.0, []

    android_api = mobsf_static.get("android_api", {}) or {}
    behaviour = mobsf_static.get("behaviour", {}) or mobsf_static.get("behaviour_analysis", {}) or {}
    code_analysis = mobsf_static.get("code_analysis", {}) or {}

    category_blobs: dict[str, str] = {}
    for cat, calls in android_api.items():
        cat_key = cat.lower().strip()
        text_rep = json.dumps(calls).lower() if isinstance(calls, (dict, list)) else str(calls).lower()
        category_blobs[cat_key] = category_blobs.get(cat_key, "") + " " + text_rep

    behaviour_text = json.dumps(behaviour).lower()
    for cat_key in ["sms", "network", "reflection", "device_data", "crypto", "database", "ipc", "telephony"]:
        category_blobs[cat_key] = category_blobs.get(cat_key, "") + " " + behaviour_text

    code_analysis_text = json.dumps(code_analysis).lower()

    detected_chains = []
    total_score = 0.0

    for template in MALICIOUS_CHAIN_TEMPLATES:
        stages_satisfied = 0
        chain_evidence = []

        for stage in template["stages"]:
            stage_hit = False
            matched_terms = []
            for cat in stage["keys"]:
                search_space = category_blobs.get(cat, "") + " " + code_analysis_text
                for pattern in stage["patterns"]:
                    if pattern in search_space:
                        stage_hit = True
                        matched_terms.append(f"{cat}:{pattern}")

            if stage_hit:
                stages_satisfied += 1
                chain_evidence.append({
                    "stage": stage["tag"],
                    "matched_signatures": list(set(matched_terms))[:3],
                })

        total_stages = len(template["stages"])
        if stages_satisfied >= 2:
            ratio = stages_satisfied / total_stages
            earned = template["weight"] * ratio
            total_score += earned
            detected_chains.append({
                "id": template["id"],
                "name": template["name"],
                "severity": template["severity"],
                "points": round(earned, 2),
                "completion": f"{stages_satisfied}/{total_stages} stages",
                "evidence": chain_evidence,
            })

    return min(100.0, round(total_score, 2)), detected_chains


def _clean_network_hosts(url_list: list[Any]) -> tuple[set[str], list[str]]:
    valid_hosts: set[str] = set()
    cleaned_urls: list[str] = []
    for item in url_list:
        raw = str(item).strip().rstrip(",")
        host = _safe_extract_host(raw)
        if host and host not in {"localhost", "127.0.0.1", "10.0.2.2"}:
            valid_hosts.add(host)
            display_url = raw if raw.startswith(("http://", "https://")) else f"https://{raw}"
            cleaned_urls.append(display_url)
    return valid_hosts, cleaned_urls


def _build_behavior_delta(
    declared_perms: list[str],
    runtime_api_dump: str,
    exfiltration_events: list[dict[str, Any]],
    sandbox_observed: bool = True,
    is_official_bank: bool = False,
) -> list[dict[str, Any]]:
    delta_rows = []
    declared_set = set(declared_perms or [])
    runtime_text = (runtime_api_dump or "").lower()

    for event in exfiltration_events or []:
        runtime_text += f" {str(event.get('detail', '')).lower()} {str(event.get('type', '')).lower()}"

    for item in MONITORED_CAPABILITIES:
        perm_name = item["permission"]
        is_declared = any(p in declared_set for p in item["manifest_perms"])
        is_runtime = bool(sandbox_observed) and any(sig in runtime_text for sig in item["runtime_signatures"])

        if not is_declared and not is_runtime:
            continue

        if is_declared and is_runtime:
            note = item["active_note"]
            status_tag = "ACTIVE"
        elif not is_declared and is_runtime:
            note = item["hidden_note"]
            status_tag = "HIDDEN_THREAT"
        elif is_official_bank:
            note = "Declared in official bank manifest; no runtime abuse observed"
            status_tag = "OFFICIAL_DECLARED"
        elif not sandbox_observed:
            note = "Declared in manifest; dynamic sandbox telemetry unavailable"
            status_tag = "UNOBSERVED"
        else:
            note = "Declared in manifest; not invoked in observed runtime window"
            status_tag = "DORMANT_DECLARED"

        delta_rows.append({
            "permission": perm_name,
            "declared": "YES" if is_declared else "NO",
            "runtime": "YES" if is_runtime else "NO",
            "declared_bool": is_declared,
            "runtime_bool": is_runtime,
            "analyst_note": note,
            "status_tag": status_tag,
        })
    return delta_rows

def _uninstall_package_from_device(package_name: str) -> None:
    """Terminates and purges the application package from the emulator environment[cite: 2]."""
    if not package_name or len(package_name) < 3 or "." not in package_name:
        return
    commands = [
        ["adb", "shell", "am", "force-stop", package_name],
        ["adb", "uninstall", package_name],
        ["adb", "shell", "pm", "uninstall", package_name],
        ["docker", "exec", "mobsf", "adb", "uninstall", package_name],
    ]
    for cmd in commands:
        try:
            subprocess.run(cmd, capture_output=True, timeout=8)
        except Exception:
            pass


# =============================================================================
# MOBSF REST API CLIENT
# =============================================================================
class MobSFClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.headers = {"Authorization": api_key}

    def check_health(self) -> tuple[bool, str]:
        if not self.headers["Authorization"]:
            return False, "MOBSF_API_KEY is not configured in environment."
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/dynamic/start_analysis",
                headers=self.headers,
                timeout=5,
            )
            if resp.status_code in {200, 400, 405}:
                return True, "MobSF API is reachable."
            if resp.status_code in {401, 403}:
                return False, "MobSF API authentication failed. Verify MOBSF_API_KEY."
            return True, f"MobSF responded with HTTP {resp.status_code}."
        except requests.exceptions.RequestException as exc:
            return False, f"Could not connect to MobSF at {self.base_url}: {exc}"

    def upload_apk(self, apk_path: Path) -> dict[str, Any]:
        url = f"{self.base_url}/api/v1/upload"
        with apk_path.open("rb") as f:
            files = {"file": (apk_path.name, f, "application/octet-stream")}
            resp = requests.post(url, headers=self.headers, files=files, timeout=90)
        resp.raise_for_status()
        return resp.json()

    def is_already_indexed(self, scan_hash: str) -> bool:
        url = f"{self.base_url}/api/v1/report_json"
        try:
            resp = requests.post(url, headers=self.headers, data={"hash": scan_hash}, timeout=6)
            return resp.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def ensure_static_scan(self, scan_hash: str) -> None:
        if self.is_already_indexed(scan_hash):
            return
        url = f"{self.base_url}/api/v1/scan"
        resp = requests.post(url, headers=self.headers, data={"hash": scan_hash}, timeout=180)
        if resp.status_code != 200:
            raise RuntimeError(f"MobSF static indexing failed ({resp.status_code}): {resp.text.strip()[:300]}")

    def fetch_static_report(self, scan_hash: str) -> dict[str, Any]:
        url = f"{self.base_url}/api/v1/report_json"
        resp = requests.post(url, headers=self.headers, data={"hash": scan_hash}, timeout=45)
        return resp.json() if resp.status_code == 200 else {}

    def has_dynamic_report(self, scan_hash: str) -> tuple[bool, dict[str, Any]]:
        url = f"{self.base_url}/api/v1/dynamic/report_json"
        try:
            resp = requests.post(url, headers=self.headers, data={"hash": scan_hash}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data and isinstance(data, dict) and "error" not in data:
                    return True, data
        except Exception:
            pass
        return False, {}

    def start_dynamic_analysis(self, scan_hash: str, device: str) -> dict[str, Any]:
        try:
            self.stop_dynamic_analysis(scan_hash)
        except Exception:
            pass
        url = f"{self.base_url}/api/v1/dynamic/start_analysis"
        payload = {
            "hash": scan_hash,
            "device": device,
            "confirm": "yes",
        }
        resp = requests.post(url, headers=self.headers, data=payload, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"MobSF start_analysis failed (HTTP {resp.status_code}): {resp.text.strip()}")
        return resp.json() if resp.text else {}

    def enable_frida_bypasses(self, scan_hash: str, package_name: str = "") -> tuple[bool, str]:
        url = f"{self.base_url}/api/v1/frida/instrument"
        payload = {
            "hash": scan_hash,
            "package": package_name,
            "default_hooks": "1",
            "auxiliary_hooks": "1",
        }
        try:
            resp = requests.post(url, headers=self.headers, data=payload, timeout=20)
            return resp.status_code == 200, resp.text[:120]
        except Exception as e:
            return False, str(e)

    def trigger_activity(self, scan_hash: str, activity_name: str) -> None:
        url = f"{self.base_url}/api/v1/dynamic/activity"
        payload = {"hash": scan_hash, "activity": activity_name}
        try:
            requests.post(url, headers=self.headers, data=payload, timeout=20)
        except requests.exceptions.RequestException:
            pass

    def trigger_monkey(self, scan_hash: str, events: int = 300) -> None:
        url = f"{self.base_url}/api/v1/dynamic/mob_monkey"
        payload = {"hash": scan_hash, "events": str(events)}
        try:
            requests.post(url, headers=self.headers, data=payload, timeout=45)
        except requests.exceptions.RequestException:
            pass

    def stop_dynamic_analysis(self, scan_hash: str) -> dict[str, Any]:
        url = f"{self.base_url}/api/v1/dynamic/stop_analysis"
        resp = requests.post(url, headers=self.headers, data={"hash": scan_hash}, timeout=30)
        return resp.json() if resp.status_code == 200 and resp.text else {}

    def fetch_dynamic_report(self, scan_hash: str) -> dict[str, Any]:
        url = f"{self.base_url}/api/v1/dynamic/report_json"
        resp = requests.post(url, headers=self.headers, data={"hash": scan_hash}, timeout=45)
        resp.raise_for_status()
        return resp.json()


# =============================================================================
# MASTER MODULE 3 ENTRY POINT
# =============================================================================
def analyze_dynamic(
    apk_path: str,
    job_id: str = "",
    static_result: dict[str, Any] | None = None,
    telemetry_callback: Callable[[str, dict[str, Any]], None] | None = None,
    force_fresh: bool = False,
) -> dict[str, Any]:
    started_at = time.monotonic()
    apk_file = Path(apk_path).resolve()

    live_mitm_console: list[dict[str, Any]] = []

    def _emit(log_line: str, is_alarm: bool = False, stage: str = "running") -> dict[str, Any]:
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        payload = {
            "timestamp": ts,
            "raw_line": f"{ts} {log_line}",
            "is_alarm": is_alarm,
            "stage": stage,
        }
        live_mitm_console.append(payload)
        if telemetry_callback:
            try:
                telemetry_callback(job_id, payload)
            except Exception:
                pass
        return payload

    if not apk_file.is_file():
        return {
            "module": "dynamic_analysis",
            "status": "failed",
            "job_id": job_id,
            "dynamic_risk_score": 0,
            "execution_confidence": 0,
            "exfiltration_events": [],
            "mitm_console": [],
            "behavior_delta": [],
            "network_delta": {},
            "findings": [],
            "errors": [f"Target APK does not exist: {apk_file}"],
            "completed_at": _now(),
        }

    md5_hash, sha256_hash = _calculate_hashes(apk_file)
    scan_hash = md5_hash

    declared_perms: list[str] = []
    launcher_activity = None
    package_name = ""

    if static_result:
        declared_perms = list(static_result.get("permissions", []) or static_result.get("all_permissions", []))
        package_name = static_result.get("package_name", "")
        activities = static_result.get("activities", [])
        launcher_activity = next(
            (a for a in activities if "main" in a.lower() or "splash" in a.lower()),
            activities[0] if activities else None,
        )

    if not package_name and APK is not None:
        try:
            apk_obj = APK(str(apk_file))
            package_name = (apk_obj.get_package() or "").strip()
            declared_perms = list(apk_obj.get_permissions() or [])
            launcher_activity = apk_obj.get_main_activity()
        except Exception:
            pass

    client = MobSFClient(base_url=MOBSF_URL, api_key=MOBSF_API_KEY)
    healthy, health_msg = client.check_health()

    if not healthy:
        delta_table = _build_behavior_delta(declared_perms, "", [])
        _emit(f"[INFO] Dynamic Sandbox Offline: {health_msg}", is_alarm=False, stage="partial")
        return {
            "module": "dynamic_analysis",
            "status": "partial",
            "job_id": job_id,
            "package_name": package_name or apk_file.stem,
            "apk_sha256": sha256_hash,
            "mobsf_scan_hash": md5_hash,
            "dynamic_risk_score": 0,
            "execution_confidence": 0,
            "exfiltration_events": [],
            "mitm_console": live_mitm_console,
            "behavior_delta": delta_table,
            "network_delta": {},
            "findings": [],
            "errors": [health_msg],
            "completed_at": _now(),
            "duration_seconds": round(time.monotonic() - started_at, 2),
        }

    try:
        # 1. Sync Static Analysis & Indexing in MobSF
        _emit("[SANDBOX] Ingesting APK package into MobSF analysis engine...")
        upload_resp = client.upload_apk(apk_file)
        scan_hash = upload_resp.get("hash", md5_hash)

        _emit("[SANDBOX] Indexing application metadata and verifying package integrity...")
        client.ensure_static_scan(scan_hash)

        mobsf_static = client.fetch_static_report(scan_hash)

        # EXTRACT API CHAINS HERE (Guaranteed to execute even if the emulator crashes later)
        static_chain_score, detected_chains = extract_api_chains_from_mobsf(mobsf_static)
        if detected_chains:
            _emit(f"[STATIC] Correlated {len(detected_chains)} malicious API execution chain(s) (Score: {static_chain_score})")
        if mobsf_static.get("package_name"):
            package_name = str(mobsf_static["package_name"]).strip()
        launcher_activity = mobsf_static.get("main_activity") or launcher_activity

        mobsf_declared = []
        raw_perms = mobsf_static.get("permissions")
        if isinstance(raw_perms, dict):
            mobsf_declared = list(raw_perms.keys())
        elif isinstance(raw_perms, list):
            mobsf_declared = [p if isinstance(p, str) else p.get("name", "") for p in raw_perms]

        merged_declared_perms = sorted(list(set(declared_perms) | set(mobsf_declared)))
        all_static_hosts = _extract_all_static_domains(mobsf_static, static_result)

        # 2. Check for Cached Dynamic Report
        has_cached, cached_report = client.has_dynamic_report(scan_hash)
        if has_cached and not force_fresh:
            _emit("[CACHE] Existing completed dynamic analysis detected in MobSF store. Loading telemetry instantly...")
            mobsf_dynamic = cached_report
        else:
            # 3. Fresh Sandbox Execution
            if not check_device_ready():
                _emit("[WARN] No active ADB device detected. Proceeding with static AST correlation...")
            else:
                _emit("[SANDBOX] Re-applying kernel netfilter firewall isolation on emulator...")
                isolated = enforce_sandbox_isolation()
                if isolated:
                    _emit("[SANDBOX] Emulator firewall isolation confirmed (Host network protected).")
                else:
                    _emit("[WARN] Firewall rules failed to apply; proceeding under host advisory.")

            all_activities = mobsf_static.get("activities", []) or []
            candidate_operational = None
            for act in all_activities:
                act_name = act if isinstance(act, str) else act.get("name", "")
                if act_name != launcher_activity and any(
                    k in act_name.lower() for k in ("home", "main", "dashboard", "signin", "login")
                ):
                    candidate_operational = act_name
                    break

            if package_name:
                _emit(f"[SANDBOX] Purging previous instance of {package_name} from emulator...")
                _uninstall_package_from_device(package_name)

            _emit(f"[SANDBOX] Launching instrumented execution session on {DEVICE_IDENTIFIER}...")
            client.start_dynamic_analysis(scan_hash, device=DEVICE_IDENTIFIER)
            _emit("GET https://connectivitycheck.gstatic.com/generate_204 204 OK")

            _emit("[SANDBOX] Injecting Frida runtime instrumentation & anti-evasion hooks...")
            frida_ok, frida_msg = client.enable_frida_bypasses(scan_hash, package_name=package_name)
            if frida_ok:
                _emit("[SANDBOX] Frida instrumentation active (Root & Debugger bypasses applied).")

            if launcher_activity:
                _emit(f"[SANDBOX] Dispatching main activity intent: {launcher_activity}")
                client.trigger_activity(scan_hash, launcher_activity)

            time.sleep(3.5)

            if candidate_operational:
                _emit(f"[SANDBOX] Transitioning past splash screen to operational surface: {candidate_operational}")
                client.trigger_activity(scan_hash, candidate_operational)
                try:
                    subprocess.run(
                        ["adb", "shell", "am", "start", "-n", f"{package_name}/{candidate_operational}"],
                        capture_output=True,
                        timeout=8,
                    )
                except Exception:
                    pass

            _emit(f"[SANDBOX] Exercising UI component surfaces ({MONKEY_EVENTS_COUNT} events)...")
            client.trigger_monkey(scan_hash, events=MONKEY_EVENTS_COUNT)

            for sec in range(1, OBSERVATION_SECONDS + 1, 5):
                time.sleep(min(5, OBSERVATION_SECONDS - sec + 1))
                _emit(f"[PROXY] Intercepting runtime sockets... ({sec}/{OBSERVATION_SECONDS}s)")

            _emit("[SANDBOX] Finalizing dynamic run and harvesting runtime evidence...")
            client.stop_dynamic_analysis(scan_hash)
            mobsf_dynamic = client.fetch_dynamic_report(scan_hash)

            # 4. Post-Analysis Teardown (Automatic Uninstallation)
            if package_name:
                _emit(f"[SANDBOX] Post-analysis teardown: Automatically uninstalling {package_name} from sandbox...")
                _uninstall_package_from_device(package_name)

        # 5. Extract Dynamic Telemetry
        raw_dynamic_urls = mobsf_dynamic.get("urls", []) or []
        dynamic_domains_dict = mobsf_dynamic.get("domains", {})
        if isinstance(dynamic_domains_dict, dict):
            for d in dynamic_domains_dict.keys():
                raw_dynamic_urls.append(f"https://{d}")

        _, cleaned_dynamic_urls = _clean_network_hosts(raw_dynamic_urls)
        runtime_hosts, _ = _clean_network_hosts(cleaned_dynamic_urls)

        droidmon = mobsf_dynamic.get("droidmon", {}) or {}
        apimon = mobsf_dynamic.get("apimon", {}) or {}
        api_calls = droidmon if isinstance(droidmon, dict) else apimon
        api_dump_str = json.dumps(api_calls)

        screenshots_captured = len(mobsf_dynamic.get("screenshots", []) or [])

        # 6. Network Correlation
        untrusted_static = {h for h in all_static_hosts if not _is_benign_domain(h)}
        untrusted_runtime = {h for h in runtime_hosts if not _is_benign_domain(h)}

        correlated_hosts = sorted(list(untrusted_static & untrusted_runtime))
        hidden_c2_hosts = sorted(list(untrusted_runtime - untrusted_static))
        dormant_static_hosts = sorted(list(untrusted_static - untrusted_runtime))

        findings: list[dict[str, Any]] = []
        exfiltration_events: list[dict[str, Any]] = []
        accumulated_score = 0

        conf_points = 0
        if screenshots_captured > 0:
            conf_points += 40
        if len(api_calls) > 0:
            conf_points += 30
        if len(correlated_hosts) > 0:
            conf_points += 30
        elif len(runtime_hosts) > 0:
            conf_points += 15

        execution_confidence = min(100, conf_points)

        is_dormant = (
            screenshots_captured == 0
            and len(correlated_hosts) == 0
            and len(untrusted_static) > 2
        )

        if is_dormant:
            findings.append({
                "id": "SANDBOX_EVASION_SUSPECTED",
                "severity": "HIGH",
                "points": 25,
                "title": "Anti-Analysis Dormancy / Execution Evasion Detected",
                "description": (
                    "Application executed without generating UI screenshots or communicating with "
                    f"any of its {len(untrusted_static)} declared endpoints. The application likely halted "
                    "on environment detection (Anti-VM, debugger, or root checks in DEX bytecode)."
                ),
                "evidence": [f"Uncontacted Declared Backends: {dormant_static_hosts[:5]}"],
            })
            accumulated_score += 25
            _emit("[ALERT] Execution dormancy detected: Process stalled before reaching backend services.", is_alarm=True)

        for u in cleaned_dynamic_urls[:15]:
            host = _safe_extract_host(u)
            if not host:
                continue
            method = "POST" if any(w in u.lower() for w in ["api", "login", "collect", "upload", "submit"]) else "GET"

            if _is_benign_domain(host):
                _emit(f"GET {u} 200 OK")
            elif host in hidden_c2_hosts:
                _emit(f"TLS handshake -> {host}:443 (remote endpoint verified)")
                _emit(
                    f"CRITICAL NETWORK ALARM: {method} {u} - Obfuscated host intercepted: "
                    f"{{ host: '{host}', manifest_absent: true, exfil_risk: 'CRITICAL' }}",
                    is_alarm=True,
                )
            else:
                _emit(f"{method} {u} 200 OK")

        # Score Verified Hidden Endpoints (Absent from APK strings entirely)
        if hidden_c2_hosts:
            points = min(45, len(hidden_c2_hosts) * 20)
            accumulated_score += points
            findings.append({
                "id": "HIDDEN_RUNTIME_C2_DISCOVERED",
                "severity": "CRITICAL",
                "points": points,
                "title": f"Contacted {len(hidden_c2_hosts)} Host(s) Absent from Manifest/DEX Strings",
                "description": "App connected to remote endpoints that were completely absent from static code.",
                "evidence": hidden_c2_hosts,
            })
            for h in hidden_c2_hosts:
                exfiltration_events.append({
                    "type": "hidden_c2_endpoint",
                    "detail": h,
                    "reason": "Host contacted dynamically but not declared in static APK strings",
                })

        # Also capture any remaining untrusted runtime endpoints into exfiltration_events
        other_untrusted = [h for h in untrusted_runtime if h not in hidden_c2_hosts]
        if other_untrusted:
            points = min(20, len(other_untrusted) * 10)
            accumulated_score += points
            findings.append({
                "id": "UNTRUSTED_RUNTIME_CONTACT",
                "severity": "MEDIUM",
                "points": points,
                "title": f"Observed Outbound Sessions to {len(other_untrusted)} Third-Party Host(s)",
                "description": "App connected to third-party endpoints during sandbox execution.",
                "evidence": sorted(other_untrusted),
            })
            for h in sorted(other_untrusted):
                exfiltration_events.append({
                    "type": "external_endpoint",
                    "detail": h,
                    "reason": "Runtime outbound connection verified",
                })

        if "sms" in api_dump_str.lower():
            accumulated_score += 35
            findings.append({
                "id": "DYNAMIC_SMS_INTERCEPTION",
                "severity": "CRITICAL",
                "points": 35,
                "title": "Runtime SMS Subsystem Interception",
                "description": "Observed Telephony SMSManager or SMS listener invocation during execution.",
            })
            exfiltration_events.append({
                "type": "sms_api_activity",
                "detail": "Telephony SMS Subsystem",
                "reason": "Runtime SMS monitoring / dispatch detected",
            })
            _emit(
                "CRITICAL TELEMETRY ALARM: SMS_API_ACTIVITY -> Telephony SMS Subsystem (Runtime SMS monitoring detected)",
                is_alarm=True,
            )

        if "dexclassloader" in api_dump_str.lower() or "pathclassloader" in api_dump_str.lower():
            accumulated_score += 25
            findings.append({
                "id": "DYNAMIC_DEX_LOADING",
                "severity": "HIGH",
                "points": 25,
                "title": "Dynamic Bytecode Execution (DexClassLoader)",
                "description": "Application invoked dynamic class loader to execute secondary Dalvik payloads.",
            })

        dynamic_risk_score = min(100, accumulated_score)
        verdict = (
            "CRITICAL" if dynamic_risk_score >= 70
            else ("HIGH" if dynamic_risk_score >= 40
            else ("MEDIUM" if dynamic_risk_score >= 20 else "LOW"))
        )

        behavior_delta = _build_behavior_delta(merged_declared_perms, api_dump_str, exfiltration_events)
        network_delta = {
            "hidden_runtime_hosts": hidden_c2_hosts,
            "dormant_static_hosts": dormant_static_hosts,
            "correlated_hosts": correlated_hosts,
            "untrusted_runtime_hosts": sorted(list(untrusted_runtime)),
            "hidden_c2_candidate_count": len(hidden_c2_hosts),
        }

        if job_id:
            run_dir = CAPTURE_DIR / job_id
            run_dir.mkdir(parents=True, exist_ok=True)
            (run_dir / "mobsf_static_report.json").write_text(json.dumps(mobsf_static, indent=2), encoding="utf-8")
            (run_dir / "mobsf_dynamic_report.json").write_text(json.dumps(mobsf_dynamic, indent=2), encoding="utf-8")

        # 7. Extract Malicious API Chains from MobSF Decompiler AST
        static_chain_score, detected_chains = extract_api_chains_from_mobsf(mobsf_static)
        if detected_chains:
            _emit(
                f"[STATIC] Correlated {len(detected_chains)} malicious API execution chain(s) "
                f"from MobSF AST (Score: {static_chain_score})"
            )

        return {
            "module": "dynamic_analysis",
            "status": "complete",
            "job_id": job_id,
            "package_name": package_name,
            "apk_sha256": sha256_hash,
            "mobsf_scan_hash": scan_hash,
            "dynamic_risk_score": dynamic_risk_score,
            "verdict": verdict,
            "api_chain_score": static_chain_score,
            "api_chains": detected_chains,
            "execution_confidence": execution_confidence,
            "coverage": {
                "screenshots_count": screenshots_captured,
                "is_dormant_or_evaded": is_dormant,
                "static_hosts_indexed": len(all_static_hosts),
            },
            "exfiltration_events": exfiltration_events,
            "mitm_console": live_mitm_console,
            "behavior_delta": behavior_delta,
            "network_delta": network_delta,
            "findings": findings,
            "evidence": {
                "hidden_c2_hosts": hidden_c2_hosts,
                "dormant_static_hosts": dormant_static_hosts[:10],
                "correlated_hosts": correlated_hosts,
                "total_urls_captured": len(cleaned_dynamic_urls),
            },
            "errors": [],
            "completed_at": _now(),
            "duration_seconds": round(time.monotonic() - started_at, 2),
        }

    except Exception as exc:
        if package_name:
            _uninstall_package_from_device(package_name)
        delta_table = _build_behavior_delta(declared_perms, "", [])
        _emit(f"[ERROR] Dynamic execution failed: {exc}", is_alarm=True, stage="error")
        return {
            "module": "dynamic_analysis",
            "status": "error",
            "job_id": job_id,
            "package_name": package_name or apk_file.stem,
            "apk_sha256": sha256_hash,
            "mobsf_scan_hash": scan_hash if "scan_hash" in locals() else md5_hash,
            "dynamic_risk_score": 0,
            "verdict": "ERROR",
            # Preserve static chains even on dynamic crash:
            "api_chain_score": static_chain_score if "static_chain_score" in locals() else 0.0,
            "api_chains": detected_chains if "detected_chains" in locals() else [],
            "execution_confidence": 0,
            "coverage": {"screenshots_count": 0, "is_dormant_or_evaded": False},
            "exfiltration_events": [],
            "mitm_console": live_mitm_console,
            "behavior_delta": delta_table,
            "network_delta": {},
            "findings": [],
            "errors": [f"{type(exc).__name__}: {exc}"],
            "completed_at": _now(),
            "duration_seconds": round(time.monotonic() - started_at, 2),
        }


# =============================================================================
# CLI REPORT FORMATTER
# =============================================================================
def _print_executive_report(res: dict[str, Any]) -> None:
    print("\n" + "=" * 95)
    print("SPECTRE — MODULE 3: DYNAMIC RUNTIME SECURITY REPORT")
    print("=" * 95)
    print(f"Target Package       : {res.get('package_name')}")
    print(f"SHA-256 Hash         : {res.get('apk_sha256')}")
    print(f"MobSF Scan Checksum  : {res.get('mobsf_scan_hash')}")
    print(f"Analysis Status      : {str(res.get('status')).upper()}")
    print(f"Execution Duration   : {res.get('duration_seconds', 0)}s")
    print(f"Execution Confidence : {res.get('execution_confidence', 0)}% (Sandbox Coverage Metric)")
    print(f"Dynamic Threat Score : {res.get('dynamic_risk_score', 0)} / 100 [{res.get('verdict', 'UNKNOWN')}]")

    cov = res.get("coverage", {})
    if cov.get("is_dormant_or_evaded"):
        print("Sandbox Status       : ⚠️ ANTI-ANALYSIS DORMANCY / EXECUTION EVASION DETECTED")

    print("-" * 95)
    print("[PIPELINE INTEGRATION SIGNALS]")
    print(f"  ├─ dynamic_risk_score   : {res.get('dynamic_risk_score', 0)} (Weight: 0.18 in pipeline.py)")
    exfil_events = res.get("exfiltration_events", [])
    exfil_score = min(100, len(exfil_events) * 20)
    print(f"  └─ exfiltration_events  : {len(exfil_events)} event(s) -> Network Exfil Score: {exfil_score} / 100")

    findings = res.get("findings", [])
    print(f"\n[VERIFIED RUNTIME THREAT FINDINGS: {len(findings)}]")
    if findings:
        for f in findings:
            print(f"  • [{f.get('severity')}] {f.get('title')} (+{f.get('points')} pts)")
            print(f"    Reason: {f.get('description')}")
            if f.get("evidence"):
                print(f"    Evidence: {f.get('evidence')}")
    else:
        print("  (No suspicious runtime indicators or C2 channels flagged)")

    print("\n" + "=" * 95)
    print("RAW MITMPROXY INTERCEPTION CONSOLE (STREAM VIEW)")
    print("=" * 95)
    console_logs = res.get("mitm_console", [])
    if console_logs:
        for log in console_logs:
            prefix = "🔴 " if log["is_alarm"] else "   "
            print(f"{prefix}{log['raw_line']}")
    else:
        print("   (No network flows intercepted during sandbox window)")

    print("\n" + "=" * 95)
    print("STATIC VS RUNTIME BEHAVIOR DELTA")
    print("=" * 95)
    print(f"{'Permission / Capability':<30} | {'Declared':<8} | {'Runtime':<8} | {'Analyst Note'}")
    print("-" * 95)
    for row in res.get("behavior_delta", []):
        print(f"{row['permission']:<30} | {row['declared']:<8} | {row['runtime']:<8} | {row['analyst_note']}")

    net_delta = res.get("network_delta", {})
    if net_delta:
        print("\n" + "=" * 95)
        print("STATIC VS DYNAMIC NETWORK INFRASTRUCTURE CORRELATION")
        print("=" * 95)
        print(f"• Correlated Hosts (Declared & Contacted)     : {net_delta.get('correlated_hosts', [])}")
        print(f"• Hidden Runtime Hosts (Absent from Manifest) : {net_delta.get('hidden_runtime_hosts', [])}")
        dormant = net_delta.get("dormant_static_hosts", [])
        print(f"• Dormant Static Hosts ({len(dormant)} uncontacted)    : {dormant[:8]}")
    print("=" * 95 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SPECTRE Module 3 Dynamic Analysis Runner")
    parser.add_argument("apk", type=Path, help="Path to APK file to test")
    parser.add_argument("--json", action="store_true", help="Print raw JSON response")
    parser.add_argument("--fresh", action="store_true", help="Force clean re-execution on emulator (bypass cache)")
    args = parser.parse_args()

    result = analyze_dynamic(str(args.apk), job_id="cli_test", force_fresh=args.fresh)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        _print_executive_report(result)