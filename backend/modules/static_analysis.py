from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import zipfile
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.util import set_log

set_log("WARNING")

# =============================================================================
# DANGEROUS / RELEVANT PERMISSIONS
# =============================================================================

DANGEROUS_PERMISSIONS: dict[str, dict[str, Any]] = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "risk": "CRITICAL",
        "score": 30,
        "reason": (
            "Accessibility service can observe UI content and perform actions; "
            "it can be abused for credential and OTP interception."
        ),
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "risk": "CRITICAL",
        "score": 25,
        "reason": (
            "Allows overlays over other applications and can support "
            "credential or OTP interception."
        ),
    },
    "android.permission.RECEIVE_SMS": {
        "risk": "CRITICAL",
        "score": 25,
        "reason": (
            "Allows interception of incoming SMS messages, including OTPs."
        ),
    },
    "android.permission.READ_SMS": {
        "risk": "HIGH",
        "score": 20,
        "reason": "Allows reading stored SMS messages, potentially exposing OTPs.",
    },
    "android.permission.SEND_SMS": {
        "risk": "HIGH",
        "score": 18,
        "reason": (
            "Allows sending SMS messages and can support unauthorized messaging "
            "or propagation."
        ),
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "risk": "HIGH",
        "score": 20,
        "reason": (
            "Allows requesting installation of APK packages; relevant to "
            "package-delivery or propagation behavior."
        ),
    },
    "android.permission.INSTALL_PACKAGES": {
        "risk": "CRITICAL",
        "score": 25,
        "reason": (
            "Package installation capability is highly privileged and can be "
            "abused to install additional applications."
        ),
    },
    "android.permission.WRITE_SETTINGS": {
        "risk": "HIGH",
        "score": 15,
        "reason": "Allows modification of selected system settings.",
    },
    "android.permission.PACKAGE_USAGE_STATS": {
        "risk": "HIGH",
        "score": 12,
        "reason": (
            "Can expose application-usage information and may support "
            "surveillance or targeting."
        ),
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "risk": "HIGH",
        "score": 10,
        "reason": (
            "Allows broad package visibility; relevant when combined with "
            "target discovery or abuse behavior."
        ),
    },
    "android.permission.PROCESS_OUTGOING_CALLS": {
        "risk": "HIGH",
        "score": 15,
        "reason": "Can be associated with interception or manipulation of calls.",
    },
    "android.permission.READ_CALL_LOG": {
        "risk": "HIGH",
        "score": 15,
        "reason": "Allows access to call history and communication metadata.",
    },
    "android.permission.CALL_PHONE": {
        "risk": "HIGH",
        "score": 10,
        "reason": "Allows placing calls without the normal dialer interaction.",
    },
    "android.permission.ANSWER_PHONE_CALLS": {
        "risk": "HIGH",
        "score": 10,
        "reason": "Allows programmatic answering of phone calls.",
    },
    "android.permission.READ_PHONE_STATE": {
        "risk": "MEDIUM",
        "score": 7,
        "reason": "Exposes telephony/device state that can aid device fingerprinting.",
    },
    "android.permission.READ_PHONE_NUMBERS": {
        "risk": "MEDIUM",
        "score": 7,
        "reason": "Can expose the device's phone number where available.",
    },
    "android.permission.RECORD_AUDIO": {
        "risk": "MEDIUM",
        "score": 10,
        "reason": "Provides microphone access and may enable audio surveillance.",
    },
    "android.permission.CAMERA": {
        "risk": "MEDIUM",
        "score": 8,
        "reason": "Provides camera access and may enable surveillance.",
    },
    "android.permission.READ_CONTACTS": {
        "risk": "MEDIUM",
        "score": 8,
        "reason": "Allows access to contacts and may support targeted abuse.",
    },
    "android.permission.WRITE_CONTACTS": {
        "risk": "MEDIUM",
        "score": 7,
        "reason": "Allows modification of contact records.",
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "risk": "MEDIUM",
        "score": 6,
        "reason": "Allows precise location tracking.",
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "risk": "MEDIUM",
        "score": 4,
        "reason": "Allows approximate location tracking.",
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "risk": "MEDIUM",
        "score": 5,
        "reason": "Allows reading shared/external storage on applicable Android versions.",
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "risk": "MEDIUM",
        "score": 5,
        "reason": "Allows writing shared/external storage on applicable Android versions.",
    },
    "android.permission.INTERNET": {
        "risk": "LOW",
        "score": 3,
        "reason": (
            "Network communication is required by many legitimate applications; "
            "risk depends on accompanying behavior."
        ),
    },
    "android.permission.ACCESS_NETWORK_STATE": {
        "risk": "LOW",
        "score": 1,
        "reason": "Allows checking network connectivity.",
    },
    "android.permission.ACCESS_WIFI_STATE": {
        "risk": "LOW",
        "score": 1,
        "reason": "Allows reading Wi-Fi connectivity/state information.",
    },
    "android.permission.WAKE_LOCK": {
        "risk": "LOW",
        "score": 2,
        "reason": "Allows keeping the device awake and may support background activity.",
    },
    "android.permission.REORDER_TASKS": {
        "risk": "MEDIUM",
        "score": 4,
        "reason": "Allows manipulation of application task ordering.",
    },
    "android.permission.BLUETOOTH": {
        "risk": "LOW",
        "score": 2,
        "reason": "Bluetooth capability; risk depends on how it is used.",
    },
    "android.permission.FOREGROUND_SERVICE": {
        "risk": "LOW",
        "score": 2,
        "reason": "Allows long-running foreground services.",
    },
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC": {
        "risk": "LOW",
        "score": 2,
        "reason": "Allows a foreground service dedicated to data synchronization.",
    },
    "android.permission.USE_FINGERPRINT": {
        "risk": "LOW",
        "score": 1,
        "reason": "Allows use of legacy fingerprint authentication APIs.",
    },
    "android.permission.USE_BIOMETRIC": {
        "risk": "LOW",
        "score": 1,
        "reason": "Allows biometric authentication APIs.",
    },
    "android.permission.FLASHLIGHT": {
        "risk": "LOW",
        "score": 1,
        "reason": "Allows flashlight-related device functionality.",
    },
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "risk": "LOW",
        "score": 3,
        "reason": "Allows receiving the boot-completed broadcast for startup behavior.",
    },
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": {
        "risk": "MEDIUM",
        "score": 5,
        "reason": "Can request exemption from battery optimization restrictions.",
    },
}

# =============================================================================
# HIGH-VALUE PERMISSION COMBINATIONS
# =============================================================================

CRITICAL_COMBOS: list[tuple[list[str], str, str]] = [
    (
        [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ],
        "OVERLAY_ACCESSIBILITY_CONFIG",
        (
            "Accessibility capability combined with overlay capability can "
            "support credential or OTP interception."
        ),
    ),
    (
        [
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
        ],
        "OTP_STEALER_CONFIG",
        (
            "SMS receive/read/send combination can support interception and "
            "forwarding of OTP messages."
        ),
    ),
    (
        [
            "android.permission.READ_SMS",
            "android.permission.INTERNET",
        ],
        "SMS_NETWORK_CONFIG",
        (
            "SMS access combined with network access creates a candidate path "
            "for sensitive-message transmission; runtime evidence is required "
            "to establish actual exfiltration."
        ),
    ),
    (
        [
            "android.permission.RECEIVE_SMS",
            "android.permission.INTERNET",
        ],
        "OTP_NETWORK_CONFIG",
        (
            "Incoming SMS capability combined with network access can support "
            "OTP interception and transmission."
        ),
    ),
    (
        [
            "android.permission.RECORD_AUDIO",
            "android.permission.INTERNET",
        ],
        "AUDIO_NETWORK_CONFIG",
        (
            "Microphone access combined with network capability can support "
            "collection and transmission of audio."
        ),
    ),
    (
        [
            "android.permission.CAMERA",
            "android.permission.INTERNET",
        ],
        "CAMERA_NETWORK_CONFIG",
        (
            "Camera access combined with network capability can support "
            "collection and transmission of captured data."
        ),
    ),
    (
        [
            "android.permission.READ_CONTACTS",
            "android.permission.SEND_SMS",
        ],
        "CONTACT_SMS_CONFIG",
        (
            "Contact access combined with SMS sending can support targeted "
            "propagation or unauthorized messaging."
        ),
    ),
    (
        [
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
        ],
        "LOCATION_NETWORK_CONFIG",
        (
            "Precise location access combined with network capability can "
            "support collection and transmission of location data."
        ),
    ),
]

# =============================================================================
# SUSPICIOUS COMPONENT HEURISTICS
# =============================================================================

SUSPICIOUS_COMPONENTS: dict[str, dict[str, Any]] = {
    "vpn": {
        "risk": "HIGH",
        "score": 15,
        "reason": (
            "VPN-related component may be relevant to traffic interception "
            "or tunneling."
        ),
    },
    "accessibility": {
        "risk": "CRITICAL",
        "score": 20,
        "reason": (
            "Accessibility-related component may enable UI monitoring or "
            "automated interaction."
        ),
    },
    "sms": {
        "risk": "HIGH",
        "score": 15,
        "reason": (
            "SMS-related component may be associated with OTP interception "
            "or SMS abuse."
        ),
    },
    "overlay": {
        "risk": "HIGH",
        "score": 15,
        "reason": (
            "Overlay-related component naming may be relevant to UI "
            "interception; corroborating evidence is required."
        ),
    },
}

# =============================================================================
# API-CHAIN CATEGORIES & RULES
# =============================================================================

API_CATEGORY_PREFIXES: dict[str, tuple[str, ...]] = {
    "sms_message": ("android.telephony.smsmessage",),
    "sms_provider": ("android.provider.telephony", "android.provider.browser"),
    "sms_manager": ("android.telephony.smsmanager",),
    "network": (
        "java.net.url",
        "java.net.httpurlconnection",
        "java.net.urlconnection",
        "java.net.socket",
        "javax.net.",
        "okhttp3.",
        "retrofit2.",
        "com.android.volley.",
        "com.squareup.okhttp.",
        "org.apache.http.",
        "android.net.http.",
    ),
    "accessibility": ("android.accessibilityservice.", "android.view.accessibility."),
    "window": ("android.view.windowmanager",),
    "clipboard": ("android.content.clipboardmanager",),
    "contacts": ("android.provider.contactscontract",),
    "telephony": ("android.telephony.telephonymanager",),
    "credential_ui": (
        "android.widget.edittext",
        "android.widget.textview",
        "android.widget.autocompletetextview",
        "android.view.inputmethod.",
    ),
    "crypto": ("javax.crypto.", "javax.crypto.spec.", "android.security.keystore."),
    "encoding": ("android.util.base64", "java.util.base64"),
    "dynamic_code": (
        "dalvik.system.dexclassloader",
        "dalvik.system.pathclassloader",
        "dalvik.system.inmemorydexclassloader",
    ),
    "reflection": ("java.lang.class", "java.lang.reflect."),
    "process": ("java.lang.runtime", "java.lang.processbuilder"),
}

NETWORK_SINK_METHODS = {
    "openConnection", "openStream", "connect", "getInputStream", "getOutputStream",
    "getResponseCode", "execute", "enqueue", "newCall", "add", "request", "send",
    "post", "put", "patch", "write",
}

SMS_SOURCE_METHODS = {
    "getMessageBody", "getOriginatingAddress", "getDisplayOriginatingAddress", "getTimestampMillis",
}

SMS_SINK_METHODS = {
    "sendTextMessage", "sendMultipartTextMessage", "sendDataMessage", "sendTextMessageWithoutPersisting",
}

TELEPHONY_SENSITIVE_METHODS = {
    "getDeviceId", "getSubscriberId", "getImei", "getMeid", "getSimSerialNumber",
    "getLine1Number", "getSimOperator", "getSimOperatorName", "getNetworkOperator", "getNetworkOperatorName",
}

CLIPBOARD_SOURCE_METHODS = {"getPrimaryClip", "getPrimaryClipDescription", "hasPrimaryClip"}
WINDOW_SINK_METHODS = {"addView", "addViewImmediate", "updateViewLayout", "removeView", "removeViewImmediate"}
CREDENTIAL_INPUT_METHODS = {"getText", "getEditableText", "getTextBeforeCursor", "getTextAfterCursor"}
CRYPTO_METHODS = {"getInstance", "init", "doFinal", "update", "updateAAD"}
ENCODING_METHODS = {"encode", "decode", "encodeToString", "decodeString"}

API_CHAIN_RULES = [
    {"required_order": ("sms_message", "network"), "name": "SMS_MESSAGE_TO_NETWORK", "strength": "STRONG", "risk": "CRITICAL", "score": 45, "reason": "SMS/message data reaches a network sink."},
    {"required_order": ("sms_provider", "network"), "name": "SMS_PROVIDER_TO_NETWORK", "strength": "STRONG", "risk": "CRITICAL", "score": 45, "reason": "SMS/provider data reaches a network sink."},
    {"required_order": ("telephony", "network"), "name": "TELEPHONY_ID_TO_NETWORK", "strength": "STRONG", "risk": "HIGH", "score": 35, "reason": "Sensitive device/telephony identifier reaches a network sink."},
    {"required_order": ("clipboard", "network"), "name": "CLIPBOARD_TO_NETWORK", "strength": "STRONG", "risk": "HIGH", "score": 35, "reason": "Clipboard data reaches a network sink."},
    {"required_order": ("accessibility", "network"), "name": "ACCESSIBILITY_TO_NETWORK", "strength": "STRONG", "risk": "HIGH", "score": 45, "reason": "Accessibility-derived data reaches a network sink."},
    {"required_order": ("accessibility", "window"), "name": "ACCESSIBILITY_TO_OVERLAY", "strength": "STRONG", "risk": "CRITICAL", "score": 50, "reason": "Accessibility activity precedes overlay manipulation."},
    {"required_order": ("credential_ui", "network"), "name": "CREDENTIAL_INPUT_TO_NETWORK", "strength": "STRONG", "risk": "CRITICAL", "score": 50, "reason": "Credential-capable UI input reaches a network sink."},
    {"required_order": ("credential_ui", "crypto", "network"), "name": "CREDENTIAL_TO_CRYPTO_TO_NETWORK", "strength": "STRONG", "risk": "CRITICAL", "score": 65, "reason": "Credential input is transformed cryptographically before network transmission."},
    {"required_order": ("credential_ui", "encoding", "network"), "name": "CREDENTIAL_TO_ENCODING_TO_NETWORK", "strength": "STRONG", "risk": "CRITICAL", "score": 60, "reason": "Credential input is encoded before network transmission."},
    {"required_order": ("sms_message", "encoding", "network"), "name": "SMS_TO_ENCODING_TO_NETWORK", "strength": "STRONG", "risk": "CRITICAL", "score": 60, "reason": "SMS data is encoded before network transmission."},
    {"required_order": ("telephony", "encoding", "network"), "name": "TELEPHONY_TO_ENCODING_TO_NETWORK", "strength": "STRONG", "risk": "HIGH", "score": 50, "reason": "Telephony identifier is encoded before network transmission."},
    {"required_order": ("clipboard", "encoding", "network"), "name": "CLIPBOARD_TO_ENCODING_TO_NETWORK", "strength": "STRONG", "risk": "HIGH", "score": 50, "reason": "Clipboard data is encoded before network transmission."},
    {"required_order": ("contacts", "network"), "name": "CONTACTS_TO_NETWORK", "strength": "CONTEXTUAL", "risk": "MEDIUM", "score": 25, "reason": "Contacts API usage precedes network activity."},
    {"required_order": ("dynamic_code", "network"), "name": "DYNAMIC_CODE_TO_NETWORK", "strength": "CONTEXTUAL", "risk": "MEDIUM", "score": 20, "reason": "Dynamic code loading precedes network activity."},
    {"required_order": ("process", "network"), "name": "PROCESS_TO_NETWORK", "strength": "CONTEXTUAL", "risk": "HIGH", "score": 25, "reason": "Process/shell execution precedes network activity."},
]

TRUSTED_SIGNING_CERTIFICATES: dict[str, set[str]] = {}
BANK_IDENTITY_REGISTRY_ENV = "SPECTRE_BANK_IDENTITY_REGISTRY"
DEFAULT_BANK_IDENTITY_REGISTRY = Path(__file__).resolve().parents[1] / "config" / "bank_identity_registry.json"

_DESCRIPTOR_RE = re.compile(r"L([A-Za-z0-9_/$.-]+);")
_INVOKE_PREFIX = "invoke-"
_INVOKE_REFERENCE_RE = re.compile(r"L(?P<class>[A-Za-z0-9_/$.-]+);->(?P<method>[^\s(:]+)")
_IGNORED_URL_PREFIXES = (
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://www.w3.org/",
    "https://www.w3.org/",
)
_INFO_DOMAINS = {
    "google.com", "googleapis.com", "firebase.google.com", "gstatic.com",
    "cloudflare.com", "amazon.com", "amazonaws.com", "android.com",
}


def _normalize_fingerprint(value: str) -> str:
    return value.replace(":", "").replace(" ", "").lower()


def _load_bank_identity_registry() -> dict[str, dict[str, Any]]:
    configured = os.environ.get(BANK_IDENTITY_REGISTRY_ENV, str(DEFAULT_BANK_IDENTITY_REGISTRY))
    path = Path(configured)
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    registry: dict[str, dict[str, Any]] = {}
    for package_name, record in payload.items():
        if not isinstance(record, dict):
            continue
        certs = record.get("cert_sha256", [])
        if isinstance(certs, str):
            certs = [certs]
        registry[str(package_name)] = {
            "app_name": str(record.get("app_name", "")),
            "cert_sha256": {_normalize_fingerprint(str(v)) for v in certs if v},
            "notes": str(record.get("notes", "")),
        }
    return registry


def _iter_dex_objects(dex_objects: Any) -> Iterable[Any]:
    if dex_objects is None:
        return ()
    if isinstance(dex_objects, (list, tuple)):
        return dex_objects
    return (dex_objects,)


def _normalize_descriptor(descriptor: str) -> str:
    return descriptor.replace("/", ".").replace("$", ".")


def _extract_invoke_reference(instruction: Any) -> tuple[str, str, str]:
    try:
        raw_output = str(instruction.get_output() or "").strip()
    except Exception:
        return "", "", ""
    if not raw_output:
        return "", "", ""
    match = _INVOKE_REFERENCE_RE.search(raw_output)
    if match:
        return _normalize_descriptor(match.group("class")), match.group("method").strip(), raw_output
    if "->" in raw_output:
        prefix, tail = raw_output.split("->", 1)
        desc = _DESCRIPTOR_RE.search(prefix)
        if desc:
            method_name = re.split(r"[\s(:]", tail, maxsplit=1)[0].strip()
            return _normalize_descriptor(desc.group(1)), method_name, raw_output
    return "", "", raw_output


def _method_categories(api_class: str, method_name: str) -> set[str]:
    cls = str(api_class).strip().lstrip("L").rstrip(";").replace("/", ".").replace("$", ".").lower()
    method = str(method_name).strip().split("(", 1)[0].split(":", 1)[0].strip()
    categories: set[str] = set()

    if cls.startswith("android.telephony.smsmessage") and method in SMS_SOURCE_METHODS:
        categories.add("sms_message")
    if cls.startswith("android.provider.telephony") and method in {"query", "getString", "getColumnIndex", "getType"}:
        categories.add("sms_provider")
    if cls.startswith("android.telephony.smsmanager") and method in SMS_SINK_METHODS:
        categories.add("sms_manager")
    if any(cls.startswith(p.lower()) for p in API_CATEGORY_PREFIXES["network"]) and method in NETWORK_SINK_METHODS:
        categories.add("network")
    if any(cls.startswith(p.lower()) for p in API_CATEGORY_PREFIXES["accessibility"]):
        categories.add("accessibility")
    if cls.startswith("android.view.windowmanager") and method in WINDOW_SINK_METHODS:
        categories.add("window")
    if cls.startswith("android.content.clipboardmanager") and method in CLIPBOARD_SOURCE_METHODS:
        categories.add("clipboard")
    if cls.startswith("android.provider.contactscontract"):
        categories.add("contacts")
    if cls.startswith("android.telephony.telephonymanager") and method in TELEPHONY_SENSITIVE_METHODS:
        categories.add("telephony")

    credential_class = (
        "edittext" in cls
        or "textinputedittext" in cls
        or cls.startswith("android.widget.textview")
        or cls.startswith("android.view.inputmethod")
    )
    if credential_class and method in CREDENTIAL_INPUT_METHODS:
        categories.add("credential_ui")
    if cls.startswith("android.view.accessibility.accessibilitynodeinfo") and method in {"getText", "getContentDescription"}:
        categories.add("credential_ui")

    if any(cls.startswith(p.lower()) for p in API_CATEGORY_PREFIXES["crypto"]) and method in CRYPTO_METHODS:
        categories.add("crypto")
    if any(cls.startswith(p.lower()) for p in API_CATEGORY_PREFIXES["encoding"]) and method in ENCODING_METHODS:
        categories.add("encoding")
    if any(cls.startswith(p.lower()) for p in API_CATEGORY_PREFIXES["dynamic_code"]):
        categories.add("dynamic_code")
    if any(cls.startswith(p.lower()) for p in API_CATEGORY_PREFIXES["reflection"]) and method in {
        "forName", "getDeclaredMethod", "getMethod", "invoke", "setAccessible"
    }:
        categories.add("reflection")
    if any(cls.startswith(p.lower()) for p in API_CATEGORY_PREFIXES["process"]) and method in {"exec", "start"}:
        categories.add("process")

    return categories


def _find_ordered_category_chain(calls: list[dict[str, Any]], required_order: tuple[str, ...]) -> list[dict[str, Any]] | None:
    selected = []
    last_position = -1
    for required_category in required_order:
        found = None
        for position in range(last_position + 1, len(calls)):
            if required_category in calls[position]["categories"]:
                found = calls[position]
                last_position = position
                break
        if found is None:
            return None
        selected.append(found)
    return selected


def _safe_package_name(value: Any) -> str:
    try:
        return str(value or "")
    except Exception:
        return ""


def _scan_dex_bytes_for_network_indicators(dex_bytes: bytes) -> tuple[set[str], set[str], set[str]]:
    urls: set[str] = set()
    ips: set[str] = set()
    api_paths: set[str] = set()
    printable_strings = re.findall(rb"[\x20-\x7e]{5,600}", dex_bytes)
    url_re = re.compile(r"https?://[^\s\"'<>]{4,500}", re.IGNORECASE)
    ip_re = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])")
    api_re = re.compile(
        r"/(?:api|v\d+|auth|login|register|upload|download|token|user|users|admin|config|data)(?:/[^\s\"'<>]{0,200})?",
        re.IGNORECASE,
    )

    def add_public_ip(candidate: str) -> None:
        candidate = candidate.strip()
        host = candidate.split(":", 1)[0]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return
        if address.is_global:
            ips.add(candidate)

    for raw_string in printable_strings:
        value = raw_string.decode("ascii", errors="ignore").strip()
        if not value:
            continue
        for match in url_re.findall(value):
            url = match.rstrip(".,;)]}>")
            if not url.lower().startswith(("http://", "https://")) or url.lower().startswith(_IGNORED_URL_PREFIXES):
                continue
            urls.add(url)
            try:
                host = (urlparse(url).hostname or "").strip()
            except Exception:
                host = ""
            if host:
                add_public_ip(host)
        stripped = value.rstrip(".,;)]}>")
        if ip_re.fullmatch(stripped):
            add_public_ip(stripped)
        for match in api_re.findall(value):
            path = match.rstrip(".,;)]}>")
            if path:
                api_paths.add(path)

    return urls, ips, api_paths


def extract_urls_and_apis(apk_path: str | Path) -> dict[str, Any]:
    path = Path(apk_path)
    urls: set[str] = set()
    ips: set[str] = set()
    api_paths: set[str] = set()
    with zipfile.ZipFile(path, "r") as archive:
        dex_names = [name for name in archive.namelist() if re.fullmatch(r"classes\d*\.dex", Path(name).name)]
        for name in dex_names:
            try:
                dex_bytes = archive.read(name)
            except Exception:
                continue
            d_urls, d_ips, d_paths = _scan_dex_bytes_for_network_indicators(dex_bytes)
            urls.update(d_urls)
            ips.update(d_ips)
            api_paths.update(d_paths)
    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "api_paths": sorted(api_paths),
        "url_count": len(urls),
        "ip_count": len(ips),
        "api_path_count": len(api_paths),
    }


def classify_network_indicators(urls: Iterable[str], ips: Iterable[str], api_paths: Iterable[str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    url_values = sorted({str(u).strip() for u in urls if str(u).strip()})
    ip_values = sorted({str(i).strip() for i in ips if str(i).strip()})
    path_values = sorted({str(p).strip() for p in api_paths if str(p).strip()})

    external_hosts: set[str] = set()
    http_hosts: set[str] = set()

    for url in url_values:
        scheme = ""
        host = ""
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            scheme = parsed.scheme.lower()
        except Exception:
            pass
        if not host:
            continue
        if any(host == d or host.endswith("." + d) for d in _INFO_DOMAINS):
            findings.append({"indicator": url, "type": "url", "risk": "INFO", "score": 0, "reason": "Common infrastructure domain."})
            continue
        external_hosts.add(host)
        if scheme == "http":
            http_hosts.add(host)
            findings.append({"indicator": url, "type": "url", "risk": "MEDIUM", "score": 3, "reason": "Hard-coded cleartext HTTP URL found in DEX data."})
        else:
            findings.append({"indicator": url, "type": "url", "risk": "LOW", "score": 0, "reason": "Hard-coded network URL found in APK."})

    host_score = min(10, len(external_hosts))
    http_score = min(18, len(http_hosts) * 3)
    public_ip_values: set[str] = set()

    for value in ip_values:
        try:
            parsed_ip = ipaddress.ip_address(value)
            if not parsed_ip.is_private and not parsed_ip.is_loopback:
                public_ip_values.add(value)
            findings.append({"indicator": value, "type": "ip", "risk": "MEDIUM", "score": 2, "reason": "Hard-coded IP address found in DEX data."})
        except ValueError:
            findings.append({"indicator": value, "type": "ip", "risk": "INFO", "score": 0, "reason": "Unparsed IP token."})

    public_ip_score = min(12, len(public_ip_values) * 2)
    sensitive_path_count = 0
    for path in path_values:
        lower_path = path.lower()
        if any(tok in lower_path for tok in ("/login", "/auth", "/token", "/otp", "/password", "/credential", "/upload", "/exfil", "/payment", "/transfer")):
            sensitive_path_count += 1
            findings.append({"indicator": path, "type": "api_path", "risk": "MEDIUM", "score": 2, "reason": "Sensitive API-like path found in static strings."})
        else:
            findings.append({"indicator": path, "type": "api_path", "risk": "INFO", "score": 0, "reason": "Informational API-like path in static strings."})

    sensitive_path_score = min(10, sensitive_path_count * 2)
    raw_network_score = host_score + http_score + public_ip_score + sensitive_path_score
    return {
        "network_score": min(40, raw_network_score),
        "raw_network_score": raw_network_score,
        "host_score": host_score,
        "http_score": http_score,
        "public_ip_score": public_ip_score,
        "sensitive_path_score": sensitive_path_score,
        "unique_external_host_count": len(external_hosts),
        "http_host_count": len(http_hosts),
        "public_ip_host_count": len(public_ip_values),
        "findings": findings[:200],
    }


def analyze_certificates(apk: Any) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    certificate_score = 0
    certificates: list[dict[str, Any]] = []
    signing_schemes: list[str] = []

    try:
        signed = bool(apk.is_signed())
    except Exception:
        signed = None

    if signed is False:
        return {
            "certificate_score": 50,
            "signed": False,
            "signing_schemes": [],
            "certificates": [],
            "certificate_findings": [{"risk": "HIGH", "score": 50, "reason": "APK does not contain a detectable signing certificate."}],
            "certificate_identity_status": "invalid_or_unknown",
        }

    for scheme_name, checker_name in (("v1", "is_signed_v1"), ("v2", "is_signed_v2"), ("v3", "is_signed_v3"), ("v4", "is_signed_v4")):
        try:
            if getattr(apk, checker_name)():
                signing_schemes.append(scheme_name)
        except Exception:
            continue

    try:
        raw_certs = apk.get_certificates() or []
    except Exception as exc:
        return {
            "certificate_score": 0,
            "signed": signed,
            "signing_schemes": signing_schemes,
            "certificates": [],
            "certificate_findings": [{"risk": "INFO", "score": 0, "reason": f"Certificate analysis failed: {exc}"}],
            "certificate_identity_status": "unknown",
        }

    for cert in raw_certs:
        sha1 = cert.sha1.hex() if hasattr(cert, "sha1") and cert.sha1 else ""
        sha256 = cert.sha256.hex() if hasattr(cert, "sha256") and cert.sha256 else ""
        issuer = str(getattr(getattr(cert, "issuer", None), "human_friendly", ""))
        subject = str(getattr(getattr(cert, "subject", None), "human_friendly", ""))
        certificates.append({
            "sha1": sha1,
            "sha256": sha256,
            "issuer": issuer,
            "subject": subject,
            "hash_algorithm": str(getattr(cert, "hash_algo", "")),
            "signature_algorithm": str(getattr(cert, "signature_algo", "")),
            "serial_number": str(getattr(cert, "serial_number", "")),
        })
        combined = f"{issuer} {subject}".lower()
        if "android debug" in combined or "androiddebugkey" in combined:
            certificate_score += 25
            findings.append({"risk": "HIGH", "score": 25, "reason": "Certificate appears to use an Android debug signing identity.", "sha256": sha256})
        try:
            validity_days = (cert.not_valid_after - cert.not_valid_before).days
        except Exception:
            validity_days = None
        if validity_days is not None and validity_days <= 30:
            certificate_score += 10
            findings.append({"risk": "MEDIUM", "score": 10, "reason": f"Certificate validity is unusually short ({validity_days} days).", "sha256": sha256})

    if not findings:
        findings.append({"risk": "INFO", "score": 0, "reason": "Signing certificate information extracted."})

    return {
        "certificate_score": min(100, certificate_score),
        "signed": signed,
        "signing_schemes": signing_schemes,
        "certificates": certificates,
        "certificate_findings": findings,
        "certificate_identity_status": "unknown",
    }


def analyze_exported_components(apk: Any) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    exported_score = 0
    try:
        manifest = apk.get_android_manifest_xml()
    except Exception as exc:
        return {"exported_score": 0, "findings": [{"risk": "INFO", "score": 0, "reason": f"Exported-component analysis failed: {exc}"}]}

    android_ns = "{http://schemas.android.com/apk/res/android}"
    for component_type in ("activity", "service", "receiver", "provider"):
        for component in manifest.findall(f".//application/{component_type}"):
            if component.get(f"{android_ns}exported") != "true":
                continue
            name = component.get(f"{android_ns}name", "unknown")
            intent_filters = []
            for intent_filter in component.findall("intent-filter"):
                actions = [a.get(f"{android_ns}name") for a in intent_filter.findall("action") if a.get(f"{android_ns}name")]
                categories = [c.get(f"{android_ns}name") for c in intent_filter.findall("category") if c.get(f"{android_ns}name")]
                data = []
                for d_el in intent_filter.findall("data"):
                    item = {attr: d_el.get(f"{android_ns}{attr}") for attr in ("scheme", "host", "port", "path", "pathPrefix", "mimeType") if d_el.get(f"{android_ns}{attr}")}
                    if item:
                        data.append(item)
                intent_filters.append({"actions": actions, "categories": categories, "data": data})

            has_launcher = any("android.intent.action.MAIN" in f["actions"] and "android.intent.category.LAUNCHER" in f["categories"] for f in intent_filters)
            score = 2 if has_launcher and component_type == "activity" else 0
            risk = "LOW" if score else "INFO"
            reason = "Explicitly exported launcher activity." if score else "Explicitly exported component."
            if any(act and not act.startswith("android.intent.") for f in intent_filters for act in f["actions"]):
                score = max(score, 5)
                risk = "MEDIUM"
                reason = "Explicitly exported component exposes a custom intent action."
            if component_type in {"service", "receiver", "provider"} and not has_launcher:
                score = max(score, 3)
                risk = "LOW"
                reason = f"Explicitly exported {component_type}."
            findings.append({"component": name, "type": component_type, "exported": True, "risk": risk, "score": score, "intent_filters": intent_filters, "reason": reason})
            exported_score += score

    return {"exported_score": min(100, exported_score), "findings": findings[:200]}


def analyze_components(activities: Iterable[str], services: Iterable[str], receivers: Iterable[str]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    component_score = 0
    for c_type, items in (("activity", activities), ("service", services), ("receiver", receivers)):
        for c_name in items:
            lowered = str(c_name).lower()
            matched = next((k for k in ("accessibility", "vpn", "sms", "overlay") if k in lowered), None)
            if matched:
                info = SUSPICIOUS_COMPONENTS[matched]
                findings.append({"component": c_name, "type": c_type, "risk": info["risk"], "score": info["score"], "reason": info["reason"]})
                component_score += int(info["score"])
    return {"component_score": min(100, component_score), "findings": findings[:200]}


def extract_api_chains(dex_objects: Any) -> dict[str, Any]:
    suspicious_chains: list[dict[str, Any]] = []
    total_invocations = 0
    recognized_references = 0
    methods_with_api_calls = 0
    methods_with_source_sink_candidates = 0
    category_totals: dict[str, int] = {}
    category_samples: list[dict[str, Any]] = []
    raw_api_samples: list[dict[str, Any]] = []
    raw_instruction_samples: list[dict[str, Any]] = []
    multi_category_methods = 0
    multi_category_samples = []

    for dex in _iter_dex_objects(dex_objects):
        try:
            classes = dex.get_classes()
        except Exception:
            continue
        for cls in classes:
            try:
                defining_class = _normalize_descriptor(str(cls.get_name()).strip("L;"))
            except Exception:
                defining_class = "unknown"
            try:
                methods = cls.get_methods()
            except Exception:
                continue
            for method in methods:
                try:
                    instructions = method.get_instructions()
                except Exception:
                    continue
                if instructions is None:
                    continue
                calls: list[dict[str, Any]] = []
                for instruction_index, instruction in enumerate(instructions):
                    try:
                        opcode_name = str(instruction.get_name()).lower()
                    except Exception:
                        continue
                    if not opcode_name.startswith(_INVOKE_PREFIX):
                        continue
                    total_invocations += 1
                    api_class, invoked_method, raw_output = _extract_invoke_reference(instruction)
                    if len(raw_instruction_samples) < 30:
                        raw_instruction_samples.append({"index": instruction_index, "raw": raw_output, "class": api_class, "method": invoked_method})
                    if not api_class:
                        continue
                    recognized_references += 1
                    if len(raw_api_samples) < 50:
                        raw_api_samples.append({"class": api_class, "method": invoked_method})
                    categories = _method_categories(api_class, invoked_method)
                    if categories and len(category_samples) < 50:
                        category_samples.append({"class": api_class, "method": invoked_method, "categories": sorted(categories)})
                    for cat in categories:
                        category_totals[cat] = category_totals.get(cat, 0) + 1
                    if categories:
                        calls.append({"index": instruction_index, "api_class": api_class, "method": invoked_method, "categories": categories})

                method_categories = sorted({cat for call in calls for cat in call["categories"]})
                if len(method_categories) >= 2:
                    multi_category_methods += 1
                    if len(multi_category_samples) < 30:
                        multi_category_samples.append({
                            "defining_class": defining_class,
                            "method": str(getattr(method, "get_name", lambda: "unknown")()),
                            "categories": method_categories,
                            "calls": [{"class": c["api_class"], "method": c["method"], "categories": sorted(c["categories"])} for c in calls if c["categories"]][:20],
                        })

                if not calls:
                    continue
                methods_with_api_calls += 1
                found_in_method = False
                for rule in API_CHAIN_RULES:
                    selected = _find_ordered_category_chain(calls, tuple(rule["required_order"]))
                    if not selected:
                        continue
                    found_in_method = True
                    source = selected[0]
                    sink = selected[-1]
                    transform = selected[1] if len(selected) == 3 else None
                    owner_method = str(getattr(method, "get_name", lambda: "unknown")())
                    suspicious_chains.append({
                        "chain": rule["name"],
                        "chain_type": "source_transform_sink" if len(selected) == 3 else "source_sink",
                        "strength": rule["strength"],
                        "risk": rule["risk"],
                        "score": int(rule["score"]),
                        "reason": rule["reason"],
                        "defining_class": defining_class,
                        "method": owner_method,
                        "categories": list(rule["required_order"]),
                        "source_api": source["api_class"],
                        "source_method": source["method"],
                        "transform_api": transform["api_class"] if transform else "",
                        "transform_method": transform["method"] if transform else "",
                        "sink_api": sink["api_class"],
                        "sink_method": sink["method"],
                        "evidence": [{"api_class": it["api_class"], "method": it["method"], "categories": sorted(it["categories"]), "instruction_index": it["index"]} for it in selected],
                    })
                if found_in_method:
                    methods_with_source_sink_candidates += 1

    suspicious_chains.sort(key=lambda item: (-int(item.get("score", 0)), item.get("chain", ""), item.get("defining_class", ""), item.get("method", "")))
    unique: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for finding in suspicious_chains:
        key = (finding.get("chain", ""), finding.get("defining_class", ""), finding.get("method", ""))
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(finding)

    distinct_rules = {item["chain"] for item in unique}
    scoring_chains = [item for item in unique if item.get("strength") in {"STRONG", "MEDIUM"}]
    distinct_scoring_rules = {item["chain"] for item in scoring_chains}
    max_rule_score = max((int(item["score"]) for item in scoring_chains), default=0)
    api_chain_score = 0
    if scoring_chains:
        api_chain_score = min(
            100,
            max_rule_score
            + 12 * max(0, len(distinct_scoring_rules) - 1)
            + 4 * min(4, max(0, len(scoring_chains) - len(distinct_scoring_rules))),
        )

    return {
        "suspicious_chains": unique[:100],
        "chain_count": len(unique),
        "api_chain_score": api_chain_score,
        "malicious_api_chain_score": api_chain_score,
        "api_invocation_count": total_invocations,
        "recognized_api_reference_count": recognized_references,
        "methods_with_api_calls": methods_with_api_calls,
        "strong_chain_count": sum(1 for item in unique if item.get("strength") == "STRONG"),
        "medium_chain_count": sum(1 for item in unique if item.get("strength") == "MEDIUM"),
        "contextual_chain_count": sum(1 for item in unique if item.get("strength") == "CONTEXTUAL"),
        "distinct_rule_count": len(distinct_rules),
        "distinct_scoring_rule_count": len(distinct_scoring_rules),
        "methods_with_source_sink_candidates": methods_with_source_sink_candidates,
        "api_chain_score_status": "EXPERIMENTAL_UNCALIBRATED",
        "api_category_totals": category_totals,
        "api_category_samples": category_samples,
        "raw_api_samples": raw_api_samples,
        "raw_instruction_samples": raw_instruction_samples,
        "multi_category_method_count": multi_category_methods,
        "multi_category_method_samples": multi_category_samples,
    }


def parse_manifest(apk_path: str | Path) -> dict[str, Any]:
    apk_path = Path(apk_path)
    a = APK(str(apk_path))

    api_chain_analysis: dict[str, Any] | None = None
    dex_file_count = 0
    try:
        from modules import behavioral_dna as _bd
        from modules import static_analysis as _sa
        from modules.fast_dex_extractor import fast_extract_all

        m2_fast, chain_fast = fast_extract_all(apk_path, _bd, sa_module=_sa)
        if chain_fast is not None:
            api_chain_analysis = chain_fast
            dex_file_count = int(m2_fast.get("dex_files", 0))
    except Exception:
        api_chain_analysis = None

    if api_chain_analysis is None:
        dex_objects = []
        for raw_dex in a.get_all_dex():
            try:
                dex_objects.append(DEX(raw_dex))
            except Exception:
                continue
        if not dex_objects:
            raise ValueError("No parseable DEX files found in APK.")
        dex_file_count = len(dex_objects)
        api_chain_analysis = extract_api_chains(dex_objects)
    elif dex_file_count <= 0:
        raise ValueError("No parseable DEX files found in APK.")

    permissions = sorted({str(p) for p in (a.get_permissions() or []) if p})
    dangerous_found: list[dict[str, Any]] = []
    permission_score = 0

    for permission in permissions:
        info = DANGEROUS_PERMISSIONS.get(permission)
        if info:
            dangerous_found.append({
                "permission": permission,
                "risk": info["risk"],
                "score": info["score"],
                "reason": info["reason"],
            })
            permission_score += int(info["score"])

    permission_score_raw = permission_score
    max_permission_score = max((int(item["score"]) for item in dangerous_found), default=0)
    remaining_permission_score = max(0, permission_score_raw - max_permission_score)
    permission_risk = min(100, int(round(max_permission_score + 0.35 * remaining_permission_score)))

    combo_alerts = [
        {"combo": combo_name, "reason": combo_reason}
        for combo_perms, combo_name, combo_reason in CRITICAL_COMBOS
        if all(perm in permissions for perm in combo_perms)
    ]

    permission_heatmap = []
    heatmap_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NORMAL": 0}
    for permission in permissions:
        info = DANGEROUS_PERMISSIONS.get(permission)
        if info:
            risk = str(info["risk"])
            score = int(info["score"])
            reason = str(info["reason"])
        else:
            risk = "NORMAL"
            score = 0
            reason = "Declared permission without a configured static risk rule."
        heatmap_counts[risk] = heatmap_counts.get(risk, 0) + 1
        permission_heatmap.append({
            "permission": permission,
            "short_name": permission.rsplit(".", 1)[-1],
            "risk": risk,
            "score": score,
            "reason": reason,
            "declared": True,
        })

    network_raw = extract_urls_and_apis(apk_path)
    network_analysis = classify_network_indicators(network_raw["urls"], network_raw["ips"], network_raw["api_paths"])
    certificate_analysis = analyze_certificates(a)
    exported_analysis = analyze_exported_components(a)

    for getter_name, target_list in (("get_activities", []), ("get_services", []), ("get_receivers", [])):
        try:
            items = list(getattr(a, getter_name)() or [])
        except Exception:
            items = []
        if getter_name == "get_activities":
            activities = items
        elif getter_name == "get_services":
            services = items
        else:
            receivers = items

    component_analysis = analyze_components(activities, services, receivers)
    package_name = _safe_package_name(a.get_package())

    certificate_identity_status = certificate_analysis.get("certificate_identity_status", "unknown")
    observed = {_normalize_fingerprint(str(c.get("sha256", ""))) for c in certificate_analysis.get("certificates", []) if c.get("sha256")}
    bank_record = _load_bank_identity_registry().get(package_name)

    identity_penalty = 0
    bank_identity: dict[str, Any] = {
        "is_known_bank_package": False,
        "package_name": package_name,
        "app_name": "",
        "status": "not_a_configured_bank_package",
        "observed_cert_sha256": sorted(observed),
        "trusted_cert_sha256": [],
        "notes": "",
    }

    if bank_record is not None:
        bank_identity["is_known_bank_package"] = True
        bank_identity["app_name"] = bank_record["app_name"]
        bank_identity["trusted_cert_sha256"] = sorted(bank_record["cert_sha256"])
        bank_identity["notes"] = bank_record["notes"]
        trusted_certs = bank_record["cert_sha256"]
        if not trusted_certs:
            bank_identity["status"] = "bank_package_known_certificate_unconfigured"
            certificate_identity_status = "unknown"
        elif observed & trusted_certs:
            bank_identity["status"] = "verified_package_and_certificate"
            certificate_identity_status = "trusted_match"
        else:
            bank_identity["status"] = "certificate_mismatch"
            certificate_identity_status = "mismatch"
            identity_penalty = 30
            certificate_analysis["certificate_score"] = max(int(certificate_analysis["certificate_score"]), 60)
            certificate_analysis["certificate_findings"].append({
                "risk": "HIGH",
                "score": 60,
                "reason": "Known banking package uses a signing certificate that does not match the trusted certificate set.",
            })

    certificate_analysis["certificate_identity_status"] = certificate_identity_status

    if bank_identity["status"] == "verified_package_and_certificate":
        authenticity = {"score": 100, "status": "VERIFIED", "known_bank": True, "package_match": True, "certificate_match": True, "bank_name": bank_identity.get("app_name", ""), "observed_certificates": bank_identity.get("observed_cert_sha256", []), "trusted_certificates": bank_identity.get("trusted_cert_sha256", []), "reason": "Package name and signing certificate match the configured official banking identity."}
    elif bank_identity["status"] == "certificate_mismatch":
        authenticity = {"score": 0, "status": "CERTIFICATE_MISMATCH", "known_bank": True, "package_match": True, "certificate_match": False, "bank_name": bank_identity.get("app_name", ""), "observed_certificates": bank_identity.get("observed_cert_sha256", []), "trusted_certificates": bank_identity.get("trusted_cert_sha256", []), "reason": "Known banking package uses a signing certificate that does not match the trusted certificate set."}
    elif bank_identity["status"] == "bank_package_known_certificate_unconfigured":
        authenticity = {"score": None, "status": "CERTIFICATE_UNCONFIGURED", "known_bank": True, "package_match": True, "certificate_match": None, "bank_name": bank_identity.get("app_name", ""), "observed_certificates": bank_identity.get("observed_cert_sha256", []), "trusted_certificates": [], "reason": "Bank package is known, but no trusted certificate is configured for verification."}
    else:
        authenticity = {"score": None, "status": "UNVERIFIED", "known_bank": False, "package_match": False, "certificate_match": None, "bank_name": "", "observed_certificates": bank_identity.get("observed_cert_sha256", []), "trusted_certificates": [], "reason": "APK does not match a configured banking identity."}

    endpoint_score = int(network_analysis.get("network_score", 0))
    combo_bonus = min(20, 5 * len(combo_alerts))
    permission_risk_with_combos = min(100, permission_risk + combo_bonus)
    composite = (
        permission_risk_with_combos * 0.50
        + int(certificate_analysis["certificate_score"]) * 0.10
        + int(api_chain_analysis["api_chain_score"]) * 0.25
        + endpoint_score * 0.15
    )
    static_risk_score = min(100, int(round(composite)) + identity_penalty)

    return {
        "module": "static_analysis",
        "status": "complete",
        "package_name": package_name,
        "static_risk_score": static_risk_score,
        "permissions": permissions,
        "all_permissions": permissions,
        "permission_heatmap": permission_heatmap,
        "permission_summary": heatmap_counts,
        "dangerous_permissions": dangerous_found,
        "permission_score": permission_score_raw,
        "permission_score_raw": permission_score_raw,
        "permission_risk_base": permission_risk,
        "permission_risk": permission_risk_with_combos,
        "combo_alerts": combo_alerts,
        "suspicious_api_chains": api_chain_analysis["suspicious_chains"],
        "api_chain_score": api_chain_analysis["api_chain_score"],
        "malicious_api_chain_score": api_chain_analysis["malicious_api_chain_score"],
        "malicious_api_chain": api_chain_analysis["api_chain_score"],
        "api_call_chain_score": api_chain_analysis["api_chain_score"],
        "chain_count": api_chain_analysis["chain_count"],
        "api_invocation_count": api_chain_analysis["api_invocation_count"],
        "recognized_api_reference_count": api_chain_analysis["recognized_api_reference_count"],
        "distinct_scoring_rule_count": api_chain_analysis["distinct_scoring_rule_count"],
        "api_category_totals": api_chain_analysis["api_category_totals"],
        "api_category_samples": api_chain_analysis["api_category_samples"],
        "raw_api_samples": api_chain_analysis["raw_api_samples"],
        "raw_instruction_samples": api_chain_analysis["raw_instruction_samples"],
        "methods_with_api_calls": api_chain_analysis["methods_with_api_calls"],
        "strong_chain_count": api_chain_analysis["strong_chain_count"],
        "medium_chain_count": api_chain_analysis["medium_chain_count"],
        "contextual_chain_count": api_chain_analysis["contextual_chain_count"],
        "distinct_api_chain_rule_count": api_chain_analysis["distinct_rule_count"],
        "methods_with_source_sink_candidates": api_chain_analysis["methods_with_source_sink_candidates"],
        "api_chain_score_status": api_chain_analysis["api_chain_score_status"],
        "network_score": network_analysis.get("network_score", 0),
        "raw_network_score": network_analysis.get("raw_network_score", 0),
        "host_score": network_analysis.get("host_score", 0),
        "http_score": network_analysis.get("http_score", 0),
        "public_ip_score": network_analysis.get("public_ip_score", 0),
        "sensitive_path_score": network_analysis.get("sensitive_path_score", 0),
        "unique_external_host_count": network_analysis.get("unique_external_host_count", 0),
        "http_host_count": network_analysis.get("http_host_count", 0),
        "public_ip_host_count": network_analysis.get("public_ip_host_count", 0),
        "urls": network_raw.get("urls", []),
        "ips": network_raw.get("ips", []),
        "api_paths": network_raw.get("api_paths", []),
        "url_count": len(network_raw.get("urls", [])),
        "ip_count": len(network_raw.get("ips", [])),
        "api_path_count": len(network_raw.get("api_paths", [])),
        "certificate_score": certificate_analysis["certificate_score"],
        "signed": certificate_analysis["signed"],
        "signing_schemes": certificate_analysis["signing_schemes"],
        "certificates": certificate_analysis["certificates"],
        "certificate_findings": certificate_analysis["certificate_findings"],
        "certificate_anomalies": certificate_analysis["certificate_findings"],
        "certificate_identity_status": certificate_analysis["certificate_identity_status"],
        "bank_identity": bank_identity,
        "identity_penalty": identity_penalty,
        "authenticity": authenticity,
        "component_score": component_analysis["component_score"],
        "component_findings": component_analysis["findings"],
        "exported_score": exported_analysis["exported_score"],
        "exported_components": exported_analysis["findings"],
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "dex_files": dex_file_count,
        "analysis_notes": [
            "Static evidence does not by itself establish that an APK is malicious.",
            "Certificate identity is 'unknown' unless a package-specific trusted fingerprint is configured.",
        ],
    }


def analyze_static(apk_path: str) -> dict[str, Any]:
    try:
        return parse_manifest(apk_path)
    except FileNotFoundError as exc:
        return {"module": "static_analysis", "status": "error", "static_risk_score": 0, "error": f"APK not found: {exc}"}
    except zipfile.BadZipFile as exc:
        return {"module": "static_analysis", "status": "error", "static_risk_score": 0, "error": f"Invalid APK/ZIP archive: {exc}"}
    except Exception as exc:
        return {"module": "static_analysis", "status": "error", "static_risk_score": 0, "error": f"{type(exc).__name__}: {exc}"}


check_certificate = analyze_certificates


def _print_summary(result: dict[str, Any]) -> None:
    print(f"Status: {result.get('status')} | Package: {result.get('package_name', '')} | Static risk: {result.get('static_risk_score', 0)}")
    print(f"Permissions: {len(result.get('permissions', []))} | Heatmap entries: {len(result.get('permission_heatmap', []))}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python static_analysis.py <path-to-apk>")
        raise SystemExit(2)
    _print_summary(analyze_static(str(Path(sys.argv[1]))))