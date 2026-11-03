
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


# Keep Androguard output reasonably quiet during normal SPECTRE operation.
set_log("WARNING")


# =============================================================================
# DANGEROUS / RELEVANT PERMISSIONS
# =============================================================================

DANGEROUS_PERMISSIONS: dict[str, dict[str, Any]] = {
    # -------------------------------------------------------------------------
    # High / critical for banking-security analysis
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Medium
    # -------------------------------------------------------------------------
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

    # -------------------------------------------------------------------------
    # Lower risk / context-dependent
    # -------------------------------------------------------------------------
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
# API-CHAIN CATEGORIES
# =============================================================================

# =============================================================================
# API-CHAIN CATEGORIES
# =============================================================================

API_CATEGORY_PREFIXES: dict[str, tuple[str, ...]] = {

    "sms_message": (
        "android.telephony.smsmessage",
    ),

    "sms_provider": (
        "android.provider.telephony",
        "android.provider.browser",
    ),

    "sms_manager": (
        "android.telephony.smsmanager",
    ),

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

    "accessibility": (
        "android.accessibilityservice.",
        "android.view.accessibility.",
    ),

    "window": (
        "android.view.windowmanager",
    ),

    "clipboard": (
        "android.content.clipboardmanager",
    ),

    "contacts": (
        "android.provider.contactscontract",
    ),

    "telephony": (
        "android.telephony.telephonymanager",
    ),

    "credential_ui": (
        "android.widget.edittext",
        "android.widget.textview",
        "android.widget.autocompletetextview",
        "android.view.inputmethod.",
    ),

    "crypto": (
        "javax.crypto.",
        "javax.crypto.spec.",
        "android.security.keystore.",
    ),

    "encoding": (
        "android.util.base64",
        "java.util.base64",
    ),

    "dynamic_code": (
        "dalvik.system.dexclassloader",
        "dalvik.system.pathclassloader",
        "dalvik.system.inmemorydexclassloader",
    ),

    "reflection": (
        "java.lang.class",
        "java.lang.reflect.",
    ),

    "process": (
        "java.lang.runtime",
        "java.lang.processbuilder",
    ),
}


# -------------------------------------------------------------------------
# Method-level qualification
# -------------------------------------------------------------------------

NETWORK_SINK_METHODS = {
    "openConnection",
    "openStream",
    "connect",
    "getInputStream",
    "getOutputStream",
    "getResponseCode",
    "execute",
    "enqueue",
    "newCall",
    "add",
    "request",
    "send",
    "post",
    "put",
    "patch",
    "write",
}

SMS_SOURCE_METHODS = {
    "getMessageBody",
    "getOriginatingAddress",
    "getDisplayOriginatingAddress",
    "getTimestampMillis",
}

SMS_SINK_METHODS = {
    "sendTextMessage",
    "sendMultipartTextMessage",
    "sendDataMessage",
    "sendTextMessageWithoutPersisting",
}

TELEPHONY_SENSITIVE_METHODS = {
    "getDeviceId",
    "getSubscriberId",
    "getImei",
    "getMeid",
    "getSimSerialNumber",
    "getLine1Number",
    "getSimOperator",
    "getSimOperatorName",
    "getNetworkOperator",
    "getNetworkOperatorName",
}

CLIPBOARD_SOURCE_METHODS = {
    "getPrimaryClip",
    "getPrimaryClipDescription",
    "hasPrimaryClip",
}

WINDOW_SINK_METHODS = {
    "addView",
    "addViewImmediate",
    "updateViewLayout",
    "removeView",
    "removeViewImmediate",
}

CREDENTIAL_INPUT_METHODS = {
    "getText",
    "getEditableText",
    "getTextBeforeCursor",
    "getTextAfterCursor",
}

CRYPTO_METHODS = {
    "getInstance",
    "init",
    "doFinal",
    "update",
    "updateAAD",
}

ENCODING_METHODS = {
    "encode",
    "decode",
    "encodeToString",
    "decodeString",
}


# =============================================================================
# API-CHAIN RULES
# =============================================================================

API_CHAIN_RULES = [

    # Strong direct source -> sink
    {
        "required_order": ("sms_message", "network"),
        "name": "SMS_MESSAGE_TO_NETWORK",
        "strength": "STRONG",
        "risk": "CRITICAL",
        "score": 45,
        "reason": (
            "SMS/message data reaches a network sink."
        ),
    },

    {
        "required_order": ("sms_provider", "network"),
        "name": "SMS_PROVIDER_TO_NETWORK",
        "strength": "STRONG",
        "risk": "CRITICAL",
        "score": 45,
        "reason": (
            "SMS/provider data reaches a network sink."
        ),
    },

    {
        "required_order": ("telephony", "network"),
        "name": "TELEPHONY_ID_TO_NETWORK",
        "strength": "STRONG",
        "risk": "HIGH",
        "score": 35,
        "reason": (
            "Sensitive device/telephony identifier reaches a network sink."
        ),
    },

    {
        "required_order": ("clipboard", "network"),
        "name": "CLIPBOARD_TO_NETWORK",
        "strength": "STRONG",
        "risk": "HIGH",
        "score": 35,
        "reason": (
            "Clipboard data reaches a network sink."
        ),
    },

    {
        "required_order": ("accessibility", "network"),
        "name": "ACCESSIBILITY_TO_NETWORK",
        "strength": "STRONG",
        "risk": "HIGH",
        "score": 45,
        "reason": (
            "Accessibility-derived data reaches a network sink."
        ),
    },

    {
        "required_order": ("accessibility", "window"),
        "name": "ACCESSIBILITY_TO_OVERLAY",
        "strength": "STRONG",
        "risk": "CRITICAL",
        "score": 50,
        "reason": (
            "Accessibility activity precedes overlay manipulation."
        ),
    },

    {
        "required_order": ("credential_ui", "network"),
        "name": "CREDENTIAL_INPUT_TO_NETWORK",
        "strength": "STRONG",
        "risk": "CRITICAL",
        "score": 50,
        "reason": (
            "Credential-capable UI input reaches a network sink."
        ),
    },

    # Source -> transform -> sink
    {
        "required_order": ("credential_ui", "crypto", "network"),
        "name": "CREDENTIAL_TO_CRYPTO_TO_NETWORK",
        "strength": "STRONG",
        "risk": "CRITICAL",
        "score": 65,
        "reason": (
            "Credential input is transformed cryptographically before "
            "network transmission."
        ),
    },

    {
        "required_order": ("credential_ui", "encoding", "network"),
        "name": "CREDENTIAL_TO_ENCODING_TO_NETWORK",
        "strength": "STRONG",
        "risk": "CRITICAL",
        "score": 60,
        "reason": (
            "Credential input is encoded before network transmission."
        ),
    },

    {
        "required_order": ("sms_message", "encoding", "network"),
        "name": "SMS_TO_ENCODING_TO_NETWORK",
        "strength": "STRONG",
        "risk": "CRITICAL",
        "score": 60,
        "reason": (
            "SMS data is encoded before network transmission."
        ),
    },

    {
        "required_order": ("telephony", "encoding", "network"),
        "name": "TELEPHONY_TO_ENCODING_TO_NETWORK",
        "strength": "STRONG",
        "risk": "HIGH",
        "score": 50,
        "reason": (
            "Telephony identifier is encoded before network transmission."
        ),
    },

    {
        "required_order": ("clipboard", "encoding", "network"),
        "name": "CLIPBOARD_TO_ENCODING_TO_NETWORK",
        "strength": "STRONG",
        "risk": "HIGH",
        "score": 50,
        "reason": (
            "Clipboard data is encoded before network transmission."
        ),
    },

    # Contextual
    {
        "required_order": ("contacts", "network"),
        "name": "CONTACTS_TO_NETWORK",
        "strength": "CONTEXTUAL",
        "risk": "MEDIUM",
        "score": 25,
        "reason": (
            "Contacts API usage precedes network activity."
        ),
    },

    {
        "required_order": ("dynamic_code", "network"),
        "name": "DYNAMIC_CODE_TO_NETWORK",
        "strength": "CONTEXTUAL",
        "risk": "MEDIUM",
        "score": 20,
        "reason": (
            "Dynamic code loading precedes network activity."
        ),
    },

    

    {
        "required_order": ("process", "network"),
        "name": "PROCESS_TO_NETWORK",
        "strength": "CONTEXTUAL",
        "risk": "HIGH",
        "score": 25,
        "reason": (
            "Process/shell execution precedes network activity."
        ),
    },
]



# =============================================================================
# BANK CERTIFICATE ALLOWLIST
# =============================================================================
#
# Deliberately empty initially. For the real banking-impersonation detector,
# package-specific official certificate SHA-256 fingerprints should eventually
# be populated here from independently verified official apps.
#
# Example:
# TRUSTED_SIGNING_CERTIFICATES = {
#     "com.example.bank": {"AA:BB:..."},
# }
#
# An absent entry produces status='unknown', not 'malicious'.
# =============================================================================

TRUSTED_SIGNING_CERTIFICATES: dict[str, set[str]] = {}

BANK_IDENTITY_REGISTRY_ENV = "SPECTRE_BANK_IDENTITY_REGISTRY"
DEFAULT_BANK_IDENTITY_REGISTRY = (
    Path(__file__).resolve().parents[1] / "config" / "bank_identity_registry.json"
)


def _load_bank_identity_registry() -> dict[str, dict[str, Any]]:
    """Load package -> allowed signing SHA-256 fingerprints."""
    configured = os.environ.get(
        BANK_IDENTITY_REGISTRY_ENV,
        str(DEFAULT_BANK_IDENTITY_REGISTRY),
    )
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
            "cert_sha256": {
                _normalize_fingerprint(str(value))
                for value in certs
                if value
            },
            "notes": str(record.get("notes", "")),
        }

    return registry


# =============================================================================
# GENERAL HELPERS
# =============================================================================

_DESCRIPTOR_RE = re.compile(r"L([A-Za-z0-9_/$.-]+);")
_INVOKE_PREFIX = "invoke-"

_URL_RE_BYTES = re.compile(
    rb"https?://[^\x00\r\n\t <>\"']{4,500}",
    re.IGNORECASE,
)
_IP_RE_BYTES = re.compile(
    rb"(?<![\d.])"
    rb"(?:\d{1,3}\.){3}\d{1,3}"
    rb"(?::\d{1,5})?"
    rb"(?![\d.])"
)
_API_PATH_RE_BYTES = re.compile(
    rb"/(?:api|v\d+|auth|login|register|upload|download|token|user|users|"
    rb"admin|config|data)(?:/[^\x00\r\n\t <>\"']{0,200})?",
    re.IGNORECASE,
)

_IGNORED_URL_PREFIXES = (
    "http://schemas.android.com/",
    "https://schemas.android.com/",
    "http://www.w3.org/",
    "https://www.w3.org/",
)

_INFO_DOMAINS = {
    "google.com",
    "googleapis.com",
    "firebase.google.com",
    "gstatic.com",
    "cloudflare.com",
    "amazon.com",
    "amazonaws.com",
    "android.com",
}


def _iter_dex_objects(dex_objects: Any) -> Iterable[Any]:
    """Normalize AnalyzeAPK's DEX return value to an iterable."""
    if dex_objects is None:
        return ()
    if isinstance(dex_objects, (list, tuple)):
        return dex_objects
    return (dex_objects,)


def _normalize_descriptor(descriptor: str) -> str:
    """Convert Landroid/foo/Bar; into android.foo.Bar."""
    return descriptor.replace("/", ".").replace("$", ".")

_INVOKE_REFERENCE_RE = re.compile(
    r"L(?P<class>[A-Za-z0-9_/$.-]+);->(?P<method>[^\s(:]+)"
)


def _extract_invoke_reference(
    instruction: Any,
) -> tuple[str, str, str]:
    """
    Robustly extract:
        normalized_api_class
        method_name
        raw_instruction_output

    Supports the normal Androguard invoke output form:
        Ljava/net/URL;->openConnection(...)
    """
    try:
        raw_output = str(
            instruction.get_output() or ""
        ).strip()
    except Exception:
        return "", "", ""

    if not raw_output:
        return "", "", ""

    match = _INVOKE_REFERENCE_RE.search(raw_output)

    if match:
        api_class = _normalize_descriptor(
            match.group("class")
        )
        method_name = match.group("method").strip()

        return (
            api_class,
            method_name,
            raw_output,
        )

    # Fallback for slightly different invoke formatting.
    if "->" in raw_output:
        prefix, tail = raw_output.split(
            "->",
            1,
        )

        descriptor_match = _DESCRIPTOR_RE.search(
            prefix
        )

        if descriptor_match:
            api_class = _normalize_descriptor(
                descriptor_match.group(1)
            )

            method_name = re.split(
                r"[\s(:]",
                tail,
                maxsplit=1,
            )[0].strip()

            return (
                api_class,
                method_name,
                raw_output,
            )

    return "", "", raw_output


def _extract_class_from_instruction(
    instruction: Any,
) -> str | None:
    api_class, _, _ = _extract_invoke_reference(
        instruction
    )

    return api_class or None


def _extract_method_name_from_instruction(
    instruction: Any,
) -> str:
    _, method_name, _ = _extract_invoke_reference(
        instruction
    )

    return method_name

def _method_categories(
    api_class: str,
    method_name: str,
) -> set[str]:

    cls = (
        str(api_class)
        .strip()
        .lstrip("L")
        .rstrip(";")
        .replace("/", ".")
        .replace("$", ".")
        .lower()
    )

    method = (
        str(method_name)
        .strip()
        .split("(", 1)[0]
        .split(":", 1)[0]
        .strip()
    )

    categories: set[str] = set()

    # ------------------------------------------------------------------
    # SMS message source
    # ------------------------------------------------------------------
    if cls.startswith(
        "android.telephony.smsmessage"
    ):
        if method in SMS_SOURCE_METHODS:
            categories.add("sms_message")

    # ------------------------------------------------------------------
    # SMS provider
    # ------------------------------------------------------------------
    if cls.startswith(
        "android.provider.telephony"
    ):
        if method in {
            "query",
            "getString",
            "getColumnIndex",
            "getType",
        }:
            categories.add("sms_provider")

    # ------------------------------------------------------------------
    # SMS manager / sending
    # ------------------------------------------------------------------
    if cls.startswith(
        "android.telephony.smsmanager"
    ):
        if method in SMS_SINK_METHODS:
            categories.add("sms_manager")

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------
    if any(
        cls.startswith(prefix.lower())
        for prefix in API_CATEGORY_PREFIXES["network"]
    ):
        if method in NETWORK_SINK_METHODS:
            categories.add("network")

    # ------------------------------------------------------------------
    # Accessibility
    # ------------------------------------------------------------------
    if any(
        cls.startswith(prefix.lower())
        for prefix in API_CATEGORY_PREFIXES["accessibility"]
    ):
        categories.add("accessibility")

    # ------------------------------------------------------------------
    # Overlay / WindowManager
    # ------------------------------------------------------------------
    if cls.startswith(
        "android.view.windowmanager"
    ):
        if method in WINDOW_SINK_METHODS:
            categories.add("window")

    # ------------------------------------------------------------------
    # Clipboard
    # ------------------------------------------------------------------
    if cls.startswith(
        "android.content.clipboardmanager"
    ):
        if method in CLIPBOARD_SOURCE_METHODS:
            categories.add("clipboard")

    # ------------------------------------------------------------------
    # Contacts
    # ------------------------------------------------------------------
    if cls.startswith(
        "android.provider.contactscontract"
    ):
        categories.add("contacts")

    # ------------------------------------------------------------------
    # Telephony identifiers
    # ------------------------------------------------------------------
    if cls.startswith(
        "android.telephony.telephonymanager"
    ):
        if method in TELEPHONY_SENSITIVE_METHODS:
            categories.add("telephony")

    # ------------------------------------------------------------------
    # Credential-capable UI
    # ------------------------------------------------------------------
    credential_class = (
        "edittext" in cls
        or "textinputedittext" in cls
        or cls.startswith(
            "android.widget.textview"
        )
        or cls.startswith(
            "android.view.inputmethod"
        )
    )

    if (
        credential_class
        and method in CREDENTIAL_INPUT_METHODS
    ):
        categories.add("credential_ui")

    # AccessibilityNodeInfo text extraction
    if (
        cls.startswith(
            "android.view.accessibility.accessibilitynodeinfo"
        )
        and method in {
            "getText",
            "getContentDescription",
        }
    ):
        categories.add("credential_ui")

    # ------------------------------------------------------------------
    # Cryptography
    # ------------------------------------------------------------------
    if any(
        cls.startswith(prefix.lower())
        for prefix in API_CATEGORY_PREFIXES["crypto"]
    ):
        if method in CRYPTO_METHODS:
            categories.add("crypto")

    # ------------------------------------------------------------------
    # Encoding
    # ------------------------------------------------------------------
    if any(
        cls.startswith(prefix.lower())
        for prefix in API_CATEGORY_PREFIXES["encoding"]
    ):
        if method in ENCODING_METHODS:
            categories.add("encoding")

    # ------------------------------------------------------------------
    # Dynamic code loading
    # ------------------------------------------------------------------
    if any(
        cls.startswith(prefix.lower())
        for prefix in API_CATEGORY_PREFIXES["dynamic_code"]
    ):
        categories.add("dynamic_code")

    # ------------------------------------------------------------------
    # Reflection
    # ------------------------------------------------------------------
    if any(
        cls.startswith(prefix.lower())
        for prefix in API_CATEGORY_PREFIXES["reflection"]
    ):
        if method in {
            "forName",
            "getDeclaredMethod",
            "getMethod",
            "invoke",
            "setAccessible",
        }:
            categories.add("reflection")

    # ------------------------------------------------------------------
    # Process execution
    # ------------------------------------------------------------------
    if any(
        cls.startswith(prefix.lower())
        for prefix in API_CATEGORY_PREFIXES["process"]
    ):
        if method in {
            "exec",
            "start",
        }:
            categories.add("process")

    return categories

def _find_ordered_category_chain(
    calls: list[dict[str, Any]],
    required_order: tuple[str, ...],) -> list[dict[str, Any]] | None:

    selected = []
    last_position = -1

    for required_category in required_order:

        found = None

        for position in range(
            last_position + 1,
            len(calls),
        ):

            if (
                required_category
                in calls[position]["categories"]
            ):
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


def _normalize_fingerprint(value: str) -> str:
    return value.replace(":", "").replace(" ", "").lower()


def _valid_ipv4(value: str) -> bool:
    try:
        ipaddress.ip_address(value.split(":", 1)[0])
        return True
    except ValueError:
        return False


# =============================================================================
# URL / IP / API-PATH EXTRACTION
# =============================================================================

def _scan_dex_bytes_for_network_indicators(
    dex_bytes: bytes,
) -> tuple[set[str], set[str], set[str]]:
    """
    Extract static network indicators from printable DEX strings.

    IP extraction is deliberately conservative:
      - accept IPs used as URL hosts;
      - accept a standalone public/global IP string;
      - reject private/loopback/reserved/link-local addresses;
      - do not treat arbitrary digit patterns inside obfuscated strings as IPs.

    This reduces the very large false-positive IP counts seen in some APKs.
    """
    urls: set[str] = set()
    ips: set[str] = set()
    api_paths: set[str] = set()

    printable_strings = re.findall(rb"[\x20-\x7e]{5,600}", dex_bytes)

    url_re = re.compile(
        r"https?://[^\s\"'<>]{4,500}",
        re.IGNORECASE,
    )
    ip_re = re.compile(
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\d.])"
    )
    api_re = re.compile(
        r"/(?:api|v\d+|auth|login|register|upload|download|token|user|users|"
        r"admin|config|data)(?:/[^\s\"'<>]{0,200})?",
        re.IGNORECASE,
    )

    def add_public_ip(candidate: str) -> None:
        candidate = candidate.strip()
        host = candidate.split(":", 1)[0]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return

        # Only count globally routable IPs as C2/network indicators.
        # Private/loopback/link-local/reserved/test addresses are not counted.
        if not address.is_global:
            return

        ips.add(candidate)

    for raw_string in printable_strings:
        value = raw_string.decode("ascii", errors="ignore").strip()
        if not value:
            continue

        # 1) URLs.
        for match in url_re.findall(value):
            url = match.rstrip(".,;)]}>")
            if not url.lower().startswith(("http://", "https://")):
                continue

            if url.lower().startswith(_IGNORED_URL_PREFIXES):
                continue

            urls.add(url)

            # Only take the IP when it is actually the URL host.
            try:
                parsed = urlparse(url)
                host = (parsed.hostname or "").strip()
            except Exception:
                host = ""

            if host:
                add_public_ip(host)

        # 2) Standalone public IP strings only.
        # Do NOT extract arbitrary digit sequences from a long obfuscated string.
        stripped = value.rstrip(".,;)]}>")
        if ip_re.fullmatch(stripped):
            add_public_ip(stripped)

        # 3) API-like paths remain informational.
        for match in api_re.findall(value):
            path = match.rstrip(".,;)]}>")
            if path:
                api_paths.add(path)

    return urls, ips, api_paths


def extract_urls_and_apis(apk_path: str | Path) -> dict[str, Any]:
    """
    Extract statically visible URLs, IPv4 addresses, and API-like paths.

    Raw DEX byte scanning is used rather than dex.get_strings(), which keeps
    M1 more robust against unusual/obfuscated DEX string encodings.
    """
    path = Path(apk_path)
    urls: set[str] = set()
    ips: set[str] = set()
    api_paths: set[str] = set()

    with zipfile.ZipFile(path, "r") as archive:
        dex_names = [
            name
            for name in archive.namelist()
            if re.fullmatch(r"classes\d*\.dex", Path(name).name)
        ]

        for name in dex_names:
            try:
                dex_bytes = archive.read(name)
            except Exception:
                continue

            dex_urls, dex_ips, dex_paths = _scan_dex_bytes_for_network_indicators(
                dex_bytes
            )
            urls.update(dex_urls)
            ips.update(dex_ips)
            api_paths.update(dex_paths)

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "api_paths": sorted(api_paths),
        "url_count": len(urls),
        "ip_count": len(ips),
        "api_path_count": len(api_paths),
    }

def classify_network_indicators(
    urls: Iterable[str],
    ips: Iterable[str],
    api_paths: Iterable[str],
) -> dict[str, Any]:
    """
    Classify static network indicators as evidence only.

    Hard-coded network strings do not prove runtime communication or
    exfiltration.

    Static network evidence is intentionally capped so that legitimate
    banking applications with many endpoints are not automatically
    assigned high network risk.

    Scoring:
      - Unique external hosts:  max 10
      - HTTP hosts:             max 18
      - Public IP hosts:        max 12
      - Sensitive API paths:    max 10
      - Final static network score: max 40
    """

    findings: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Normalize / deduplicate indicators
    # ------------------------------------------------------------------

    url_values = sorted({
        str(url).strip()
        for url in urls
        if str(url).strip()
    })

    ip_values = sorted({
        str(ip).strip()
        for ip in ips
        if str(ip).strip()
    })

    path_values = sorted({
        str(path).strip()
        for path in api_paths
        if str(path).strip()
    })

    # ------------------------------------------------------------------
    # URL / host classification
    # ------------------------------------------------------------------

    parsed_hosts: set[str] = set()
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

        parsed_hosts.add(host)

        is_info_domain = any(
            host == domain or host.endswith("." + domain)
            for domain in _INFO_DOMAINS
        )

        if is_info_domain:
            findings.append(
                {
                    "indicator": url,
                    "type": "url",
                    "risk": "INFO",
                    "score": 0,
                    "reason": (
                        "Common infrastructure domain; not treated as "
                        "suspicious by this static rule."
                    ),
                }
            )
            continue

        # Unique external host evidence
        external_hosts.add(host)

        if scheme == "http":
            http_hosts.add(host)

            findings.append(
                {
                    "indicator": url,
                    "type": "url",
                    "risk": "MEDIUM",
                    "score": 3,
                    "reason": (
                        "Hard-coded cleartext HTTP URL found in DEX data. "
                        "Runtime behavior is required to establish actual traffic."
                    ),
                }
            )

        else:
            findings.append(
                {
                    "indicator": url,
                    "type": "url",
                    "risk": "LOW",
                    "score": 0,
                    "reason": (
                        "Hard-coded network URL found in APK. Static presence "
                        "does not confirm runtime communication."
                    ),
                }
            )

    # ------------------------------------------------------------------
    # Host score
    # ------------------------------------------------------------------

    host_score = min(10, len(external_hosts))

    # ------------------------------------------------------------------
    # HTTP score
    # ------------------------------------------------------------------

    http_score = min(18, len(http_hosts) * 3)

    # ------------------------------------------------------------------
    # Public IP score
    # ------------------------------------------------------------------

    public_ip_values: set[str] = set()

    for value in ip_values:
        try:
            parsed_ip = ipaddress.ip_address(value)

            if not parsed_ip.is_private and not parsed_ip.is_loopback:
                public_ip_values.add(value)

            findings.append(
                {
                    "indicator": value,
                    "type": "ip",
                    "risk": "MEDIUM",
                    "score": 2,
                    "reason": (
                        "Hard-coded IP address found in DEX data. "
                        "Runtime communication is not confirmed."
                    ),
                }
            )

        except ValueError:
            findings.append(
                {
                    "indicator": value,
                    "type": "ip",
                    "risk": "INFO",
                    "score": 0,
                    "reason": "Value could not be parsed as a valid IP address.",
                }
            )

    public_ip_score = min(12, len(public_ip_values) * 2)

    # ------------------------------------------------------------------
    # Sensitive API-path evidence
    # ------------------------------------------------------------------

    sensitive_path_count = 0

    for path in path_values:
        lower_path = path.lower()

        # Use your existing sensitive-path patterns here if already defined.
        is_sensitive = any(
            token in lower_path
            for token in (
                "/login",
                "/auth",
                "/token",
                "/otp",
                "/password",
                "/credential",
                "/upload",
                "/exfil",
                "/payment",
                "/transfer",
            )
        )

        if is_sensitive:
            sensitive_path_count += 1

            findings.append(
                {
                    "indicator": path,
                    "type": "api_path",
                    "risk": "MEDIUM",
                    "score": 2,
                    "reason": (
                        "Sensitive API-like path found in static strings. "
                        "Static presence does not establish runtime use."
                    ),
                }
            )
        else:
            findings.append(
                {
                    "indicator": path,
                    "type": "api_path",
                    "risk": "INFO",
                    "score": 0,
                    "reason": (
                        "API-like path found in static strings; it may be UI "
                        "text, a file path, or an actual endpoint. Runtime "
                        "evidence is required."
                    ),
                }
            )

    sensitive_path_score = min(10, sensitive_path_count * 2)

    # ------------------------------------------------------------------
    # Final static network evidence score
    # ------------------------------------------------------------------

    raw_network_score = (
        host_score
        + http_score
        + public_ip_score
        + sensitive_path_score
    )

    network_score = min(40, raw_network_score)

    # ------------------------------------------------------------------
    # Return
    # ------------------------------------------------------------------

    return {
        "network_score": network_score,
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


# =============================================================================
# CERTIFICATE ANALYSIS
# =============================================================================

def analyze_certificates(apk: Any) -> dict[str, Any]:
    """
    Analyze signing certificates as evidence.

    Important Android-specific rule:
    An ordinary developer-signed application certificate is normally not
    CA-trusted in the browser sense. Therefore "issuer == subject" is NOT,
    by itself, treated as a malicious certificate.
    """
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
            "certificate_findings": [
                {
                    "risk": "HIGH",
                    "score": 50,
                    "reason": "APK does not contain a detectable signing certificate.",
                }
            ],
            "certificate_identity_status": "invalid_or_unknown",
        }

    for scheme_name, checker_name in (
        ("v1", "is_signed_v1"),
        ("v2", "is_signed_v2"),
        ("v3", "is_signed_v3"),
        ("v4", "is_signed_v4"),
    ):
        try:
            checker = getattr(apk, checker_name)
            if checker():
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
            "certificate_findings": [
                {
                    "risk": "INFO",
                    "score": 0,
                    "reason": f"Certificate analysis failed: {exc}",
                }
            ],
            "certificate_identity_status": "unknown",
        }

    for cert in raw_certs:
        try:
            sha1 = cert.sha1.hex()
        except Exception:
            sha1 = ""

        try:
            sha256 = cert.sha256.hex()
        except Exception:
            sha256 = ""

        try:
            issuer = str(cert.issuer.human_friendly)
        except Exception:
            issuer = ""

        try:
            subject = str(cert.subject.human_friendly)
        except Exception:
            subject = ""

        cert_record = {
            "sha1": sha1,
            "sha256": sha256,
            "issuer": issuer,
            "subject": subject,
            "hash_algorithm": str(getattr(cert, "hash_algo", "")),
            "signature_algorithm": str(getattr(cert, "signature_algo", "")),
            "serial_number": str(getattr(cert, "serial_number", "")),
        }

        certificates.append(cert_record)

        combined = f"{issuer} {subject}".lower()

        # Debug certificate detection is meaningful evidence.
        if "android debug" in combined or "androiddebugkey" in combined:
            certificate_score += 25
            findings.append(
                {
                    "risk": "HIGH",
                    "score": 25,
                    "reason": (
                        "Certificate appears to use a standard Android debug "
                        "signing identity."
                    ),
                    "sha256": sha256,
                }
            )

        # Very short validity is only a weak anomaly signal.
        try:
            validity_days = (
                cert.not_valid_after - cert.not_valid_before
            ).days
        except Exception:
            validity_days = None

        if validity_days is not None and validity_days <= 30:
            certificate_score += 10
            findings.append(
                {
                    "risk": "MEDIUM",
                    "score": 10,
                    "reason": (
                        f"Certificate validity is unusually short ({validity_days} days)."
                    ),
                    "sha256": sha256,
                }
            )

    if not findings:
        findings.append(
            {
                "risk": "INFO",
                "score": 0,
                "reason": (
                    "Signing certificate information extracted. A normal "
                    "developer certificate is not treated as suspicious by itself."
                ),
            }
        )

    return {
        "certificate_score": min(100, certificate_score),
        "signed": signed,
        "signing_schemes": signing_schemes,
        "certificates": certificates,
        "certificate_findings": findings,
        "certificate_identity_status": "unknown",
    }


# =============================================================================
# EXPORT EXPORTED COMPONENTS
# =============================================================================

def analyze_exported_components(apk: Any) -> dict[str, Any]:
    """
    Analyze explicitly exported Android components.

    Exported components are common in legitimate apps, so the score remains
    conservative and depends on component type / custom intent exposure.
    """
    findings: list[dict[str, Any]] = []
    exported_score = 0

    try:
        manifest = apk.get_android_manifest_xml()
    except Exception as exc:
        return {
            "exported_score": 0,
            "findings": [
                {
                    "risk": "INFO",
                    "score": 0,
                    "reason": f"Exported-component analysis failed: {exc}",
                }
            ],
        }

    android_ns = "{http://schemas.android.com/apk/res/android}"
    component_types = ("activity", "service", "receiver", "provider")

    for component_type in component_types:
        for component in manifest.findall(
            f".//application/{component_type}"
        ):
            exported = component.get(f"{android_ns}exported")
            if exported != "true":
                continue

            name = component.get(f"{android_ns}name", "unknown")
            intent_filters: list[dict[str, Any]] = []

            for intent_filter in component.findall("intent-filter"):
                actions: list[str] = []
                categories: list[str] = []
                data: list[dict[str, str]] = []

                for action in intent_filter.findall("action"):
                    value = action.get(f"{android_ns}name")
                    if value:
                        actions.append(value)

                for category in intent_filter.findall("category"):
                    value = category.get(f"{android_ns}name")
                    if value:
                        categories.append(value)

                for data_element in intent_filter.findall("data"):
                    item: dict[str, str] = {}
                    for attribute in (
                        "scheme",
                        "host",
                        "port",
                        "path",
                        "pathPrefix",
                        "mimeType",
                    ):
                        value = data_element.get(f"{android_ns}{attribute}")
                        if value:
                            item[attribute] = value
                    if item:
                        data.append(item)

                intent_filters.append(
                    {
                        "actions": actions,
                        "categories": categories,
                        "data": data,
                    }
                )

            has_launcher = any(
                "android.intent.action.MAIN" in f["actions"]
                and "android.intent.category.LAUNCHER" in f["categories"]
                for f in intent_filters
            )

            score = 2 if has_launcher and component_type == "activity" else 0
            risk = "LOW" if score else "INFO"
            reason = (
                "Explicitly exported launcher activity."
                if score
                else "Explicitly exported component; exported status alone is not malicious."
            )

            custom_action = any(
                action and not action.startswith("android.intent.")
                for f in intent_filters
                for action in f["actions"]
            )

            if custom_action:
                score = max(score, 5)
                risk = "MEDIUM"
                reason = (
                    "Explicitly exported component exposes at least one custom "
                    "intent action."
                )

            if component_type in {"service", "receiver", "provider"} and not has_launcher:
                score = max(score, 3)
                risk = "LOW"
                reason = (
                    f"Explicitly exported {component_type}; corroborating evidence "
                    "is required."
                )

            findings.append(
                {
                    "component": name,
                    "type": component_type,
                    "exported": True,
                    "risk": risk,
                    "score": score,
                    "intent_filters": intent_filters,
                    "reason": reason,
                }
            )
            exported_score += score

    return {
        "exported_score": min(100, exported_score),
        "findings": findings[:200],
    }


# =============================================================================
# COMPONENT NAME HEURISTICS
# =============================================================================

def analyze_components(
    activities: Iterable[str],
    services: Iterable[str],
    receivers: Iterable[str],
) -> dict[str, Any]:
    """Apply conservative name-based heuristics to manifest components."""
    findings: list[dict[str, Any]] = []
    component_score = 0

    all_components: list[tuple[str, str]] = []
    all_components.extend(("activity", value) for value in activities)
    all_components.extend(("service", value) for value in services)
    all_components.extend(("receiver", value) for value in receivers)

    for component_type, component_name in all_components:
        lowered = component_name.lower()

        matched: str | None = None
        if "accessibility" in lowered:
            matched = "accessibility"
        elif "vpn" in lowered:
            matched = "vpn"
        elif "sms" in lowered:
            matched = "sms"
        elif "overlay" in lowered:
            matched = "overlay"

        if matched is None:
            continue

        info = SUSPICIOUS_COMPONENTS[matched]
        findings.append(
            {
                "component": component_name,
                "type": component_type,
                "risk": info["risk"],
                "score": info["score"],
                "reason": info["reason"],
            }
        )
        component_score += int(info["score"])

    return {
        "component_score": min(100, component_score),
        "findings": findings[:200],
    }


# =============================================================================
# SUSPICIOUS API-CHAIN DETECTION
# =============================================================================

def extract_api_chains(
    dex_objects: Any,
) -> dict[str, Any]:

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
                defining_class = _normalize_descriptor(
                    str(
                        cls.get_name()
                    ).strip("L;")
                )
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

                for instruction_index, instruction in enumerate(
                    instructions
                ):

                    try:
                        opcode_name = str(
                            instruction.get_name()
                        ).lower()
                    except Exception:
                        continue

                    if not opcode_name.startswith(
                        _INVOKE_PREFIX
                    ):
                        continue

                    total_invocations += 1

                    api_class, invoked_method, raw_output = (
                        _extract_invoke_reference(
                            instruction
                        )
                    )

                    # Always retain raw invoke evidence for diagnostics.
                    if len(raw_instruction_samples) < 30:
                        raw_instruction_samples.append(
                            {
                                "index": instruction_index,
                                "raw": raw_output,
                                "class": api_class,
                                "method": invoked_method,
                            }
                        )

                    if not api_class:
                        continue

                    recognized_references += 1

                    if len(raw_api_samples) < 50:
                        raw_api_samples.append(
                            {
                                "class": api_class,
                                "method": invoked_method,
                            }
                        )

                    categories = _method_categories(
                        api_class,
                        invoked_method,
                    )

                    if categories and len(category_samples) < 50:
                        category_samples.append({
                            "class": api_class,
                            "method": invoked_method,
                            "categories": sorted(categories),
                        })

                    for category in categories:
                        category_totals[category] = (
                            category_totals.get(
                                category,
                                0,
                            )
                            + 1
                        )

                    if not categories:
                        continue

                    calls.append(
                        {
                            "index": instruction_index,
                            "api_class": api_class,
                            "method": invoked_method,
                            "categories": categories,
                        }
                    )
                method_categories = sorted({
                    category
                    for call in calls
                    for category in call["categories"]
                })

                if len(method_categories) >= 2:
                    multi_category_methods += 1

                    if len(multi_category_samples) < 30:
                        multi_category_samples.append({
                            "defining_class": defining_class,
                            "method": str(
                                getattr(method, "get_name", lambda: "unknown")()
                            ),
                            "categories": method_categories,
                            "calls": [
                                {
                                    "class": call["api_class"],
                                    "method": call["method"],
                                    "categories": sorted(
                                        call["categories"]
                                    ),
                                }
                                for call in calls
                                if call["categories"]
                            ][:20],
                        })
                if not calls:
                    continue

                methods_with_api_calls += 1

                found_in_method = False

                for rule in API_CHAIN_RULES:

                    selected = _find_ordered_category_chain(
                        calls,
                        tuple(
                            rule["required_order"]
                        ),
                    )

                    if not selected:
                        continue

                    found_in_method = True

                    source = selected[0]
                    sink = selected[-1]

                    transform = (
                        selected[1]
                        if len(selected) == 3
                        else None
                    )

                    try:
                        owner_method = str(
                            method.get_name()
                        )
                    except Exception:
                        owner_method = "unknown"

                    suspicious_chains.append(
                        {
                            "chain": rule["name"],
                            "chain_type": (
                                "source_transform_sink"
                                if len(selected) == 3
                                else "source_sink"
                            ),
                            "strength": rule["strength"],
                            "risk": rule["risk"],
                            "score": int(
                                rule["score"]
                            ),
                            "reason": rule["reason"],
                            "defining_class": defining_class,
                            "method": owner_method,
                            "categories": list(
                                rule["required_order"]
                            ),

                            "source_api": source[
                                "api_class"
                            ],
                            "source_method": source[
                                "method"
                            ],

                            "transform_api": (
                                transform[
                                    "api_class"
                                ]
                                if transform
                                else ""
                            ),
                            "transform_method": (
                                transform[
                                    "method"
                                ]
                                if transform
                                else ""
                            ),

                            "sink_api": sink[
                                "api_class"
                            ],
                            "sink_method": sink[
                                "method"
                            ],

                            "evidence": [
                                {
                                    "api_class": item[
                                        "api_class"
                                    ],
                                    "method": item[
                                        "method"
                                    ],
                                    "categories": sorted(
                                        item[
                                            "categories"
                                        ]
                                    ),
                                    "instruction_index": item[
                                        "index"
                                    ],
                                }
                                for item in selected
                            ],
                        }
                    )

                if found_in_method:
                    methods_with_source_sink_candidates += 1

    # ------------------------------------------------------------------
    # Sort
    # ------------------------------------------------------------------

    suspicious_chains.sort(
        key=lambda item: (
            -int(
                item.get(
                    "score",
                    0,
                )
            ),
            item.get(
                "chain",
                "",
            ),
            item.get(
                "defining_class",
                "",
            ),
            item.get(
                "method",
                "",
            ),
        )
    )

    # ------------------------------------------------------------------
    # De-duplicate same rule/method
    # ------------------------------------------------------------------

    unique: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()

    for finding in suspicious_chains:

        key = (
            finding.get("chain", ""),
            finding.get(
                "defining_class",
                "",
            ),
            finding.get(
                "method",
                "",
            ),
        )

        if key in seen_keys:
            continue

        seen_keys.add(key)
        unique.append(finding)

    distinct_rules = {
        item["chain"]
        for item in unique
    }

    # ------------------------------------------------------------------
    # ONLY STRONG / MEDIUM chains affect the score.
    # CONTEXTUAL chains remain telemetry only.
    # ------------------------------------------------------------------

    scoring_chains = [
        item
        for item in unique
        if item.get("strength")
        in {
            "STRONG",
            "MEDIUM",
        }
    ]

    distinct_scoring_rules = {
        item["chain"]
        for item in scoring_chains
    }

    max_rule_score = max(
        (
            int(item["score"])
            for item in scoring_chains
        ),
        default=0,
    )

    api_chain_score = 0

    if scoring_chains:
        api_chain_score = min(
            100,
            max_rule_score
            + 12 * max(
                0,
                len(
                    distinct_scoring_rules
                ) - 1,
            )
            + 4 * min(
                4,
                max(
                    0,
                    len(scoring_chains)
                    - len(
                        distinct_scoring_rules
                    ),
                ),
            ),
        )

    strong_count = sum(
        item.get("strength") == "STRONG"
        for item in unique
    )

    medium_count = sum(
        item.get("strength") == "MEDIUM"
        for item in unique
    )

    contextual_count = sum(
        item.get("strength") == "CONTEXTUAL"
        for item in unique
    )

    return {
        "suspicious_chains": unique[:100],
        "chain_count": len(unique),

        "api_chain_score": api_chain_score,
        "malicious_api_chain_score": api_chain_score,

        "api_invocation_count": total_invocations,
        "recognized_api_reference_count": recognized_references,

        "methods_with_api_calls": methods_with_api_calls,

        "strong_chain_count": strong_count,
        "medium_chain_count": medium_count,
        "contextual_chain_count": contextual_count,

        "distinct_rule_count": len(
            distinct_rules
        ),

        "distinct_scoring_rule_count": len(
            distinct_scoring_rules
        ),

        "methods_with_source_sink_candidates": (
            methods_with_source_sink_candidates
        ),

        "api_chain_score_status":
            "EXPERIMENTAL_UNCALIBRATED",

        "api_category_totals":
            category_totals,

        "api_category_samples":
            category_samples,

        "raw_api_samples":
            raw_api_samples,

        "raw_instruction_samples":
            raw_instruction_samples,
        "multi_category_method_count": multi_category_methods,
        "multi_category_method_samples": multi_category_samples,
    }


# =============================================================================
# MANIFEST PARSER / ASSEMBLER
# =============================================================================

def parse_manifest(apk_path: str | Path) -> dict[str, Any]:
    """
    Parse the manifest and assemble static evidence using one AnalyzeAPK call.
    """
    apk_path = Path(apk_path)

    # IMPORTANT: AnalyzeAPK() also constructs the Analysis/xref/basic-block
    # object. M1 does not need that graph, and those basic-block calculations
    # were a major source of multi-minute/hanging runs on complex banking APKs.
    # Parse the APK metadata and DEX files separately instead.
    a = APK(str(apk_path))

    dex_objects = []
    for raw_dex in a.get_all_dex():
        try:
            dex_objects.append(DEX(raw_dex))
        except Exception as exc:
            # Keep static metadata available even if one DEX cannot be parsed.
            # Record the parse problem in the returned result below.
            continue

    if not dex_objects:
        raise ValueError("No parseable DEX files found in APK.")

    permissions = sorted(
        {
            str(permission)
            for permission in (a.get_permissions() or [])
            if permission
        }
    )

    dangerous_found: list[dict[str, Any]] = []
    permission_score = 0

    for permission in permissions:
        info = DANGEROUS_PERMISSIONS.get(permission)
        if not info:
            continue

        dangerous_found.append(
            {
                "permission": permission,
                "risk": info["risk"],
                "score": info["score"],
                "reason": info["reason"],
            }
        )
        permission_score += int(info["score"])

    permission_score_raw = permission_score
    max_permission_score = max(
        (int(item["score"]) for item in dangerous_found),
        default=0,
    )
    remaining_permission_score = max(
        0,
        permission_score_raw - max_permission_score,
    )

    # Diminishing-returns permission risk prevents a legitimate banking app
    # requesting many capabilities from automatically saturating at 100.
    permission_risk = min(
        100,
        int(
            round(
                max_permission_score
                + 0.35 * remaining_permission_score
            )
        ),
    )

    combo_alerts: list[dict[str, Any]] = []
    for combo_perms, combo_name, combo_reason in CRITICAL_COMBOS:
        if all(permission in permissions for permission in combo_perms):
            combo_alerts.append(
                {
                    "combo": combo_name,
                    "reason": combo_reason,
                }
            )

    # Frontend-ready permission heatmap. Every declared permission gets an
    # explicit state so the UI does not need hard-coded demo values.
    permission_heatmap = []
    heatmap_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "NORMAL": 0,
    }

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

        permission_heatmap.append(
            {
                "permission": permission,
                "short_name": permission.rsplit(".", 1)[-1],
                "risk": risk,
                "score": score,
                "reason": reason,
                "declared": True,
            }
        )

    network_raw = extract_urls_and_apis(apk_path)
    network_analysis = classify_network_indicators(
        network_raw["urls"],
        network_raw["ips"],
        network_raw["api_paths"],
    )

    certificate_analysis = analyze_certificates(a)
    exported_analysis = analyze_exported_components(a)

    try:
        activities = list(a.get_activities() or [])
    except Exception:
        activities = []

    try:
        services = list(a.get_services() or [])
    except Exception:
        services = []

    try:
        receivers = list(a.get_receivers() or [])
    except Exception:
        receivers = []

    component_analysis = analyze_components(
        activities,
        services,
        receivers,
    )

    api_chain_analysis = extract_api_chains(dex_objects)
    

    package_name = _safe_package_name(a.get_package())

    # Package + signing-certificate identity verification.
    # This is especially important for bank-app impersonation detection:
    # matching a bank package name alone is not enough.
    certificate_identity_status = certificate_analysis.get(
        "certificate_identity_status",
        "unknown",
    )

    certs = certificate_analysis.get("certificates", [])
    observed = {
        _normalize_fingerprint(str(cert.get("sha256", "")))
        for cert in certs
        if cert.get("sha256")
    }

    bank_registry = _load_bank_identity_registry()
    bank_record = bank_registry.get(package_name)

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
        bank_identity["trusted_cert_sha256"] = sorted(
            bank_record["cert_sha256"]
        )
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
            certificate_analysis["certificate_score"] = max(
                int(certificate_analysis["certificate_score"]),
                60,
            )
            certificate_analysis["certificate_findings"].append(
                {
                    "risk": "HIGH",
                    "score": 60,
                    "reason": (
                        "The package name matches a configured banking app, "
                        "but the observed signing certificate does not match "
                        "the trusted certificate set. This is an impersonation/"
                        "repackaging candidate and requires verification."
                    ),
                }
            )

    certificate_analysis["certificate_identity_status"] = (
        certificate_identity_status
    )

    # -------------------------------------------------------------------------
    # Authenticity result
    # -------------------------------------------------------------------------

    if bank_identity["status"] == "verified_package_and_certificate":

        authenticity = {
            "score": 100,
            "status": "VERIFIED",
            "known_bank": True,
            "package_match": True,
            "certificate_match": True,
            "bank_name": bank_identity.get("app_name", ""),
            "observed_certificates": bank_identity.get(
                "observed_cert_sha256", []
            ),
            "trusted_certificates": bank_identity.get(
                "trusted_cert_sha256", []
            ),
            "reason": (
                "Package name and signing certificate match the "
                "configured official banking identity."
            ),
        }

    elif bank_identity["status"] == "certificate_mismatch":

        authenticity = {
            "score": 0,
            "status": "CERTIFICATE_MISMATCH",
            "known_bank": True,
            "package_match": True,
            "certificate_match": False,
            "bank_name": bank_identity.get("app_name", ""),
            "observed_certificates": bank_identity.get(
                "observed_cert_sha256", []
            ),
            "trusted_certificates": bank_identity.get(
                "trusted_cert_sha256", []
            ),
            "reason": (
                "Known banking package uses a signing certificate that "
                "does not match the trusted certificate set."
            ),
        }

    elif bank_identity["status"] == "bank_package_known_certificate_unconfigured":

        authenticity = {
            "score": None,
            "status": "CERTIFICATE_UNCONFIGURED",
            "known_bank": True,
            "package_match": True,
            "certificate_match": None,
            "bank_name": bank_identity.get("app_name", ""),
            "observed_certificates": bank_identity.get(
                "observed_cert_sha256", []
            ),
            "trusted_certificates": [],
            "reason": (
                "Bank package is known, but no trusted certificate "
                "is configured for verification."
            ),
        }

    else:

        authenticity = {
            "score": None,
            "status": "UNVERIFIED",
            "known_bank": False,
            "package_match": False,
            "certificate_match": None,
            "bank_name": "",
            "observed_certificates": bank_identity.get(
                "observed_cert_sha256", []
            ),
            "trusted_certificates": [],
            "reason": (
                "APK does not match a configured banking identity."
            ),
        }
    # Module-local composite score follows the documented M1 design:
    #   50% contextual permission risk
    #   10% certificate evidence
    #   25% suspicious API chains
    #   15% static endpoint evidence
    #
    # No hard 85-point floor is applied for permission combinations because
    # legitimate banking apps can legitimately request combinations such as
    # SMS + camera + location. The combination is retained as explicit evidence.
    endpoint_hosts = set()
    for url in network_raw["urls"]:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            host = ""
        if host and not (
            any(
                host == domain or host.endswith("." + domain)
                for domain in _INFO_DOMAINS
            )
        ):
            endpoint_hosts.add(host)

    http_urls = sum(
        1
        for url in network_raw["urls"]
        if url.lower().startswith("http://")
    )

    endpoint_score = int(network_analysis.get("network_score", 0))

    combo_bonus = min(20, 5 * len(combo_alerts))
    permission_risk_with_combos = min(
        100,
        permission_risk + combo_bonus,
    )

    composite = (
        permission_risk_with_combos * 0.50
        + int(certificate_analysis["certificate_score"]) * 0.10
        + int(api_chain_analysis["api_chain_score"]) * 0.25
        + endpoint_score * 0.15
    )

    # Certificate mismatch on a known banking package is a targeted,
    # bank-impersonation signal rather than a generic APK signal.
    static_risk_score = min(
        100,
        int(round(composite)) + identity_penalty,
    )

    return {
        # Compatibility / module identity
        "module": "static_analysis",
        "status": "complete",
        "package_name": package_name,

        # Static composite
        "static_risk_score": static_risk_score,

        # Permissions
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

       # API-chain evidence
        "suspicious_api_chains": api_chain_analysis["suspicious_chains"],
        "api_chain_score": api_chain_analysis["api_chain_score"],
        "malicious_api_chain_score": api_chain_analysis[
            "malicious_api_chain_score"
        ],
        "malicious_api_chain": api_chain_analysis["api_chain_score"],
        "api_call_chain_score": api_chain_analysis["api_chain_score"],
        "chain_count": api_chain_analysis["chain_count"],
        "api_invocation_count": api_chain_analysis["api_invocation_count"],
        "recognized_api_reference_count": api_chain_analysis[
            "recognized_api_reference_count"
        ],

        "distinct_scoring_rule_count": api_chain_analysis[
            "distinct_scoring_rule_count"
        ],

        "api_category_totals": api_chain_analysis[
            "api_category_totals"
        ],

        "api_category_samples": api_chain_analysis[
            "api_category_samples"
        ],

        "raw_api_samples": api_chain_analysis[
            "raw_api_samples"
        ],

        "raw_instruction_samples": api_chain_analysis[
            "raw_instruction_samples"
        ],
        "methods_with_api_calls": api_chain_analysis[
            "methods_with_api_calls"
        ],

        "strong_chain_count": api_chain_analysis[
            "strong_chain_count"
        ],

        "medium_chain_count": api_chain_analysis[
            "medium_chain_count"
        ],

        "contextual_chain_count": api_chain_analysis[
            "contextual_chain_count"
        ],

        "distinct_api_chain_rule_count": api_chain_analysis[
            "distinct_rule_count"
        ],

        "methods_with_source_sink_candidates": (
            api_chain_analysis[
                "methods_with_source_sink_candidates"
            ]
        ),

        "api_chain_score_status": (
            api_chain_analysis[
                "api_chain_score_status"
            ]
        ),

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

        # Certificates
        "certificate_score": certificate_analysis["certificate_score"],
        "signed": certificate_analysis["signed"],
        "signing_schemes": certificate_analysis["signing_schemes"],
        "certificates": certificate_analysis["certificates"],
        "certificate_findings": certificate_analysis["certificate_findings"],
        "certificate_anomalies": certificate_analysis["certificate_findings"],
        "certificate_identity_status": certificate_analysis[
            "certificate_identity_status"
        ],
        "bank_identity": bank_identity,
        "identity_penalty": identity_penalty,
        "authenticity": authenticity,

        # Components
        "component_score": component_analysis["component_score"],
        "component_findings": component_analysis["findings"],
        "exported_score": exported_analysis["exported_score"],
        "exported_components": exported_analysis["findings"],

        # Manifest component inventory
        "activities": activities,
        "services": services,
        "receivers": receivers,

        # Useful metadata
        "dex_files": len(dex_objects),
        "analysis_notes": [
            (
                "Static evidence does not by itself establish that an APK is "
                "malicious."
            ),
            (
                "Certificate identity is 'unknown' unless a package-specific "
                "trusted fingerprint is configured."
            ),
        ],
    }


# =============================================================================
# MASTER M1 API
# =============================================================================

def analyze_static(apk_path: str) -> dict[str, Any]:
    """
    Master Module 1 entry point.

    Signature intentionally remains:
        analyze_static(apk_path)

    so the existing SPECTRE pipeline can call it without modification.
    """
    try:
        result = parse_manifest(apk_path)
        return result
    except FileNotFoundError as exc:
        return {
            "module": "static_analysis",
            "status": "error",
            "static_risk_score": 0,
            "error": f"APK not found: {exc}",
        }
    except zipfile.BadZipFile as exc:
        return {
            "module": "static_analysis",
            "status": "error",
            "static_risk_score": 0,
            "error": f"Invalid APK/ZIP archive: {exc}",
        }
    except Exception as exc:
        return {
            "module": "static_analysis",
            "status": "error",
            "static_risk_score": 0,
            "error": f"{type(exc).__name__}: {exc}",
        }


# =============================================================================
# BACKWARD-COMPATIBILITY ALIASES
# =============================================================================

# Older drafts / friend code used these names.
check_certificate = analyze_certificates


# =============================================================================
# SIMPLE CLI SMOKE TEST
# =============================================================================

def _print_summary(result: dict[str, Any]) -> None:
    print()
    print("=" * 90)
    print("SPECTRE MODULE 1 — STATIC ANALYSIS")
    print("=" * 90)
    print(f"Status              : {result.get('status')}")
    print(f"Package             : {result.get('package_name', '')}")
    print(f"Static risk score   : {result.get('static_risk_score', 0)}")
    print(f"Permission raw      : {result.get('permission_score_raw', result.get('permission_score', 0))}")
    print(f"Permission risk     : {result.get('permission_risk', 0)}")
    print(f"Heatmap permissions : {len(result.get('permission_heatmap', []))}")
    print(f"Bank identity       : {result.get('bank_identity', {}).get('status', 'unknown')}")
    authenticity = result.get("authenticity", {})
    print(
        f"Authenticity        : "
        f"{authenticity.get('status', 'UNVERIFIED')}"
    )
    print(
        f"Authenticity score  : "
        f"{authenticity.get('score', 'N/A')}"
    )
    print(f"API-chain score     : {result.get('api_chain_score', 0)}")
    print(f"API-chain status    : {result.get('api_chain_score_status', 'UNKNOWN')}")
    print(f"API invocations     : {result.get('api_invocation_count', 0)}")
    print(f"Methods w/API calls : {result.get('methods_with_api_calls', 0)}")
    print(
        f"Strong chains       : "
        f"{result.get('strong_chain_count', 0)}"
    )
    print(
        f"Medium chains       : "
        f"{result.get('medium_chain_count', 0)}"
    )
    print(
        f"Contextual chains   : "
        f"{result.get('contextual_chain_count', 0)}"
    )
    print(
        f"Distinct chain rules: "
        f"{result.get('distinct_api_chain_rule_count', 0)}"
    )
    print(
        f"Source/sink methods : "
        f"{result.get('methods_with_source_sink_candidates', 0)}"
    )
    print(
    f"Recognized API refs : "
    f"{result.get('recognized_api_reference_count', 0)}")

    print(
        f"Scoring chain rules : "
        f"{result.get('distinct_scoring_rule_count', 0)}"
    )

    print(
        f"API categories      : "
        f"{result.get('api_category_totals', {})}"
    )

    if result.get("api_category_samples"):
        print("API category samples:")
        for item in result[
            "api_category_samples"
        ][:15]:
            print(
                f"  {item['class']} -> "
                f"{item['method']} -> "
                f"{item['categories']}"
            )

    if result.get("raw_api_samples"):
        print("RAW API SAMPLES:")
        for item in result[
            "raw_api_samples"
        ][:20]:
            print(
                f"  {item['class']} -> "
                f"{item['method']}"
            )

    if result.get("raw_instruction_samples"):
        print("RAW INSTRUCTION SAMPLES:")
        for item in result[
            "raw_instruction_samples"
        ][:10]:
            print(
                f"  [{item['index']}] "
                f"{item['raw']}"
            )
    print(f"Network score       : {result.get('network_score', 0)}")
    print(f"  ├─ Raw score       : {result.get('raw_network_score', 0)}")
    print(f"  ├─ Host score      : {result.get('host_score', 0)}")
    print(f"  ├─ HTTP score      : {result.get('http_score', 0)}")
    print(f"  ├─ Public IP score : {result.get('public_ip_score', 0)}")
    print(f"  └─ API path score  : {result.get('sensitive_path_score', 0)}")
    print(f"Unique ext. hosts   : {result.get('unique_external_host_count', 0)}")
    print(f"HTTP hosts          : {result.get('http_host_count', 0)}")
    print(f"Public IP hosts     : {result.get('public_ip_host_count', 0)}")
    print(f"Certificate score   : {result.get('certificate_score', 0)}")
    print(f"Exported score      : {result.get('exported_score', 0)}")
    print(f"Dangerous perms     : {len(result.get('dangerous_permissions', []))}")
    print(f"Suspicious chains   : {len(result.get('suspicious_api_chains', []))}")
    print(f"URLs                : {result.get('url_count', 0)}")
    print(f"IPs                 : {result.get('ip_count', 0)}")
    print(f"Exported components : {len(result.get('exported_components', []))}")
    print(
        f"Certificate identity: "
        f"{result.get('certificate_identity_status', 'unknown')}"
    )
    print(
    f"Multi-category methods: "
    f"{result.get('multi_category_method_count', 0)}"
)
    if result.get("multi_category_method_samples"):
        print("MULTI-CATEGORY METHOD SAMPLES:")
        for item in result[
            "multi_category_method_samples"
        ][:10]:
            print(
                f"  {item['defining_class']} -> "
                f"{item['method']} -> "
                f"{item['categories']}"
            )

            for call in item["calls"]:
                print(
                    f"      {call['class']} -> "
                    f"{call['method']} -> "
                    f"{call['categories']}"
                )

    if result.get("combo_alerts"):
        print()
        print("CRITICAL / HIGH-VALUE PERMISSION COMBINATIONS")
        print("-" * 90)
        for item in result["combo_alerts"]:
            print(f"- {item['combo']}: {item['reason']}")

    if result.get("suspicious_api_chains"):
        print()
        print("TOP SUSPICIOUS API CHAINS")
        print("-" * 90)
        for item in result["suspicious_api_chains"][:10]:
            print(
                f"- {item['chain']} | "
                f"{item['risk']} | "
                f"{item['defining_class']}::{item['method']}"
            )

    if result.get("status") == "error":
        print()
        print(f"ERROR: {result.get('error', '')}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python static_analysis.py <path-to-apk>")
        raise SystemExit(2)

    apk = Path(sys.argv[1])
    _print_summary(analyze_static(str(apk)))
