from __future__ import annotations

import contextlib
import io
import logging
import re
import zipfile
from pathlib import Path
from typing import Any

import spacy
from spacy.matcher import PhraseMatcher

# -----------------------------------------------------------------------------
# 1. Suppress all Androguard logger emissions
# -----------------------------------------------------------------------------
for _logger in [
    "androguard",
    "androguard.core",
    "androguard.core.apk",
    "androguard.core.bytecodes",
    "androguard.core.bytecodes.apk",
]:
    _l = logging.getLogger(_logger)
    _l.setLevel(logging.CRITICAL)
    _l.propagate = False


class ComprehensiveSocialEngineeringAnalyzer:
    def __init__(self) -> None:
        self.nlp = spacy.blank("en")
        self.phrase_matcher = PhraseMatcher(self.nlp.vocab, attr="LOWER")

        # Linguistic lure patterns
        self.categories: dict[str, dict[str, Any]] = {
            "SCAREWARE_URGENCY": {
                "weight": 25.0,
                "phrases": [
                    "virus detected", "threat found", "infected", "battery damaged",
                    "device at risk", "security warning", "system corrupted", "immediate action",
                    "account suspended", "account blocked", "kyc expired", "sim blocked",
                    "unauthorized access", "verification failed", "critical alert", "compromised",
                    "warning", "trojan", "malware", "danger", "security alert", "risk",
                ],
            },
            "PRIVILEGE_COERCION": {
                "weight": 25.0,
                "phrases": [
                    "enable accessibility", "accessibility service", "turn on accessibility",
                    "device administrator", "grant admin", "activate administrator",
                    "display over other apps", "draw over", "system alert window",
                    "allow notification access", "install unknown apps", "allow permission",
                    "request permissions", "service authorization", "device admin",
                ],
            },
            "MASQUERADE_UPDATE": {
                "weight": 20.0,
                "phrases": [
                    "system update", "google play update", "security update",
                    "software update required", "update required", "download update",
                    "install patch", "plugin required", "flash player", "whatsapp update",
                    "version update", "critical update", "service upgrade", "installer",
                ],
            },
            "CREDENTIAL_HARVEST": {
                "weight": 30.0,
                "phrases": [
                    "enter upi pin", "upi pin", "atm pin", "cvv number", "card expiry",
                    "debit card details", "credit card number", "netbanking password",
                    "login password", "transaction pin", "otp verification", "one time password",
                    "mpin", "verify account", "enter password", "enter credentials",
                ],
            },
        }

        for cat_name, data in self.categories.items():
            patterns = [self.nlp.make_doc(text) for text in data["phrases"]]
            self.phrase_matcher.add(cat_name, patterns)

    def extract_app_metadata(self, apk_path: Path) -> dict[str, str]:
        """Extracts package name, app label, and launcher activity silently."""
        raw_name = apk_path.stem
        if "_" in raw_name and len(raw_name.split("_")[0]) in (8, 64):
            raw_name = "_".join(raw_name.split("_")[1:])

        clean_title = raw_name.split(".")[-1].replace("_", " ").title()
        meta = {
            "app_name": clean_title,
            "package_name": raw_name,
            "main_activity": "MainActivity",
        }

        devnull = io.StringIO()
        with contextlib.redirect_stderr(devnull), contextlib.redirect_stdout(devnull):
            try:
                apk_cls = None
                try:
                    from androguard.core.apk import APK as apk_cls
                except ImportError:
                    try:
                        from androguard.core.apk import APK as apk_cls
                    except ImportError:
                        pass

                if apk_cls is not None:
                    apk_obj = apk_cls(str(apk_path))
                    label = apk_obj.get_app_name()
                    if label and isinstance(label, str) and len(label.strip()) > 1:
                        meta["app_name"] = label.strip()

                    pkg = apk_obj.get_package()
                    if pkg and isinstance(pkg, str) and len(pkg.strip()) > 1:
                        meta["package_name"] = pkg.strip()

                    act = apk_obj.get_main_activity()
                    if act and isinstance(act, str):
                        meta["main_activity"] = act.split(".")[-1]
            except Exception:
                pass

        return meta

    def extract_strings_dual_encoding(self, apk_path: Path) -> tuple[list[str], list[str]]:
        """
        Extracts both UTF-8 and UTF-16LE strings and identifies structural
        deceptive UI capabilities in raw bytecode and manifest.
        """
        if not apk_path.is_file():
            return [], []

        extracted_strings: list[str] = []
        detected_capabilities: list[str] = []

        ascii_regex = re.compile(rb"[a-zA-Z0-9\s\.\,\:\;\-\_\!\?\@\#\$\%]{4,80}")
        utf16_regex = re.compile(rb"(?:[a-zA-Z0-9\s\.\,\:\;\-\_\!\?\@\#\$\%]\x00){4,80}")

        combined_code_bytes = b""

        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                for name in z.namelist():
                    lower = name.lower()
                    if lower == "androidmanifest.xml" or (lower.startswith("classes") and lower.endswith(".dex")):
                        try:
                            entry_data = z.read(name)[: 4 * 1024 * 1024]
                            combined_code_bytes += entry_data
                            # Extract ASCII strings from code
                            for m in ascii_regex.findall(entry_data):
                                s = m.decode("ascii", errors="ignore").strip()
                                if len(s) > 3 and not s.startswith(("http", "android/", "Landroid", "androidx/")):
                                    extracted_strings.append(s)
                        except Exception:
                            continue

                    elif lower == "resources.arsc":
                        try:
                            arsc_data = z.read(name)[: 4 * 1024 * 1024]
                            # 1. UTF-8 strings
                            for m in ascii_regex.findall(arsc_data):
                                s = m.decode("ascii", errors="ignore").strip()
                                if len(s) > 3 and not s.startswith(("http", "android/")):
                                    extracted_strings.append(s)
                            # 2. UTF-16LE strings (critical for compiled resources.arsc)
                            for m in utf16_regex.findall(arsc_data):
                                s = m.decode("utf-16le", errors="ignore").strip()
                                if len(s) > 3 and not s.startswith(("http", "android/")):
                                    extracted_strings.append(s)
                        except Exception:
                            continue
        except Exception:
            pass

        # ---------------------------------------------------------------------
        # Structural Deceptive Mechanism Detection (Bytecode & Manifest)
        # ---------------------------------------------------------------------
        if b"BIND_ACCESSIBILITY_SERVICE" in combined_code_bytes or b"AccessibilityService" in combined_code_bytes:
            detected_capabilities.append("ACCESSIBILITY_HIJACK")
        if b"DEVICE_ADMIN" in combined_code_bytes or b"ADD_DEVICE_ADMIN" in combined_code_bytes or b"DeviceAdminReceiver" in combined_code_bytes:
            detected_capabilities.append("DEVICE_ADMIN_COERCION")
        if b"SYSTEM_ALERT_WINDOW" in combined_code_bytes or b"TYPE_APPLICATION_OVERLAY" in combined_code_bytes or b"TYPE_SYSTEM_ALERT" in combined_code_bytes:
            detected_capabilities.append("OVERLAY_MASQUERADE")
        if b"REQUEST_INSTALL_PACKAGES" in combined_code_bytes or b"application/vnd.android.package-archive" in combined_code_bytes:
            detected_capabilities.append("FAKE_UPDATE_DROPPER")
        if b"setComponentEnabledSetting" in combined_code_bytes and b"DONT_KILL_APP" in combined_code_bytes:
            detected_capabilities.append("STEALTH_ICON_HIDING")

        return extracted_strings[:4000], detected_capabilities

    def analyze(
        self,
        apk_path: str | Path,
        *args: Any,
        job_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        p = Path(apk_path)
        meta = self.extract_app_metadata(p)
        strings, capabilities = self.extract_strings_dual_encoding(p)

        app_name = meta["app_name"]
        pkg = meta["package_name"]
        main_act = meta["main_activity"]

        # 1. NLP Pattern Matching on Decoded Strings
        full_corpus = " . ".join(strings).lower()
        doc = self.nlp(full_corpus[:150000])
        matches = self.phrase_matcher(doc)

        matched_categories: dict[str, set[str]] = {}
        for match_id, start, end in matches:
            cat_name = self.nlp.vocab.strings[match_id]
            span_text = doc[start:end].text
            if cat_name not in matched_categories:
                matched_categories[cat_name] = set()
            matched_categories[cat_name].add(span_text)

        # 2. Score Calculation: Blend Structural Indicators with NLP Lures
        raw_score = 0.0

        # Structural capability contributions
        capability_weights = {
            "ACCESSIBILITY_HIJACK": 35.0,
            "DEVICE_ADMIN_COERCION": 30.0,
            "OVERLAY_MASQUERADE": 25.0,
            "FAKE_UPDATE_DROPPER": 25.0,
            "STEALTH_ICON_HIDING": 20.0,
        }
        for cap in capabilities:
            raw_score += capability_weights.get(cap, 20.0)

        # Linguistic lure contributions
        for cat, phrases in matched_categories.items():
            base_w = self.categories[cat]["weight"]
            raw_score += base_w * min(2.0, 1.0 + (len(phrases) - 1) * 0.25)

        final_score = min(100.0, round(raw_score, 2))

        # Check threat status
        static_res = kwargs.get("static_result") or {}
        perm_score = float(static_res.get("permission_score", 0.0))
        is_threat = (final_score >= 25.0) or (len(capabilities) > 0) or (perm_score >= 55.0)

        # ---------------------------------------------------------------------
        # Synchronized Storyboard Definition (matches phone-frame.tsx props)
        # ---------------------------------------------------------------------
        if is_threat and (final_score > 0 or len(capabilities) > 0):
            # Dynamic summary of detected traps
            active_traps = []
            if "ACCESSIBILITY_HIJACK" in capabilities:
                active_traps.append("Accessibility takeover")
            if "DEVICE_ADMIN_COERCION" in capabilities:
                active_traps.append("Device Administrator lock")
            if "OVERLAY_MASQUERADE" in capabilities:
                active_traps.append("Overlay window spoofing")
            if "FAKE_UPDATE_DROPPER" in capabilities:
                active_traps.append("Secondary payload installation")

            trap_detail = ", ".join(active_traps[:2]) if active_traps else "Privilege elevation requested"

            storyboard = [
                {
                    "id": 1,
                    "step": 1,
                    "title": "Authority Impersonation",
                    "subtitle": f"{app_name} Launcher Masquerade",
                    "description": f"Executable disguises as '{app_name}' to establish initial victim trust.",
                    "device": {
                        "screen_type": "SPLASH",
                        "header": f"{app_name} Service",
                        "sub": f"Welcome to {app_name}",
                        "body": f"Loading runtime modules for {pkg}. Requesting service synchronization...",
                        "button": "Continue",
                        "icon": "shield",
                        "inputs": [f"PACKAGE: {pkg[:26]}", f"ACTIVITY: {main_act[:24]}"],
                    },
                },
                {
                    "id": 2,
                    "step": 2,
                    "title": "Urgency Engineering",
                    "subtitle": "Privilege Access Trap",
                    "description": f"Coercive prompt detected: {trap_detail}.",
                    "device": {
                        "screen_type": "ALERT_MODAL",
                        "header": "Action Required",
                        "sub": "Execution Warning",
                        "body": f"{app_name} requires elevated runtime permissions ({trap_detail}) to proceed.",
                        "button": "Grant Permissions",
                        "extra_info": "Immediate Action Required",
                        "icon": "alert",
                    },
                },
                {
                    "id": 3,
                    "step": 3,
                    "title": "Credential Harvest Screen",
                    "subtitle": "Form Extraction Hook",
                    "description": "Harvesting credentials and hardware identifiers.",
                    "device": {
                        "screen_type": "FORM",
                        "header": "Identity Verification",
                        "sub": "Account Authentication",
                        "body": "Confirm device credentials to synchronize local configuration.",
                        "button": "Submit Credentials",
                        "inputs": ["DEVICE ANDROID ID", "USER ACCESS PIN"],
                        "icon": "smartphone",
                    },
                },
                {
                    "id": 4,
                    "step": 4,
                    "title": "Covert Data Exfiltration",
                    "subtitle": "C2 Dispatch Preparation",
                    "description": "Encoding captured device buffers for remote transmission.",
                    "device": {
                        "screen_type": "OTP",
                        "header": "Telemetry Dispatch",
                        "body": f"Packaging captured artifacts from {pkg} for transmission to remote command listener.",
                        "button": "Complete",
                        "extra_info": "Encrypted socket stream awaiting network window",
                        "icon": "lock",
                    },
                },
            ]
        else:
            # Benign application lifecycle (e.g., Candle11, calculators, clean utilities)
            storyboard = [
                {
                    "id": 1,
                    "step": 1,
                    "title": "Application Launch",
                    "subtitle": f"{app_name} Main Splash",
                    "description": f"Standard user launch initialization for '{app_name}'.",
                    "device": {
                        "screen_type": "SPLASH",
                        "header": app_name,
                        "sub": f"Welcome to {app_name}",
                        "body": f"Starting {app_name}. Loading user settings and local database...",
                        "button": "Open Application",
                        "icon": "sparkles",
                        "inputs": [f"ID: {pkg[:26]}"],
                    },
                },
                {
                    "id": 2,
                    "step": 2,
                    "title": "Normal Lifecycle Initialization",
                    "subtitle": "Interface Load",
                    "description": f"Loads {main_act} without coercive security alerts.",
                    "device": {
                        "screen_type": "ALERT_MODAL",
                        "header": f"{app_name} Ready",
                        "sub": "Operational State",
                        "body": "Application running in safe sandbox environment. No elevated access requested.",
                        "button": "Continue",
                        "extra_info": "Status: Verified Normal",
                        "icon": "shield",
                    },
                },
                {
                    "id": 3,
                    "step": 3,
                    "title": "Local Storage & User State",
                    "subtitle": "Internal App Storage",
                    "description": "Stores preferences locally in SQLite / SharedPreferences.",
                    "device": {
                        "screen_type": "FORM",
                        "header": "Application Settings",
                        "sub": "User Preferences",
                        "body": "Manage local graphics and offline application settings.",
                        "button": "Save Changes",
                        "inputs": ["INTERFACE THEME", "LOCAL NOTIFICATIONS"],
                        "icon": "file-text",
                    },
                },
                {
                    "id": 4,
                    "step": 4,
                    "title": "Network Synchronization",
                    "subtitle": "Routine Endpoint Sync",
                    "description": "Routine connection to content delivery networks or analytics.",
                    "device": {
                        "screen_type": "OTP",
                        "header": "Connected",
                        "body": "Application state synchronized with local storage.",
                        "button": "Done",
                        "extra_info": "Standard HTTPS connection",
                        "icon": "lock",
                    },
                },
            ]

        return {
            "social_engineering_score": final_score,
            "social_score": final_score,
            "detected_capabilities": capabilities,
            "detected_lures": {k: list(v) for k, v in matched_categories.items()},
            "storyboard": storyboard,
            "screenplay": storyboard,
            "app_name": app_name,
            "brand_name": app_name,
            "app_profile": {
                "app_name": app_name,
                "package_name": pkg,
                "main_activity": main_act,
            },
            "job_id": job_id,
        }


# Global singleton instance
_ANALYZER = None


def analyze_social_engineering(
    apk_path: str | Path,
    *args: Any,
    job_id: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    global _ANALYZER
    if _ANALYZER is None:
        _ANALYZER = ComprehensiveSocialEngineeringAnalyzer()
    return _ANALYZER.analyze(apk_path, *args, job_id=job_id, **kwargs)