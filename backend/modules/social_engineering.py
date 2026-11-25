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

URL_REGEX = re.compile(rb"https?://[a-zA-Z0-9\.\-\_/\:\?\=\&\%]{6,120}")
BENIGN_URL_TOKENS = (
    "schemas.android.com",
    "w3.org",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "apache.org",
    "github.com",
    "xmlpull.org",
    "openssl.org",
)


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
                from androguard.core.apk import APK as apk_cls

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

    def extract_strings_dual_encoding(
        self, apk_path: Path
    ) -> tuple[list[str], list[str], list[str]]:
        """
        Extracts UTF-8 & UTF-16LE strings, structural deceptive capabilities,
        and non-benign URLs from raw bytecode and resources.arsc.
        """
        if not apk_path.is_file():
            return [], [], []

        extracted_strings: list[str] = []
        detected_capabilities: list[str] = []
        extracted_urls: list[str] = []
        seen_urls: set[str] = set()

        ascii_regex = re.compile(rb"[a-zA-Z0-9\s\.\,\:\;\-\_\!\?\@\#\$\%]{4,120}")
        utf16_regex = re.compile(rb"(?:[a-zA-Z0-9\s\.\,\:\;\-\_\!\?\@\#\$\%]\x00){4,120}")

        combined_code_bytes = b""

        try:
            with zipfile.ZipFile(apk_path, "r") as z:
                for name in z.namelist():
                    lower = name.lower()
                    if lower == "androidmanifest.xml" or (lower.startswith("classes") and lower.endswith(".dex")):
                        try:
                            entry_data = z.read(name)[: 4 * 1024 * 1024]
                            combined_code_bytes += entry_data
                            for m in ascii_regex.findall(entry_data):
                                s = m.decode("ascii", errors="ignore").strip()
                                if len(s) > 3 and not s.startswith(("http", "android/", "Landroid", "androidx/")):
                                    extracted_strings.append(s)
                            for u_m in URL_REGEX.findall(entry_data):
                                u = u_m.decode("ascii", errors="ignore").strip()
                                if u not in seen_urls and not any(b in u.lower() for b in BENIGN_URL_TOKENS):
                                    seen_urls.add(u)
                                    extracted_urls.append(u)
                        except Exception:
                            continue

                    elif lower == "resources.arsc":
                        try:
                            arsc_data = z.read(name)[: 4 * 1024 * 1024]
                            for m in ascii_regex.findall(arsc_data):
                                s = m.decode("ascii", errors="ignore").strip()
                                if len(s) > 3 and not s.startswith(("http", "android/")):
                                    extracted_strings.append(s)
                            for m in utf16_regex.findall(arsc_data):
                                s = m.decode("utf-16le", errors="ignore").strip()
                                if len(s) > 3 and not s.startswith(("http", "android/")):
                                    extracted_strings.append(s)
                        except Exception:
                            continue
        except Exception:
            pass

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

        return extracted_strings[:4000], detected_capabilities, extracted_urls[:8]

    def _find_evidence_sentences(
        self, strings: list[str], matched_phrases: set[str], limit: int = 3
    ) -> list[str]:
        """Finds clean, human-readable strings from the APK containing spaCy-matched phrases."""
        if not matched_phrases:
            return []
        hits: list[str] = []
        seen: set[str] = set()
        for s in strings:
            clean = " ".join(s.split())
            # Prefer human-readable phrases (contains spaces, not a class/path token)
            if len(clean) < 6 or len(clean) > 110 or " " not in clean:
                continue
            if "/" in clean or clean.startswith(("com.", "org.", "io.", "java.")):
                continue
            low = clean.lower()
            if low in seen:
                continue
            if any(p in low for p in matched_phrases):
                seen.add(low)
                hits.append(clean)
                if len(hits) >= limit:
                    break
        # Fallback to matched phrases themselves if only short tokens exist
        return hits if hits else sorted(matched_phrases)[:limit]

    def analyze(
        self,
        apk_path: str | Path,
        *args: Any,
        job_id: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        p = Path(apk_path)
        meta = self.extract_app_metadata(p)
        strings, capabilities, extracted_urls = self.extract_strings_dual_encoding(p)

        app_name = meta["app_name"]
        pkg = meta["package_name"]
        main_act = meta["main_activity"]

        # 1. spaCy NLP Pattern Matching on Decoded Strings
        full_corpus = " . ".join(strings).lower()
        doc = self.nlp(full_corpus[:150000])
        matches = self.phrase_matcher(doc)

        matched_categories: dict[str, set[str]] = {}
        for match_id, start, end in matches:
            cat_name = self.nlp.vocab.strings[match_id]
            span_text = doc[start:end].text
            matched_categories.setdefault(cat_name, set()).add(span_text)

        # 2. Score Calculation
        raw_score = 0.0
        capability_weights = {
            "ACCESSIBILITY_HIJACK": 35.0,
            "DEVICE_ADMIN_COERCION": 30.0,
            "OVERLAY_MASQUERADE": 25.0,
            "FAKE_UPDATE_DROPPER": 25.0,
            "STEALTH_ICON_HIDING": 20.0,
        }
        for cap in capabilities:
            raw_score += capability_weights.get(cap, 20.0)

        for cat, phrases in matched_categories.items():
            base_w = self.categories[cat]["weight"]
            raw_score += base_w * min(2.0, 1.0 + (len(phrases) - 1) * 0.25)

        final_score = min(100.0, round(raw_score, 2))

        static_res = kwargs.get("static_result") or {}
        perm_score = float(static_res.get("permission_score", 0.0) or static_res.get("permission_risk", 0.0))
        raw_static_perms = [
            (d.get("permission") if isinstance(d, dict) else str(d))
            for d in (static_res.get("dangerous_permissions") or static_res.get("permissions") or [])
        ]
        short_perms = [p_name.split(".")[-1] for p_name in raw_static_perms if p_name][:3]

        is_threat = (final_score >= 25.0) or (len(capabilities) > 0) or (perm_score >= 55.0)

        # Pick primary archetype for UI header
        if "CREDENTIAL_HARVEST" in matched_categories:
            archetype = "CREDENTIAL_PHISH"
        elif "PRIVILEGE_COERCION" in matched_categories or "ACCESSIBILITY_HIJACK" in capabilities:
            archetype = "PRIVILEGE_TRAP"
        elif "MASQUERADE_UPDATE" in matched_categories or "FAKE_UPDATE_DROPPER" in capabilities:
            archetype = "FAKE_UPDATE_LURE"
        elif "SCAREWARE_URGENCY" in matched_categories:
            archetype = "SCAREWARE_LURE"
        else:
            archetype = "GENERAL"

        # 3. Extract Real Evidence Sentences per Stage
        ev_masq = self._find_evidence_sentences(strings, matched_categories.get("MASQUERADE_UPDATE", set()))
        ev_urg = self._find_evidence_sentences(
            strings,
            matched_categories.get("SCAREWARE_URGENCY", set()) | matched_categories.get("PRIVILEGE_COERCION", set()),
        )
        ev_cred = self._find_evidence_sentences(strings, matched_categories.get("CREDENTIAL_HARVEST", set()))

        # Build real capability/permission trap list (never hardcode Accessibility if absent!)
        cap_labels = {
            "ACCESSIBILITY_HIJACK": "Accessibility Service takeover",
            "DEVICE_ADMIN_COERCION": "Device Administrator lock",
            "OVERLAY_MASQUERADE": "Screen overlay spoofing",
            "FAKE_UPDATE_DROPPER": "Unknown-source APK installer",
            "STEALTH_ICON_HIDING": "Launcher icon hiding",
        }
        active_traps = [cap_labels[c] for c in capabilities if c in cap_labels]
        if not active_traps and short_perms:
            active_traps = short_perms[:2]
        trap_detail = ", ".join(active_traps[:2]) if active_traps else "No coercive permissions detected"

        # Real credential input labels extracted from spaCy matches
        real_cred_inputs = [
            phrase.upper() for phrase in sorted(matched_categories.get("CREDENTIAL_HARVEST", set()))
        ][:3]

        # ---------------------------------------------------------------------
        # 4. Telemetry-Grounded 4-Stage Storyboard (synced with phone-frame.tsx)
        # ---------------------------------------------------------------------
        if is_threat:
            s1_body = (
                f'Extracted lure copy: "{ev_masq[0]}"'
                if ev_masq
                else f"Disguises as '{app_name}' ({pkg}) via launcher activity {main_act} to establish initial user trust."
            )
            s2_body = (
                f'Extracted coercive prompt: "{ev_urg[0]}"'
                if ev_urg
                else f"{app_name} requests elevated capabilities ({trap_detail}) to gain persistent control."
            )
            s3_body = (
                f'Extracted harvest lure: "{ev_cred[0]}"'
                if ev_cred
                else "No static credential-entry form strings were found in resources.arsc (may rely on permissions or WebView)."
            )
            s4_body = (
                f"Prepared to dispatch collected telemetry from {pkg} to external endpoint(s) discovered in binary."
                if extracted_urls
                else f"No hardcoded external exfiltration URLs extracted from {pkg} strings; relies on declared capabilities ({trap_detail})."
            )

            storyboard = [
                {
                    "id": 1,
                    "step": 1,
                    "title": "Authority Impersonation",
                    "subtitle": "Extracted Update/Brand Lure" if ev_masq else f"{app_name} Launcher Identity",
                    "description": f"Attacker presents '{app_name}' ({main_act}) to lower victim suspicion before requesting privileges.",
                    "device": {
                        "screen_type": "SPLASH",
                        "lure_tag": "EXTRACTED_LURE" if ev_masq else "IDENTITY_MASQUERADE",
                        "header": app_name,
                        "sub": f"pkg: {pkg}",
                        "body": s1_body,
                        "indicators": ev_masq,
                        "button": "Continue",
                        "icon": "shield",
                    },
                },
                {
                    "id": 2,
                    "step": 2,
                    "title": "Urgency & Privilege Trap",
                    "subtitle": trap_detail[:36],
                    "description": f"Coercive mechanism identified: {trap_detail}.",
                    "device": {
                        "screen_type": "ALERT_MODAL",
                        "lure_tag": "EXTRACTED_LURE" if ev_urg else "CAPABILITY_TRAP",
                        "header": "Action Required" if (ev_urg or capabilities) else "Permission Request",
                        "sub": "Privilege Coercion",
                        "body": s2_body,
                        "indicators": ev_urg,
                        "button": "Grant Permissions",
                        "extra_info": trap_detail,
                        "icon": "alert",
                    },
                },
                {
                    "id": 3,
                    "step": 3,
                    "title": "Credential Harvest Screen",
                    "subtitle": f"{len(real_cred_inputs)} Lure Field(s) Extracted" if real_cred_inputs else "No Static Form Strings",
                    "description": (
                        f"spaCy matched credential-harvesting lures: {', '.join(real_cred_inputs)}."
                        if real_cred_inputs
                        else "No static PIN/OTP/Card form strings found in APK resources."
                    ),
                    "device": {
                        "screen_type": "FORM",
                        "lure_tag": "EXTRACTED_HARVEST" if real_cred_inputs else "NOT_OBSERVED",
                        "header": "Credential Verification" if real_cred_inputs else "No Form Lure Detected",
                        "sub": "Extracted APK Fields" if real_cred_inputs else "Static Resource Audit",
                        "body": s3_body,
                        "inputs": real_cred_inputs,
                        "indicators": ev_cred,
                        "button": "Submit" if real_cred_inputs else "",
                        "icon": "smartphone",
                    },
                },
                {
                    "id": 4,
                    "step": 4,
                    "title": "Covert Data Exfiltration",
                    "subtitle": f"{len(extracted_urls)} URL(s) in Binary" if extracted_urls else "Background Capability",
                    "description": (
                        f"Binary contains {len(extracted_urls)} external URL(s) for potential data dispatch."
                        if extracted_urls
                        else "No external C2 URLs extracted from static strings."
                    ),
                    "device": {
                        "screen_type": "OTP",
                        "lure_tag": "ENDPOINT_EXTRACTED" if extracted_urls else "TELEMETRY_ONLY",
                        "header": "Exfiltration Channel" if extracted_urls else "Background Execution",
                        "body": s4_body,
                        "urls": extracted_urls[:2],
                        "indicators": [c.replace("_", " ") for c in capabilities[:2]],
                        "button": "Complete",
                        "extra_info": extracted_urls[0] if extracted_urls else "No hardcoded C2 URL observed",
                        "icon": "lock",
                    },
                },
            ]
        else:
            storyboard = [
                {
                    "id": 1,
                    "step": 1,
                    "title": "Application Launch",
                    "subtitle": f"{app_name} Main Splash",
                    "description": f"Standard launch initialization for '{app_name}' with zero deceptive lures detected.",
                    "device": {
                        "screen_type": "SPLASH",
                        "lure_tag": "CLEAN_PROFILE",
                        "header": app_name,
                        "sub": f"pkg: {pkg}",
                        "body": f"Starting {app_name}. No scareware or impersonation strings found in APK resources.",
                        "button": "Open Application",
                        "icon": "sparkles",
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
                        "lure_tag": "CLEAN_PROFILE",
                        "header": f"{app_name} Ready",
                        "sub": "Operational State",
                        "body": "No privilege coercion or accessibility/admin traps detected.",
                        "button": "Continue",
                        "extra_info": "Status: Verified Normal",
                        "icon": "shield",
                    },
                },
                {
                    "id": 3,
                    "step": 3,
                    "title": "Local Storage & User State",
                    "subtitle": "No Credential Harvest",
                    "description": "No phishing or credential-harvesting strings found in APK.",
                    "device": {
                        "screen_type": "FORM",
                        "lure_tag": "CLEAN_PROFILE",
                        "header": "Application Settings",
                        "sub": "User Preferences",
                        "body": "No sensitive banking/OTP input lures detected in resources.arsc.",
                        "inputs": [],
                        "button": "",
                        "icon": "file-text",
                    },
                },
                {
                    "id": 4,
                    "step": 4,
                    "title": "Network Synchronization",
                    "subtitle": "Routine Endpoint Sync",
                    "description": "No suspicious exfiltration endpoints extracted from binary.",
                    "device": {
                        "screen_type": "OTP",
                        "lure_tag": "CLEAN_PROFILE",
                        "header": "Connected",
                        "body": "No covert exfiltration channels detected in static strings.",
                        "button": "Done",
                        "extra_info": "Standard application profile",
                        "icon": "lock",
                    },
                },
            ]

        return {
            "social_engineering_score": final_score,
            "social_score": final_score,
            "archetype": archetype,
            "detected_capabilities": capabilities,
            "detected_lures": {k: list(v) for k, v in matched_categories.items()},
            "matched_keywords": sorted({p for phrases in matched_categories.values() for p in phrases}),
            "phishing_urls": extracted_urls,
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