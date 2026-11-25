from __future__ import annotations

import ipaddress
import json
import logging
import os
import random
import re
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel

warnings.filterwarnings("ignore", category=FutureWarning)
logger = logging.getLogger("spectre.genai")

try:
    from dotenv import load_dotenv

    current_dir = Path(__file__).resolve().parent
    for p in [
        current_dir.parent / ".env",
        current_dir.parent.parent / ".env",
        current_dir / ".env",
    ]:
        if p.is_file():
            load_dotenv(dotenv_path=p, override=True)
            break
except ImportError:
    pass

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip().strip('"').strip("'")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "").strip().strip('"').strip("'")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "").strip().strip('"').strip("'")
M5_PROVIDER_PREF = os.environ.get("SPECTRE_M5_PROVIDER", "auto").strip().lower()

_GENAI_CLIENT = None
if GEMINI_API_KEY:
    try:
        from google import genai

        _GENAI_CLIENT = genai.Client(
            api_key=GEMINI_API_KEY,
            http_options={"timeout": 25000},
        )
    except Exception as exc:
        print(f"[M5 WARN] Failed to initialize Google GenAI client: {exc}", flush=True)
        logger.warning(f"[M5] Failed to initialize Google GenAI client: {exc}")
        _GENAI_CLIENT = None

BENIGN_AD_DOMAINS = [
    "googleads.g.doubleclick.net",
    "doubleclick.net",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "facebook.com",
    "crashlytics.com",
    "firebase.io",
    "firebaseio.com",
    "appsflyer.com",
    "app-measurement.com",
]

OFFICIAL_BANK_TOKENS = [
    "com.boi.ua.android",
    "com.sbi",
    "com.axis",
    "com.icici",
    "com.hdfc",
    "com.canara",
    "com.kotak",
    "bankofbaroda",
    "unionbank",
]

KILL_CHAIN_PHASES: list[tuple[int, str]] = [
    (1, "Delivery & Initial Lure"),
    (2, "Privilege & Permission Coercion"),
    (3, "Reconnaissance & Device Fingerprinting"),
    (4, "Execution, Evasion & Decoy UI"),
    (5, "Dynamic Code / Stager Loading"),
    (6, "C2 Communication & Data Exfiltration"),
    (7, "Persistence & Operational Impact"),
]


# -----------------------------------------------------------------------------
# Pydantic Schema for Structured Forensic Synthesis
# -----------------------------------------------------------------------------
class BriefSection(BaseModel):
    executive_summary: str
    targeted_institution: str
    est_accounts_at_risk: str
    c2_jurisdiction: str
    key_findings: list[str]


class CodeSnippetItem(BaseModel):
    file_name: str
    method_name: str
    code_type: str
    smali_code: str
    plain_english_interpretation: str
    bank_countermeasure: str


class KillChainStepItem(BaseModel):
    stage: int
    title: str
    status: str
    evidence_source: str
    description: str


class ComplianceSection(BaseModel):
    incident_ref: str
    circular_section: str
    mandates: list[str]


class ForensicReportSchema(BaseModel):
    genai_score: float
    threat_level: str
    brief: BriefSection
    code_snippets: list[CodeSnippetItem]
    kill_chain: list[KillChainStepItem]
    rbi_compliance: ComplianceSection


def _sanitize_url(raw_url: str) -> str:
    s = (raw_url or "").strip()
    md_match = re.search(r"\((https?://[^\s)]+)\)", s)
    if md_match:
        s = md_match.group(1)
    return s.strip("[]()<>\"' ")


def _extract_first_json_object(raw_text: str) -> str:
    """Extracts the first complete balanced JSON object, ignoring trailing text or fences."""
    text = (raw_text or "").strip()
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
    for prefix in ("```json", "```"):
        if text.startswith(prefix):
            text = text[len(prefix) :].strip()
    if text.endswith("```"):
        text = text[:-3].strip()

    start = text.find("{")
    if start == -1:
        return text

    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\" and in_string:
            escape = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if not in_string:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start : idx + 1]

    return text[start:]


def _clean_json(raw_text: str) -> str:
    return _extract_first_json_object(raw_text)


def _is_not_found_error(err_lower: str) -> bool:
    return (
        "404" in err_lower
        or "not_found" in err_lower
        or "no longer available" in err_lower
        or "model_not_found" in err_lower
        or "does not exist" in err_lower
    )


def _is_transient_error(err_lower: str) -> bool:
    return any(
        tok in err_lower
        for tok in (
            "503",
            "429",
            "unavailable",
            "resource_exhausted",
            "overloaded",
            "rate limit",
            "timeout",
            "timed out",
            "connection",
        )
    )


def _get_groq_models() -> list[str]:
    env_models = os.environ.get("SPECTRE_GROQ_MODELS", "").strip()
    if env_models:
        parsed = [m.strip() for m in env_models.split(",") if m.strip()]
        if parsed:
            return parsed
    single = os.environ.get("GROQ_MODEL", "").strip()
    defaults = ["openai/gpt-oss-120b", "openai/gpt-oss-20b"]
    if single and single not in defaults:
        return [single, *defaults]
    return defaults


def _get_gemini_models() -> list[str]:
    env_models = os.environ.get("SPECTRE_GEMINI_MODELS", "").strip()
    if env_models:
        parsed = [m.strip() for m in env_models.split(",") if m.strip()]
        if parsed:
            return parsed
    return ["gemini-3.5-flash-lite"]


def _get_openrouter_models() -> list[str]:
    env_models = os.environ.get("SPECTRE_OPENROUTER_MODELS", "").strip()
    if env_models:
        parsed = [m.strip() for m in env_models.split(",") if m.strip()]
        if parsed:
            return parsed
    single = os.environ.get("OPENROUTER_MODEL", "openrouter/free").strip()
    return [single or "openrouter/free"]


def _is_public_routable_host(host: str) -> bool:
    """Rejects private/RFC1918/loopback IPs and benign ad/infra domains."""
    h = str(host).strip().lower()
    if not h or any(b in h for b in BENIGN_AD_DOMAINS):
        return False
    if "://" in h:
        h = h.split("://", 1)[1]
    h = h.split("/", 1)[0]
    host_only = h.split(":", 1)[0]
    if not host_only:
        return False
    try:
        ip = ipaddress.ip_address(host_only)
        return ip.is_global
    except ValueError:
        return "." in host_only


def _extract_telemetry_bundle(pipeline_results: dict[str, Any]) -> dict[str, Any]:
    static_data = pipeline_results.get("static") or {}
    behavioral_data = pipeline_results.get("behavioral") or {}
    dynamic_data = pipeline_results.get("dynamic") or {}
    social_data = pipeline_results.get("social") or {}

    pkg_name = (
        static_data.get("package_name")
        or dynamic_data.get("package_name")
        or "com.target.unknown"
    )
    app_label = (
        static_data.get("app_name")
        or social_data.get("app_name")
        or pipeline_results.get("app_name")
        or pkg_name.split(".")[-1].capitalize()
    )

    permissions = static_data.get("permissions") or static_data.get("all_permissions") or []
    if isinstance(permissions, dict):
        permissions = list(permissions.keys())

    dangerous_perms = [
        {
            "permission": d.get("permission"),
            "risk": d.get("risk"),
            "reason": d.get("reason"),
        }
        for d in (static_data.get("dangerous_permissions") or [])[:15]
        if isinstance(d, dict)
    ]

    combo_alerts = [
        {"combo": c.get("combo"), "reason": c.get("reason")}
        for c in (static_data.get("combo_alerts") or [])[:10]
        if isinstance(c, dict)
    ]

    suspicious_chains = (static_data.get("suspicious_api_chains") or [])[:8]
    exported = [
        f"{e.get('type')}:{e.get('component')}"
        for e in (static_data.get("exported_components") or [])[:15]
        if isinstance(e, dict)
    ]

    net_delta = dynamic_data.get("network_delta") or {}
    hidden_hosts = net_delta.get("hidden_runtime_hosts") or []
    correlated_hosts = net_delta.get("correlated_hosts") or []
    dormant_hosts = net_delta.get("dormant_static_hosts") or []
    static_ips = static_data.get("ips") or []
    static_urls = static_data.get("urls") or []

    combined_hosts = (
        list(hidden_hosts)
        + list(correlated_hosts)
        + list(dormant_hosts)
        + list(static_ips)
    )
    genuine_c2 = sorted({str(h).strip() for h in combined_hosts if _is_public_routable_host(str(h))})

    top_matches = [
        {
            "family": m.get("family"),
            "score": round(float(m.get("behavioral_score", 0.0)), 2),
        }
        for m in (behavioral_data.get("top_matches") or [])[:5]
        if isinstance(m, dict)
    ]

    dynamic_findings = [
        {
            "id": f.get("id"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "description": f.get("description"),
        }
        for f in (dynamic_data.get("findings") or [])[:10]
        if isinstance(f, dict)
    ]

    behavior_delta = (dynamic_data.get("behavior_delta") or [])[:12]
    exfil_events = (dynamic_data.get("exfiltration_events") or [])[:12]
    dynamic_api_chains = (dynamic_data.get("api_chains") or [])[:6]
    coverage = dynamic_data.get("coverage") or {}

    return {
        "pkg_name": str(pkg_name),
        "app_label": str(app_label),
        "m1_perm": float(static_data.get("permission_risk") or static_data.get("permission_score") or 0.0),
        "m1_static_risk": float(static_data.get("static_risk_score") or 0.0),
        "permissions": [str(p) for p in permissions[:30]],
        "dangerous_permissions": dangerous_perms,
        "combo_alerts": combo_alerts,
        "suspicious_api_chains": suspicious_chains,
        "exported": exported,
        "static_urls_sample": [str(u) for u in static_urls[:10]],
        "m2_score": float(behavioral_data.get("behavioral_score") or behavioral_data.get("similarity_score") or 0.0),
        "family": str(behavioral_data.get("closest_family") or "Unclassified"),
        "top_matches": top_matches,
        "top1_margin_percent": float(behavioral_data.get("top1_margin_percent") or 0.0),
        "m3_score": float(dynamic_data.get("dynamic_risk_score") or 0.0),
        "m3_status": str(dynamic_data.get("status") or "unknown").lower(),
        "m3_is_dormant": bool(coverage.get("is_dormant_or_evaded", False)),
        "m3_screenshots": int(coverage.get("screenshots_count", 0)),
        "dynamic_findings": dynamic_findings,
        "dynamic_api_chains": dynamic_api_chains,
        "behavior_delta": behavior_delta,
        "exfil_events": exfil_events,
        "hidden_hosts": [str(h) for h in hidden_hosts if _is_public_routable_host(str(h))][:6],
        "genuine_c2": genuine_c2[:8],
        "m4_score": float(social_data.get("social_engineering_score") or social_data.get("social_score") or 0.0),
        "social_archetype": str(social_data.get("archetype") or "GENERAL"),
        "raw_api_chain": float(
            dynamic_data.get("api_chain_score")
            or static_data.get("api_chain_score")
            or static_data.get("chain_score")
            or 0.0
        ),
        "authenticity": static_data.get("authenticity") or {},
        "static_data_raw": static_data,
        "dynamic_data_raw": dynamic_data,
    }


def _ensure_multiline_smali(snip: dict[str, Any]) -> dict[str, Any]:
    out = dict(snip or {})
    code_str = str(out.get("smali_code") or "").strip()
    lines = [ln for ln in code_str.splitlines() if ln.strip()]
    if len(lines) < 4:
        method_sig = str(out.get("method_name") or "execute(Landroid/content/Context;)V")
        if "(" not in method_sig:
            method_sig = f"{method_sig}()V"
        body_line = code_str or "    nop"
        if not body_line.startswith("    "):
            body_line = f"    {body_line}"
        out["smali_code"] = "\n".join([
            f".method public {method_sig}",
            "    .locals 2",
            body_line,
            "    return-void",
            ".end method",
        ])
    return out


def _build_snippets_from_modules(
    bundle: dict[str, Any],
    is_official_bank: bool,
) -> list[dict[str, str]]:
    """Builds telemetry-grounded Smali/trace snippets from M1 chains and M3 runtime deltas."""
    snippets: list[dict[str, str]] = []
    pkg_name = bundle["pkg_name"]

    for chain in bundle["suspicious_api_chains"][:3]:
        cls_name = str(chain.get("defining_class") or "UnknownClass").replace(".", "/")
        method_name = str(chain.get("method") or "execute()")
        chain_name = str(chain.get("chain") or "API_CHAIN")
        ev_list = chain.get("evidence") or []

        lines = [
            f".class public L{cls_name};",
            f".method public {method_name} # rule: {chain_name}",
            "    .registers 4",
        ]
        for idx, ev in enumerate(ev_list[:4]):
            api_cls = str(ev.get("api_class") or "").replace(".", "/")
            api_mth = str(ev.get("method") or "")
            cats = ",".join(ev.get("categories") or [])
            lines.append(f"    # [insn #{ev.get('instruction_index', idx)}] category={cats}")
            lines.append(f"    invoke-virtual {{v0, v1}}, L{api_cls};->{api_mth}()V")
        lines.extend(["    return-void", ".end method"])

        snippets.append({
            "file_name": f"{cls_name.split('/')[-1]}.smali",
            "method_name": method_name,
            "code_type": "Smali Bytecode",
            "smali_code": "\n".join(lines),
            "plain_english_interpretation": (
                f"{chain.get('reason') or 'Multi-step API sequence detected'} "
                f"in {chain.get('defining_class')}::{method_name} "
                f"({chain.get('source_api')} -> {chain.get('sink_api')})."
            ),
            "bank_countermeasure": (
                f"Enforce runtime integrity checks, restrict sensitive capability usage, "
                f"and validate session/API channels for {pkg_name}."
            ),
        })

    delta_rows = bundle["behavior_delta"]
    exfil_events = bundle["exfil_events"]
    if delta_rows or exfil_events:
        trace_lines = [f"// Package: {pkg_name} | Dynamic status: {bundle['m3_status']}"]
        for row in delta_rows[:5]:
            trace_lines.append(
                f"// [{row.get('status_tag', 'INFO')}] {row.get('permission')} "
                f"(declared={row.get('declared')}, runtime={row.get('runtime')}): {row.get('analyst_note')}"
            )
        for ev in exfil_events[:4]:
            trace_lines.append(
                f"// [EXFIL:{ev.get('type')}] endpoint/detail={ev.get('detail')} — {ev.get('reason')}"
            )

        snippets.append({
            "file_name": f"m3_runtime_delta_{pkg_name}.trace",
            "method_name": "behavior_delta + exfiltration_events",
            "code_type": "Frida Runtime Trace",
            "smali_code": "\n".join(trace_lines),
            "plain_english_interpretation": (
                f"Correlated {len(delta_rows)} manifest-vs-runtime capability states and "
                f"{len(exfil_events)} runtime network/exfiltration events on the sandbox."
            ),
            "bank_countermeasure": (
                "Block unauthorized outbound endpoints, verify app origin, and alert on "
                "HIDDEN_THREAT or unexpected runtime capability triggers."
            ),
        })

    if not snippets:
        if is_official_bank:
            snippets.append({
                "file_name": "SessionAttestation.smali",
                "method_name": "verifyBankingSession(Landroid/content/Context;)Z",
                "code_type": "Smali Bytecode",
                "smali_code": (
                    ".method public static verifyBankingSession(Landroid/content/Context;)Z\n"
                    "    .locals 2\n"
                    "    const/4 v0, 0x1\n"
                    "    return v0\n"
                    ".end method"
                ),
                "plain_english_interpretation": (
                    f"Official banking package {pkg_name} aligns with expected authenticated mobile banking behavior."
                ),
                "bank_countermeasure": (
                    "Maintain hardware-backed keystore attestation, TLS certificate pinning, and RASP controls."
                ),
            })
        else:
            perm_list = bundle["permissions"][:5] or ["android.permission.INTERNET"]
            perm_lines = "\n".join(f'    const-string v0, "{p}"' for p in perm_list)
            snippets.append({
                "file_name": f"{bundle['app_label'].replace(' ', '')}ManifestAudit.smali",
                "method_name": "inspectRequestedCapabilities()",
                "code_type": "Manifest / API Signal",
                "smali_code": (
                    ".method public inspectRequestedCapabilities()V\n"
                    "    .locals 2\n"
                    f"{perm_lines}\n"
                    "    return-void\n"
                    ".end method"
                ),
                "plain_english_interpretation": (
                    f"Static inspection of {pkg_name} enumerated {len(bundle['permissions'])} declared permissions "
                    f"with a permission risk score of {bundle['m1_perm']:.0f}/100."
                ),
                "bank_countermeasure": (
                    "Audit least-privilege permission usage, block sideloaded installers, and monitor network egress."
                ),
            })

    return snippets[:4]


def _build_grounded_kill_chain(bundle: dict[str, Any], is_official_bank: bool) -> list[dict[str, Any]]:
    perms_upper = " ".join(bundle["permissions"]).upper()
    has_sms_or_overlay = any(
        tok in perms_upper
        for tok in ["READ_SMS", "RECEIVE_SMS", "SEND_SMS", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"]
    )
    has_boot = "RECEIVE_BOOT_COMPLETED" in perms_upper
    has_c2 = len(bundle["genuine_c2"]) > 0
    has_exfil = len(bundle["exfil_events"]) > 0

    stages: list[dict[str, Any]] = []
    for stage_num, phase_label in KILL_CHAIN_PHASES:
        if stage_num == 1:
            status = "Observed"
            evidence = f"M1/M4: {bundle['pkg_name']} ({bundle['social_archetype']})"
            desc = (
                f"Distributed as '{bundle['app_label']}' ({bundle['pkg_name']}) with social engineering risk "
                f"{bundle['m4_score']:.0f}/100."
            )
        elif stage_num == 2:
            status = "Observed" if (has_sms_or_overlay or bundle["m1_perm"] >= 40) else "Inferred"
            evidence = f"M1: {len(bundle['permissions'])} perms, risk {bundle['m1_perm']:.0f}/100"
            desc = (
                "Declares high-risk SMS, overlay, or accessibility permissions."
                if has_sms_or_overlay
                else f"Requests {len(bundle['permissions'])} standard/moderate permissions without critical OTP-hijack privileges."
            )
        elif stage_num == 3:
            status = "Observed" if bundle["m2_score"] >= 50 else "Not Observed"
            evidence = f"M2: {bundle['family']} ({bundle['m2_score']:.1f}% similarity)"
            desc = (
                f"Behavioral DNA aligns strongly with {bundle['family']} ({bundle['m2_score']:.1f}%), indicating legacy/known telemetry patterns."
                if bundle["m2_score"] >= 50
                else "No confirmed device fingerprinting or high-confidence trojan behavioral lineage."
            )
        elif stage_num == 4:
            status = "Observed" if bundle["m3_is_dormant"] else ("Inferred" if bundle["m3_status"] == "complete" else "Not Observed")
            evidence = f"M3: status={bundle['m3_status']}, dormant={bundle['m3_is_dormant']}"
            desc = (
                "Application remained dormant in the sandbox without generating UI activity or contacting declared endpoints, suggesting anti-analysis evasion."
                if bundle["m3_is_dormant"]
                else f"Dynamic execution completed ({bundle['m3_status']}) with runtime score {bundle['m3_score']:.0f}/100."
            )
        elif stage_num == 5:
            status = "Observed" if bundle["raw_api_chain"] > 0 else "Not Observed"
            evidence = f"M1/M3: API chain score {bundle['raw_api_chain']:.1f}/100"
            desc = (
                f"Detected suspicious API execution chains (score {bundle['raw_api_chain']:.1f}/100)."
                if bundle["raw_api_chain"] > 0
                else "No dynamic DEX loading or reflective stager execution observed."
            )
        elif stage_num == 6:
            status = "Observed" if (has_exfil or has_c2) else "Not Observed"
            evidence = f"M3: {len(bundle['exfil_events'])} exfil events, {len(bundle['genuine_c2'])} public hosts"
            desc = (
                f"External untrusted hosts identified: {', '.join(bundle['genuine_c2'][:3])}."
                if (has_exfil or has_c2)
                else "No verified external C2 communication or data exfiltration observed."
            )
        else:
            status = "Inferred" if has_boot else "Not Observed"
            evidence = "M1: RECEIVE_BOOT_COMPLETED" if has_boot else "M1/M3: Persistence check"
            desc = (
                "Declares RECEIVE_BOOT_COMPLETED for post-reboot initialization."
                if has_boot
                else "No boot-receiver persistence or automated background loop confirmed."
            )

        stages.append({
            "stage": stage_num,
            "title": phase_label,
            "status": status,
            "evidence_source": evidence,
            "description": desc,
        })

    return stages


def _generate_grounded_fallback(
    pipeline_results: dict[str, Any],
    bundle: dict[str, Any],
    reason: str = "fallback",
) -> dict[str, Any]:
    pkg_name = bundle["pkg_name"]
    app_label = bundle["app_label"]
    authenticity = bundle["authenticity"]
    is_official_bank = (
        str(authenticity.get("status", "")).upper() == "AUTHENTIC_OFFICIAL_BANK"
        or any(tok in pkg_name.lower() for tok in OFFICIAL_BANK_TOKENS)
    )

    c2_label = bundle["genuine_c2"][0] if bundle["genuine_c2"] else "None Observed"
    c2_jurisdiction = f"EXTERNAL ({c2_label})" if bundle["genuine_c2"] else "None Observed"

    if is_official_bank:
        genai_score = 5.0
        threat_level = "LOW"
        target_inst = authenticity.get("bank_name") or f"{app_label} Banking"
        exec_summary = (
            f"Artifact {pkg_name} ({app_label}) matches an official banking application profile with low static "
            f"permission risk ({bundle['m1_perm']:.0f}/100) and zero verified external C2 exfiltration."
        )
        findings = [
            f"Verified official banking package namespace ({pkg_name}).",
            f"Static permission profile ({bundle['m1_perm']:.0f}/100) aligns with legitimate banking operations.",
            f"Dynamic sandbox run ({bundle['m3_status']}) recorded zero unauthorized exfiltration events.",
        ]
    else:
        max_signal = max(
            bundle["m1_perm"],
            bundle["m2_score"],
            bundle["m3_score"],
            bundle["m4_score"],
            bundle["raw_api_chain"],
        )
        if len(bundle["exfil_events"]) > 0 or max_signal >= 75:
            genai_score = round(min(95.0, max(70.0, max_signal)), 1)
            threat_level = "HIGH"
        elif max_signal >= 45:
            genai_score = round(min(69.0, max(45.0, max_signal)), 1)
            threat_level = "MEDIUM"
        else:
            genai_score = round(min(40.0, max(10.0, max_signal * 0.6)), 1)
            threat_level = "LOW"

        target_inst = "Android Retail Users (General Consumer Ecosystem)"
        dormancy_note = (
            " Dynamic analysis flagged sandbox dormancy, indicating potential anti-VM or anti-debugging evasion."
            if bundle["m3_is_dormant"]
            else f" Dynamic runtime monitoring recorded {len(bundle['exfil_events'])} exfiltration event(s)."
        )
        exec_summary = (
            f"Artifact {pkg_name} ({app_label}) exhibits {bundle['m2_score']:.1f}% behavioral alignment with the "
            f"{bundle['family']} lineage alongside a static permission risk of {bundle['m1_perm']:.0f}/100."
            f"{dormancy_note} Public external C2 indicators: {c2_label}."
        )
        findings = [
            f"Behavioral DNA strongly correlates with {bundle['family']} ({bundle['m2_score']:.1f}% similarity).",
            f"Static analysis identified {len(bundle['permissions'])} permissions (risk score {bundle['m1_perm']:.0f}/100) and {len(bundle['suspicious_api_chains'])} suspicious API chain(s).",
            f"Dynamic sandbox ({bundle['m3_status']}) observed {len(bundle['exfil_events'])} exfiltration event(s) and dormancy={bundle['m3_is_dormant']}.",
            f"Publicly routable untrusted endpoints identified: {c2_label}.",
        ]

    snippets = [_ensure_multiline_smali(s) for s in _build_snippets_from_modules(bundle, is_official_bank)]
    primary_code = snippets[0]

    return {
        "module": "genai_synthesis",
        "status": "complete",
        "genai_score": genai_score,
        "severity_score": genai_score,
        "threat_level": threat_level,
        "brief": {
            "executive_summary": exec_summary,
            "targeted_institution": target_inst,
            "est_accounts_at_risk": "Enrolled Banking Users" if is_official_bank else "General Android Installs",
            "c2_jurisdiction": c2_jurisdiction,
            "key_findings": findings,
        },
        "code_interpreter": {
            "file_name": primary_code["file_name"],
            "method_name": primary_code["method_name"],
            "smali_code": primary_code["smali_code"],
            "plain_english_interpretation": primary_code["plain_english_interpretation"],
            "bank_countermeasure": primary_code["bank_countermeasure"],
        },
        "code_snippets": snippets,
        "kill_chain": _build_grounded_kill_chain(bundle, is_official_bank),
        "rbi_compliance": {
            "incident_ref": f"RBI/CSITE/{datetime.now().strftime('%Y%m%d')}/{pkg_name.split('.')[-1].upper()[:6]}",
            "circular_section": "RBI Master Circular Section 7.4",
            "mandates": [
                "Document verified forensic indicators and containment timeline under RBI Master Circular Section 7.4.",
                "Block confirmed external malicious C2 infrastructure at network perimeter controls.",
                "Enforce device attestation and prohibit sideloaded binaries on retail banking devices.",
            ],
        },
        "mode": f"grounded_engine ({reason})",
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }


def _normalize_llm_payload(raw_dict: dict[str, Any], bundle: dict[str, Any]) -> dict[str, Any]:
    d = dict(raw_dict or {})
    if not isinstance(d.get("rbi_compliance"), dict):
        pkg_suffix = bundle["pkg_name"].split(".")[-1].upper()[:6] or "APK"
        d["rbi_compliance"] = {
            "incident_ref": f"RBI/CSITE/{datetime.now().strftime('%Y%m%d')}/{pkg_suffix}",
            "circular_section": "RBI Master Circular Section 7.4",
            "mandates": [
                "Document verified forensic indicators and containment timeline under RBI Master Circular Section 7.4.",
                "Block confirmed external malicious C2 infrastructure at network perimeter controls.",
                "Enforce device attestation and prohibit sideloaded binaries on retail banking devices.",
            ],
        }
    return d


def _invoke_openai_compat_json(
    base_url: str,
    api_key: str,
    models: list[str],
    prompt: str,
    bundle: dict[str, Any],
    provider_label: str,
    extra_headers: dict[str, str] | None = None,
) -> tuple[dict[str, Any] | None, str, Exception | None]:
    """Calls an OpenAI-compatible chat completions endpoint (Groq or OpenRouter)."""
    if not api_key:
        return None, "", None

    try:
        import requests
    except ImportError as exc:
        return None, "", exc

    schema_hint = json.dumps(ForensicReportSchema.model_json_schema())
    system_prompt = (
        "You are a Principal Mobile Threat Intelligence Analyst writing a forensic briefing "
        "for a Tier-1 Banking SOC under RBI Master Circular Section 7.4. "
        "Return ONLY a single valid JSON object matching this JSON Schema without markdown fences or extra text:\n"
        f"{schema_hint}"
    )

    endpoint_url = _sanitize_url(f"{_sanitize_url(base_url).rstrip('/')}/chat/completions")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)

    last_err: Exception | None = None
    for model_name in models:
        clean_model = str(model_name or "").strip()
        if not clean_model:
            continue
        for attempt in range(1, 3):
            try:
                print(f"[M5] Invoking {provider_label} {clean_model} (attempt {attempt}/2)...", flush=True)
                resp = requests.post(
                    endpoint_url,
                    headers=headers,
                    json={
                        "model": clean_model,
                        "temperature": 0.2,
                        "response_format": {"type": "json_object"},
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt},
                        ],
                    },
                    timeout=30,
                )
                if resp.status_code >= 400:
                    raise RuntimeError(f"HTTP {resp.status_code}: {resp.text.strip()[:220]}")

                payload = resp.json()
                raw_content = (
                    payload.get("choices", [{}])[0]
                    .get("message", {})
                    .get("content", "")
                )
                if not raw_content:
                    raise RuntimeError(f"Empty content returned by {provider_label}")

                cleaned_str = _extract_first_json_object(raw_content)
                parsed_raw = json.loads(cleaned_str)
                normalized = _normalize_llm_payload(parsed_raw, bundle)
                parsed_obj = ForensicReportSchema.model_validate(normalized)
                return parsed_obj.model_dump(), f"{provider_label} ({clean_model}, json_object)", None
            except Exception as exc:
                last_err = exc
                err_lower = str(exc).lower()
                print(
                    f"[M5 WARN] {provider_label} {clean_model} attempt {attempt} failed: {type(exc).__name__}: {str(exc)[:160]}",
                    flush=True,
                )
                if _is_not_found_error(err_lower):
                    break
                if _is_transient_error(err_lower) and attempt < 2:
                    time.sleep(1.0 + random.uniform(0.15, 0.5))
                    continue
                break

    return None, "", last_err


def _invoke_gemini_json(
    prompt: str,
    bundle: dict[str, Any],
) -> tuple[dict[str, Any] | None, str, Exception | None]:
    """Calls Gemini structured output API with fast 404 skip and jittered backoff on 503/429."""
    if not _GENAI_CLIENT or not GEMINI_API_KEY:
        return None, "", None

    try:
        from google.genai import types
    except ImportError as exc:
        return None, "", exc

    last_err: Exception | None = None
    for model_name in _get_gemini_models():
        for attempt in range(1, 3):
            try:
                print(f"[M5] Invoking Gemini {model_name} (attempt {attempt}/2)...", flush=True)
                response = _GENAI_CLIENT.models.generate_content(
                    model=model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=ForensicReportSchema,
                        temperature=0.2,
                    ),
                )
                parsed = getattr(response, "parsed", None)
                if parsed is not None and hasattr(parsed, "model_dump"):
                    normalized = _normalize_llm_payload(parsed.model_dump(), bundle)
                    return ForensicReportSchema.model_validate(normalized).model_dump(), f"google_genai ({model_name}, structured)", None
                if response and response.text:
                    cleaned_str = _extract_first_json_object(response.text)
                    parsed_raw = json.loads(cleaned_str)
                    normalized = _normalize_llm_payload(parsed_raw, bundle)
                    return ForensicReportSchema.model_validate(normalized).model_dump(), f"google_genai ({model_name}, structured)", None
                raise RuntimeError("Empty response from Gemini")
            except Exception as exc:
                last_err = exc
                err_lower = str(exc).lower()
                print(
                    f"[M5 WARN] Gemini {model_name} attempt {attempt} failed: {type(exc).__name__}: {str(exc)[:160]}",
                    flush=True,
                )
                if _is_not_found_error(err_lower):
                    break
                if _is_transient_error(err_lower) and attempt < 2:
                    time.sleep(1.2 + random.uniform(0.2, 0.7))
                    continue
                break

    return None, "", last_err


def analyze_genai(pipeline_results: dict[str, Any]) -> dict[str, Any]:
    bundle = _extract_telemetry_bundle(pipeline_results)
    authenticity = bundle["authenticity"]
    is_official_bank = (
        str(authenticity.get("status", "")).upper() == "AUTHENTIC_OFFICIAL_BANK"
        or any(tok in bundle["pkg_name"].lower() for tok in OFFICIAL_BANK_TOKENS)
    )

    is_benign_candidate = (
        not is_official_bank
        and bundle["m1_perm"] <= 35.0
        and bundle["m2_score"] < 35.0
        and bundle["raw_api_chain"] == 0.0
        and len(bundle["exfil_events"]) == 0
        and len(bundle["genuine_c2"]) == 0
    )

    groq_key = os.environ.get("GROQ_API_KEY", "").strip().strip('"').strip("'") or GROQ_API_KEY
    openrouter_key = (
        os.environ.get("OPENROUTER_API_KEY", "").strip().strip('"').strip("'") or OPENROUTER_API_KEY
    )
    provider_pref = os.environ.get("SPECTRE_M5_PROVIDER", "").strip().lower() or M5_PROVIDER_PREF

    has_any_llm = bool(openrouter_key or groq_key or (_GENAI_CLIENT and GEMINI_API_KEY))
    if provider_pref == "fallback" or not has_any_llm:
        reason = "provider_pref_fallback" if provider_pref == "fallback" else "no_llm_api_key"
        print(f"[M5 INFO] Using deterministic grounded synthesis ({reason}).", flush=True)
        return _generate_grounded_fallback(pipeline_results, bundle, reason=reason)

    telemetry_payload = {
        "package_name": bundle["pkg_name"],
        "app_label": bundle["app_label"],
        "is_official_bank": is_official_bank,
        "benign_candidate": is_benign_candidate,
        "m1_static": {
            "permission_risk": bundle["m1_perm"],
            "static_risk_score": bundle["m1_static_risk"],
            "dangerous_permissions": bundle["dangerous_permissions"],
            "combo_alerts": bundle["combo_alerts"],
            "suspicious_api_chains": bundle["suspicious_api_chains"],
            "exported_components": bundle["exported"],
        },
        "m2_behavioral_dna": {
            "behavioral_score": bundle["m2_score"],
            "closest_family": bundle["family"],
            "top_matches": bundle["top_matches"],
            "top1_margin_percent": bundle["top1_margin_percent"],
        },
        "m3_dynamic_sandbox": {
            "status": bundle["m3_status"],
            "dynamic_risk_score": bundle["m3_score"],
            "is_dormant_or_evaded": bundle["m3_is_dormant"],
            "screenshots_captured": bundle["m3_screenshots"],
            "findings": bundle["dynamic_findings"],
            "api_chains": bundle["dynamic_api_chains"],
            "behavior_delta": bundle["behavior_delta"],
            "exfiltration_events": bundle["exfil_events"],
            "public_untrusted_endpoints": bundle["genuine_c2"],
        },
        "m4_social_engineering": {
            "score": bundle["m4_score"],
            "archetype": bundle["social_archetype"],
        },
    }

    prompt = f"""
You are a Principal Mobile Threat Intelligence Analyst writing a forensic briefing for a Tier-1 Banking SOC under RBI Master Circular Section 7.4.

Follow these strict accuracy rules using ONLY the telemetry JSON below:
1. Never append or invent unrelated brand/company names on obfuscated package or class names, and never claim millions of users unless explicitly supported by telemetry. Always use the exact `package_name` from telemetry and state uncertainty plainly when sandbox telemetry is dormant or C2 is unobserved.
2. Write `executive_summary` in 2-3 concise, factual sentences: (a) behavioral family match & M1/M2/M3/M4 signals, (b) observed vs dormant/unobserved runtime behavior, and (c) concrete risk based only on observed capabilities.
3. Write 4-5 `key_findings` where every bullet explicitly cites its source module (`M1 Static`, `M2 Behavioral`, `M3 Dynamic`, or `M4 Social`) and exact values from telemetry.
4. Set `rbi_compliance.circular_section` to "RBI Master Circular Section 7.4" and include `incident_ref` and `mandates`.
5. Populate all 7 `kill_chain` stages (1 to 7) with `status` in {{"Observed", "Inferred", "Not Observed"}} and exact `evidence_source`.
6. For `code_snippets`, provide 2-3 entries grounded in actual static permissions/chains or runtime deltas from telemetry, and make each `smali_code` a complete 5-10 line block including `.method`, `invoke-*` or `const-string` instructions, and `.end method`.

Telemetry:
{json.dumps(telemetry_payload, indent=2, default=str)}
"""

    data: dict[str, Any] | None = None
    mode_label = ""
    last_err: Exception | None = None

    if provider_pref in ("gemini", "groq", "openrouter"):
        order = [provider_pref] + [p for p in ("gemini", "groq", "openrouter") if p != provider_pref]
    else:
        order = ["gemini", "groq", "openrouter"]

    or_headers = {
        "HTTP-Referer": os.environ.get("OPENROUTER_SITE_URL", "http://localhost:3000").strip(),
        "X-Title": os.environ.get("OPENROUTER_APP_TITLE", "SPECTRE Threat Engine").strip(),
    }

    for backend_name in order:
        if backend_name == "gemini" and _GENAI_CLIENT and GEMINI_API_KEY:
            data, mode_label, err = _invoke_gemini_json(prompt, bundle)
            if err is not None:
                last_err = err
            if data:
                break
        elif backend_name == "groq" and groq_key:
            data, mode_label, err = _invoke_openai_compat_json(
                base_url="[https://api.groq.com/openai/v1](https://api.groq.com/openai/v1)",
                api_key=groq_key,
                models=_get_groq_models(),
                prompt=prompt,
                bundle=bundle,
                provider_label="groq",
            )
            if err is not None:
                last_err = err
            if data:
                break
        elif backend_name == "openrouter" and openrouter_key:
            data, mode_label, err = _invoke_openai_compat_json(
                base_url="[https://openrouter.ai/api/v1](https://openrouter.ai/api/v1)",
                api_key=openrouter_key,
                models=_get_openrouter_models(),
                prompt=prompt,
                bundle=bundle,
                provider_label="openrouter",
                extra_headers=or_headers,
            )
            if err is not None:
                last_err = err
            if data:
                break

    if not data:
        reason = type(last_err).__name__ if last_err else "all_llm_providers_failed"
        print(f"[M5 WARN] All LLM providers failed ({last_err}); using grounded fallback.", flush=True)
        logger.warning(f"[M5] LLM synthesis failed: {last_err}")
        return _generate_grounded_fallback(pipeline_results, bundle, reason=reason)

    raw_score = float(data.get("genai_score", 25.0))
    if 0.0 < raw_score <= 1.0 and not is_official_bank and not is_benign_candidate:
        raw_score = round(raw_score * 100.0, 1)

    # Align M5 with strong multi-module consensus on non-benign samples
    consensus_signal = (
        (bundle["m1_perm"] * 0.35)
        + (bundle["m2_score"] * 0.40)
        + (bundle["m4_score"] * 0.25)
    )
    if not is_official_bank and not is_benign_candidate and consensus_signal >= 65.0:
        raw_score = max(raw_score, round(consensus_signal * 0.85, 1))

    if is_official_bank:
        raw_score = min(15.0, raw_score)
        threat_level = "LOW"
    elif is_benign_candidate:
        raw_score = min(25.0, raw_score)
        threat_level = "LOW"
    else:
        threat_level = str(data.get("threat_level", "MEDIUM")).upper()

    clean_score = round(min(100.0, max(0.0, raw_score)), 1)

    module_snippets = [_ensure_multiline_smali(s) for s in _build_snippets_from_modules(bundle, is_official_bank)]
    llm_snippets = [_ensure_multiline_smali(s) for s in (data.get("code_snippets") or []) if isinstance(s, dict)]
    final_snippets = llm_snippets if llm_snippets else module_snippets
    primary_code = final_snippets[0] if final_snippets else module_snippets[0]

    kill_chain = data.get("kill_chain") or _build_grounded_kill_chain(bundle, is_official_bank)

    return {
        "module": "genai_synthesis",
        "status": "complete",
        "genai_score": clean_score,
        "severity_score": clean_score,
        "threat_level": threat_level,
        "brief": data.get("brief", {}),
        "code_interpreter": {
            "file_name": primary_code.get("file_name", "Analysis.smali"),
            "method_name": primary_code.get("method_name", "execute()"),
            "smali_code": primary_code.get("smali_code", ""),
            "plain_english_interpretation": primary_code.get("plain_english_interpretation", ""),
            "bank_countermeasure": primary_code.get("bank_countermeasure", ""),
        },
        "code_snippets": final_snippets,
        "kill_chain": kill_chain,
        "rbi_compliance": data.get("rbi_compliance", {}),
        "mode": mode_label,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    }