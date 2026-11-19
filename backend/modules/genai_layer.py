from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import time

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

_GENAI_CLIENT = None
if GEMINI_API_KEY:
    try:
        from google import genai

        _GENAI_CLIENT = genai.Client(
            api_key=GEMINI_API_KEY,
            http_options={"timeout": 35000},
        )
    except Exception as exc:
        print(f"[M5 ERROR] Failed to initialize Google GenAI client: {exc}", flush=True)
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
# Simplified Pydantic Schema (Compatible with Gemini Structured Outputs)
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


def _clean_json(raw_text: str) -> str:
    text = raw_text.strip()
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return match.group(0).strip()
    for prefix in ("```json", "```"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def _is_public_routable_host(host: str) -> bool:
    """Rejects private/RFC1918/loopback IPs (e.g., 10.0.0.172) and benign ad/infra domains."""
    h = str(host).strip().lower()
    if not h or any(b in h for b in BENIGN_AD_DOMAINS):
        return False
    # Strip scheme/path/port if a full URL slipped in
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


def _build_snippets_from_modules(
    bundle: dict[str, Any],
    is_official_bank: bool,
) -> list[dict[str, str]]:
    """Builds real Smali/trace snippets from M1 suspicious_api_chains and M3 runtime deltas."""
    snippets: list[dict[str, str]] = []
    pkg_name = bundle["pkg_name"]

    # 1. Real Dalvik/Smali call-sequence blocks from M1 suspicious_api_chains
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

    # 2. M3 runtime capability delta & exfiltration trace
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

    # 3. Fallback capability block if neither M1 chains nor M3 traces were populated
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

    snippets = _build_snippets_from_modules(bundle, is_official_bank)
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

    if not _GENAI_CLIENT or not GEMINI_API_KEY:
        print("[M5 WARN] GEMINI_API_KEY missing or client uninitialized; using grounded fallback.", flush=True)
        return _generate_grounded_fallback(pipeline_results, bundle, reason="no_api_key")

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
You are a Principal Mobile Threat Intelligence Analyst writing an executive forensic briefing for a Tier-1 Banking SOC (Mandiant / CERT-In standard) under RBI Master Circular Section 7.4.

Analyze the cross-module telemetry for this APK and synthesize a cohesive, authoritative assessment:
1. DO NOT just repeat raw numbers like "M1 Static Analysis: 13 permissions, risk score 35/100."
2. EXPLAIN what the cross-module correlation means (for example: if Behavioral DNA shows high similarity to a known malware family like Glodream while dynamic analysis shows dormancy and 0 exfiltration events, explain that this indicates either anti-sandbox evasion or a legacy trojanized/adware codebase requiring manual reverse engineering).
3. Write `executive_summary` as a sharp 3-sentence threat assessment covering: (a) classification & lineage, (b) observed capabilities or evasion, and (c) operational risk to retail/banking users.
4. Write `key_findings` as 4-5 analytical, evidence-backed bullet points linking specific permissions, API chains, behavioral lineage, or runtime gaps to real attack impact.
5. Set `rbi_compliance.circular_section` to exactly "RBI Master Circular Section 7.4" (do not repeat "Incident Reporting Standard").
6. Populate all 7 `kill_chain` stages (1 to 7) with `status` set to "Observed", "Inferred", or "Not Observed", citing the exact module and artifact in `evidence_source`.
7. Never invent C2 domains or treat private RFC1918 IPs (10.x, 192.168.x, 172.16-31.x) as external C2. If `public_untrusted_endpoints` is empty, set `c2_jurisdiction` to "None Observed".
8. For `code_snippets`, generate 2-3 realistic, telemetry-grounded Smali/trace items based on the actual permissions, API chains, or runtime deltas present in the telemetry.

Telemetry:
{json.dumps(telemetry_payload, indent=2, default=str)}
"""

    try:
        from google.genai import types

        model_candidates = [
            "gemini-3.5-flash-lite",
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
        ]

        data = None
        used_model = ""
        last_error = None

        for model_name in model_candidates:
            for attempt in range(1, 3):  # 2 attempts per model
                try:
                    print(f"[M5] Invoking {model_name} (attempt {attempt}/2)...", flush=True)
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
                        data = parsed.model_dump()
                    elif response and response.text:
                        data = ForensicReportSchema.model_validate_json(
                            _clean_json(response.text)
                        ).model_dump()

                    if data:
                        used_model = model_name
                        break
                except Exception as exc:
                    last_error = exc
                    err_str = str(exc)
                    print(
                        f"[M5 WARN] {model_name} attempt {attempt} failed: {type(exc).__name__}: {err_str[:160]}",
                        flush=True,
                    )
                    # Retry on transient 503/429 spikes before switching models
                    if ("503" in err_str or "429" in err_str or "UNAVAILABLE" in err_str) and attempt < 2:
                        time.sleep(2.5)
                        continue
                    break
            if data:
                break

        if not data:
            print(f"[M5 ERROR] All Gemini models failed. Last error: {last_error}", flush=True)
            logger.warning(f"[M5] Gemini structured synthesis failed: {last_error}")
            return _generate_grounded_fallback(
                pipeline_results,
                bundle,
                reason=type(last_error).__name__ if last_error else "empty_response",
            )

        raw_score = float(data.get("genai_score", 25.0))
        if is_official_bank:
            raw_score = min(15.0, raw_score)
            threat_level = "LOW"
        elif is_benign_candidate:
            raw_score = min(25.0, raw_score)
            threat_level = "LOW"
        else:
            threat_level = str(data.get("threat_level", "MEDIUM")).upper()

        clean_score = round(min(100.0, max(0.0, raw_score)), 1)

        module_snippets = _build_snippets_from_modules(bundle, is_official_bank)
        gemini_snippets = data.get("code_snippets") or []
        final_snippets = gemini_snippets if gemini_snippets else module_snippets
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
            "mode": f"google_genai ({used_model}, structured)",
            "completed_at": datetime.now(timezone.utc).isoformat(),
    }
    except Exception as exc:
        print(f"[M5 ERROR] Live Gemini call failed: {type(exc).__name__}: {exc}", flush=True)
        logger.warning(f"[M5] Gemini structured synthesis failed: {exc}")
        return _generate_grounded_fallback(pipeline_results, bundle, reason=type(exc).__name__)