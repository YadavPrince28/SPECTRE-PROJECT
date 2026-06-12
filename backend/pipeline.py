# pipeline.py — Main analysis orchestrator
# Week 1: All functions are stubs
# Week 2-7: Replace stubs with real module calls one by one

import logging
logging.getLogger('androguard').setLevel(logging.ERROR)

from modules.static_analysis import analyze_static
from modules.behavioral_dna import analyze_behavioral_dna
from modules.dynamic_analysis import analyze_dynamic
from modules.script_extractor import analyze_social_engineering
from modules.genai_layer import analyze_genai
from modules.risk_scoring import apply_hard_overrides

def run_pipeline(apk_path: str, job_id: str) -> dict:
    print(f'[PIPELINE] Starting analysis: {apk_path}')
    results = {}

    # Module 1 — Static Analysis (Week 2-3)
    print("[PIPELINE] M1: Static Analysis starting...")
    results["static"] = analyze_static(apk_path)
    print(f"[PIPELINE] M1: Done. Score: {results['static'].get('static_risk_score', 0)}")

    # Module 2 — Behavioral DNA (Week 4)
    print('[PIPELINE] M2: Behavioral DNA starting...')
    results['behavioral'] = analyze_behavioral_dna(apk_path)
    print(f"[PIPELINE] M2: Done. Score: {results['behavioral'].get('behavioral_score', 0)}")

    # Module 3 — Dynamic Analysis (Week 5)
    print('[PIPELINE] M3: Dynamic Analysis starting...')
    results['dynamic'] = analyze_dynamic(apk_path, job_id=job_id)
    print(f"[PIPELINE] M3: Done. Score: {results['dynamic'].get('dynamic_risk_score', 0)}")

    # Module 4 — Social Engineering (Week 6)
    print("[PIPELINE] M4: Social Engineering starting...")
    results['social'] = analyze_social_engineering(apk_path)
    print(f"[PIPELINE] M4: Done. Score: {results['social'].get('social_score', 0)}")

    # Module 5 — GenAI Layer (Week 7)
    print("[PIPELINE] M5: GenAI Layer starting...")
    results['genai'] = analyze_genai(results)
    print(f"[PIPELINE] M5: Done.")

    # Final risk score aggregation
    print("[PIPELINE] Calculating final risk score...")
    final_score = calculate_final_score(results)

    override = apply_hard_overrides(results)
    if override.get("override_applied", False):
        final_score["score"]           = override["forced_score"]
        final_score["verdict"]         = override["forced_verdict"]
        final_score["override_reasons"] = override["reasons"]

    results["final_score"] = final_score

    print(f"[PIPELINE] Complete. Final score: {final_score['score']} — {final_score['verdict']}")
    return results

def calculate_final_score(results: dict) -> dict:
    # Risk weight formula from SPECTRE spec
    weights = {
        'malicious_api_chain':        0.18,
        'dynamic_runtime':            0.18,
        'social_engineering':         0.16,
        'behavioral_family':          0.15,
        'permission_risk':            0.13,
        'genai_severity':             0.10,
        'network_exfiltration':       0.10,
    }

    # Placeholder scores until modules are built
    scores = {
        'malicious_api_chain':   results.get('static',   {}).get('chain_score', 0),
        'dynamic_runtime':       results.get('dynamic',  {}).get('dynamic_risk_score', 0),
        'social_engineering':    results.get('social',   {}).get('social_score', 0),
        'behavioral_family':     results.get('behavioral',{}).get('behavioral_score', 0),
        'permission_risk':       results.get('static',   {}).get('permission_score', 0),
        'genai_severity':        results.get('genai',    {}).get('genai_score', 0),
        'network_exfiltration':  results.get('dynamic',  {}).get('dynamic_risk_score', 0),
    }

    final = sum(scores[k] * weights[k] for k in weights)
    final = min(100, int(final))

    # Hard CRITICAL override
    if final >= 95:
        verdict = 'CRITICAL'
    elif final >= 70:
        verdict = 'HIGH'
    elif final >= 40:
        verdict = 'MEDIUM'
    else:
        verdict = 'LOW'

    return {'score': final, 'verdict': verdict, 'component_scores': scores}