def analyze_static(apk_path: str) -> dict:
    return {
        'module': 'static_analysis',
        'status': 'stub',
        'static_risk_score': 0
    }