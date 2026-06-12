def apply_hard_overrides(results: dict) -> dict:
    try:
        perms = results.get('static', {}).get(
            'permission_data', {}
        ).get('dangerous_permissions', [])
        
        perm_names = [p.get('permission', '') for p in perms]
        # .get('permission', '') safely gets the permission field
        # '' default prevents crash if field is missing

        has_accessibility = 'android.permission.BIND_ACCESSIBILITY_SERVICE' in perm_names
        has_overlay = 'android.permission.SYSTEM_ALERT_WINDOW' in perm_names
        exfil = results.get('dynamic', {}).get('exfiltration_events', [])
        behavioral_score = results.get('behavioral', {}).get('behavioral_score', 0)

        override_reasons = []

        if has_accessibility and has_overlay:
            override_reasons.append('ACCESSIBILITY + OVERLAY combo detected')

        if len(exfil) > 0:
            override_reasons.append('OTP exfiltration captured by mitmproxy')

        if behavioral_score > 85:
            override_reasons.append('Behavioral similarity >85% to Drebin family')

        if override_reasons:
            return {
                'override_applied': True,
                'forced_verdict': 'CRITICAL',
                'forced_score': 97,
                'reasons': override_reasons
            }

        # ALWAYS return a dict — never return None
        return {
            'override_applied': False,
            'forced_verdict': None,
            'forced_score': None,
            'reasons': []
        }

    except Exception as e:
        # Safety net — never crash the pipeline
        print(f'[OVERRIDE] Error in override check: {e}')
        return {
            'override_applied': False,
            'forced_verdict': None,
            'forced_score': None,
            'reasons': []
        }