# profile_builder.py 
# Interactive onboarding script. Asks different questions based on target_type.
# For a traditional-only client (your full-stack app), skip all ML questions.
# For a full_spectrum client, answer both sections.
# Run: python profile_builder.py

import yaml, os

def ask(prompt, default=None):
    """Ask a question with an optional default value shown in brackets."""
    suffix = f' [{default}]' if default else ''
    val = input(f'{prompt}{suffix}: ').strip()
    return val if val else default

def build_profile():
    print('\n═══════════════════════════════════════════════════')
    print('   OgunAI  Profile Builder                      ')
    print('═══════════════════════════════════════════════════')
    print('Press Enter to accept default values.\n')

    profile = {}
    profile['client_name'] = ask('Client name (e.g. FraudShield, MyEcommerceApp)')
    profile['api_url'] = ask('Base URL (e.g. https://api.client.com)')

    # Target type determines which attack families will be active.
    print('\nTarget type:')
    print('  1. ml_only          — ML API only (fraud detection, scoring)')
    print('  2. traditional_only — Web app / REST API only (no ML)')
    print('  3. full_spectrum    — Both ML and traditional surfaces')
    choice = ask('Choose (1/2/3)', '1')
    profile['target_type'] = {
        '1': 'ml_only', '2': 'traditional_only', '3': 'full_spectrum'
    }.get(choice, 'ml_only')

    # Auth settings apply regardless of target type.
    profile['auth_type'] = ask('Auth type (api_key / bearer_token / none)', 'api_key')
    if profile['auth_type'] != 'none':
        profile['auth_header'] = ask('Auth header name', 'X-API-KEY')

    # ── ML SURFACE CONFIGURATION ─────────────────────────────────────
    if profile['target_type'] in ('ml_only', 'full_spectrum'):
        print('\n--- ML Surface ---')
        profile['predict_endpoint'] = ask('Predict endpoint path', '/predict')

        print('List the input fields the predict endpoint accepts.')
        print('Enter field name then type (string/float/int). Empty name to stop.')
        profile['input_schema'] = {}
        while True:
            field = input('  Field name: ').strip()
            if not field: break
            ftype = ask(f'  Type of {field}', 'string')
            profile['input_schema'][field] = ftype

        profile['output_schema'] = {
            'score_field':   ask('Score field in response JSON', 'score'),
            'score_range':   [0, 100],
            'decision_field': ask('Decision field in response JSON', 'decision'),
            'decision_values': {
                'approve': ask('Value meaning approve', 'approve'),
                'review':  ask('Value meaning review/hold', 'review'),
                'block':   ask('Value meaning block/decline', 'block'),
            },
            'explanation_field': ask('Explanation field (press Enter if none)', None),
        }

        print('\nDefences present? (y/n):')
        profile['defences'] = {
            'velocity_checks':   ask('Velocity/rate tracking?', 'n') == 'y',
            'shap_explanations': ask('SHAP or LIME explanations?', 'n') == 'y',
            'anomaly_detector':  ask('Anomaly detector?', 'n') == 'y',
        }

        primary_field = ask('Primary value field for threshold probing', 'amount')
        profile['probe_range'] = {
            'field':     primary_field,
            'min_value': int(ask('Min probe value', '1000')),
            'max_value': int(ask('Max probe value', '1000000')),
            'currency':  ask('Currency', 'NGN'),
        }

    # ── TRADITIONAL SURFACE CONFIGURATION ────────────────────────────
    if profile['target_type'] in ('traditional_only', 'full_spectrum'):
        print('\n--- Traditional Surface ---')
        profile['traditional_surface'] = {'endpoints': [], 'probe_paths': []}

        print('List the endpoints to test. Empty path to stop.')
        print('Available tests: sqli, xss, idor, brute_force, auth_bypass, rate_limit, mass_assignment')
        while True:
            path = input('  Endpoint path (e.g. /api/users/{id}): ').strip()
            if not path: break
            method   = ask(f'  Method', 'GET')
            auth_req = ask(f'  Auth required?', 'y') == 'y'
            tests_raw = input('  Tests (comma-separated): ').strip()
            tests = [t.strip() for t in tests_raw.split(',') if t.strip()]
            profile['traditional_surface']['endpoints'].append({
                'path': path, 'method': method.upper(),
                'auth_required': auth_req, 'tests': tests
            })

        print('\nExtra sensitive paths to probe (comma-separated, leave empty for defaults only):')
        extra = input('Enter paths separated by commas:').strip()
        if extra:
            profile['traditional_surface']['probe_paths'] = [p.strip() for p in extra.split(',')]

    # Market context — injected into the system prompt as domain knowledge.
    print('\nMarket context (fraud patterns, amount ranges, common attack patterns for this client):')
    profile['market_context'] = input(' Describe the client risk profile:').strip() or 'General system.'

    # Save the profile.
    os.makedirs('client_profiles', exist_ok=True)
    filename = profile['client_name'].lower().replace(' ', '_') + '.yaml'
    path = f'client_profiles/{filename}'
    with open(path, 'w') as f:
        yaml.dump(profile, f, default_flow_style=False, allow_unicode=True)

    print(f'\n✅ Profile saved to: {path}')
    print(f'Run a session: python run.py {path}')
    return path

if __name__ == '__main__':
    build_profile()
