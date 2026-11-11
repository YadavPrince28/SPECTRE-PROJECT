import os
import time
from dotenv import load_dotenv

load_dotenv(r'D:\Spectre_BOI_project\SPECTRE\.env')
api_key = os.getenv('GEMINI_API_KEY', '').strip().strip('"').strip("'")

print('=' * 60)
print('GEMINI API & ACTIVE MODEL CONNECTIVITY TEST')
print('=' * 60)
print(f'API Key Detected : {bool(api_key)} (Length: {len(api_key)})')

try:
    from google import genai
    # 25,000 milliseconds = 25 seconds
    client = genai.Client(api_key=api_key, http_options={'timeout': 25000})

    models_to_test = ['gemini-3.8-flash', 'gemini-3.5-flash-lite']
    working_model = None

    for m in models_to_test:
        print(f'\nContacting Google API endpoint with active model [{m}]...')
        t0 = time.time()
        try:
            resp = client.models.generate_content(
                model=m,
                contents='Output exactly the word: SUCCESS',
            )
            elapsed = round(time.time() - t0, 2)
            if resp and resp.text:
                print(f'-> [SUCCESS] Model {m} responded in {elapsed}s: {resp.text.strip()}')
                working_model = m
                break
        except Exception as e:
            elapsed = round(time.time() - t0, 2)
            print(f'-> [FAILED] {m} failed after {elapsed}s: {type(e).__name__} - {e}')

    print('\n' + '=' * 60)
    if working_model:
        print(f'[FINAL VERDICT] API is FULLY FUNCTIONAL with: {working_model}')
    else:
        print('[FINAL VERDICT] All models failed. Inspect the exception details above.')
    print('=' * 60)

except Exception as err:
    print(f'[FATAL] Client initialization error: {type(err).__name__} - {err}')
