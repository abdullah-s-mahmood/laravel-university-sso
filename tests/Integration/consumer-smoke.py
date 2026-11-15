"""Boot an independent Laravel application through its Composer-installed SDK."""
from pathlib import Path
import tempfile, subprocess, os, time, urllib.request, urllib.error
root = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix='sdk-consumer-smoke-') as tmp:
    p = Path(tmp)
    for directory in ['bootstrap/cache', 'storage/framework/sessions', 'storage/framework/cache', 'storage/logs']:
        (p / directory).mkdir(parents=True, exist_ok=True)
    (p / 'bootstrap/providers.php').write_text('<?php return [];')
    env = os.environ | {
        'CONSUMER_RUNTIME': tmp,
        'CONSUMER_APP_KEY': 'base64:eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg=',
        'CONSUMER_CLIENT_ID': 'sdk-one', 'CONSUMER_COOKIE': 'sdk_one',
        'CONSUMER_ORIGIN': 'https://localhost:3000',
        'OIDC_ISSUER': 'https://localhost:8443/realms/sdk-test',
    }
    with (p / 'server.log').open('w') as log:
        process = subprocess.Popen(['php', '-S', '127.0.0.1:18000', 'tests/Integration/consumer.php'],
                                   cwd=root, env=env, stdout=log, stderr=log)
        try:
            time.sleep(1)
            for path, expected in [('/', 200), ('/account', 401), ('/logout-form', 200)]:
                try:
                    response = urllib.request.urlopen('http://127.0.0.1:18000' + path)
                    status = response.status
                except urllib.error.HTTPError as error:
                    status = error.code
                if status != expected:
                    raise RuntimeError(f'{path}: expected {expected}, received {status}; { (p / "server.log").read_text() }')
            print('Independent Laravel consumer boots and rejects unauthenticated access.')
        finally:
            process.terminate()
            process.wait()
