"""Copy only sanitized textual diagnostics, never realm, cookies, sessions or keys."""
from pathlib import Path
import os, re, sys
source, target = map(Path, sys.argv[1:])
target.mkdir(parents=True, exist_ok=True)
secrets = [os.environ.get(key, '') for key in ['SDK_ONE_SECRET', 'SDK_TWO_SECRET', 'OIDC_TEST_PASSWORD']]
for path in source.rglob('*.log'):
    text = path.read_text(errors='replace')
    for secret in secrets:
        if secret:
            text = text.replace(secret, '[REDACTED]')
    text = re.sub(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', '[JWT REDACTED]', text)
    text = re.sub(r'(https?://[^\s?]+)\?[^\s]+', r'\1?[QUERY REDACTED]', text)
    text = re.sub(r'(?i)((?:access_token|id_token|refresh_token|client_secret|password|authorization|code_verifier)[\s"\x27:=]+)[^\s,}]+', r'\1[REDACTED]', text)
    name = '-'.join(path.relative_to(source).parts)
    (target / name).write_text(text)
