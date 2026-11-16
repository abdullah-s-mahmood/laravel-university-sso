#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
SDK_PACKAGE_ROOT="$PWD"
export SDK_PACKAGE_ROOT
docker info >/dev/null
export INTEGRATION_RUNTIME
INTEGRATION_RUNTIME=$(mktemp -d)
export SDK_ONE_SECRET SDK_TWO_SECRET
SDK_ONE_SECRET=$(openssl rand -hex 32)
SDK_TWO_SECRET=$(openssl rand -hex 32)
export OIDC_TEST_USERNAME=synthetic-sdk-user
export OIDC_TEST_PASSWORD
OIDC_TEST_PASSWORD=$(openssl rand -hex 24)
export OIDC_ISSUER=https://localhost:8443/realms/sdk-test
export TLS_KEY="$INTEGRATION_RUNTIME/server.key" TLS_CERT="$INTEGRATION_RUNTIME/server.crt"
container="sdk-keycloak-$$"
pids=()
cleanup() {
  exit_status=$?
  if [ "$exit_status" -ne 0 ]; then
    # The runner changes directory later; always use the original package root.
    diagnostics="$SDK_PACKAGE_ROOT/tests/Integration/diagnostics"
    mkdir -p "$diagnostics"
    docker logs "$container" > "$INTEGRATION_RUNTIME/keycloak.log" 2>&1 || true
    python3 "$SDK_PACKAGE_ROOT/tests/Integration/sanitize-diagnostics.py" "$INTEGRATION_RUNTIME" "$diagnostics"
  fi
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$INTEGRATION_RUNTIME"
}
trap cleanup EXIT
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$TLS_KEY" -out "$TLS_CERT" -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,DNS:one.localhost,DNS:two.localhost,DNS:native.localhost,IP:127.0.0.1' >/dev/null 2>&1
# A temporary development CA is trusted explicitly; TLS verification stays enabled.
export NODE_EXTRA_CA_CERTS="$TLS_CERT" SSL_CERT_FILE="$TLS_CERT"
python3 tests/Integration/generate-realm.py
chmod 755 "$INTEGRATION_RUNTIME"
chmod 644 "$INTEGRATION_RUNTIME/realm.json"
docker run -d --name "$container" --network host -v "$INTEGRATION_RUNTIME/realm.json:/opt/keycloak/data/import/realm.json:ro" quay.io/keycloak/keycloak:26.8.2 start-dev --http-host=127.0.0.1 --import-realm --hostname=https://localhost:8443 --proxy-headers=xforwarded >/dev/null
node tests/Integration/proxy.mjs >"$INTEGRATION_RUNTIME/proxy.log" 2>&1 &
pids+=("$!")
for attempt in $(seq 1 120); do
  if curl --cacert "$TLS_CERT" -fsS "$OIDC_ISSUER/.well-known/openid-configuration" > /dev/null 2>&1; then break; fi
  if [ "$attempt" = 120 ]; then docker logs "$container"; exit 1; fi
  sleep 1
done
COMPOSER_ROOT_VERSION=dev-main composer install --working-dir=examples/consumer --prefer-dist --no-interaction
COMPOSER_ROOT_VERSION=dev-main composer reinstall --working-dir=examples/consumer university-sso/laravel-university-sso --no-interaction
for index in 0 1; do
  runtime="$INTEGRATION_RUNTIME/consumer-$index"
  mkdir -p "$runtime/bootstrap/cache" "$runtime/storage/framework/sessions" "$runtime/storage/framework/cache" "$runtime/storage/logs"
  printf '<?php return [];' > "$runtime/bootstrap/providers.php"
  client=sdk-one
  cookie=sdk_one
  host=one.localhost
  secret="$SDK_ONE_SECRET"
  if [ "$index" = 1 ]; then client=sdk-two; cookie=sdk_two; host=two.localhost; secret="$SDK_TWO_SECRET"; fi
  CONSUMER_RUNTIME="$runtime" CONSUMER_APP_KEY="base64:$(openssl rand -base64 32)" CONSUMER_CLIENT_ID="$client" CONSUMER_CLIENT_SECRET="$secret" CONSUMER_COOKIE="$cookie" CONSUMER_ORIGIN="https://$host:$((3000+index))" php -d "openssl.cafile=$TLS_CERT" -d "curl.cainfo=$TLS_CERT" -S "127.0.0.1:$((8000+index))" tests/Integration/consumer.php >"$runtime/server.log" 2>&1 &
  pids+=("$!")
done
php -d "openssl.cafile=$TLS_CERT" -d "curl.cainfo=$TLS_CERT" -S 127.0.0.1:8002 tests/Integration/broker.php >"$INTEGRATION_RUNTIME/broker.log" 2>&1 &
pids+=("$!")
cd tests/Integration
npm ci
npx playwright install chromium
# Browser accepts the ephemeral fixture certificate; PHP SDK trusts its CA explicitly.
set +e
npx playwright test >"$INTEGRATION_RUNTIME/playwright.log" 2>&1
test_status=$?
set -e
python3 "$SDK_PACKAGE_ROOT/tests/Integration/sanitize-diagnostics.py" "$INTEGRATION_RUNTIME" "$SDK_PACKAGE_ROOT/tests/Integration/diagnostics"
cat "$SDK_PACKAGE_ROOT/tests/Integration/diagnostics/playwright.log"
exit "$test_status"
