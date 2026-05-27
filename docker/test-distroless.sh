#!/bin/bash
#
# Smoke test for the distroless Web3Signer image.
#
# Runs the container with `--read-only` and no `--tmpfs` mount to prove that
# nothing anywhere on the rootfs is written at startup. If this test fails,
# something regressed that started writing outside /opt/web3signer/native-libs
# (e.g. a new dependency that triggers Netty native transport extraction, or
# jblst reverting the jar-strip in Dockerfile.distroless stage 2) — investigate
# before masking it with `--tmpfs /tmp`.
#
# The test also bulk-loads an EIP-2335 keystore via --keystores-path. This
# forces the jblst static initializer to load libblst.so, which is the exact
# code path that failed in issue #1175 before the jar-strip fix. Asserting the
# pubkey is returned from /api/v1/eth2/publicKeys proves BLS actually loaded.

set -euo pipefail

IMAGE="${1:?Usage: $0 <image> <reports-dir>}"
REPORTS_DIR="${2:?Usage: $0 <image> <reports-dir>}"
mkdir -p "$REPORTS_DIR"
REPORT="$REPORTS_DIR/smoke-report.txt"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYSTORE_SRC="$SCRIPT_DIR/../acceptance-tests/src/test/resources/eth2/bls_keystore.json"
KEYSTORE_PASSWORD="somepassword"
EXPECTED_PUBKEY="0x98d083489b3b06b8740da2dfec5cc3c01b2086363fe023a9d7dc1f907633b1ff11f7b99b19e0533e969862270061d884"

STAGE_DIR="$(mktemp -d)"
cp "$KEYSTORE_SRC" "$STAGE_DIR/keystore.json"
printf '%s' "$KEYSTORE_PASSWORD" > "$STAGE_DIR/password.txt"
# Distroless runs as uid 65532 (nonroot); mktemp defaults to mode 0700 owned
# by the host user. Open the dir/files so the container process can read them
# across the bind mount.
chmod 0755 "$STAGE_DIR"
chmod 0644 "$STAGE_DIR/keystore.json" "$STAGE_DIR/password.txt"

NAME="w3s_distroless_smoke_$$"
cleanup() {
  {
    echo
    echo "--- container logs ---"
    docker logs "$NAME" 2>&1 || true
  } >> "$REPORT"
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  rm -rf "$STAGE_DIR"
}
dump_logs_on_failure() {
  echo
  echo "--- container logs (tail) ---"
  docker logs --tail 80 "$NAME" 2>&1 || true
}
trap cleanup EXIT

echo "Running distroless smoke test against $IMAGE" | tee "$REPORT"

docker run -d --name "$NAME" \
  --read-only \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  -v "$STAGE_DIR":/keys:ro \
  -p 9000:9000 \
  "$IMAGE" \
  --http-listen-host=0.0.0.0 \
  eth2 --slashing-protection-enabled=false \
       --keystores-path=/keys \
       --keystores-password-file=/keys/password.txt

for i in $(seq 1 30); do
  if curl -fsS http://localhost:9000/upcheck >/dev/null 2>&1; then
    echo "upcheck passed after ${i}s" | tee -a "$REPORT"
    break
  fi
  sleep 1
  if [ "$i" -eq 30 ]; then
    echo "upcheck never succeeded" | tee -a "$REPORT"
    dump_logs_on_failure
    exit 1
  fi
done

# Keystore loading runs in a background thread; wait up to 15s for BLS +
# decryption to finish and the pubkey to appear.
SCENARIO1_OK=0
for i in $(seq 1 15); do
  PUBKEYS_JSON="$(curl -fsS http://localhost:9000/api/v1/eth2/publicKeys || true)"
  if [[ "$PUBKEYS_JSON" == *"$EXPECTED_PUBKEY"* ]]; then
    echo "keystore loaded and BLS native library resolved under --read-only" | tee -a "$REPORT"
    SCENARIO1_OK=1
    break
  fi
  sleep 1
done

if [ "$SCENARIO1_OK" -eq 0 ]; then
  echo "publicKeys response: $PUBKEYS_JSON" | tee -a "$REPORT"
  echo "expected pubkey $EXPECTED_PUBKEY not found in /api/v1/eth2/publicKeys" | tee -a "$REPORT"
  dump_logs_on_failure
  exit 1
fi

# ---------------------------------------------------------------------------
# Scenario 2: Key Manager API import under --read-only
#
# The container starts with an EMPTY keystores dir so BLS is NOT initialised
# at startup.  The first POST /eth/v1/keystores call triggers blstJNI.<clinit>
# for the first time.  With the jar-strip fix that initialiser falls through to
# System.loadLibrary("blst") → /opt/web3signer/native-libs/libblst.so and
# succeeds without touching /tmp.  Without the fix it tries to extract to
# /tmp/blst@… and fails with "Read-only file system".
# ---------------------------------------------------------------------------

NAME2="w3s_distroless_km_$$"
KM_PORT=9002

# Minimal config file for Scenario 2: Key Manager API enabled,
# Xkey-manager-skip-keystore-storage so no keystore files need writing,
# keystores-passwords-path (dir) so empty dir at startup is fine.
KM_CONFIG_DIR="$(mktemp -d)"
KM_KS_DIR="$KM_CONFIG_DIR/ks"
KM_PWDS_DIR="$KM_CONFIG_DIR/pwds"
mkdir -p "$KM_KS_DIR" "$KM_PWDS_DIR"
chmod 0755 "$KM_CONFIG_DIR" "$KM_KS_DIR" "$KM_PWDS_DIR"
cat > "$KM_CONFIG_DIR/config.yaml" <<'EOF'
http-listen-host: "0.0.0.0"
http-host-allowlist: "*"
eth2.key-manager-api-enabled: true
eth2.Xkey-manager-skip-keystore-storage: true
eth2.keystores-path: /km/ks
eth2.keystores-passwords-path: /km/pwds
EOF
chmod 0644 "$KM_CONFIG_DIR/config.yaml"

cleanup2() {
  {
    echo
    echo "--- scenario 2 container logs ---"
    docker logs "$NAME2" 2>&1 || true
  } >> "$REPORT"
  docker rm -f "$NAME2" >/dev/null 2>&1 || true
  rm -rf "$KM_CONFIG_DIR"
}
dump_logs2_on_failure() {
  echo
  echo "--- scenario 2 container logs (tail) ---"
  docker logs --tail 80 "$NAME2" 2>&1 || true
}
trap 'cleanup; cleanup2' EXIT

echo "" | tee -a "$REPORT"
echo "=== Scenario 2: Key Manager API import under --read-only ===" | tee -a "$REPORT"

docker run -d --name "$NAME2" \
  --read-only \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  -v "$KM_CONFIG_DIR":/km:ro \
  -p "${KM_PORT}:9000" \
  "$IMAGE" \
  --config-file=/km/config.yaml \
  eth2 --slashing-protection-enabled=false

for i in $(seq 1 30); do
  if curl -fsS "http://localhost:${KM_PORT}/upcheck" >/dev/null 2>&1; then
    echo "scenario 2 upcheck passed after ${i}s" | tee -a "$REPORT"
    break
  fi
  sleep 1
  if [ "$i" -eq 30 ]; then
    echo "scenario 2: upcheck never succeeded" | tee -a "$REPORT"
    dump_logs2_on_failure
    exit 1
  fi
done

# Build the Key Manager API request body: keystore JSON as an escaped string.
KM_PAYLOAD="$(jq -n \
  --argjson ks "$(jq -c . "$KEYSTORE_SRC")" \
  --arg pw "$KEYSTORE_PASSWORD" \
  '{keystores: [$ks | tojson], passwords: [$pw]}')"

KM_RESPONSE="$(curl -fsS \
  -X POST "http://localhost:${KM_PORT}/eth/v1/keystores" \
  -H 'Content-Type: application/json' \
  -d "$KM_PAYLOAD" || true)"

if [[ "$KM_RESPONSE" == *'"status":"imported"'* ]]; then
  echo "Key Manager API import succeeded under --read-only (BLS native library resolved)" | tee -a "$REPORT"
  exit 0
fi

echo "Key Manager API response: $KM_RESPONSE" | tee -a "$REPORT"
echo "expected status:imported in Key Manager API response" | tee -a "$REPORT"
dump_logs2_on_failure
exit 1
