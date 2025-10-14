#!/usr/bin/env bash
set -euo pipefail

echo "NebulaCore Bootstrap Wizard"
echo

echo "Checking system dependencies..."
REQUIRED_CMDS=(docker docker-compose vault git python3 openssl)
MISSING=()
for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    MISSING+=("$cmd")
  fi
done

if [ "${#MISSING[@]}" -ne 0 ]; then
  echo "Missing required commands: ${MISSING[*]}"
  echo "Please install them and re-run this script."
  exit 1
fi

export VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
HF_TOKEN="${HF_TOKEN:-}"
MODEL_DIR="${MODEL_DIR:-./mistral-7b}"

echo "VAULT_ADDR = $VAULT_ADDR"
echo

echo "Initializing Vault (docker-compose up -d vault)..."
docker-compose up -d vault

echo "Waiting for Vault API to respond..."
MAX_WAIT=120
WAITED=0
SLEEP_INTERVAL=2
while true; do
  if vault status -format=json >/dev/null 2>&1; then
    STATUS_JSON=$(vault status -format=json 2>/dev/null || echo "")
    if [ -n "$STATUS_JSON" ]; then
      INITIALIZED=$(printf '%s' "$STATUS_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('initialized'))")
      if [ "$INITIALIZED" = "True" ] || [ "$INITIALIZED" = "true" ]; then
        echo "Vault is initialized."
        break
      else
        echo "Vault reachable but not initialized yet."
        break
      fi
    fi
  fi

  sleep $SLEEP_INTERVAL
  WAITED=$((WAITED + SLEEP_INTERVAL))
  if [ "$WAITED" -ge "$MAX_WAIT" ]; then
    echo "Timeout waiting for Vault to become reachable."
    exit 1
  fi
done

echo "Checking if Vault is initialized..."
STATUS_JSON=$(vault status -format=json 2>/dev/null || echo "")
INITIALIZED="false"
if [ -n "$STATUS_JSON" ]; then
  INITIALIZED=$(printf '%s' "$STATUS_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('initialized'))")
fi

ROOT_TOKEN_FILE="./vault-root-token.txt"
UNSEAL_KEY_FILE="./vault-unseal-key.txt"

if [ "$INITIALIZED" != "True" ] && [ "$INITIALIZED" != "true" ]; then
  echo "Vault not initialized. Initializing (1 key share, threshold 1)..."
  INIT_JSON=$(vault operator init -key-shares=1 -key-threshold=1 -format=json)
  ROOT_TOKEN=$(printf '%s' "$INIT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")
  UNSEAL_KEY=$(printf '%s' "$INIT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['unseal_keys_b64'][0])")

  printf '%s\n' "$ROOT_TOKEN" > "$ROOT_TOKEN_FILE"
  chmod 600 "$ROOT_TOKEN_FILE"
  printf '%s\n' "$UNSEAL_KEY" > "$UNSEAL_KEY_FILE"
  chmod 600 "$UNSEAL_KEY_FILE"

  echo "Unsealing Vault..."
  vault operator unseal "$UNSEAL_KEY"

  echo "Vault initialized. Root token stored in: $ROOT_TOKEN_FILE"
  echo "Unseal key stored in: $UNSEAL_KEY_FILE"
  export VAULT_TOKEN="$ROOT_TOKEN"
else
  echo "Vault already initialized. Attempting to read token file ($ROOT_TOKEN_FILE) if present..."
  if [ -f "$ROOT_TOKEN_FILE" ]; then
    export VAULT_TOKEN
    VAULT_TOKEN=$(cat "$ROOT_TOKEN_FILE")
    export VAULT_TOKEN
    echo "Using root token from $ROOT_TOKEN_FILE"
  else
    echo "Root token file not found; ensure VAULT_TOKEN env var is set if you need to perform admin operations."
  fi
fi

if [ -z "${VAULT_TOKEN:-}" ]; then
  echo "Warning: VAULT_TOKEN is not set. Some operations (writing secrets) may fail."
else
  export VAULT_TOKEN
fi

echo "Setting Vault secrets for NebulaCore..."
MASTER_PASSWORD=$(openssl rand -base64 32)
if vault kv put secret/nebula/master_password master_password="$MASTER_PASSWORD" >/dev/null 2>&1; then
  echo "Master password stored in Vault at secret/nebula/master_password"
else
  echo "Failed to write master_password to Vault. Please check VAULT_TOKEN and Vault status."
fi

if [ -n "$HF_TOKEN" ]; then
  if vault kv put secret/nebula/hf_token hf_token="$HF_TOKEN" >/dev/null 2>&1; then
    echo "HF_TOKEN stored in Vault at secret/nebula/hf_token"
  else
    echo "Failed to write HF_TOKEN to Vault. Please check VAULT_TOKEN and Vault status."
  fi
else
  echo "HF_TOKEN not provided; skipping storing HuggingFace token."
fi

echo "Starting services (postgres redis ai-model control-plane agent-local)..."
docker-compose up -d postgres redis ai-model control-plane agent-local

echo "Checking docker-compose services status..."
docker-compose ps

echo
echo "NebulaCore bootstrap complete."
echo "If Vault was just initialized, root token saved to: $ROOT_TOKEN_FILE (secure this file!)."
echo "Access web UI at http://localhost:8080"