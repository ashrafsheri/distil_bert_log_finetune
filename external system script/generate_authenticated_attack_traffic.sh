#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  generate_authenticated_attack_traffic.sh \
    --base-url https://api.barterease.co \
    --firebase-api-key "$FIREBASE_API_KEY" \
    --email "$TEST_EMAIL" \
    --password "$TEST_PASSWORD"

Optional:
  --user-id 3
  --community-id cf6315da-5347-40a7-9c7f-a3c824b79f98
  --delay-seconds 1
  --insecure

This script is intended only for systems you own or are explicitly authorized to test.
It sends read-only attack probes to validate LogGuard detection.
EOF
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1" >&2
    exit 1
  fi
}

BASE_URL=""
FIREBASE_API_KEY=""
EMAIL=""
PASSWORD=""
USER_ID="3"
COMMUNITY_ID=""
DELAY_SECONDS="1"
INSECURE=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      BASE_URL="$2"
      shift 2
      ;;
    --firebase-api-key)
      FIREBASE_API_KEY="$2"
      shift 2
      ;;
    --email)
      EMAIL="$2"
      shift 2
      ;;
    --password)
      PASSWORD="$2"
      shift 2
      ;;
    --user-id)
      USER_ID="$2"
      shift 2
      ;;
    --community-id)
      COMMUNITY_ID="$2"
      shift 2
      ;;
    --delay-seconds)
      DELAY_SECONDS="$2"
      shift 2
      ;;
    --insecure)
      INSECURE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$BASE_URL" || -z "$FIREBASE_API_KEY" || -z "$EMAIL" || -z "$PASSWORD" ]]; then
  usage >&2
  exit 1
fi

require_cmd curl
require_cmd jq

CURL_COMMON=(-sS --max-time 25)
if [[ "$INSECURE" -eq 1 ]]; then
  CURL_COMMON+=(-k)
fi

FIREBASE_URL="https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}"
AUTH_RESPONSE="$(
  curl "${CURL_COMMON[@]}" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"${EMAIL}\",\"password\":\"${PASSWORD}\",\"returnSecureToken\":true}" \
    "$FIREBASE_URL"
)"

ID_TOKEN="$(printf '%s' "$AUTH_RESPONSE" | jq -r '.idToken // empty')"
if [[ -z "$ID_TOKEN" ]]; then
  echo "Firebase sign-in failed:" >&2
  printf '%s\n' "$AUTH_RESPONSE" >&2
  exit 1
fi

declare -a LABELS=()
declare -a METHODS=()
declare -a PATHS=()
declare -a CURL_MODE=()

add_probe() {
  LABELS+=("$1")
  METHODS+=("$2")
  PATHS+=("$3")
  CURL_MODE+=("${4:-normal}")
}

add_probe "sqli_search" "GET" "/products?search=%27%20OR%201%3D1--"
add_probe "sqli_profile" "GET" "/users/${USER_ID}/public?sort=%27%20UNION%20SELECT%20NULL--"
add_probe "sqli_community" "GET" "/communities/user/my-communities?status=%27%20OR%20%271%27%3D%271"
add_probe "xss_search" "GET" "/products?search=%3Cscript%3Ealert(1)%3C%2Fscript%3E"
add_probe "xss_wants" "GET" "/users/me/wants?q=%22%3E%3Csvg%2Fonload%3Dalert(1)%3E"
add_probe "cmdi_sort" "GET" "/products?sort=name;cat%20/etc/passwd"
add_probe "cmdi_filter" "GET" "/products?filter=%24%28id%29"
add_probe "header_sqli" "GET" "/users/me"
add_probe "header_xss" "GET" "/users/me"
add_probe "path_traversal_root" "GET" "/../../etc/passwd" "path_as_is"
add_probe "path_traversal_user" "GET" "/users/../../../etc/passwd" "path_as_is"
add_probe "encoded_traversal" "GET" "/user/%2e%2e/%2e%2e/etc/passwd"

if [[ -n "$COMMUNITY_ID" ]]; then
  add_probe "community_sqli" "GET" "/products/community/${COMMUNITY_ID}?q=%27%20OR%201%3D1--"
fi

successes=0
failures=0

printf '%s\n' '{'
printf '  "base_url": "%s",\n' "$BASE_URL"
printf '  "probe_count": %d,\n' "${#LABELS[@]}"
printf '  "results": [\n'

for idx in "${!LABELS[@]}"; do
  label="${LABELS[$idx]}"
  method="${METHODS[$idx]}"
  path="${PATHS[$idx]}"
  mode="${CURL_MODE[$idx]}"
  url="${BASE_URL}${path}"

  extra_headers=(
    -H "Authorization: Bearer ${ID_TOKEN}"
    -H "User-Agent: logguard-attack-probe/1.0"
  )

  if [[ "$label" == "header_sqli" ]]; then
    extra_headers+=(-H "X-Forwarded-For: 127.0.0.1' OR '1'='1")
  fi
  if [[ "$label" == "header_xss" ]]; then
    extra_headers+=(-H "Referer: <script>alert(1)</script>")
  fi

  curl_args=("${CURL_COMMON[@]}" -o /tmp/logguard_attack_probe_body.txt -w "%{http_code}" -X "$method")
  if [[ "$mode" == "path_as_is" ]]; then
    curl_args+=(--path-as-is)
  fi

  status="$(
    curl "${curl_args[@]}" "${extra_headers[@]}" "$url" || true
  )"

  if [[ "$status" =~ ^2|3|4|5 ]]; then
    :
  else
    status="000"
  fi

  if [[ "$status" == "000" ]]; then
    failures=$((failures + 1))
  else
    successes=$((successes + 1))
  fi

  body_preview="$(tr '\n' ' ' </tmp/logguard_attack_probe_body.txt | head -c 160 | sed 's/"/\\"/g')"
  printf '    {"label":"%s","method":"%s","path":"%s","status":%s,"body_preview":"%s"}' \
    "$label" "$method" "$path" "$status" "$body_preview"
  if [[ "$idx" -lt $((${#LABELS[@]} - 1)) ]]; then
    printf ','
  fi
  printf '\n'

  sleep "$DELAY_SECONDS"
done

printf '  ],\n'
printf '  "successful_requests": %d,\n' "$successes"
printf '  "failed_requests": %d\n' "$failures"
printf '}\n'

rm -f /tmp/logguard_attack_probe_body.txt
