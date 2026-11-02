#!/usr/bin/env bash
set -euo pipefail

# Required inputs
if [ -z "${INPUT_URL:-}" ]; then
  echo "::error::Input 'url' is required (e.g. https://bomhort.example.com)" >&2
  exit 1
fi

if [ -z "${INPUT_TOKEN:-}" ]; then
  echo "::error::Input 'token' is required" >&2
  exit 1
fi

if [ -z "${INPUT_SBOM:-}" ]; then
  echo "::error::Input 'sbom' is required" >&2
  exit 1
fi

# Resolve a literal path first so spaces are preserved. If it is not a literal
# path, expand it as a glob without splitting on whitespace.
RESOLVED_FILES=()
if [ -e "${INPUT_SBOM}" ]; then
  RESOLVED_FILES=("${INPUT_SBOM}")
else
  SBOM_PATTERN="${INPUT_SBOM}"
  case "${INPUT_SBOM:0:2}" in
    [A-Za-z]:) SBOM_PATTERN="${INPUT_SBOM//\\//}" ;;
  esac
  ORIGINAL_IFS=$IFS
  IFS=
  shopt -s nullglob
  RESOLVED_FILES=( $SBOM_PATTERN )
  shopt -u nullglob
  IFS=$ORIGINAL_IFS
fi

if [ ${#RESOLVED_FILES[@]} -eq 0 ] || [ ! -e "${RESOLVED_FILES[0]}" ]; then
  echo "::error::No file found matching sbom path: ${INPUT_SBOM}" >&2
  exit 1
fi

if [ ${#RESOLVED_FILES[@]} -gt 1 ]; then
  echo "::error::Expected single SBOM file matching '${INPUT_SBOM}', but found ${#RESOLVED_FILES[@]} files" >&2
  exit 1
fi

SBOM_FILE="${RESOLVED_FILES[0]}"
if [ ! -f "${SBOM_FILE}" ]; then
  echo "::error::SBOM path is not a regular file: ${SBOM_FILE}" >&2
  exit 1
fi

FILENAME=$(basename "${SBOM_FILE}")

reject_header_newlines() {
  local name="$1"
  local value="$2"
  if [[ "${value}" == *$'\r'* || "${value}" == *$'\n'* ]]; then
    echo "::error::Input '${name}' must not contain newline characters" >&2
    exit 1
  fi
}

reject_header_newlines "sbom filename" "${FILENAME}"
reject_header_newlines "token" "${INPUT_TOKEN}"
reject_header_newlines "source-repo" "${INPUT_SOURCE_REPO:-}"
reject_header_newlines "source-ref" "${INPUT_SOURCE_REF:-}"

AUTH_TYPE="${INPUT_AUTH_TYPE:-bearer}"
case "${AUTH_TYPE}" in
  bearer)
    AUTH_HEADER_NAME="Authorization"
    AUTH_HEADER_VALUE="Bearer ${INPUT_TOKEN}"
    ;;
  api-key)
    AUTH_HEADER_NAME="X-API-Key"
    AUTH_HEADER_VALUE="${INPUT_TOKEN}"
    ;;
  *)
    echo "::error::Input 'auth-type' must be 'bearer' or 'api-key'" >&2
    exit 1
    ;;
esac

# Ensure endpoint path is normalized
BASE_URL="${INPUT_URL%/}"
UPLOAD_URL="${BASE_URL}/api/v1/sboms/upload"

# Build query parameters
QUERY_PARAMS=""
urlencode() {
  local LC_ALL=C
  local input="$1"
  local output=""
  local char hex i

  for ((i = 0; i < ${#input}; i++)); do
    char="${input:i:1}"
    case "${char}" in
      [a-zA-Z0-9.~_-]) output+="${char}" ;;
      *)
        printf -v hex '%%%02X' "'${char}"
        output+="${hex}"
        ;;
    esac
  done

  printf '%s' "${output}"
}

add_param() {
  local key="$1"
  local val="$2"
  if [ -n "${val}" ]; then
    local encoded
    encoded=$(urlencode "${val}")

    if [ -z "${QUERY_PARAMS}" ]; then
      QUERY_PARAMS="?${key}=${encoded}"
    else
      QUERY_PARAMS="${QUERY_PARAMS}&${key}=${encoded}"
    fi
  fi
}

add_param "project" "${INPUT_PROJECT:-}"
add_param "cluster" "${INPUT_CLUSTER:-}"
add_param "namespace" "${INPUT_NAMESPACE:-}"
add_param "parent" "${INPUT_PARENT:-}"
add_param "tags" "${INPUT_TAGS:-}"

TARGET_URL="${UPLOAD_URL}${QUERY_PARAMS}"

echo "Uploading ${FILENAME} to ${BASE_URL}/api/v1/sboms/upload..."

# Prepare config file for curl to securely pass headers without exposing tokens in logs/process table
CURL_CONFIG=$(mktemp)
RESPONSE_FILE=$(mktemp)
trap 'rm -f "${CURL_CONFIG}" "${RESPONSE_FILE}"' EXIT

escape_curl_config() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "${value}"
}

ESCAPED_FILENAME=$(escape_curl_config "${FILENAME}")
ESCAPED_AUTH_HEADER_VALUE=$(escape_curl_config "${AUTH_HEADER_VALUE}")

{
  printf 'header = "X-Filename: %s"\n' "${ESCAPED_FILENAME}"
  printf 'header = "%s: %s"\n' "${AUTH_HEADER_NAME}" "${ESCAPED_AUTH_HEADER_VALUE}"
  if [ -n "${INPUT_SOURCE_REPO:-}" ]; then
    ESCAPED_REPO=$(escape_curl_config "${INPUT_SOURCE_REPO}")
    printf 'header = "X-Source-Repo: %s"\n' "${ESCAPED_REPO}"
  fi
  if [ -n "${INPUT_SOURCE_REF:-}" ]; then
    ESCAPED_REF=$(escape_curl_config "${INPUT_SOURCE_REF}")
    printf 'header = "X-Source-Ref: %s"\n' "${ESCAPED_REF}"
  fi
} > "${CURL_CONFIG}"

# Execute curl request
if ! HTTP_CODE=$(curl -sS -o "${RESPONSE_FILE}" -w "%{http_code}" \
  --connect-timeout 10 \
  --max-time 300 \
  --retry 3 \
  --retry-delay 2 \
  --retry-max-time 120 \
  --retry-connrefused \
  -K "${CURL_CONFIG}" \
  -X POST \
  --data-binary "@${SBOM_FILE}" \
  -- "${TARGET_URL}"); then
  echo "::error::Upload request failed after retries" >&2
  exit 1
fi

RESPONSE_BODY=$(cat "${RESPONSE_FILE}")

escape_workflow_command_data() {
  local value="$1"
  value="${value//'%'/'%25'}"
  value="${value//$'\r'/'%0D'}"
  value="${value//$'\n'/'%0A'}"
  printf '%s' "${value}"
}

if [ "${HTTP_CODE}" -ne 200 ] && [ "${HTTP_CODE}" -ne 202 ]; then
  SAFE_RESPONSE_BODY=$(escape_workflow_command_data "${RESPONSE_BODY}")
  printf '::error::Upload failed with HTTP status %s: %s\n' "${HTTP_CODE}" "${SAFE_RESPONSE_BODY}" >&2
  exit 1
fi

extract_json_field() {
  local field="$1"
  local file="$2"
  if command -v jq >/dev/null 2>&1; then
    jq -r ".${field} // empty" "${file}" 2>/dev/null || true
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c "import json, sys; d = json.load(open(sys.argv[1])); v = d.get(sys.argv[2]); sys.stdout.write(str(v) if v is not None else '')" "${file}" "${field}" 2>/dev/null || true
  else
    grep -o "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "${file}" | head -n1 | sed -E "s/\"${field}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\"/\1/" || true
  fi
}

STATUS=$(extract_json_field "status" "${RESPONSE_FILE}")
JOB_ID=$(extract_json_field "job_id" "${RESPONSE_FILE}")
SHA256_HASH=$(extract_json_field "sha256_hash" "${RESPONSE_FILE}")

validate_output_value() {
  local name="$1"
  local value="$2"
  if [[ "${value}" == *$'\r'* || "${value}" == *$'\n'* ]]; then
    echo "::error::API response field '${name}' must not contain newline characters" >&2
    exit 1
  fi
}

validate_output_value "status" "${STATUS}"
validate_output_value "job-id" "${JOB_ID}"
validate_output_value "sha256-hash" "${SHA256_HASH}"

echo "Upload completed successfully (HTTP ${HTTP_CODE}, status=${STATUS:-unknown})"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  write_output() {
    printf '%s=%s\n' "$1" "$2" >> "${GITHUB_OUTPUT}"
  }
  write_output "status" "${STATUS}"
  write_output "job-id" "${JOB_ID}"
  write_output "sha256-hash" "${SHA256_HASH}"
fi
