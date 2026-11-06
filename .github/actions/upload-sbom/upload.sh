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
reject_header_newlines "fail-on" "${INPUT_FAIL_ON:-}"
reject_header_newlines "sarif" "${INPUT_SARIF:-}"

FAIL_ON=$(printf '%s' "${INPUT_FAIL_ON:-none}" | tr '[:upper:]' '[:lower:]')
case "${FAIL_ON}" in
  none|low|medium|high|critical) ;;
  *)
    echo "::error::Input 'fail-on' must be one of: none, low, medium, high, critical" >&2
    exit 1
    ;;
esac

WAIT_TIMEOUT="${INPUT_WAIT_TIMEOUT:-300}"
if ! [[ "${WAIT_TIMEOUT}" =~ ^[0-9]+$ ]] || [ "${WAIT_TIMEOUT}" -le 0 ]; then
  echo "::error::Input 'wait-timeout' must be a positive integer" >&2
  exit 1
fi

DO_WAIT=$(printf '%s' "${INPUT_WAIT:-false}" | tr '[:upper:]' '[:lower:]')
case "${DO_WAIT}" in
  true|1|yes) DO_WAIT="true" ;;
  *) DO_WAIT="false" ;;
esac

if [ -n "${INPUT_SARIF:-}" ] || [ "${FAIL_ON}" != "none" ]; then
  DO_WAIT="true"
fi

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

# Prepare config files for curl to securely pass headers without exposing tokens in logs/process table
CURL_CONFIG=$(mktemp)
AUTH_CURL_CONFIG=$(mktemp)
RESPONSE_FILE=$(mktemp)
DETAIL_RESPONSE=$(mktemp)
trap 'rm -f "${CURL_CONFIG}" "${AUTH_CURL_CONFIG}" "${RESPONSE_FILE}" "${DETAIL_RESPONSE}"' EXIT

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

printf 'header = "%s: %s"\n' "${AUTH_HEADER_NAME}" "${ESCAPED_AUTH_HEADER_VALUE}" > "${AUTH_CURL_CONFIG}"

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

compute_sbom_id() {
  local hash="$1"
  if [ -z "${hash}" ]; then
    return
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import uuid, sys; sys.stdout.write(str(uuid.uuid5(uuid.NAMESPACE_DNS, sys.argv[1])))" "${hash}" 2>/dev/null || true
  elif command -v python >/dev/null 2>&1; then
    python -c "import uuid, sys; sys.stdout.write(str(uuid.uuid5(uuid.NAMESPACE_DNS, sys.argv[1])))" "${hash}" 2>/dev/null || true
  fi
}

STATUS=$(extract_json_field "status" "${RESPONSE_FILE}")
JOB_ID=$(extract_json_field "job_id" "${RESPONSE_FILE}")
SHA256_HASH=$(extract_json_field "sha256_hash" "${RESPONSE_FILE}")
SBOM_ID=$(extract_json_field "sbom_id" "${RESPONSE_FILE}")

if [ -z "${SBOM_ID}" ] && [ -n "${SHA256_HASH}" ]; then
  SBOM_ID=$(compute_sbom_id "${SHA256_HASH}")
fi

SBOM_URL=""
if [ -n "${SBOM_ID}" ]; then
  SBOM_URL="${BASE_URL}/sboms/${SBOM_ID}"
fi

VULNERABILITIES_JSON=""
CRITICAL_VULNS=0
HIGH_VULNS=0
MEDIUM_VULNS=0
LOW_VULNS=0

if [ "${DO_WAIT}" = "true" ]; then
  if [ -z "${SBOM_ID}" ]; then
    echo "::error::Cannot wait for completion: could not determine SBOM ID" >&2
    exit 1
  fi

  DETAIL_URL="${BASE_URL}/api/v1/sboms/${SBOM_ID}/detail"
  TIMEOUT="${WAIT_TIMEOUT}"
  INTERVAL="${POLL_INTERVAL:-5}"
  PROCESSED=false
  START_TIME=$(date +%s)

  echo "Waiting for SBOM ${SBOM_ID} to be processed (timeout: ${TIMEOUT}s)..."

  while true; do
    POLL_CODE=$(curl -sS -o "${DETAIL_RESPONSE}" -w "%{http_code}" \
      --connect-timeout 10 \
      --max-time 30 \
      --retry 2 \
      --retry-delay 1 \
      --retry-max-time 30 \
      --retry-connrefused \
      -K "${AUTH_CURL_CONFIG}" \
      -X GET \
      -- "${DETAIL_URL}" || true)

    if [ "${POLL_CODE}" -eq 200 ]; then
      PROCESSED=true
      break
    elif [ "${POLL_CODE}" -ne 404 ]; then
      BODY=$(cat "${DETAIL_RESPONSE}" 2>/dev/null || true)
      SAFE_BODY=$(escape_workflow_command_data "${BODY}")
      echo "::warning::Unexpected HTTP status ${POLL_CODE} while polling SBOM: ${SAFE_BODY}" >&2
    fi

    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    if [ "${ELAPSED}" -ge "${TIMEOUT}" ]; then
      break
    fi

    sleep "${INTERVAL}"
  done

  if [ "${PROCESSED}" != "true" ]; then
    echo "::error::Timed out after ${TIMEOUT}s waiting for SBOM ${SBOM_ID} to be processed" >&2
    exit 1
  fi

  CRITICAL_VULNS=$(extract_json_field "critical_vulns" "${DETAIL_RESPONSE}")
  HIGH_VULNS=$(extract_json_field "high_vulns" "${DETAIL_RESPONSE}")
  MEDIUM_VULNS=$(extract_json_field "medium_vulns" "${DETAIL_RESPONSE}")
  LOW_VULNS=$(extract_json_field "low_vulns" "${DETAIL_RESPONSE}")

  if ! [[ "${CRITICAL_VULNS}" =~ ^[0-9]+$ ]]; then CRITICAL_VULNS=0; fi
  if ! [[ "${HIGH_VULNS}" =~ ^[0-9]+$ ]]; then HIGH_VULNS=0; fi
  if ! [[ "${MEDIUM_VULNS}" =~ ^[0-9]+$ ]]; then MEDIUM_VULNS=0; fi
  if ! [[ "${LOW_VULNS}" =~ ^[0-9]+$ ]]; then LOW_VULNS=0; fi

  VULNERABILITIES_JSON="{\"critical\":${CRITICAL_VULNS},\"high\":${HIGH_VULNS},\"medium\":${MEDIUM_VULNS},\"low\":${LOW_VULNS}}"

  echo "SBOM ${SBOM_ID} processed: critical=${CRITICAL_VULNS}, high=${HIGH_VULNS}, medium=${MEDIUM_VULNS}, low=${LOW_VULNS}"

  # Download SARIF report if requested
  if [ -n "${INPUT_SARIF:-}" ]; then
    echo "Downloading SARIF 2.1.0 report to ${INPUT_SARIF}..."
    SARIF_DIR=$(dirname "${INPUT_SARIF}")
    if [ -n "${SARIF_DIR}" ] && [ ! -d "${SARIF_DIR}" ]; then
      mkdir -p "${SARIF_DIR}"
    fi
    SARIF_URL="${BASE_URL}/api/v1/sboms/${SBOM_ID}/vulnerabilities?format=sarif"
    if ! SARIF_CODE=$(curl -sS -o "${INPUT_SARIF}" -w "%{http_code}" \
      --connect-timeout 10 \
      --max-time 60 \
      --retry 3 \
      --retry-delay 2 \
      --retry-max-time 120 \
      --retry-connrefused \
      -K "${AUTH_CURL_CONFIG}" \
      -X GET \
      -- "${SARIF_URL}"); then
      echo "::error::Failed to download SARIF report: request failed after retries" >&2
      exit 1
    fi

    if [ "${SARIF_CODE}" -ne 200 ]; then
      echo "::error::Failed to download SARIF report (HTTP ${SARIF_CODE})" >&2
      exit 1
    fi
    echo "SARIF report saved to ${INPUT_SARIF}"
  fi
fi

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
validate_output_value "sbom-id" "${SBOM_ID:-}"
validate_output_value "url" "${SBOM_URL:-}"
validate_output_value "vulnerabilities" "${VULNERABILITIES_JSON:-}"

echo "Upload completed successfully (HTTP ${HTTP_CODE}, status=${STATUS:-unknown})"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  write_output() {
    printf '%s=%s\n' "$1" "$2" >> "${GITHUB_OUTPUT}"
  }
  write_output "status" "${STATUS}"
  write_output "job-id" "${JOB_ID}"
  write_output "sha256-hash" "${SHA256_HASH}"
  if [ -n "${SBOM_ID:-}" ]; then
    write_output "sbom-id" "${SBOM_ID}"
  fi
  if [ -n "${SBOM_URL:-}" ]; then
    write_output "url" "${SBOM_URL}"
  fi
  if [ -n "${VULNERABILITIES_JSON:-}" ]; then
    write_output "vulnerabilities" "${VULNERABILITIES_JSON}"
  fi
fi

if [ "${DO_WAIT}" = "true" ] && [ "${FAIL_ON}" != "none" ]; then
  case "${FAIL_ON}" in
    critical)
      if [ "${CRITICAL_VULNS}" -gt 0 ]; then
        echo "::error::Vulnerability threshold exceeded (fail-on=critical): found ${CRITICAL_VULNS} critical vulnerabilities" >&2
        exit 1
      fi
      ;;
    high)
      if [ "${CRITICAL_VULNS}" -gt 0 ] || [ "${HIGH_VULNS}" -gt 0 ]; then
        echo "::error::Vulnerability threshold exceeded (fail-on=high): found ${CRITICAL_VULNS} critical, ${HIGH_VULNS} high vulnerabilities" >&2
        exit 1
      fi
      ;;
    medium)
      if [ "${CRITICAL_VULNS}" -gt 0 ] || [ "${HIGH_VULNS}" -gt 0 ] || [ "${MEDIUM_VULNS}" -gt 0 ]; then
        echo "::error::Vulnerability threshold exceeded (fail-on=medium): found ${CRITICAL_VULNS} critical, ${HIGH_VULNS} high, ${MEDIUM_VULNS} medium vulnerabilities" >&2
        exit 1
      fi
      ;;
    low)
      if [ "${CRITICAL_VULNS}" -gt 0 ] || [ "${HIGH_VULNS}" -gt 0 ] || [ "${MEDIUM_VULNS}" -gt 0 ] || [ "${LOW_VULNS}" -gt 0 ]; then
        echo "::error::Vulnerability threshold exceeded (fail-on=low): found ${CRITICAL_VULNS} critical, ${HIGH_VULNS} high, ${MEDIUM_VULNS} medium, ${LOW_VULNS} low vulnerabilities" >&2
        exit 1
      fi
      ;;
  esac
  echo "Vulnerability policy passed: threshold '${FAIL_ON}' not exceeded"
fi
