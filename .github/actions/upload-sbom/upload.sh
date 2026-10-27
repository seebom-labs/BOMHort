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

# Expand file path / glob
RESOLVED_FILES=( $INPUT_SBOM )

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

# Ensure endpoint path is normalized
BASE_URL="${INPUT_URL%/}"
UPLOAD_URL="${BASE_URL}/api/v1/sboms/upload"

# Build query parameters
QUERY_PARAMS=""
add_param() {
  local key="$1"
  local val="$2"
  if [ -n "${val}" ]; then
    local encoded
    if command -v jq >/dev/null 2>&1; then
      encoded=$(jq -rn --arg v "${val}" '$v|@uri')
    elif command -v python3 >/dev/null 2>&1; then
      encoded=$(python3 -c "import urllib.parse, sys; sys.stdout.write(urllib.parse.quote(sys.argv[1]))" "${val}")
    elif command -v node >/dev/null 2>&1; then
      encoded=$(node -e "process.stdout.write(encodeURIComponent(process.argv[1]))" "${val}")
    else
      encoded="${val}"
    fi

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

ESCAPED_TOKEN="${INPUT_TOKEN//\\/\\\\}"
ESCAPED_TOKEN="${ESCAPED_TOKEN//\"/\\\"}"

{
  printf 'header = "X-Filename: %s"\n' "${FILENAME}"
  printf 'header = "Authorization: Bearer %s"\n' "${ESCAPED_TOKEN}"
  if [ -n "${INPUT_SOURCE_REPO:-}" ]; then
    ESCAPED_REPO="${INPUT_SOURCE_REPO//\\/\\\\}"
    ESCAPED_REPO="${ESCAPED_REPO//\"/\\\"}"
    printf 'header = "X-Source-Repo: %s"\n' "${ESCAPED_REPO}"
  fi
  if [ -n "${INPUT_SOURCE_REF:-}" ]; then
    ESCAPED_REF="${INPUT_SOURCE_REF//\\/\\\\}"
    ESCAPED_REF="${ESCAPED_REF//\"/\\\"}"
    printf 'header = "X-Source-Ref: %s"\n' "${ESCAPED_REF}"
  fi
} > "${CURL_CONFIG}"

# Execute curl request
HTTP_CODE=$(curl -sS -o "${RESPONSE_FILE}" -w "%{http_code}" \
  -K "${CURL_CONFIG}" \
  -X POST "${TARGET_URL}" \
  --data-binary "@${SBOM_FILE}")

RESPONSE_BODY=$(cat "${RESPONSE_FILE}")

if [ "${HTTP_CODE}" -ne 200 ] && [ "${HTTP_CODE}" -ne 202 ]; then
  echo "::error::Upload failed with HTTP status ${HTTP_CODE}: ${RESPONSE_BODY}" >&2
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
    grep -o "\"${field}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "${file}" | head -n1 | sed -E "s/\"${field}\"[[:space:]]*:[[:space:]]*\"([^\"]*)\"/\1/"
  fi
}

STATUS=$(extract_json_field "status" "${RESPONSE_FILE}")
JOB_ID=$(extract_json_field "job_id" "${RESPONSE_FILE}")
SHA256_HASH=$(extract_json_field "sha256_hash" "${RESPONSE_FILE}")

echo "Upload completed successfully (HTTP ${HTTP_CODE}, status=${STATUS:-unknown})"

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "status=${STATUS}" >> "${GITHUB_OUTPUT}"
  echo "job-id=${JOB_ID}" >> "${GITHUB_OUTPUT}"
  echo "sha256-hash=${SHA256_HASH}" >> "${GITHUB_OUTPUT}"
fi
