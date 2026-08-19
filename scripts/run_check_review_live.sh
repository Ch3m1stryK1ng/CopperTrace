#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_url="${CLIPROXY_REVIEW_BASE_URL:-http://127.0.0.1:8318/v1}"
api_key="${CLIPROXY_REVIEW_API_KEY:-coppertrace-review-local-key}"
model_alias="${CLIPROXY_REVIEW_MODEL_ALIAS:-gpt-5.6-sol}"
preflight="${CLIPROXY_REVIEW_PREFLIGHT:-${repo_root}/artifacts/check_review_preflight.json}"

python3 "${repo_root}/scripts/cliproxy_review_preflight.py" \
  --base-url "${base_url}" \
  --api-key "${api_key}" \
  --expected-model-alias "${model_alias}" \
  --out "${preflight}"

export OPENAI_API_BASE="${base_url}"
export OPENAI_BASE_URL="${base_url}"
export OPENAI_API_KEY="${api_key}"

exec python3 "${repo_root}/scripts/run_check_review_corpus.py" \
  --mode live \
  --model "openai/${model_alias}" \
  --expected-model-alias "${model_alias}" \
  --preflight-record "${preflight}" \
  "$@"
