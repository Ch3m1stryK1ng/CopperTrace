#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
proxy_root="${CLIPROXY_ROOT:-${repo_root}/../CLIProxyAPI}"
config="${CLIPROXY_REVIEW_CONFIG:-${repo_root}/cliproxy/config.review.yaml}"

cd "${proxy_root}"
exec go run ./cmd/server -config "${config}"
