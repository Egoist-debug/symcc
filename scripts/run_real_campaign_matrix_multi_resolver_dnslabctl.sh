#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec env REPLAY_BACKEND=dnslabctl "$ROOT_DIR/scripts/run_real_campaign_matrix_multi_resolver.sh" "$@"
