#!/usr/bin/env sh
# Build the SNMPathy executable and store it in <Claude folder>/SNMPathy (macOS / Linux).
# Extra arguments are passed through, e.g.  ./scripts/build_executable.sh --dest ~/Tools/SNMPathy
set -e
cd "$(dirname "$0")/.."
PY=$(command -v python3 || command -v python)
exec "$PY" scripts/build_executable.py "$@"
