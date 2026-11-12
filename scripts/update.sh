#!/usr/bin/env sh
# Update SNMPathy: pull the latest code, rebuild the executable and restart it.
# Options: --force | --schedule | --unschedule | --no-restart | --quiet
cd "$(dirname "$0")/.." || exit 1
exec python3 scripts/update.py "$@"
