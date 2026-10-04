#!/bin/bash
set -euo pipefail
# Supervised `bw serve` for the dev-loop secrets sync.
# BW_PASSWORD comes from EnvironmentFile=/store/muscle/secrets/bw.env
# (optional until the Bitwarden account is hardened). Fails closed when unset.
BW=/usr/local/bin/bw
if [ -z "${BW_PASSWORD:-}" ]; then
    echo "bw-serve: BW_PASSWORD is not set; refusing to start (see README for the account-hardening checklist)" >&2
    exit 1
fi
export BW_SESSION="$("$BW" unlock --passwordenv BW_PASSWORD --raw)"
exec "$BW" serve --hostname 127.0.0.1 --port 8087
