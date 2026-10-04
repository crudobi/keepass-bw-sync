#!/bin/bash
set -euo pipefail
# Supervised `bw serve` for the dev-loop secrets sync.
# Credentials come from EnvironmentFile=/store/muscle/secrets/bw.env (0600):
#   BW_PASSWORD                    master password (vault unlock/decrypt)
#   BW_CLIENTID / BW_CLIENTSECRET  API key for headless (re-)login
# Fails closed when BW_PASSWORD is unset. (Re-)login uses the API key, the
# 2FA-safe headless path: a password login would stall on the 2FA code.
BW=/usr/local/bin/bw
if [ -z "${BW_PASSWORD:-}" ]; then
    echo "bw-serve: BW_PASSWORD is not set; refusing to start (see README)" >&2
    exit 1
fi
if ! BW_SESSION="$("$BW" unlock --passwordenv BW_PASSWORD --raw 2>/dev/null)"; then
    # No usable session (first boot, rotated password, stale keyring, ...):
    # log in headless via API key, then unlock.
    if [ -z "${BW_CLIENTID:-}" ] || [ -z "${BW_CLIENTSECRET:-}" ]; then
        echo "bw-serve: unlock failed and BW_CLIENTID/BW_CLIENTSECRET are not set; cannot log in headless" >&2
        exit 1
    fi
    "$BW" logout 2>/dev/null || true
    "$BW" login --apikey >&2
    BW_SESSION="$("$BW" unlock --passwordenv BW_PASSWORD --raw)"
fi
export BW_SESSION
exec "$BW" serve --hostname 127.0.0.1 --port 8087
