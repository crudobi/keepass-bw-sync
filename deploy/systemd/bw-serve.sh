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

# Unlock and print the raw session key. The SDK may print migration notices
# to stdout alongside the key, so capture and take the last line rather
# than trusting the whole output (a polluted BW_SESSION leaves the vault
# locked). Returns non-zero when unlock itself fails.
unlock() {
    local out
    if ! out="$("$BW" unlock --passwordenv BW_PASSWORD --raw 2>/tmp/bw-unlock.err)"; then
        return 1
    fi
    printf "%s" "$out" | tail -n 1
}

if BW_SESSION="$(unlock)"; then
    echo "bw-serve: unlocked existing session" >&2
else
    echo "bw-serve: no usable session; logging in via API key" >&2
    if [ -z "${BW_CLIENTID:-}" ] || [ -z "${BW_CLIENTSECRET:-}" ]; then
        echo "bw-serve: BW_CLIENTID/BW_CLIENTSECRET are not set; cannot log in headless" >&2
        cat /tmp/bw-unlock.err >&2
        exit 1
    fi
    "$BW" logout 2>/dev/null || true
    "$BW" login --apikey >&2
    BW_SESSION="$(unlock)" || {
        echo "bw-serve: unlock after API-key login failed" >&2
        cat /tmp/bw-unlock.err >&2
        exit 1
    }
fi
export BW_SESSION
exec "$BW" serve --hostname 127.0.0.1 --port 8087
