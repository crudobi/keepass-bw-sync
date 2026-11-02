#!/bin/bash
set -euo pipefail
# ----------------------------------------------------------------------------
# EDIT FOR YOUR MACHINE:
#   BW=/usr/local/bin/bw   -> path to YOUR Bitwarden CLI binary
# Credentials come from the environment (see bw-serve.service's EDIT markers).
# ----------------------------------------------------------------------------
# Supervised `bw serve` for keepass-bw-sync.
# Credentials come from EnvironmentFile=/store/muscle/secrets/bw.env (0600):
#   BW_PASSWORD                    master password (vault unlock/decrypt)
#   BW_CLIENTID / BW_CLIENTSECRET  API key for headless (re-)login
# Fails closed when BW_PASSWORD is unset. (Re-)login uses the API key, the
# 2FA-safe headless path: a password login would stall on the 2FA code.
BW=/usr/local/bin/bw

# Unlock stderr goes to a private temp file, not the fixed
# world-readable /tmp/bw-unlock.err (the unit's PrivateTmp used to be
# the only mitigation). Removed on every exit via trap; removed
# explicitly before exec, since exec replaces the shell and the trap
# would never fire on the serve path.
ERR_FILE="$(mktemp /tmp/bw-unlock.XXXXXX)"
chmod 600 "$ERR_FILE"
trap 'rm -f "$ERR_FILE"' EXIT
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
    if ! out="$("$BW" unlock --passwordenv BW_PASSWORD --raw 2>"$ERR_FILE")"; then
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
        cat "$ERR_FILE" >&2
        exit 1
    fi
    "$BW" logout 2>/dev/null || true
    "$BW" login --apikey >&2
    BW_SESSION="$(unlock)" || {
        echo "bw-serve: unlock after API-key login failed" >&2
        cat "$ERR_FILE" >&2
        exit 1
    }
fi
export BW_SESSION
rm -f "$ERR_FILE" # trap never fires past exec; remove explicitly
exec "$BW" serve --hostname 127.0.0.1 --port 8087
