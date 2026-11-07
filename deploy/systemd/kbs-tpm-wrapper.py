#!/usr/bin/env python3
"""TPM-credential wrapper (prototype 2026-11-06).

Reads a decrypted credential file (systemd EnvironmentFile syntax) from
$CREDENTIALS_DIRECTORY, exports its KEY=VALUE lines into the environment,
then execs the given command. Never prints values: errors name only the
credential file and (at most) the offending key.

Why this exists: EnvironmentFile= is read by PID1 before the per-service
credentials directory is set up, so no EnvironmentFile path (specifier %d
or literal /run/credentials/<unit>/<name>) can reference a
LoadCredentialEncrypted file (verified 2026-11-06 on systemd 257: both
forms fail with "Failed to load environment files"). The sanctioned
systemd pattern is for the process itself to read $CREDENTIALS_DIRECTORY
at runtime, which is what this wrapper does.
"""

import os
import re
import sys

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

# systemd double-quote escapes in env files.
_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "\\": "\\",
    '"': '"',
    "$": "$",
    "`": "`",
}


def decode_double_quoted(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append(_ESCAPES.get(s[i + 1], s[i + 1]))
            i += 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def parse_env_file(path):
    values = {}
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not _KEY_RE.match(key):
                print(f"kbs-tpm-wrapper: skipping malformed key: {key}",
                      file=sys.stderr)
                continue
            if len(value) >= 2 and value[0] == value[-1] \
                    and value[0] in ("'", '"'):
                quote = value[0]
                value = value[1:-1]
                if quote == '"':
                    value = decode_double_quoted(value)
            values[key] = value
    return values


def main(argv):
    if len(argv) < 3:
        print("usage: kbs-tpm-wrapper.py <credential-name> <command...>",
              file=sys.stderr)
        return 2
    name, cmd = argv[1], argv[2:]
    creds_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not creds_dir:
        print("kbs-tpm-wrapper: CREDENTIALS_DIRECTORY is not set",
              file=sys.stderr)
        return 1
    path = os.path.join(creds_dir, name)
    try:
        values = parse_env_file(path)
    except FileNotFoundError:
        print(f"kbs-tpm-wrapper: credential file not found: {name}",
              file=sys.stderr)
        return 1
    except (OSError, UnicodeDecodeError) as exc:
        print(f"kbs-tpm-wrapper: cannot read credential {name}: "
              f"{type(exc).__name__}", file=sys.stderr)
        return 1
    if not values:
        print(f"kbs-tpm-wrapper: credential {name} holds no variables",
              file=sys.stderr)
        return 1
    env = dict(os.environ)
    env.update(values)
    os.execvpe(cmd[0], cmd, env)
    return 1  # unreachable


if __name__ == "__main__":
    sys.exit(main(sys.argv))
