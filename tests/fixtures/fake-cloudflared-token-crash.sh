#!/bin/sh
# Fixture cloudflared, token crash: imitates help/error output that repeats the
# environment token so the plugin must redact it from boot diagnostics.
echo "ERR invalid invocation, token=$TUNNEL_TOKEN" >&2
exit 5
