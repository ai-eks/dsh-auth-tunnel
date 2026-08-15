#!/bin/sh
# Fixture cloudflared, silent mode: never reports a URL or a connection, so
# the plugin's startup timeout is the only way out.
echo $$ > "${TMPDIR:-/tmp}/fake-cloudflared-$$.pid"
echo 'INF waiting forever' >&2
trap 'exit 0' TERM INT
while :; do sleep 1; done
