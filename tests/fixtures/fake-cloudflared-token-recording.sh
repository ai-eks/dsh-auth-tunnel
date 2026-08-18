#!/bin/sh
# Fixture named tunnel that records which token each spawned process captured.
echo $$ > "${TMPDIR:-/tmp}/fake-cloudflared-$$.pid"
printf '%s' "$TUNNEL_TOKEN" > "${TMPDIR:-/tmp}/fake-cloudflared-$$.token"
if [ -z "$TUNNEL_TOKEN" ]; then
  exit 3
fi
echo 'INF Registered tunnel connection connIndex=0' >&2
trap 'exit 0' TERM INT
while :; do sleep 1; done
