#!/bin/sh
# Token fixture whose rotated child becomes ready and then crashes in handoff.
echo $$ > "${TMPDIR:-/tmp}/fake-cloudflared-$$.pid"
printf '%s' "$TUNNEL_TOKEN" > "${TMPDIR:-/tmp}/fake-cloudflared-$$.token"
if [ -z "$TUNNEL_TOKEN" ]; then
  exit 3
fi
echo 'INF Registered tunnel connection connIndex=0' >&2
if [ "$TUNNEL_TOKEN" = 'fixture-token-2' ]; then
  sleep 0.2
  exit 7
fi
trap 'exit 0' TERM INT
while :; do sleep 1; done
