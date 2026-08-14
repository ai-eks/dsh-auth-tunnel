#!/bin/sh
# Fixture cloudflared, token mode: requires TUNNEL_TOKEN over the environment
# (absence is exit 3, surfacing an env-passing regression as a boot failure),
# prints a readiness marker, then idles until terminated.
echo $$ > "${TMPDIR:-/tmp}/fake-cloudflared-$$.pid"
if [ -z "$TUNNEL_TOKEN" ]; then
  echo 'ERR fixture: TUNNEL_TOKEN missing' >&2
  exit 3
fi
echo 'INF booting connectors' >&2
sleep 0.01
echo 'INF Registered tunnel connection connIndex=0' >&2
echo 'INF Registered tunnel connection connIndex=1' >&2
trap 'exit 0' TERM INT
while :; do sleep 1; done
