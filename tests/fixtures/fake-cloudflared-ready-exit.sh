#!/bin/sh
# Fixture cloudflared, ready-exit mode: reports a URL and exits before the
# plugin can adopt and publish the candidate.
echo $$ > "${TMPDIR:-/tmp}/fake-cloudflared-$$.pid"
echo 'INF |  https://already-dead.trycloudflare.com  |' >&2
exit 7
