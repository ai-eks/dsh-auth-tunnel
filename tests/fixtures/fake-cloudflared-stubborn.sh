#!/bin/sh
# Fixture cloudflared, stubborn mode: announces a URL like the quick fixture
# but ignores SIGTERM, so a teardown must escalate to SIGKILL.
echo $$ > "${TMPDIR:-/tmp}/fake-cloudflared-$$.pid"
echo 'INF |  https://zulu-yankee-xray.trycloudflare.com                                             |' >&2
trap '' TERM INT
while :; do sleep 1; done
