#!/bin/sh
# Fixture cloudflared, ready-then-crash mode: publishes a quick URL, then dies
# inside the live replacement handoff window.
echo $$ > "${TMPDIR:-/tmp}/fake-cloudflared-$$.pid"
while [ $# -gt 0 ]; do
  case $1 in
    --url)
      echo "$2" > "${TMPDIR:-/tmp}/fake-cloudflared-$$.url"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
echo 'INF |  https://ready-then-crash.trycloudflare.com  |' >&2
sleep 0.2
exit 7
