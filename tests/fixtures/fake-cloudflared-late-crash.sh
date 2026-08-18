#!/bin/sh
# Quick-tunnel fixture that exits only after the normal handoff delay.
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
echo 'INF |  https://late-crash.trycloudflare.com  |' >&2
sleep 4
exit 7
