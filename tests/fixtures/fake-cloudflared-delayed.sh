#!/bin/sh
# Fixture cloudflared, delayed-ready mode: exposes the startup window long
# enough for a live settings update to arrive before the first adoption.
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
sleep 0.5
echo 'INF |  https://alpha-bravo-charlie.trycloudflare.com  |' >&2
trap 'exit 0' TERM INT
while :; do sleep 1; done
