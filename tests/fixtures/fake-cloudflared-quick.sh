#!/bin/sh
# Fixture cloudflared, quick mode: records its pid, echoes the --url target it
# was pointed at (the password gate), overruns the plugin's rolling output
# tail, then prints a trycloudflare URL split across pipe writes and idles until
# terminated.
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
i=0
while [ $i -lt 120 ]; do
  i=$((i+1))
  echo "INF waiting for edge connection $i" >&2
done
{
  echo 'INF +--------------------------------------------------------------------------------------------+'
  echo 'INF |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |'
  printf 'INF |  https://alpha-bravo-'
  sleep 0.02
  echo 'charlie.trycloudflare.com                                             |'
  echo 'INF +--------------------------------------------------------------------------------------------+'
} >&2
trap 'exit 0' TERM INT
while :; do sleep 1; done
