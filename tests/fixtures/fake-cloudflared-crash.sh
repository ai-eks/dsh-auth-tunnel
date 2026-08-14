#!/bin/sh
# Fixture cloudflared, crash mode: dies immediately with a diagnostic marker
# the plugin must surface in the loud boot failure's output tail.
i=0
while [ $i -lt 200 ]; do
  i=$((i+1))
  echo 'ERR edge edge edge edge edge edge edge edge edge edge edge edge edge edge edge edge' >&2
done
echo 'ERR fixture fatal: cannot dial the edge' >&2
exit 1
