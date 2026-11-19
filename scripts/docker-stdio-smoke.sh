#!/usr/bin/env bash
# Prove the container image serves MCP over stdio with no credentials.
#
# This is what a server directory does to us: build the image, run it with no
# environment at all, then initialize and ask for the tool list. The image has
# no OS keychain, so a build that insists on a credential answers nothing here
# and the directory records a server with no tools.
#
# Usage: scripts/docker-stdio-smoke.sh [image]
set -euo pipefail

image="${1:-skycloak-mcp:stdio-smoke}"

transcript=$(
  {
    printf '%s\n' \
      '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"stdio-smoke","version":"1.0.0"}}}' \
      '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
      '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
    # Hold the pipe open: closing stdin ends the session, and the server may not
    # have written the reply yet.
    sleep 5
  } | timeout 60 docker run -i --rm "$image"
)

count=$(
  printf '%s\n' "$transcript" | python3 -c '
import json, sys
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    message = json.loads(line)
    if message.get("id") == 2:
        print(len(message["result"]["tools"]))
        break
else:
    sys.exit("no tools/list response in the transcript")
'
)

if [ "$count" -lt 1 ]; then
  echo "tools/list returned $count tools, want at least one" >&2
  exit 1
fi
echo "ok: $image answered tools/list with $count tools and no credentials"
