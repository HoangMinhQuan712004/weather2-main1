#!/bin/sh
# Simple attacker runner script to execute waf-test-curl.sh inside attacker container
# Usage: docker run --rm -v $(pwd)/client/public:/data --network <network> alpine:3.18 /data/run-tests.sh

TARGET=${TARGET:-http://proxy:80}

if [ -f /data/waf-test-curl.sh ]; then
  chmod +x /data/waf-test-curl.sh || true
  echo "Executing /data/waf-test-curl.sh with TARGET=${TARGET}"
  /bin/sh -c "TARGET=${TARGET} /data/waf-test-curl.sh"
else
  echo "/data/waf-test-curl.sh not found. Mount client/public to /data or copy script into container."
  exit 1
fi
