#!/usr/bin/env bash
# Start a throwaway Splunk container for detection tests and wait until it's healthy.
set -euo pipefail
: "${SPLUNK_PASSWORD:?export SPLUNK_PASSWORD first (8+ chars)}"
IMAGE="${SPLUNK_IMAGE:-splunk/splunk:latest}"
docker rm -f splunk-ci >/dev/null 2>&1 || true
docker run -d --name splunk-ci -p 18089:8089 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com \
  -e SPLUNK_PASSWORD="$SPLUNK_PASSWORD" \
  "$IMAGE" >/dev/null
echo "Waiting for Splunk to become healthy (2-5 min)..."
for _ in $(seq 1 60); do
  status=$(docker inspect -f '{{.State.Health.Status}}' splunk-ci 2>/dev/null || echo starting)
  [ "$status" = "healthy" ] && { echo "Splunk is up"; docker exec -u splunk splunk-ci /opt/splunk/bin/splunk version || true; docker image inspect -f "{{index .RepoDigests 0}}" "$IMAGE" || true; exit 0; }
  sleep 10
done
echo "Splunk did not become healthy"; docker logs splunk-ci | tail -50; exit 1
