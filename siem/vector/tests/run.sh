#!/bin/sh
# Runs the Vector unit tests in this directory against ../vector.yaml in the
# same Vector release the SIEM stack runs. The sink's credentials only need
# to exist for the config to load; nothing is sent anywhere.
set -e
here=$(cd "$(dirname "$0")/.." && pwd)
exec docker run --rm \
  -e ELASTIC_HOSTS=https://es01:9200 -e ELASTIC_USERNAME=test -e ELASTIC_PASSWORD=test \
  -v "$here:/etc/vector:ro" \
  "timberio/vector:${VECTOR_VERSION:-0.43.0}-debian" \
  test /etc/vector/vector.yaml "/etc/vector/tests/*.yaml"
