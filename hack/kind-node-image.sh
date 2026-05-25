#!/bin/bash
set -euo pipefail

K8S_VERSION=${K8S_VERSION:-v1.36.0}
NODE_IMAGE=${NODE_IMAGE:-kindest/node:${K8S_VERSION}}

if docker image inspect "$NODE_IMAGE" >/dev/null 2>&1; then
    echo "Node image ${NODE_IMAGE} already present"
    exit 0
fi

echo "Building ${NODE_IMAGE} (not published on Docker Hub yet)..."
kind build node-image "${K8S_VERSION}" --image "${NODE_IMAGE}"
