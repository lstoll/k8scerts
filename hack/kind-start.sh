#!/bin/bash
set -euo pipefail

KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-k8scerts}

"$(dirname "$0")/kind-node-image.sh"

kind create cluster --name "$KIND_CLUSTER_NAME" --config kind-config.yaml

kind get kubeconfig --name "$KIND_CLUSTER_NAME" > kind.kubeconfig

if [[ ! -f k8s/ca.crt || ! -f k8s/ca.key ]]; then
    echo "Generating CA..."
    (cd k8s && go run ../cmd/p384-ca-gen/main.go)
fi
