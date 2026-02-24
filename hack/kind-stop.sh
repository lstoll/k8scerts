#!/bin/bash
set -euo pipefail

KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-k8scerts}

kind delete cluster --name "$KIND_CLUSTER_NAME"

rm -f kind.kubeconfig .envrc
echo "Cleaned up kind.kubeconfig and .envrc"
