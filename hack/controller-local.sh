#!/bin/bash
set -euo pipefail

KUBECONFIG=${KUBECONFIG:-$(pwd)/kind.kubeconfig}

go run ./cmd/controller/main.go --mode=step --step-url=https://localhost:9000 --step-provisioner=pod-cert-issuer --step-keyset=k8s/step-ca/provisioner_keyset.json --step-root=k8s/step-ca/root_ca.crt --kubeconfig="$KUBECONFIG" --debug
