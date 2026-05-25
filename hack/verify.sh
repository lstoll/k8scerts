#!/bin/bash
set -euo pipefail

KIND_CLUSTER_NAME=${KIND_CLUSTER_NAME:-k8scerts}
MODE=${MODE:-static}

echo "--- 1. Ensuring Cluster is running ---"
if ! kind get clusters | grep -q "^${KIND_CLUSTER_NAME}$"; then
    ./hack/kind-start.sh
else
    echo "Cluster ${KIND_CLUSTER_NAME} already exists."
fi

echo "--- 2. Getting Kubeconfig ---"
kind get kubeconfig --name "$KIND_CLUSTER_NAME" > kind.kubeconfig
export KUBECONFIG=$(pwd)/kind.kubeconfig
export SIGNER_NAME=${SIGNER_NAME:-example.com/pod-signer}
export SPIFFE_TRUST_DOMAIN=${SPIFFE_TRUST_DOMAIN:-example.com}
export EXPECT_SPIFFE_ID=${EXPECT_SPIFFE_ID:-spiffe://${SPIFFE_TRUST_DOMAIN}/ns/default/sa/default}
export EXPECT_DNS_NAMES=${EXPECT_DNS_NAMES:-cert-test.default.svc.cluster.local}

echo "--- 5. Deploying Test Pods ---"
kubectl delete pod cert-test trust-bundle-test --ignore-not-found --grace-period=0 --force

# Build the verify image and inject it into the manifest
echo "Building pod-cert-verify..."
export VERIFY_IMG=$(skaffold build --push=false -q -b pod-cert-verify --output '{{range .Builds}}{{.Tag}}{{end}}')
echo "Loading image ${VERIFY_IMG} into kind cluster..."
kind load docker-image "${VERIFY_IMG}" --name "$KIND_CLUSTER_NAME"

envsubst < test-pod.yaml | kubectl apply -f -
envsubst < trust-bundle-test.yaml | kubectl apply -f -

echo "--- 6. Waiting for Pods to be ready ---"
kubectl wait --for=condition=Ready pod/cert-test pod/trust-bundle-test --timeout=120s

echo "--- 7. Verifying Results ---"
sleep 5 # Give some time for logs to appear
echo "Checking cert-test logs for success..."
if kubectl logs cert-test | grep -q "Verification SUCCESSFUL"; then
    echo "✅ cert-test: Verification SUCCESSFUL"
else
    echo "❌ cert-test: Verification FAILED"
    kubectl logs cert-test
    exit 1
fi

echo "Checking trust-bundle-test logs for success..."
if kubectl logs trust-bundle-test | grep -q "SUCCESS_CA_FOUND"; then
    echo "✅ trust-bundle-test: CA found!"
else
    echo "❌ trust-bundle-test: CA NOT found!"
    kubectl logs trust-bundle-test
    exit 1
fi

echo "--- 8. Cleaning up Test Pods ---"
kubectl delete -f test-pod.yaml -f trust-bundle-test.yaml --wait=false

echo ""
echo "✨ ALL CHECKS PASSED ✨"
