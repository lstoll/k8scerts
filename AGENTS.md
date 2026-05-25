# Project: k8scerts

This project implements a Kubernetes controller for the Pod Certificates API (KEP-4317), managing certificate issuance and trust distribution via `ClusterTrustBundle`.

## Foundational Mandates

- **Kubernetes Version:** Target Kubernetes 1.36+ (Alpha/Beta features).
- **APIs:** Use `certificates.k8s.io/v1beta1` for `PodCertificateRequest` and `ClusterTrustBundle`.
- **Signer Identity:** The controller manages the `example.com/pod-signer` signer.
- **Issuance Backends:** Supports multiple backends via the `Issuer` interface:
    - **Static:** Local self-signed CA.
    - **Step-CA:** Integration with `smallstep/step-ca` using JWK provisioners and Tink Go v2 for JWT signing.
    - **GCP KMS:** Cloud KMS-backed asymmetric signing with offline-generated CA certificate.
- **Trust Distribution:** The CA certificate is published as a `ClusterTrustBundle` named `example.com:pod-signer:ca`.
    - **Static / GCP KMS:** Publish the issuing CA certificate. In GCP KMS mode, optionally append the offline root via `--root-ca-cert` when workloads need the full chain.
    - **Step-CA:** Publish the Step-CA root certificate.

## Engineering Standards

### Cryptography & JWT
- **Library:** Use **Tink Go v2** for all JWT signing and keyset management.
- **Provisioner:** Use the **JWK provisioner** flow for Step-CA.
- **Binding:** CSRs must be bound to the JWT using the `cnf` (confirmation) claim.
- **Chain:** In Step-CA mode, the `certificateChain` status field must include both the leaf and intermediate certificates.

### Logging
- **Library:** Use `log/slog` for structured logging.
- **Integration:** Always call `klog.SetSlogLogger` to unify library output.
- **Format:** Automatic TTY detection:
    - Interactive (TTY): `slog.TextHandler`
    - Non-interactive (Cluster/Logs): `slog.JSONHandler`
- **Level:** Support a `--debug` flag to toggle `slog.LevelDebug`.

### Development Workflow
- **Local Cluster:** Use `kind` with specific feature gates (`PodCertificateRequest`, `ClusterTrustBundle`, etc.) and a locally built `kindest/node:v1.36.0` image (`hack/kind-node-image.sh`; not published on Docker Hub yet).
- **CA Setup:** Use `hack/step-ca-setup.sh` to generate Root/Intermediate CAs and provisioner keys for development.
- **Kubeconfig:** Managed via `hack/kind-start.sh` and automatically exported via `.envrc` for `direnv` users.
- **Deployment:** Prefer `skaffold` for building and deploying. Base images must be `debian:trixie-slim`.
- **Validation:** Use `hack/verify.sh` for end-to-end automated testing. Supports local or in-cluster controller testing.

### Security
- **CA Management:** CA certificates and keys must reside in `k8s/` and be ignored by `.gitignore`.
- **RBAC:** The controller requires `sign` and `attest` permissions on the specific signer resource name.
- **GCP KMS:** The controller validates at startup that the KMS key version public key matches the configured CA certificate. On GKE, authenticate via Workload Identity (`iam.gke.io/gcp-service-account` annotation on the Kubernetes ServiceAccount).

## Code Conventions
- **Client:** Use direct `client-go` instead of `controller-runtime` to maintain compatibility with bleeding-edge Kubernetes alpha/beta types.
- **Reconciliation:** Implement a workqueue-based pattern with informers.
- **Issuers:** All signing logic must be abstracted behind the `Issuer` interface.
