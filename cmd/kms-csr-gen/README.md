# kms-csr-gen

This utility tool generates a Certificate Signing Request (CSR) for an asymmetric key stored in Google Cloud Key Management Service (KMS). Since the private key remains secure within KMS and cannot be exported, the CSR is signed by making a remote signing call to GCP KMS.

The generated CSR can then be signed offline by your Root CA to produce the subordinate CA certificate used by the `k8scerts` controller.

## Authentication & IAM Requirements

To run this tool locally, your authenticated user/identity must have permissions to access the KMS key.

### 1. Required GCP IAM Roles

The executing identity needs the following IAM permissions on the specific KMS key version:
- **`roles/cloudkms.viewer`**: Required to fetch the public key configuration (`cloudkms.cryptoKeyVersions.getPublicKey`).
- **`roles/cloudkms.signer`** or **`roles/cloudkms.signerVerifier`**: Required to perform the signing operation (`cloudkms.cryptoKeyVersions.useToSign`).

### 2. Local Authentication via gcloud

Set up Application Default Credentials (ADC) on your terminal using the Google Cloud SDK:

```bash
gcloud auth application-default login
```

This command opens a browser window for login, after which the credentials are saved locally (typically at `~/.config/gcloud/application_default_credentials.json`). The Go SDK automatically detects and uses this credential file to authenticate API calls to KMS.

### 3. In-Cluster Authentication (GKE Workload Identity)

When the controller runs in `--mode=gcpkms`, it uses the same KMS permissions at runtime. On GKE, bind a Google service account to the controller's Kubernetes ServiceAccount:

```bash
# Grant KMS access to the Google service account
gcloud kms keys add-iam-policy-binding MY_KEY \
  --keyring=MY_KEYRING --location=MY_LOCATION \
  --member="serviceAccount:pod-signer@MY_PROJECT.iam.gserviceaccount.com" \
  --role="roles/cloudkms.signer"

# Allow the Kubernetes ServiceAccount to impersonate the GSA
gcloud iam service-accounts add-iam-policy-binding pod-signer@MY_PROJECT.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:MY_PROJECT.svc.id.goog[default/pod-cert-controller]"
```

Annotate the Kubernetes ServiceAccount with `iam.gke.io/gcp-service-account: pod-signer@MY_PROJECT.iam.gserviceaccount.com`. See `k8s/controller.yaml` for a full deployment example.

## How to Run

Compile and run the tool by providing the full GCP KMS key version resource ID:

```bash
go run ./cmd/kms-csr-gen \
  --kms-key-id="projects/YOUR_PROJECT_ID/locations/YOUR_LOCATION/keyRings/YOUR_KEYRING/cryptoKeys/YOUR_KEY_NAME/cryptoKeyVersions/YOUR_VERSION" \
  --common-name="Example Pod Signer CA" \
  --org="Example Org" \
  --out="kms.csr"
```

### Command Flags

- `--kms-key-id`: (Required) The full GCP resource path to the key version.
- `--common-name`: (Optional) The Common Name (`CN`) subject field for the certificate. Default is `Example Pod Signer CA`.
- `--org`: (Optional) The Organization (`O`) subject field. Default is `Example Org`.
- `--out`: (Optional) Output filepath for the PEM-encoded CSR. Default is `kms.csr`.

## Next Steps: Offline Signing

Once you have the `kms.csr` file, sign it using your offline Root CA.

For example, using standard `openssl`:

```bash
openssl x509 -req \
  -in kms.csr \
  -CA root_ca.crt \
  -CAkey root_ca.key \
  -CAcreateserial \
  -out ca.crt \
  -days 365 \
  -sha256 \
  -extfile <(echo "basicConstraints=critical,CA:true")
```

The resulting `ca.crt` (the subordinate CA certificate) and the original `kmsKeyID` are the two inputs required to configure the `k8scerts` controller in `--mode=gcpkms` mode.

## Trust Bundle

The controller publishes a `ClusterTrustBundle` containing the subordinate CA certificate (`ca.crt`). Pods use this bundle to validate certificates issued by the controller.

If your offline root CA is not already trusted by workloads, append it to the trust bundle so clients can validate the full chain:

```bash
# Controller flag
--root-ca-cert=/etc/k8scerts/root_ca.crt
```

When `--root-ca-cert` is set, the `ClusterTrustBundle` contains the subordinate CA followed by the offline root (PEM concatenation). When omitted, only the subordinate CA is published. This is appropriate when the subordinate CA is installed as a direct trust anchor.

At startup, the controller also validates that the KMS key version public key matches the public key embedded in `ca.crt`.
