package kms

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"sync"

	gkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// Signer implements crypto.Signer using Google Cloud KMS.
type Signer struct {
	client         *gkms.KeyManagementClient
	keyVersionName string
	publicKey      crypto.PublicKey

	mu      sync.Mutex
	signCtx context.Context
}

// NewSigner creates a Signer for the given KMS key version.
// When expectedPubKey is non-nil, the KMS public key must match it.
func NewSigner(ctx context.Context, keyVersionName string, expectedPubKey crypto.PublicKey) (*Signer, error) {
	client, err := gkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create KMS client: %w", err)
	}

	pubKey, err := fetchPublicKey(ctx, client, keyVersionName)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	if expectedPubKey != nil && !PublicKeysEqual(pubKey, expectedPubKey) {
		_ = client.Close()
		return nil, fmt.Errorf("KMS public key does not match CA certificate public key")
	}

	return &Signer{
		client:         client,
		keyVersionName: keyVersionName,
		publicKey:      pubKey,
	}, nil
}

// Close releases the underlying KMS client.
func (k *Signer) Close() error {
	if k.client == nil {
		return nil
	}
	return k.client.Close()
}

// SetSignContext sets the context used for subsequent Sign calls.
// crypto.Signer does not accept a context, so callers must set it before signing.
func (k *Signer) SetSignContext(ctx context.Context) {
	k.mu.Lock()
	k.signCtx = ctx
	k.mu.Unlock()
}

// Public returns the public key associated with the KMS key.
func (k *Signer) Public() crypto.PublicKey {
	return k.publicKey
}

// Sign signs the digest with the KMS key.
func (k *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	k.mu.Lock()
	ctx := k.signCtx
	k.mu.Unlock()
	if ctx == nil {
		ctx = context.Background()
	}

	req := &kmspb.AsymmetricSignRequest{
		Name: k.keyVersionName,
	}

	switch opts.HashFunc() {
	case crypto.SHA256:
		req.Digest = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha256{
				Sha256: digest,
			},
		}
	case crypto.SHA384:
		req.Digest = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha384{
				Sha384: digest,
			},
		}
	case crypto.SHA512:
		req.Digest = &kmspb.Digest{
			Digest: &kmspb.Digest_Sha512{
				Sha512: digest,
			},
		}
	default:
		return nil, fmt.Errorf("unsupported hash function: %v", opts.HashFunc())
	}

	resp, err := k.client.AsymmetricSign(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("KMS asymmetric sign failed: %w", err)
	}

	return resp.Signature, nil
}
