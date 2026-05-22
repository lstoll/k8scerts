package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	gkms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

func fetchPublicKey(ctx context.Context, client *gkms.KeyManagementClient, keyVersionName string) (crypto.PublicKey, error) {
	resp, err := client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{
		Name: keyVersionName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch KMS public key: %w", err)
	}

	block, _ := pem.Decode([]byte(resp.Pem))
	if block == nil {
		return nil, fmt.Errorf("failed to decode KMS public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS public key: %w", err)
	}

	return pubKey, nil
}

// PublicKeysEqual reports whether two public keys are equivalent.
func PublicKeysEqual(a, b crypto.PublicKey) bool {
	aBytes, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bBytes, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(aBytes, bBytes)
}
