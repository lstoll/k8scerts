package main

import (
	"fmt"
	"strings"
)

const defaultSignerName = "example.com/pod-signer"

func defaultTrustBundleName(signerName string) string {
	return strings.ReplaceAll(signerName, "/", ":") + ":ca"
}

func validateTrustBundleName(signerName, trustBundleName string) error {
	if signerName == "" {
		return fmt.Errorf("signer-name must not be empty")
	}
	requiredPrefix := strings.ReplaceAll(signerName, "/", ":") + ":"
	if !strings.HasPrefix(trustBundleName, requiredPrefix) {
		return fmt.Errorf("trust-bundle-name %q must be prefixed with %q for signer-name %q", trustBundleName, requiredPrefix, signerName)
	}
	return nil
}
