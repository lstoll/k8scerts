package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"lds.li/k8scerts/internal/kms"
)

func main() {
	var kmsKeyID string
	var commonName string
	var org string
	var outFile string

	flag.StringVar(&kmsKeyID, "kms-key-id", "", "GCP KMS key version resource ID")
	flag.StringVar(&commonName, "common-name", "Example Pod Signer CA", "Subject Common Name")
	flag.StringVar(&org, "org", "Example Org", "Subject Organization")
	flag.StringVar(&outFile, "out", "kms.csr", "Output file for the PEM-encoded CSR")
	flag.Parse()

	if kmsKeyID == "" {
		fmt.Fprintln(os.Stderr, "Error: --kms-key-id is required")
		os.Exit(1)
	}

	ctx := context.Background()

	signer, err := kms.NewSigner(ctx, kmsKeyID, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize KMS signer: %v\n", err)
		os.Exit(1)
	}
	defer signer.Close()

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate CSR: %v\n", err)
		os.Exit(1)
	}

	out, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open output file: %v\n", err)
		os.Exit(1)
	}
	defer out.Close()

	err = pem.Encode(out, &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to write PEM encoded CSR: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Successfully generated CSR and wrote to %s\n", outFile)
}
