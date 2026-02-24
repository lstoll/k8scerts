package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate private key: %v\n", err)
		os.Exit(1)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate serial number: %v\n", err)
		os.Exit(1)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Example Pod Signer CA"},
			CommonName:   "Example CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create certificate: %v\n", err)
		os.Exit(1)
	}

	certOut, err := os.Create("ca.crt")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open ca.crt for writing: %v\n", err)
		os.Exit(1)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write data to ca.crt: %v\n", err)
		os.Exit(1)
	}
	certOut.Close()
	fmt.Println("wrote ca.crt")

	keyOut, err := os.OpenFile("ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open ca.key for writing: %v\n", err)
		os.Exit(1)
	}
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal private key: %v\n", err)
		os.Exit(1)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write data to ca.key: %v\n", err)
		os.Exit(1)
	}
	keyOut.Close()
	fmt.Println("wrote ca.key")
}
