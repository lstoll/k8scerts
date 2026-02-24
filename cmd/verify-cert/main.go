package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"
)

func main() {
	podCertPath := "/var/run/certs/pod.pem"
	caCertPath := "/var/run/certs/ca.crt"

	fmt.Println("Waiting for certificate and CA...")
	for {
		if _, err := os.Stat(podCertPath); err == nil {
			if _, err := os.Stat(caCertPath); err == nil {
				break
			}
		}
		time.Sleep(1 * time.Second)
	}

	fmt.Println("Certificate and CA found!")

	// Read CA cert
	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	caBlock, _ := pem.Decode(caBytes)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		log.Fatalf("Failed to decode CA PEM")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA cert: %v", err)
	}

	// Read Pod cert chain
	podBytes, err := os.ReadFile(podCertPath)
	if err != nil {
		log.Fatalf("Failed to read Pod cert: %v", err)
	}

	var podCerts []*x509.Certificate
	rest := podBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Fatalf("Failed to parse a cert in pod.pem: %v", err)
			}
			podCerts = append(podCerts, cert)
		}
	}

	if len(podCerts) == 0 {
		log.Fatalf("No certificates found in pod.pem")
	}

	leaf := podCerts[0]
	intermediates := x509.NewCertPool()
	for i := 1; i < len(podCerts); i++ {
		intermediates.AddCert(podCerts[i])
	}

	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	fmt.Println("Verifying certificate against CA...")
	if _, err := leaf.Verify(opts); err != nil {
		fmt.Printf("Verification FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Verification SUCCESSFUL")

	// Sleep forever as the pod expects to stay running
	select {}
}
