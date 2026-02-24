package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

const (
	outDir = "k8s/step-ca"
)

type StepConfig struct {
	Address   string    `json:"address"`
	Root      string    `json:"root"`
	Crt       string    `json:"crt"`
	Key       string    `json:"key"`
	DNSNames  []string  `json:"dnsNames"`
	Logger    any       `json:"logger,omitempty"`
	Authority Authority `json:"authority"`
}

type Authority struct {
	Provisioners []Provisioner `json:"provisioners"`
}

type Provisioner struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Key  any    `json:"key"`
}

func main() {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		log.Fatalf("failed to create output directory: %v", err)
	}

	// 1. Generate Root CA using 'step'
	fmt.Println("Generating Root CA...")
	rootCrt := filepath.Join(outDir, "root_ca.crt")
	rootKey := filepath.Join(outDir, "root_ca.key")
	if err := runStep("certificate", "create", "Step CA Root", rootCrt, rootKey,
		"--profile", "root-ca", "--no-password", "--insecure"); err != nil {
		log.Fatalf("failed to generate root CA: %v", err)
	}

	// 2. Generate Intermediate CA using 'step'
	fmt.Println("Generating Intermediate CA...")
	intCrt := filepath.Join(outDir, "intermediate_ca.crt")
	intKey := filepath.Join(outDir, "intermediate_ca.key")
	if err := runStep("certificate", "create", "Step CA Intermediate", intCrt, intKey,
		"--profile", "intermediate-ca", "--ca", rootCrt, "--ca-key", rootKey,
		"--no-password", "--insecure"); err != nil {
		log.Fatalf("failed to generate intermediate CA: %v", err)
	}

	// 3. Create Tink Keyset for Controller
	// Using ES256 template
	kh, err := keyset.NewHandle(jwt.RawES256Template())
	if err != nil {
		log.Fatalf("failed to create keyset handle: %v", err)
	}
	buf := new(bytes.Buffer)
	if err := insecurecleartextkeyset.Write(kh, keyset.NewJSONWriter(buf)); err != nil {
		log.Fatalf("failed to write keyset: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "provisioner_keyset.json"), buf.Bytes(), 0600); err != nil {
		log.Fatalf("failed to save keyset: %v", err)
	}

	// 4. Generate JWKS and extract the JWK for Step-CA config
	pubKH, err := kh.Public()
	if err != nil {
		log.Fatalf("failed to get public keyset handle: %v", err)
	}
	jwksJSON, err := jwt.JWKSetFromPublicKeysetHandle(pubKH)
	if err != nil {
		log.Fatalf("failed to generate JWKS: %v", err)
	}

	var jwks struct {
		Keys []any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(jwksJSON), &jwks); err != nil {
		log.Fatalf("failed to unmarshal JWKS: %v", err)
	}
	if len(jwks.Keys) == 0 {
		log.Fatalf("no keys found in JWKS")
	}

	// 5. Generate Step-CA Config
	config := StepConfig{
		Address:  ":9000",
		Root:     "/home/step/certs/root_ca.crt",
		Crt:      "/home/step/certs/intermediate_ca.crt",
		Key:      "/home/step/certs/intermediate_ca.key",
		DNSNames: []string{"step-ca", "localhost"},
		Logger: map[string]any{
			"format": "text",
		},
		Authority: Authority{
			Provisioners: []Provisioner{
				{
					Type: "JWK",
					Name: "pod-cert-issuer",
					Key:  jwks.Keys[0],
				},
			},
		},
	}
	configBytes, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "ca.json"), configBytes, 0644); err != nil {
		log.Fatalf("failed to save ca.json: %v", err)
	}

	fmt.Println("Step-CA setup artifacts generated in", outDir)
}

func runStep(args ...string) error {
	cmd := exec.Command("step", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	return cmd.Run()
}
