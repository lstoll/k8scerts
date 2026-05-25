package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/smallstep/certificates/api"
	"github.com/smallstep/certificates/ca"
	"github.com/tink-crypto/tink-go/v2/jwt"
	"github.com/tink-crypto/tink-go/v2/keyset"
)

type StepIssuer struct {
	caURL           string
	provisionerName string
	keysetHandle    *keyset.Handle
	rootCA          []byte
	client          *ca.Client
}

func NewStepIssuer(caURL, provisionerName string, keysetHandle *keyset.Handle, rootCA []byte) (*StepIssuer, error) {
	client, err := ca.NewClient(caURL, ca.WithCABundle(rootCA))
	if err != nil {
		return nil, fmt.Errorf("failed to create step-ca client: %w", err)
	}

	return &StepIssuer{
		caURL:           caURL,
		provisionerName: provisionerName,
		keysetHandle:    keysetHandle,
		rootCA:          rootCA,
		client:          client,
	}, nil
}

func (i *StepIssuer) Issue(ctx context.Context, req IssueRequest) (string, error) {
	signer, err := jwt.NewSigner(i.keysetHandle)
	if err != nil {
		return "", fmt.Errorf("failed to create JWT signer: %w", err)
	}

	cnf, err := generateCnfClaim(req.CSR.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate cnf claim: %w", err)
	}

	// Step-CA often backdates the NotBefore by 1 minute, which increases the total lifetime.
	// We subtract 5 minutes from the requested expiration to ensure we stay within maxExpirationSeconds.
	requestedExpiration := time.Now().Add(req.Expiration - 5*time.Minute)

	sans := jwtSANs(req.Identity)

	rawClaims := map[string]any{
		"sans": sans,
		"cnf":  cnf,
	}

	tokenOpts := &jwt.RawJWTOptions{
		Audiences:    []string{i.caURL + "/sign", i.caURL + "/1.0/sign"},
		Issuer:       ptr(i.provisionerName),
		Subject:      ptr(jwtSubject(req.Identity)),
		ExpiresAt:    new(time.Now().Add(1 * time.Minute)),
		CustomClaims: rawClaims,
	}

	token, err := jwt.NewRawJWT(tokenOpts)
	if err != nil {
		return "", err
	}

	signedToken, err := signer.SignAndEncode(token)
	if err != nil {
		return "", err
	}

	resp, err := i.client.Sign(&api.SignRequest{
		CsrPEM:   api.CertificateRequest{CertificateRequest: req.CSR},
		OTT:      signedToken,
		NotAfter: api.NewTimeDuration(requestedExpiration),
	})
	if err != nil {
		return "", fmt.Errorf("step-ca sign failed: %w", err)
	}

	var certChain strings.Builder
	for _, c := range resp.CertChainPEM {
		certChain.WriteString(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
	}

	return certChain.String(), nil
}

func (i *StepIssuer) TrustBundle() string {
	return string(i.rootCA)
}

func generateCnfClaim(pub crypto.PublicKey) (map[string]any, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		var crv string
		switch k.Curve {
		case elliptic.P256():
			crv = "P-256"
		case elliptic.P384():
			crv = "P-384"
		case elliptic.P521():
			crv = "P-521"
		default:
			return nil, fmt.Errorf("unsupported curve: %s", k.Curve.Params().Name)
		}
		return map[string]any{
			"jwk": map[string]any{
				"kty": "EC",
				"crv": crv,
				"x":   base64.RawURLEncoding.EncodeToString(k.X.Bytes()),
				"y":   base64.RawURLEncoding.EncodeToString(k.Y.Bytes()),
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}
