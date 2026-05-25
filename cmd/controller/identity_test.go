package main

import (
	"testing"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNormalizeTrustDomain(t *testing.T) {
	got, err := normalizeTrustDomain("spiffe://example.com/")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "example.com" {
		t.Fatalf("got %q, want example.com", got)
	}

	if _, err := normalizeTrustDomain("example.com/extra"); err == nil {
		t.Fatal("expected error for path in trust domain")
	}
}

func TestParseDNSNames(t *testing.T) {
	got, err := parseDNSNames(" a.example.com, b.example.com ,a.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || got[0] != "a.example.com" || got[1] != "b.example.com" {
		t.Fatalf("unexpected dns names: %#v", got)
	}

	if _, err := parseDNSNames("a.example.com,,b.example.com"); err == nil {
		t.Fatal("expected error for empty dns entry")
	}
}

func TestBuildWorkloadIdentity(t *testing.T) {
	cfg := identityConfig{
		spiffeTrustDomain: "example.com",
		signerName:        "example.com/pod-signer",
	}

	pcr := &certsv1beta1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "prod",
		},
		Spec: certsv1beta1.PodCertificateRequestSpec{
			PodName:            "my-pod",
			ServiceAccountName: "workload",
			UnverifiedUserAnnotations: map[string]string{
				"example.com/certificate-cn": "my-workload",
				"example.com/dns-names":      "my-workload.prod.svc.cluster.local, api.prod.example.com",
			},
		},
	}

	id, err := buildWorkloadIdentity(pcr, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.PodNamespace != "prod" {
		t.Fatalf("PodNamespace = %q, want prod", id.PodNamespace)
	}
	if id.CommonName != "my-workload" {
		t.Fatalf("CommonName = %q, want my-workload", id.CommonName)
	}
	if len(id.DNSSANs) != 2 {
		t.Fatalf("unexpected DNSSANs: %#v", id.DNSSANs)
	}
	if len(id.URISANs) != 1 || id.URISANs[0] != "spiffe://example.com/ns/prod/sa/workload" {
		t.Fatalf("unexpected URISANs: %#v", id.URISANs)
	}

	noSPIFFE, err := buildWorkloadIdentity(pcr, identityConfig{signerName: cfg.signerName})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(noSPIFFE.URISANs) != 0 {
		t.Fatalf("expected no URI SANs when trust domain unset, got %#v", noSPIFFE.URISANs)
	}
}

func TestJWTSubject(t *testing.T) {
	if got := jwtSubject(WorkloadIdentity{CommonName: "cn", URISANs: []string{"spiffe://example.com/ns/default/sa/default"}}); got != "cn" {
		t.Fatalf("jwtSubject() = %q, want cn", got)
	}
	if got := jwtSubject(WorkloadIdentity{URISANs: []string{"spiffe://example.com/ns/default/sa/default"}, PodName: "pod"}); got != "spiffe://example.com/ns/default/sa/default" {
		t.Fatalf("jwtSubject() = %q, want spiffe URI", got)
	}
}
