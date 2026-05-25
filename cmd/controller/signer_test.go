package main

import "testing"

func TestDefaultTrustBundleName(t *testing.T) {
	got := defaultTrustBundleName("example.com/pod-signer")
	want := "example.com:pod-signer:ca"
	if got != want {
		t.Fatalf("defaultTrustBundleName() = %q, want %q", got, want)
	}
}

func TestValidateTrustBundleName(t *testing.T) {
	if err := validateTrustBundleName("example.com/pod-signer", "example.com:pod-signer:ca"); err != nil {
		t.Fatalf("expected valid name, got %v", err)
	}
	if err := validateTrustBundleName("example.com/pod-signer", "wrong:ca"); err == nil {
		t.Fatal("expected invalid trust bundle name error")
	}
}
