package main

import (
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"time"

	certsv1beta1 "k8s.io/api/certificates/v1beta1"
)

const (
	annotationCertificateCN = "certificate-cn"
	annotationDNSNames      = "dns-names"
)

type identityConfig struct {
	spiffeTrustDomain string
	signerName        string
}

type WorkloadIdentity struct {
	PodName            string
	PodNamespace       string
	ServiceAccountName string
	CommonName         string
	DNSSANs            []string
	URISANs            []string
}

type IssueRequest struct {
	CSR        *x509.CertificateRequest
	Expiration time.Duration
	Identity   WorkloadIdentity
}

func signerAnnotationPrefix(signerName string) string {
	if i := strings.Index(signerName, "/"); i > 0 {
		return signerName[:i]
	}
	return signerName
}

func annotationKey(signerName, suffix string) string {
	return signerAnnotationPrefix(signerName) + "/" + suffix
}

func normalizeTrustDomain(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}

	domain := strings.TrimPrefix(raw, "spiffe://")
	domain = strings.TrimSuffix(domain, "/")
	if domain == "" {
		return "", fmt.Errorf("spiffe trust domain must not be empty when set")
	}
	if strings.Contains(domain, "/") {
		return "", fmt.Errorf("spiffe trust domain %q must not contain path segments", raw)
	}
	return domain, nil
}

func spiffeID(trustDomain, namespace, serviceAccount string) string {
	return fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", trustDomain, namespace, serviceAccount)
}

func parseDNSNames(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			return nil, fmt.Errorf("dns-names contains an empty entry")
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

func parseUserAnnotations(annotations map[string]string, signerName string) (commonName string, dnsNames []string, err error) {
	if len(annotations) == 0 {
		return "", nil, nil
	}

	if v, ok := annotations[annotationKey(signerName, annotationCertificateCN)]; ok {
		commonName = strings.TrimSpace(v)
	}

	if v, ok := annotations[annotationKey(signerName, annotationDNSNames)]; ok {
		dnsNames, err = parseDNSNames(v)
		if err != nil {
			return "", nil, fmt.Errorf("%s: %w", annotationKey(signerName, annotationDNSNames), err)
		}
	}

	return commonName, dnsNames, nil
}

func buildWorkloadIdentity(pcr *certsv1beta1.PodCertificateRequest, cfg identityConfig) (WorkloadIdentity, error) {
	commonName, dnsNames, err := parseUserAnnotations(pcr.Spec.UnverifiedUserAnnotations, cfg.signerName)
	if err != nil {
		return WorkloadIdentity{}, err
	}

	id := WorkloadIdentity{
		PodName:            pcr.Spec.PodName,
		PodNamespace:       pcr.Namespace,
		ServiceAccountName: pcr.Spec.ServiceAccountName,
		CommonName:         commonName,
		DNSSANs:            dnsNames,
	}

	if cfg.spiffeTrustDomain != "" && pcr.Spec.ServiceAccountName != "" {
		id.URISANs = append(id.URISANs, spiffeID(cfg.spiffeTrustDomain, pcr.Namespace, pcr.Spec.ServiceAccountName))
	}

	return id, nil
}

func parseURISANs(uriSANs []string) ([]*url.URL, error) {
	if len(uriSANs) == 0 {
		return nil, nil
	}

	uris := make([]*url.URL, 0, len(uriSANs))
	for _, raw := range uriSANs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parse URI SAN %q: %w", raw, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("URI SAN %q must be an absolute URI", raw)
		}
		uris = append(uris, u)
	}
	return uris, nil
}

func jwtSubject(identity WorkloadIdentity) string {
	if identity.CommonName != "" {
		return identity.CommonName
	}
	if len(identity.URISANs) > 0 {
		return identity.URISANs[0]
	}
	return identity.PodName
}

func jwtSANs(identity WorkloadIdentity) []any {
	sans := make([]any, 0, len(identity.DNSSANs)+len(identity.URISANs))
	for _, dnsName := range identity.DNSSANs {
		sans = append(sans, dnsName)
	}
	for _, uri := range identity.URISANs {
		sans = append(sans, uri)
	}
	return sans
}
