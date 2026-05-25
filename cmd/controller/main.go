package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"lds.li/k8scerts/internal/kms"
)

type controllerRuntime struct {
	signerName      string
	trustBundleName string
}

type Issuer interface {
	Issue(ctx context.Context, req IssueRequest) (string, error)
	TrustBundle() string
}

type signContextSetter interface {
	SetSignContext(context.Context)
}

type StaticIssuer struct {
	caCert      *x509.Certificate
	caKey       crypto.PrivateKey
	trustBundle []byte
}

func (i *StaticIssuer) Issue(ctx context.Context, req IssueRequest) (string, error) {
	if setter, ok := i.caKey.(signContextSetter); ok {
		setter.SetSignContext(ctx)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", err
	}

	uriSANs, err := parseURISANs(req.Identity.URISANs)
	if err != nil {
		return "", err
	}

	subject := req.CSR.Subject
	if req.Identity.CommonName != "" {
		subject.CommonName = req.Identity.CommonName
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    now,
		NotAfter:     now.Add(req.Expiration),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string(nil), req.Identity.DNSSANs...),
		URIs:         uriSANs,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, i.caCert, req.CSR.PublicKey, i.caKey)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})), nil
}

func (i *StaticIssuer) TrustBundle() string {
	return string(i.trustBundle)
}

func buildTrustBundle(caCertBytes []byte, rootCAFile string) ([]byte, error) {
	caCertBytes = bytes.TrimSpace(caCertBytes)
	if rootCAFile == "" {
		return caCertBytes, nil
	}

	rootBytes, err := os.ReadFile(rootCAFile)
	if err != nil {
		return nil, fmt.Errorf("read root CA cert: %w", err)
	}
	rootBytes = bytes.TrimSpace(rootBytes)
	if len(rootBytes) == 0 {
		return nil, fmt.Errorf("root CA cert file is empty")
	}
	if _, rest := pem.Decode(rootBytes); len(rest) > 0 {
		return nil, fmt.Errorf("root CA cert file must contain a single PEM certificate")
	}

	return append(append([]byte(nil), caCertBytes...), append([]byte("\n"), rootBytes...)...), nil
}

func ptr[T any](v T) *T {
	return &v
}

type Controller struct {
	clientset  kubernetes.Interface
	issuer     Issuer
	signerName string
	identity   identityConfig
	queue      workqueue.TypedRateLimitingInterface[string]
	informer   cache.SharedIndexInformer
}

func NewController(clientset kubernetes.Interface, issuer Issuer, informer cache.SharedIndexInformer, signerName string, identity identityConfig) *Controller {
	c := &Controller{
		clientset:  clientset,
		issuer:     issuer,
		signerName: signerName,
		identity:   identity,
		informer:   informer,
		queue:      workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
	}

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			key, _ := cache.MetaNamespaceKeyFunc(obj)
			c.queue.Add(key)
		},
		UpdateFunc: func(old, new any) {
			key, _ := cache.MetaNamespaceKeyFunc(new)
			c.queue.Add(key)
		},
	})

	return c
}

func (c *Controller) Run(ctx context.Context) {
	defer c.queue.ShutDown()
	slog.Info("Starting controller")

	go func() {
		<-ctx.Done()
		c.queue.ShutDown()
	}()

	go c.informer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		slog.Error("failed to sync cache")
		os.Exit(1)
	}

	for c.processNextItem(ctx) {
	}
}

func (c *Controller) processNextItem(ctx context.Context) bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.reconcile(ctx, key)
	if err == nil {
		c.queue.Forget(key)
		return true
	}

	slog.Error("Error reconciling", "key", key, "error", err)
	c.queue.AddRateLimited(key)
	return true
}

func (c *Controller) reconcile(ctx context.Context, key string) error {
	obj, exists, err := c.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	pcr := obj.(*certsv1beta1.PodCertificateRequest)
	if pcr.Spec.SignerName != c.signerName {
		return nil
	}

	if pcr.Status.CertificateChain != "" {
		return nil
	}

	for _, cond := range pcr.Status.Conditions {
		if (cond.Type == "Denied" || cond.Type == "Failed") && cond.Status == metav1.ConditionTrue {
			return nil
		}
	}

	slog.Info("Signing PodCertificateRequest",
		"name", pcr.Name,
		"namespace", pcr.Namespace,
		"pod", pcr.Spec.PodName,
		"serviceAccount", pcr.Spec.ServiceAccountName,
	)

	if len(pcr.Spec.StubPKCS10Request) == 0 {
		return fmt.Errorf("stubPKCS10Request is empty")
	}

	csr, err := x509.ParseCertificateRequest(pcr.Spec.StubPKCS10Request)
	if err != nil {
		return fmt.Errorf("failed to parse stubPKCS10Request: %v", err)
	}

	expiration := 24 * time.Hour
	if pcr.Spec.MaxExpirationSeconds != nil {
		expiration = time.Duration(*pcr.Spec.MaxExpirationSeconds) * time.Second
	}

	workloadIdentity, err := buildWorkloadIdentity(pcr, c.identity)
	if err != nil {
		return fmt.Errorf("invalid pod certificate identity: %w", err)
	}

	certChain, err := c.issuer.Issue(ctx, IssueRequest{
		CSR:        csr,
		Expiration: expiration,
		Identity:   workloadIdentity,
	})
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %w", err)
	}

	statusUpdate := func(latest *certsv1beta1.PodCertificateRequest) (*certsv1beta1.PodCertificateRequest, error) {
		if latest.Status.CertificateChain != "" {
			return latest, nil
		}

		updated := latest.DeepCopy()
		updated.Status.CertificateChain = certChain

		block, _ := pem.Decode([]byte(certChain))
		issuedCert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			nb := metav1.NewTime(issuedCert.NotBefore)
			na := metav1.NewTime(issuedCert.NotAfter)
			br := metav1.NewTime(issuedCert.NotBefore.Add(issuedCert.NotAfter.Sub(issuedCert.NotBefore) / 2))
			updated.Status.NotBefore = &nb
			updated.Status.NotAfter = &na
			updated.Status.BeginRefreshAt = &br
		}

		updated.Status.Conditions = append(updated.Status.Conditions, metav1.Condition{
			Type:               "Issued",
			Status:             metav1.ConditionTrue,
			Reason:             "Signed",
			Message:            "Certificate issued",
			LastTransitionTime: metav1.Now(),
		})

		return c.clientset.CertificatesV1beta1().PodCertificateRequests(updated.Namespace).UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	}

	err = retry.RetryOnConflict(retry.DefaultRetry, func() error {
		latest, getErr := c.clientset.CertificatesV1beta1().PodCertificateRequests(pcr.Namespace).Get(ctx, pcr.Name, metav1.GetOptions{})
		if getErr != nil {
			return getErr
		}
		if latest.Status.CertificateChain != "" {
			return nil
		}
		_, updateErr := statusUpdate(latest)
		return updateErr
	})
	if err != nil {
		return fmt.Errorf("failed to update PCR status: %w", err)
	}

	slog.Info("Successfully issued certificate", "name", pcr.Name, "namespace", pcr.Namespace)
	return nil
}

func syncCTB(ctx context.Context, clientset kubernetes.Interface, issuer Issuer, cfg controllerRuntime) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	sync := func() {
		slog.Debug("Syncing ClusterTrustBundle", "name", cfg.trustBundleName, "signer", cfg.signerName)
		ctb := &certsv1beta1.ClusterTrustBundle{
			ObjectMeta: metav1.ObjectMeta{
				Name: cfg.trustBundleName,
			},
			Spec: certsv1beta1.ClusterTrustBundleSpec{
				SignerName:  cfg.signerName,
				TrustBundle: issuer.TrustBundle(),
			},
		}

		existing, err := clientset.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, cfg.trustBundleName, metav1.GetOptions{})
		if err != nil {
			if _, err := clientset.CertificatesV1beta1().ClusterTrustBundles().Create(ctx, ctb, metav1.CreateOptions{}); err != nil {
				slog.Error("failed to create ClusterTrustBundle", "error", err)
			}
		} else {
			ctb.ResourceVersion = existing.ResourceVersion
			if _, err := clientset.CertificatesV1beta1().ClusterTrustBundles().Update(ctx, ctb, metav1.UpdateOptions{}); err != nil {
				slog.Error("failed to update ClusterTrustBundle", "error", err)
			}
		}
	}

	sync()
	for {
		select {
		case <-ticker.C:
			sync()
		case <-ctx.Done():
			return
		}
	}
}

func isTerminal() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func main() {
	var mode string
	var caCertFile string
	var caKeyFile string
	var kubeconfig string
	var debug bool

	var stepURL string
	var stepProvName string
	var stepKeysetFile string
	var stepRootFile string
	var kmsKeyID string
	var rootCAFile string
	var signerName string
	var trustBundleName string
	var spiffeTrustDomain string

	var leaderElect bool
	var leaderLeaseName string
	var leaderLeaseNamespace string
	var leaderLeaseDuration time.Duration
	var leaderRenewDeadline time.Duration
	var leaderRetryPeriod time.Duration

	flag.StringVar(&mode, "mode", "static", "Issuer mode: static, step or gcpkms")
	flag.StringVar(&caCertFile, "ca-cert", "k8s/ca.crt", "Path to CA certificate (static or gcpkms mode)")
	flag.StringVar(&caKeyFile, "ca-key", "k8s/ca.key", "Path to CA key (static mode)")
	flag.StringVar(&rootCAFile, "root-ca-cert", "", "Optional offline root CA certificate to append to the ClusterTrustBundle (gcpkms mode)")
	flag.StringVar(&signerName, "signer-name", defaultSignerName, "Signer name managed by this controller")
	flag.StringVar(&trustBundleName, "trust-bundle-name", "", "ClusterTrustBundle name (defaults to <signer-name-with-colons>:ca)")
	flag.StringVar(&spiffeTrustDomain, "spiffe-trust-domain", "", "Trust domain for SPIFFE URI SANs (spiffe://<domain>/ns/<namespace>/sa/<serviceaccount>); disabled when empty")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")

	flag.StringVar(&stepURL, "step-url", "", "Step-CA URL")
	flag.StringVar(&stepProvName, "step-provisioner", "", "Step-CA Provisioner Name")
	flag.StringVar(&stepKeysetFile, "step-keyset", "", "Path to Tink Keyset for Step-CA")
	flag.StringVar(&stepRootFile, "step-root", "", "Path to Step-CA Root certificate")
	flag.StringVar(&kmsKeyID, "kms-key-id", "", "GCP KMS key version resource ID for gcpkms mode")

	flag.BoolVar(&leaderElect, "leader-elect", false, "Enable leader election for HA deployments")
	flag.StringVar(&leaderLeaseName, "leader-elect-lease-name", "pod-cert-controller", "Name of the leader election lease")
	flag.StringVar(&leaderLeaseNamespace, "leader-elect-lease-namespace", "", "Namespace for the leader election lease (defaults to pod namespace or default)")
	flag.DurationVar(&leaderLeaseDuration, "leader-elect-lease-duration", 15*time.Second, "Leader election lease duration")
	flag.DurationVar(&leaderRenewDeadline, "leader-elect-renew-deadline", 10*time.Second, "Leader election renew deadline")
	flag.DurationVar(&leaderRetryPeriod, "leader-elect-retry-period", 2*time.Second, "Leader election retry period")

	flag.Parse()

	if trustBundleName == "" {
		trustBundleName = defaultTrustBundleName(signerName)
	}
	if err := validateTrustBundleName(signerName, trustBundleName); err != nil {
		slog.Error("invalid trust bundle configuration", "error", err)
		os.Exit(1)
	}

	normalizedTrustDomain, err := normalizeTrustDomain(spiffeTrustDomain)
	if err != nil {
		slog.Error("invalid spiffe trust domain", "error", err)
		os.Exit(1)
	}

	identity := identityConfig{
		spiffeTrustDomain: normalizedTrustDomain,
		signerName:        signerName,
	}

	runtime := controllerRuntime{
		signerName:      signerName,
		trustBundleName: trustBundleName,
	}
	slog.Info("controller configuration",
		"signer-name", runtime.signerName,
		"trust-bundle-name", runtime.trustBundleName,
		"spiffe-trust-domain", identity.spiffeTrustDomain,
		"user-annotation-cn", annotationKey(signerName, annotationCertificateCN),
		"user-annotation-dns-names", annotationKey(signerName, annotationDNSNames),
	)

	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}

	var handler slog.Handler
	if isTerminal() {
		handler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
	klog.SetSlogLogger(logger)

	var issuer Issuer
	if mode == "static" {
		caCertBytes, err := os.ReadFile(caCertFile)
		if err != nil {
			slog.Error("unable to read ca cert", "error", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(caCertBytes)
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Error("unable to parse ca cert", "error", err)
			os.Exit(1)
		}
		caKeyBytes, err := os.ReadFile(caKeyFile)
		if err != nil {
			slog.Error("unable to read ca key", "error", err)
			os.Exit(1)
		}
		block, _ = pem.Decode(caKeyBytes)
		caKey, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			slog.Error("unable to parse ca key", "error", err)
			os.Exit(1)
		}
		issuer = &StaticIssuer{caCert: caCert, caKey: caKey, trustBundle: caCertBytes}
	} else if mode == "gcpkms" {
		if kmsKeyID == "" {
			slog.Error("kms-key-id flag is required for gcpkms mode")
			os.Exit(1)
		}
		caCertBytes, err := os.ReadFile(caCertFile)
		if err != nil {
			slog.Error("unable to read ca cert", "error", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(caCertBytes)
		if block == nil {
			slog.Error("failed to decode ca cert PEM")
			os.Exit(1)
		}
		caCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Error("unable to parse ca cert", "error", err)
			os.Exit(1)
		}

		trustBundle, err := buildTrustBundle(caCertBytes, rootCAFile)
		if err != nil {
			slog.Error("unable to build trust bundle", "error", err)
			os.Exit(1)
		}

		kmsSigner, err := kms.NewSigner(context.Background(), kmsKeyID, caCert.PublicKey)
		if err != nil {
			slog.Error("unable to create KMS signer", "error", err)
			os.Exit(1)
		}
		slog.Info("KMS key validated against CA certificate", "kms-key-id", kmsKeyID)
		issuer = &StaticIssuer{caCert: caCert, caKey: kmsSigner, trustBundle: trustBundle}
	} else if mode == "step" {
		ksBytes, err := os.ReadFile(stepKeysetFile)
		if err != nil {
			slog.Error("unable to read step keyset", "error", err)
			os.Exit(1)
		}
		kh, err := insecurecleartextkeyset.Read(keyset.NewJSONReader(bytes.NewReader(ksBytes)))
		if err != nil {
			slog.Error("unable to parse step keyset", "error", err)
			os.Exit(1)
		}
		rootCA, err := os.ReadFile(stepRootFile)
		if err != nil {
			slog.Error("unable to read step root ca", "error", err)
			os.Exit(1)
		}

		var errGen error
		issuer, errGen = NewStepIssuer(stepURL, stepProvName, kh, rootCA)
		if errGen != nil {
			slog.Error("failed to create step issuer", "error", errGen)
			os.Exit(1)
		}
	} else {
		slog.Error("invalid mode", "mode", mode)
		os.Exit(1)
	}

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		slog.Error("unable to build kubeconfig", "error", err)
		os.Exit(1)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		slog.Error("unable to create clientset", "error", err)
		os.Exit(1)
	}

	factory := informers.NewSharedInformerFactory(clientset, 10*time.Minute)
	pcrInformer := factory.Certificates().V1beta1().PodCertificateRequests().Informer()

	controller := NewController(clientset, issuer, pcrInformer, runtime.signerName, identity)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	runWithOptionalLeaderElection(ctx, clientset, issuer, controller, runtime, leaderElectionConfig{
		enabled:       leaderElect,
		leaseName:     leaderLeaseName,
		leaseNS:       leaderElectionNamespace(leaderLeaseNamespace),
		leaseDuration: leaderLeaseDuration,
		renewDeadline: leaderRenewDeadline,
		retryPeriod:   leaderRetryPeriod,
	})
}
