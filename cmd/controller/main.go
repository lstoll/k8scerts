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
	"time"

	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	signerName = "example.com/pod-signer"
	ctbName    = "example.com:pod-signer:ca"
)

type Issuer interface {
	Issue(ctx context.Context, csr *x509.CertificateRequest, expiration time.Duration, podName, namespace string) (string, error)
	TrustBundle() string
}

type StaticIssuer struct {
	caCert      *x509.Certificate
	caKey       crypto.PrivateKey
	caCertBytes []byte
}

func (i *StaticIssuer) Issue(ctx context.Context, csr *x509.CertificateRequest, expiration time.Duration, podName, namespace string) (string, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return "", err
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,
		NotBefore:    now,
		NotAfter:     now.Add(expiration),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, i.caCert, csr.PublicKey, i.caKey)
	if err != nil {
		return "", err
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})), nil
}

func (i *StaticIssuer) TrustBundle() string {
	return string(i.caCertBytes)
}

func ptr[T any](v T) *T {
	return &v
}

type Controller struct {
	clientset kubernetes.Interface
	issuer    Issuer
	queue     workqueue.TypedRateLimitingInterface[string]
	informer  cache.SharedIndexInformer
}

func NewController(clientset kubernetes.Interface, issuer Issuer, informer cache.SharedIndexInformer) *Controller {
	c := &Controller{
		clientset: clientset,
		issuer:    issuer,
		informer:  informer,
		queue:     workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[string]()),
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
	if pcr.Spec.SignerName != signerName {
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

	slog.Info("Signing PodCertificateRequest", "name", pcr.Name, "namespace", pcr.Namespace)

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

	certChain, err := c.issuer.Issue(ctx, csr, expiration, pcr.Spec.PodName, pcr.Namespace)
	if err != nil {
		return fmt.Errorf("failed to issue certificate: %w", err)
	}

	pcrCopy := pcr.DeepCopy()
	pcrCopy.Status.CertificateChain = certChain

	// Simplification: Parse issued cert to get validity times
	block, _ := pem.Decode([]byte(certChain))
	issuedCert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		nb := metav1.NewTime(issuedCert.NotBefore)
		na := metav1.NewTime(issuedCert.NotAfter)
		br := metav1.NewTime(issuedCert.NotBefore.Add(issuedCert.NotAfter.Sub(issuedCert.NotBefore) / 2))
		pcrCopy.Status.NotBefore = &nb
		pcrCopy.Status.NotAfter = &na
		pcrCopy.Status.BeginRefreshAt = &br
	}

	pcrCopy.Status.Conditions = append(pcrCopy.Status.Conditions, metav1.Condition{
		Type:               "Issued",
		Status:             metav1.ConditionTrue,
		Reason:             "Signed",
		Message:            "Certificate issued",
		LastTransitionTime: metav1.Now(),
	})

	_, err = c.clientset.CertificatesV1beta1().PodCertificateRequests(pcr.Namespace).UpdateStatus(ctx, pcrCopy, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update PCR status: %v", err)
	}

	slog.Info("Successfully issued certificate", "name", pcr.Name, "namespace", pcr.Namespace)
	return nil
}

func syncCTB(ctx context.Context, clientset kubernetes.Interface, issuer Issuer) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	sync := func() {
		slog.Debug("Syncing ClusterTrustBundle")
		ctb := &certsv1beta1.ClusterTrustBundle{
			ObjectMeta: metav1.ObjectMeta{
				Name: ctbName,
			},
			Spec: certsv1beta1.ClusterTrustBundleSpec{
				SignerName:  signerName,
				TrustBundle: issuer.TrustBundle(),
			},
		}

		existing, err := clientset.CertificatesV1beta1().ClusterTrustBundles().Get(ctx, ctbName, metav1.GetOptions{})
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

	flag.StringVar(&mode, "mode", "static", "Issuer mode: static or step")
	flag.StringVar(&caCertFile, "ca-cert", "k8s/ca.crt", "Path to CA certificate (static mode)")
	flag.StringVar(&caKeyFile, "ca-key", "k8s/ca.key", "Path to CA key (static mode)")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")

	flag.StringVar(&stepURL, "step-url", "", "Step-CA URL")
	flag.StringVar(&stepProvName, "step-provisioner", "", "Step-CA Provisioner Name")
	flag.StringVar(&stepKeysetFile, "step-keyset", "", "Path to Tink Keyset for Step-CA")
	flag.StringVar(&stepRootFile, "step-root", "", "Path to Step-CA Root certificate")

	flag.Parse()

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
		issuer = &StaticIssuer{caCert: caCert, caKey: caKey, caCertBytes: caCertBytes}
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

	controller := NewController(clientset, issuer, pcrInformer)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go syncCTB(ctx, clientset, issuer)
	controller.Run(ctx)
}
