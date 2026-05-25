package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

type leaderElectionConfig struct {
	enabled       bool
	leaseName     string
	leaseNS       string
	leaseDuration time.Duration
	renewDeadline time.Duration
	retryPeriod   time.Duration
}

func leaderIdentity() string {
	if id := os.Getenv("POD_NAME"); id != "" {
		return id
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func leaderElectionNamespace(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		if namespace := strings.TrimSpace(string(ns)); namespace != "" {
			return namespace
		}
	}
	return "default"
}

func runController(ctx context.Context, clientset kubernetes.Interface, issuer Issuer, controller *Controller, cfg controllerRuntime) {
	go syncCTB(ctx, clientset, issuer, cfg)
	controller.Run(ctx)
}

func runWithOptionalLeaderElection(
	ctx context.Context,
	clientset kubernetes.Interface,
	issuer Issuer,
	controller *Controller,
	runtime controllerRuntime,
	cfg leaderElectionConfig,
) {
	if !cfg.enabled {
		runController(ctx, clientset, issuer, controller, runtime)
		return
	}

	id := leaderIdentity()
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      cfg.leaseName,
			Namespace: cfg.leaseNS,
		},
		Client: clientset.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	slog.Info("starting leader election",
		"identity", id,
		"lease", cfg.leaseName,
		"namespace", cfg.leaseNS,
	)

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   cfg.leaseDuration,
		RenewDeadline:   cfg.renewDeadline,
		RetryPeriod:     cfg.retryPeriod,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				slog.Info("became leader", "identity", id)
				runController(ctx, clientset, issuer, controller, runtime)
			},
			OnStoppedLeading: func() {
				slog.Info("no longer leader", "identity", id)
			},
			OnNewLeader: func(identity string) {
				if identity == id {
					return
				}
				slog.Info("new leader elected", "identity", identity)
			},
		},
	})
}
