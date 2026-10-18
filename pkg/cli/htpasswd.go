// Copyright Project Contour Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"context"
	"net"
	"sync"

	"github.com/go-logr/logr"
	"github.com/snapp-incubator/contour-auth-multi-tenant/pkg/auth"
	"github.com/tg123/go-htpasswd"
	"google.golang.org/grpc"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrl_cache "sigs.k8s.io/controller-runtime/pkg/cache"
	ctrl_metrics_server "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// NewHtpasswdCommand ...
func NewHtpasswdCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "htpasswd [OPTIONS]",
		Short: "Run a htpasswd basic authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runHtpasswd(cmd)
		},
	}

	// Controller flags.
	cmd.Flags().String("metrics-address", ":8080", "The address the metrics endpoint binds to.")
	cmd.Flags().String("health-address", ":8081", "The address the health check endpoint binds to.")
	cmd.Flags().StringSlice("watch-namespaces", []string{}, "The list of namespaces to watch for Secrets.")
	cmd.Flags().String("selector", "", "Selector (label-query) to filter Secrets, supports '=', '==', and '!='.")

	// GRPC flags.
	cmd.Flags().String("address", ":9090", "The address the authentication endpoint binds to.")
	cmd.Flags().String("tls-cert-path", "", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "", "Path to the TLS server key.")

	// Authorization flags.
	cmd.Flags().String("auth-realm", "default", "Basic authentication realm.")

	return &cmd
}

func buildManagerOptions(cmd *cobra.Command, s *runtime.Scheme) (ctrl.Options, labels.Selector, error) {
	options := ctrl.Options{
		Scheme: s,
		Metrics: ctrl_metrics_server.Options{
			BindAddress: mustString(cmd.Flags().GetString("metrics-address")),
		},
	}

	if namespaces, err := cmd.Flags().GetStringSlice("watch-namespaces"); err == nil && len(namespaces) > 0 {
		options.Cache.DefaultNamespaces = make(map[string]ctrl_cache.Config)
		for _, ns := range namespaces {
			options.Cache.DefaultNamespaces[ns] = ctrl_cache.Config{}
		}
	}

	secretsSelector, err := labels.Parse(mustString(cmd.Flags().GetString("selector")))
	if err != nil {
		return options, nil, ExitErrorf(ExConfig, "failed to parse secrets selector: %s", err)
	}
	if !secretsSelector.Empty() {
		options.Cache.DefaultLabelSelector = secretsSelector
	}

	return options, secretsSelector, nil
}

func startServices(
	ctx context.Context,
	cancel context.CancelFunc,
	log logr.Logger,
	mgr ctrl.Manager,
	htpasswd *auth.Htpasswd,
	healthChecker *auth.HealthChecker,
	listener net.Listener,
	srv *grpc.Server,
	healthAddress, grpcAddress string,
) error {
	errChan := make(chan error, 3)

	go func() {
		log.Info("started health server", "address", healthAddress)
		if err := healthChecker.RunHealthServer(ctx, healthAddress); err != nil {
			errChan <- ExitErrorf(ExFail, "health server failed: %w", err)
			return
		}
		errChan <- nil
	}()

	go func() {
		log.Info("started authorization server", "address", grpcAddress, "realm", htpasswd.Realm)
		if err := auth.RunServer(ctx, listener, srv); err != nil {
			errChan <- ExitErrorf(ExFail, "authorization server failed: %w", err)
			return
		}
		errChan <- nil
	}()

	go func() {
		log.Info("started controller")
		if err := mgr.Start(ctx); err != nil {
			errChan <- ExitErrorf(ExFail, "controller manager failed: %w", err)
			return
		}
		errChan <- nil
	}()

	var firstErr error
	for i := 0; i < 3; i++ {
		if err := <-errChan; err != nil && firstErr == nil {
			firstErr = err
			healthChecker.SetNotLive()
			healthChecker.SetNotReady()
			cancel()
		}
	}
	return firstErr
}

func runHtpasswd(cmd *cobra.Command) error {
	log := ctrl.Log.WithName("auth.htpasswd")
	s := runtime.NewScheme()

	scheme.AddToScheme(s) //nolint:gosec,errcheck

	options, secretsSelector, err := buildManagerOptions(cmd, s)
	if err != nil {
		return err
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		return ExitErrorf(ExConfig, "failed to create controller manager: %s", err)
	}

	creds := &auth.Creds{
		Map: make(map[string]map[string]*htpasswd.File),
		Mu:  &sync.RWMutex{},
	}

	htpasswd := &auth.Htpasswd{
		Log:      log,
		Client:   mgr.GetClient(),
		Realm:    mustString(cmd.Flags().GetString("auth-realm")),
		Creds:    creds,
		Mu:       &sync.Mutex{},
		Selector: secretsSelector,
	}

	if err := htpasswd.RegisterWithManager(mgr); err != nil {
		return ExitErrorf(ExFail, "htpasswd controller registration failed: %w", err)
	}

	grpcAddress := mustString(cmd.Flags().GetString("address"))
	listener, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		return ExitError{ExConfig, err}
	}

	srv, err := DefaultServer(cmd)
	if err != nil {
		return ExitErrorf(ExConfig, "invalid TLS configuration: %s", err)
	}

	// Create health checker for Kubernetes probes
	healthChecker := auth.NewHealthChecker()
	htpasswd.HealthChecker = healthChecker

	auth.RegisterServer(srv, htpasswd)

	ctx, cancel := context.WithCancel(ctrl.SetupSignalHandler())
	defer cancel()

	// Mark ready after cache syncs. Handles clusters with no matching secrets
	// where Reconcile is never triggered (no events = no reconcile calls).
	go func() {
		if mgr.GetCache().WaitForCacheSync(ctx) {
			healthChecker.SetReady()
		}
	}()

	healthAddress := mustString(cmd.Flags().GetString("health-address"))
	return startServices(ctx, cancel, log, mgr, htpasswd, healthChecker, listener, srv, healthAddress, grpcAddress)
}
