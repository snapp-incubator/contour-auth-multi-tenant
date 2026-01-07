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
	"net"
	"net/http"
	"time"

	"github.com/allegro/bigcache/v3"
	"github.com/snapp-incubator/contour-auth-multi-tenant/pkg/auth"
	"github.com/snapp-incubator/contour-auth-multi-tenant/pkg/config"
	"github.com/spf13/cobra"

	ctrl "sigs.k8s.io/controller-runtime"
)

// NewOIDCConnect - start server as OIDC and take in 'config' file as parameter...
func NewOIDCConnect() *cobra.Command {
	cmd := cobra.Command{
		Use:   "oidc Server [OPTIONS]",
		Short: "Run a OIDC authentication server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := ctrl.SetupSignalHandler()
			log := ctrl.Log.WithName("auth.oidc")

			cfgFile, err := cmd.Flags().GetString("config")
			if err != nil {
				return ExitError{ExConfig, err}
			}

			cfg, err := config.NewConfig(cfgFile)
			if err != nil {
				return ExitError{ExConfig, err}
			}

			log.Info("init oidc... ")

			bigCache, err := bigcache.New(ctx, bigcache.DefaultConfig(time.Duration(cfg.CacheTimeout)*time.Minute))
			if err != nil {
				return ExitErrorf(ExConfig, "failed to create cache: %s", err)
			}

			authOidc := &auth.OIDCConnect{
				Log:        log,
				OidcConfig: cfg,
				Cache:      bigCache,
				HTTPClient: http.DefaultClient, // need to handle client creation with TLS
			}

			listener, err := net.Listen("tcp", authOidc.OidcConfig.Address)
			if err != nil {
				return ExitError{ExConfig, err}
			}

			srv, err := DefaultServer(cmd)
			if err != nil {
				return ExitErrorf(ExConfig, "invalid TLS configuration: %s", err)
			}

			// Create health checker for Kubernetes probes
			healthChecker := auth.NewHealthChecker()

			auth.RegisterServer(srv, authOidc)

			// Mark as ready since OIDC config is successfully loaded
			healthChecker.SetReady()

			errChan := make(chan error, 2)

			// Start HTTP health server for Kubernetes probes
			healthAddress := mustString(cmd.Flags().GetString("health-address"))
			go func() {
				log.Info("started health server", "address", healthAddress)

				if err := healthChecker.RunHealthServer(ctx, healthAddress); err != nil {
					errChan <- ExitErrorf(ExFail, "health server failed: %w", err)
					return
				}

				errChan <- nil
			}()

			go func() {
				log.Info("started serving", "address", authOidc.OidcConfig.Address)

				if err := auth.RunServer(ctx, listener, srv); err != nil {
					errChan <- ExitErrorf(ExFail, "authorization server failed: %w", err)
					return
				}

				errChan <- nil
			}()

			// Wait for both goroutines or context cancellation
			for i := 0; i < 2; i++ {
				select {
				case err := <-errChan:
					if err != nil {
						return err
					}
				case <-ctx.Done():
					return nil
				}
			}
			return nil
		},
	}

	cmd.Flags().String("config", "", "Path to config file ( Yaml format ).")
	cmd.Flags().String("health-address", ":8081", "The address the health check endpoint binds to.")
	cmd.Flags().String("tls-cert-path", "", "Path to the TLS server certificate.")
	cmd.Flags().String("tls-ca-path", "", "Path to the TLS CA certificate bundle.")
	cmd.Flags().String("tls-key-path", "", "Path to the TLS server key.")

	return &cmd
}
