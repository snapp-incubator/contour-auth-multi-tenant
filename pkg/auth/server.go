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

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"sync/atomic"

	envoy_service_auth_v2 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

type CheckRequestV2 = envoy_service_auth_v2.CheckRequest   //nolint:golint
type CheckResponseV2 = envoy_service_auth_v2.CheckResponse //nolint:golint
type CheckRequestV3 = envoy_service_auth_v3.CheckRequest   //nolint:golint
type CheckResponseV3 = envoy_service_auth_v3.CheckResponse //nolint:golint

// Checker is an implementation of the Envoy External Auth API.
//
// https://github.com/envoyproxy/envoy/blob/release/v1.14/api/envoy/service/auth/v3/external_auth.proto
// https://github.com/envoyproxy/envoy/blob/release/v1.14/api/envoy/service/auth/v2/external_auth.proto
type Checker interface {
	Check(context.Context, *Request) (*Response, error)
}

type authV2 struct {
	Checker Checker
}

func (a *authV2) Check(ctx context.Context, check *CheckRequestV2) (*CheckResponseV2, error) {
	request := Request{}
	request.FromV2(check)

	response, err := a.Checker.Check(ctx, &request)
	if err != nil {
		return nil, err
	}

	return response.AsV2(), nil
}

type authV3 struct {
	Checker Checker
}

func (a *authV3) Check(ctx context.Context, check *CheckRequestV3) (*CheckResponseV3, error) {
	request := Request{}
	request.FromV3(check)

	response, err := a.Checker.Check(ctx, &request)
	if err != nil {
		return nil, err
	}

	return response.AsV3(), nil
}

// HealthChecker manages gRPC health check status for Kubernetes probes.
// It implements the standard gRPC health checking protocol.
type HealthChecker struct {
	server  *health.Server
	ready   atomic.Bool
	service string
}

// NewHealthChecker creates a new health checker for the given service name.
func NewHealthChecker(serviceName string) *HealthChecker {
	h := &HealthChecker{
		server:  health.NewServer(),
		service: serviceName,
	}
	// Start as NOT_SERVING until explicitly set ready
	h.server.SetServingStatus(serviceName, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	return h
}

// SetReady marks the service as ready to receive traffic.
// This should be called after initial setup is complete (e.g., secrets loaded).
func (h *HealthChecker) SetReady() {
	h.ready.Store(true)
	h.server.SetServingStatus(h.service, grpc_health_v1.HealthCheckResponse_SERVING)
}

// SetNotReady marks the service as not ready.
func (h *HealthChecker) SetNotReady() {
	h.ready.Store(false)
	h.server.SetServingStatus(h.service, grpc_health_v1.HealthCheckResponse_NOT_SERVING)
}

// IsReady returns true if the service is ready.
func (h *HealthChecker) IsReady() bool {
	return h.ready.Load()
}

// Register registers the health service with the gRPC server.
func (h *HealthChecker) Register(srv *grpc.Server) {
	grpc_health_v1.RegisterHealthServer(srv, h.server)
}

// RegisterServer registers the Checker with the external authorization
// GRPC server.
func RegisterServer(srv *grpc.Server, c Checker) {
	v2 := &authV2{Checker: c}
	v3 := &authV3{Checker: c}

	envoy_service_auth_v2.RegisterAuthorizationServer(srv, v2)
	envoy_service_auth_v3.RegisterAuthorizationServer(srv, v3)
}

// RunServer runs the server until signaled by stopChan.
func RunServer(ctx context.Context, listener net.Listener, srv *grpc.Server) error {
	errChan := make(chan error, 1)

	go func() {
		errChan <- srv.Serve(listener)
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		srv.GracefulStop()
		return nil
	}
}

// NewServerCredentials loads TLS transport credentials for the GRPC server.
func NewServerCredentials(certPath string, keyPath string, caPath string) (credentials.TransportCredentials, error) {
	srv, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	p := x509.NewCertPool()

	if caPath != "" {
		ca, err := os.ReadFile(caPath) //nolint:gosec
		if err != nil {
			return nil, err
		}

		p.AppendCertsFromPEM(ca)
	}

	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{srv},
		RootCAs:      p,
	}), nil
}
