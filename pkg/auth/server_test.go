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
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestHealthChecker_InitialState(t *testing.T) {
	h := NewHealthChecker("test-service")

	assert.False(t, h.IsReady(), "HealthChecker should start as not ready")
}

func TestHealthChecker_SetReady(t *testing.T) {
	h := NewHealthChecker("test-service")

	h.SetReady()
	assert.True(t, h.IsReady(), "HealthChecker should be ready after SetReady()")
}

func TestHealthChecker_SetNotReady(t *testing.T) {
	h := NewHealthChecker("test-service")

	h.SetReady()
	assert.True(t, h.IsReady())

	h.SetNotReady()
	assert.False(t, h.IsReady(), "HealthChecker should not be ready after SetNotReady()")
}

func TestHealthChecker_GRPCHealthCheck(t *testing.T) {
	serviceName := "test-grpc-service"
	h := NewHealthChecker(serviceName)

	// Create a gRPC server and register health checker
	srv := grpc.NewServer()
	h.Register(srv)

	// Start listening on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		_ = srv.Serve(listener)
	}()
	defer srv.GracefulStop()

	// Give the server time to start
	time.Sleep(50 * time.Millisecond)

	// Create a gRPC client
	conn, err := grpc.NewClient(
		listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer conn.Close()

	healthClient := grpc_health_v1.NewHealthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Check initial state - should be NOT_SERVING
	resp, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{
		Service: serviceName,
	})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status,
		"Initial health check should return NOT_SERVING")

	// Set ready
	h.SetReady()

	// Check again - should now be SERVING
	resp, err = healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{
		Service: serviceName,
	})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.Status,
		"Health check after SetReady should return SERVING")

	// Set not ready
	h.SetNotReady()

	// Check again - should be NOT_SERVING
	resp, err = healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{
		Service: serviceName,
	})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_NOT_SERVING, resp.Status,
		"Health check after SetNotReady should return NOT_SERVING")
}

func TestHealthChecker_MultipleServices(t *testing.T) {
	h1 := NewHealthChecker("service-1")
	h2 := NewHealthChecker("service-2")

	// Set h1 ready but not h2
	h1.SetReady()

	assert.True(t, h1.IsReady())
	assert.False(t, h2.IsReady())

	// Set h2 ready
	h2.SetReady()

	assert.True(t, h1.IsReady())
	assert.True(t, h2.IsReady())

	// Set h1 not ready
	h1.SetNotReady()

	assert.False(t, h1.IsReady())
	assert.True(t, h2.IsReady())
}
