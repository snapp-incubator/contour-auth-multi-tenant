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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHealthChecker_InitialState(t *testing.T) {
	h := NewHealthChecker()

	assert.False(t, h.IsReady(), "HealthChecker should start as not ready")
}

func TestHealthChecker_SetReady(t *testing.T) {
	h := NewHealthChecker()

	h.SetReady()
	assert.True(t, h.IsReady(), "HealthChecker should be ready after SetReady()")
}

func TestHealthChecker_SetNotReady(t *testing.T) {
	h := NewHealthChecker()

	h.SetReady()
	assert.True(t, h.IsReady())

	h.SetNotReady()
	assert.False(t, h.IsReady(), "HealthChecker should not be ready after SetNotReady()")
}

func TestHealthChecker_HTTPHandler_Liveness(t *testing.T) {
	h := NewHealthChecker()
	handler := h.HTTPHandler()

	// Liveness should always return OK (even when not ready)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	assert.Equal(t, "ok", string(body))

	// Still OK after SetReady
	h.SetReady()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHealthChecker_HTTPHandler_Readiness(t *testing.T) {
	h := NewHealthChecker()
	handler := h.HTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)

	// Not ready initially
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	body, _ := io.ReadAll(rec.Body)
	assert.Equal(t, "not ready", string(body))

	// Ready after SetReady
	h.SetReady()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body, _ = io.ReadAll(rec.Body)
	assert.Equal(t, "ok", string(body))

	// Not ready after SetNotReady
	h.SetNotReady()
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHealthChecker_MultipleInstances(t *testing.T) {
	h1 := NewHealthChecker()
	h2 := NewHealthChecker()

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
