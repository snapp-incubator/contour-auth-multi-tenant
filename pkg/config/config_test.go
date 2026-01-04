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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewConfig_EmptyPath(t *testing.T) {
	cfg, err := NewConfig("")
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "config file path is required")
}

func TestNewConfig_NonexistentFile(t *testing.T) {
	cfg, err := NewConfig("/nonexistent/path/config.yaml")
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to read config file")
}

func TestNewConfig_InvalidYAML(t *testing.T) {
	// Create a temp file with invalid YAML
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "invalid.yaml")
	err := os.WriteFile(tmpFile, []byte("not: valid: yaml: {{"), 0600)
	require.NoError(t, err)

	cfg, err := NewConfig(tmpFile)
	assert.Error(t, err)
	assert.Nil(t, cfg)
	assert.Contains(t, err.Error(), "failed to parse config file")
}

func TestNewConfig_ValidConfig(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "valid.yaml")

	configContent := `
issuerURL: https://idp.example.com
clientID: my-client
clientSecret: my-secret
redirectURL: https://app.example.com
redirectPath: /callback
scopes:
  - openid
  - profile
`
	err := os.WriteFile(tmpFile, []byte(configContent), 0600)
	require.NoError(t, err)

	cfg, err := NewConfig(tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, cfg)

	assert.Equal(t, "https://idp.example.com", cfg.IssuerURL)
	assert.Equal(t, "my-client", cfg.ClientID)
	assert.Equal(t, "my-secret", cfg.ClientSecret)
	assert.Equal(t, "https://app.example.com", cfg.RedirectURL)
	assert.Equal(t, "/callback", cfg.RedirectPath)
	assert.Equal(t, []string{"openid", "profile"}, cfg.Scopes)
}

func TestNewConfig_Defaults(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "minimal.yaml")

	// Minimal config - should get defaults applied
	configContent := `
issuerURL: https://idp.example.com
clientID: my-client
clientSecret: my-secret
redirectURL: https://app.example.com
`
	err := os.WriteFile(tmpFile, []byte(configContent), 0600)
	require.NoError(t, err)

	cfg, err := NewConfig(tmpFile)
	require.NoError(t, err)

	// Check defaults are applied
	assert.Equal(t, DefaultAddress, cfg.Address)
	assert.Equal(t, DefaultRedirectPath, cfg.RedirectPath)
	assert.Equal(t, DefaultScopes, cfg.Scopes)
	assert.Equal(t, int32(DefaultCacheTimeout), cfg.CacheTimeout)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *OIDCConfig
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty config",
			cfg:         &OIDCConfig{},
			wantErr:     true,
			errContains: "issuerURL is required",
		},
		{
			name: "missing clientID",
			cfg: &OIDCConfig{
				IssuerURL: "https://idp.example.com",
			},
			wantErr:     true,
			errContains: "clientID is required",
		},
		{
			name: "missing clientSecret without allowEmpty",
			cfg: &OIDCConfig{
				IssuerURL: "https://idp.example.com",
				ClientID:  "client-id",
			},
			wantErr:     true,
			errContains: "clientSecret is required",
		},
		{
			name: "empty clientSecret with allowEmpty",
			cfg: &OIDCConfig{
				IssuerURL:              "https://idp.example.com",
				ClientID:               "client-id",
				AllowEmptyClientSecret: true,
				RedirectURL:            "https://app.example.com",
				RedirectPath:           "/callback",
				CacheTimeout:           40,
			},
			wantErr: false,
		},
		{
			name: "invalid redirectURL scheme",
			cfg: &OIDCConfig{
				IssuerURL:    "https://idp.example.com",
				ClientID:     "client-id",
				ClientSecret: "secret",
				RedirectURL:  "ftp://invalid.example.com",
				RedirectPath: "/callback",
				CacheTimeout: 40,
			},
			wantErr:     true,
			errContains: "http or https scheme",
		},
		{
			name: "redirectPath without leading slash",
			cfg: &OIDCConfig{
				IssuerURL:    "https://idp.example.com",
				ClientID:     "client-id",
				ClientSecret: "secret",
				RedirectURL:  "https://app.example.com",
				RedirectPath: "callback",
				CacheTimeout: 40,
			},
			wantErr:     true,
			errContains: "must start with /",
		},
		{
			name: "negative cacheTimeout",
			cfg: &OIDCConfig{
				IssuerURL:    "https://idp.example.com",
				ClientID:     "client-id",
				ClientSecret: "secret",
				RedirectURL:  "https://app.example.com",
				RedirectPath: "/callback",
				CacheTimeout: -1,
			},
			wantErr:     true,
			errContains: "cacheTimeout must be positive",
		},
		{
			name: "valid config",
			cfg: &OIDCConfig{
				IssuerURL:    "https://idp.example.com",
				ClientID:     "client-id",
				ClientSecret: "secret",
				RedirectURL:  "https://app.example.com",
				RedirectPath: "/callback",
				CacheTimeout: 40,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestApplyDefaults(t *testing.T) {
	cfg := &OIDCConfig{}

	cfg.applyDefaults()

	assert.Equal(t, DefaultAddress, cfg.Address)
	assert.Equal(t, DefaultRedirectPath, cfg.RedirectPath)
	assert.Equal(t, DefaultScopes, cfg.Scopes)
}

func TestApplyDefaults_DoesNotOverwrite(t *testing.T) {
	cfg := &OIDCConfig{
		Address:      ":8080",
		RedirectPath: "/custom-callback",
		Scopes:       []string{"openid"},
	}

	cfg.applyDefaults()

	// Should NOT be overwritten
	assert.Equal(t, ":8080", cfg.Address)
	assert.Equal(t, "/custom-callback", cfg.RedirectPath)
	assert.Equal(t, []string{"openid"}, cfg.Scopes)
}
