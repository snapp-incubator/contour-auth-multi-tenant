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
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

// Default configuration values.
const (
	DefaultAddress      = ":9080"
	DefaultCacheTimeout = 40
	DefaultRedirectPath = "/callback"
)

// DefaultScopes are the default OIDC scopes requested.
var DefaultScopes = []string{"openid", "profile", "email"}

// OIDCConfig defines the configuration parameters used to configure the OIDC provider.
type OIDCConfig struct {
	Address string `yaml:"address"`

	ClusterName            string   `yaml:"clusterName"`
	IssuerURL              string   `yaml:"issuerURL"`
	ClientID               string   `yaml:"clientID"`
	ClientSecret           string   `yaml:"clientSecret"`
	AllowEmptyClientSecret bool     `yaml:"allowEmptyClientSecret"`
	RedirectURL            string   `yaml:"redirectURL"`  // http://gangway.auth.app.local:9080
	RedirectPath           string   `yaml:"redirectPath"` // /callback
	Scopes                 []string `yaml:"scopes"`
	UsernameClaim          string   `yaml:"usernameClaim"`
	EmailClaim             string   `yaml:"emailClaim"`
	ServeTLS               bool     `yaml:"serveTLS"`
	Audience               string   `yaml:"audience"`
	CacheTimeout           int32    `yaml:"cacheTimeout"`
	SkipIssuerCheck        bool     `yaml:"skipIssuerCheck"`

	SessionSecurityKey string `yaml:"sessionSecurityKey" envconfig:"SESSION_SECURITY_KEY"`
}

// NewConfig returns a Config struct from serialized config file.
func NewConfig(configFile string) (*OIDCConfig, error) {
	if configFile == "" {
		return nil, errors.New("config file path is required")
	}

	cfg := &OIDCConfig{
		CacheTimeout:    DefaultCacheTimeout,
		SkipIssuerCheck: false,
	}

	data, err := os.ReadFile(filepath.Clean(configFile))
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// applyDefaults sets default values for unspecified configuration options.
func (cfg *OIDCConfig) applyDefaults() {
	if cfg.Address == "" {
		cfg.Address = DefaultAddress
	}

	if cfg.RedirectPath == "" {
		cfg.RedirectPath = DefaultRedirectPath
	}

	if len(cfg.Scopes) == 0 {
		cfg.Scopes = DefaultScopes
	}
}

// Validate verifies all required properties of config struct are initialized.
func (cfg *OIDCConfig) Validate() error {
	var errs []string

	if cfg.IssuerURL == "" {
		errs = append(errs, "issuerURL is required")
	} else if _, err := url.Parse(cfg.IssuerURL); err != nil {
		errs = append(errs, fmt.Sprintf("issuerURL is invalid: %v", err))
	}

	if cfg.ClientID == "" {
		errs = append(errs, "clientID is required")
	}

	if cfg.ClientSecret == "" && !cfg.AllowEmptyClientSecret {
		errs = append(errs, "clientSecret is required (or set allowEmptyClientSecret: true)")
	}

	if cfg.RedirectURL == "" {
		errs = append(errs, "redirectURL is required")
	} else if u, err := url.Parse(cfg.RedirectURL); err != nil {
		errs = append(errs, fmt.Sprintf("redirectURL is invalid: %v", err))
	} else if u.Scheme != "http" && u.Scheme != "https" {
		errs = append(errs, "redirectURL must use http or https scheme")
	}

	if cfg.RedirectPath == "" {
		errs = append(errs, "redirectPath is required")
	} else if !strings.HasPrefix(cfg.RedirectPath, "/") {
		errs = append(errs, "redirectPath must start with /")
	}

	if cfg.CacheTimeout <= 0 {
		errs = append(errs, "cacheTimeout must be positive")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid config: %s", strings.Join(errs, "; "))
	}

	return nil
}
