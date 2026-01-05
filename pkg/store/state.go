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

package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ErrInvalidState is returned when state data cannot be unmarshalled.
var ErrInvalidState = errors.New("invalid state data")

// OIDCState defines the values kept in state.
type OIDCState struct {
	Status       int    `json:"status"`
	AccessToken  string `json:"access-token"`
	IDToken      string `json:"id-token"`
	RefreshToken string `json:"refresh-token"`

	RequestID   string `json:"req-id"`
	RequestPath string `json:"req-path"`
	OAuthState  string `json:"oauth-state"`
	Scheme      string `json:"scheme"`
}

// Status constants for OIDCState.
const (
	StatusNeedToken = iota
	StatusTokenReady
)

// NewState creates a new state to store token for OIDC.
func NewState() *OIDCState {
	return &OIDCState{
		Status: StatusNeedToken,
	}
}

// ConvertToByte converts State to byte slice.
func ConvertToByte(s *OIDCState) []byte {
	if s == nil {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	return b
}

// ConvertToType converts byte slice to State.
// Returns nil and error if unmarshalling fails.
func ConvertToType(value []byte) (*OIDCState, error) {
	if len(value) == 0 {
		return nil, ErrInvalidState
	}

	state := &OIDCState{}
	if err := json.Unmarshal(value, state); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidState, err)
	}

	return state, nil
}

// IsNewToken checks if current state is new and token from IDP is needed.
func (s *OIDCState) IsNewToken() bool {
	return s.Status == StatusNeedToken
}

// IsTokenReady checks if token is ready.
func (s *OIDCState) IsTokenReady() bool {
	return s.Status == StatusTokenReady
}

// GenerateOauthState generates a new OAuth State from random bytes.
// The state defines a unique request from a particular user and is used
// to identify the user during callback or subsequent calls.
func (s *OIDCState) GenerateOauthState() (string, error) {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("error generating oauth state: %w", err)
	}

	s.OAuthState = base64.URLEncoding.EncodeToString(b)
	return s.OAuthState, nil
}

// Validate checks if the state has required fields populated.
func (s *OIDCState) Validate() error {
	if s.OAuthState == "" {
		return errors.New("oauth state is empty")
	}
	return nil
}
