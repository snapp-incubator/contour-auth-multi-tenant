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
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewState(t *testing.T) {
	state := NewState()

	assert.NotNil(t, state)
	assert.Equal(t, StatusNeedToken, state.Status)
	assert.Empty(t, state.OAuthState)
	assert.Empty(t, state.AccessToken)
	assert.Empty(t, state.IDToken)
	assert.Empty(t, state.RefreshToken)
}

func TestGenerateOauthState(t *testing.T) {
	state := NewState()

	// Make sure OAuthState is empty initially
	assert.Empty(t, state.OAuthState)

	// Generate state
	oauthState, err := state.GenerateOauthState()
	require.NoError(t, err)

	assert.NotEmpty(t, state.OAuthState)
	assert.Equal(t, state.OAuthState, oauthState)

	// State should be base64 encoded 32 bytes = 44 characters
	assert.Len(t, state.OAuthState, 44)
}

func TestGenerateOauthState_Uniqueness(t *testing.T) {
	states := make(map[string]bool)

	// Generate multiple states and ensure they're unique
	for i := 0; i < 100; i++ {
		state := NewState()
		oauthState, err := state.GenerateOauthState()
		require.NoError(t, err)

		assert.False(t, states[oauthState], "duplicate state generated")
		states[oauthState] = true
	}
}

func TestIsNewToken(t *testing.T) {
	state := NewState()
	assert.True(t, state.IsNewToken())

	state.Status = StatusTokenReady
	assert.False(t, state.IsNewToken())
}

func TestIsTokenReady(t *testing.T) {
	state := NewState()
	assert.False(t, state.IsTokenReady())

	state.Status = StatusTokenReady
	assert.True(t, state.IsTokenReady())
}

func TestConvertToByte(t *testing.T) {
	tests := []struct {
		name  string
		state *OIDCState
		want  bool // whether result should be non-nil
	}{
		{
			name:  "nil state",
			state: nil,
			want:  false,
		},
		{
			name:  "empty state",
			state: &OIDCState{},
			want:  true,
		},
		{
			name: "populated state",
			state: &OIDCState{
				Status:       StatusTokenReady,
				AccessToken:  "access-token",
				IDToken:      "id-token",
				RefreshToken: "refresh-token",
				RequestID:    "req-123",
				RequestPath:  "/some/path",
				OAuthState:   "oauth-state-value",
				Scheme:       "https",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertToByte(tt.state)
			if tt.want {
				assert.NotNil(t, result)

				// Verify it's valid JSON
				var parsed map[string]interface{}
				err := json.Unmarshal(result, &parsed)
				assert.NoError(t, err)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestConvertToType(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "nil input",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			input:   []byte("not valid json"),
			wantErr: true,
		},
		{
			name:    "valid empty JSON object",
			input:   []byte("{}"),
			wantErr: false,
		},
		{
			name:    "valid populated state",
			input:   []byte(`{"status":1,"access-token":"token","oauth-state":"state123"}`),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, err := ConvertToType(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, state)
				assert.True(t, errors.Is(err, ErrInvalidState))
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, state)
			}
		})
	}
}

func TestConvertRoundTrip(t *testing.T) {
	original := &OIDCState{
		Status:       StatusTokenReady,
		AccessToken:  "access-token-123",
		IDToken:      "id-token-456",
		RefreshToken: "refresh-token-789",
		RequestID:    "req-abc",
		RequestPath:  "/protected/resource",
		OAuthState:   "random-state-value",
		Scheme:       "https",
	}

	// Convert to bytes
	bytes := ConvertToByte(original)
	require.NotNil(t, bytes)

	// Convert back to state
	restored, err := ConvertToType(bytes)
	require.NoError(t, err)

	// Verify all fields match
	assert.Equal(t, original.Status, restored.Status)
	assert.Equal(t, original.AccessToken, restored.AccessToken)
	assert.Equal(t, original.IDToken, restored.IDToken)
	assert.Equal(t, original.RefreshToken, restored.RefreshToken)
	assert.Equal(t, original.RequestID, restored.RequestID)
	assert.Equal(t, original.RequestPath, restored.RequestPath)
	assert.Equal(t, original.OAuthState, restored.OAuthState)
	assert.Equal(t, original.Scheme, restored.Scheme)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		state   *OIDCState
		wantErr bool
	}{
		{
			name:    "empty oauth state",
			state:   &OIDCState{},
			wantErr: true,
		},
		{
			name: "valid state",
			state: &OIDCState{
				OAuthState: "some-state",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.state.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
