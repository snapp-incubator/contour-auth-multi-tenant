package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/snapp-incubator/contour-auth-multi-tenant/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseURLUsesForwardedProto(t *testing.T) {
	req := &Request{
		Request: http.Request{
			URL: &url.URL{
				Host: "example.com",
				Path: "/foo",
			},
			Header: http.Header{
				"X-Forwarded-Proto": {"https"},
			},
		},
	}

	u := parseURL(req)
	require.NotNil(t, u)
	assert.Equal(t, "https", u.Scheme)
	assert.Equal(t, "example.com", u.Host)
	assert.Equal(t, "/foo", u.Path)
}

func TestParseURLDefaultScheme(t *testing.T) {
	req := &Request{
		Request: http.Request{
			URL: &url.URL{
				Host: "example.com",
				Path: "/foo",
			},
			Header: http.Header{},
		},
	}

	u := parseURL(req)
	require.NotNil(t, u)
	assert.Equal(t, "http", u.Scheme)
}

func TestGetStateFromCookie(t *testing.T) {
	state := &store.OIDCState{
		Status:     store.StatusTokenReady,
		OAuthState: "state-123",
	}

	stateBytes := store.ConvertToByte(state)

	req := &Request{
		Request: http.Request{
			Header: http.Header{
				"Cookie": {fmt.Sprintf("%s=%s", oauthTokenName, string(stateBytes))},
			},
			URL: &url.URL{},
		},
	}

	oidc := &OIDCConnect{}
	got, err := oidc.getStateFromCookie(req)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, state.OAuthState, got.OAuthState)
	assert.Equal(t, state.Status, got.Status)
}

func TestGetStateFromCookieMissing(t *testing.T) {
	oidc := &OIDCConnect{}
	req := &Request{
		Request: http.Request{
			Header: http.Header{},
			URL:    &url.URL{},
		},
	}

	_, err := oidc.getStateFromCookie(req)
	assert.Error(t, err)
}

func TestCreateResponseAllowFlag(t *testing.T) {
	okResp := createResponse(http.StatusOK)
	assert.True(t, okResp.Allow)
	assert.Equal(t, http.StatusOK, okResp.Response.StatusCode)

	unauthResp := createResponse(http.StatusUnauthorized)
	assert.False(t, unauthResp.Allow)
	assert.Equal(t, http.StatusUnauthorized, unauthResp.Response.StatusCode)
}
