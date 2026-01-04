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
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/go-logr/logr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tg123/go-htpasswd"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func newTestHtpasswd(t *testing.T, secrets ...v1.Secret) *Htpasswd {
	t.Helper()

	objects := make([]runtime.Object, len(secrets))
	for i := range secrets {
		objects[i] = &secrets[i]
	}

	client := fake.NewClientBuilder().WithRuntimeObjects(objects...).Build()

	selector, err := labels.Parse("auth.contour.snappcloud.io/type=basic")
	require.NoError(t, err)

	creds := &Creds{
		Map: make(map[string]map[string]*htpasswd.File),
		Mu:  &sync.RWMutex{},
	}

	return &Htpasswd{
		Log:      logr.New(log.NullLogSink{}),
		Realm:    "default",
		Creds:    creds,
		Client:   client,
		Mu:       &sync.Mutex{},
		Selector: selector,
	}
}

func TestHtpasswdAuth(t *testing.T) {
	auth := newTestHtpasswd(t,
		// filtered by label selector
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "notmatched-label",
				Namespace: "notmatched",
				Annotations: map[string]string{
					AnnotationAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=notmatched, pass=notmatched
				"auth": []byte("notmatched:$apr1$4W6cRE66$iANZepJfRTrpk3OxlzxAC0"),
			},
		},
		// filtered by wrong annotation
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "notmatched-annotation",
				Namespace: "notmatched",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "wrong",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=notmatched, pass=notmatched
				"auth": []byte("notmatched:$apr1$4W6cRE66$iANZepJfRTrpk3OxlzxAC0"),
			},
		},
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "example1",
				Namespace: "ns1",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=example1, pass=example1
				"auth": []byte("example1:$apr1$WBCC5B.w$fUu8qiKG/rLdMs3OTy9gc0"),
			},
		},
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "example2",
				Namespace: "ns1",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=example2, pass=example2
				"auth": []byte("example2:$apr1$tVsjy2r7$67D.nLwdd6EKKQR5z3lJS0"),
			},
		},
	)

	namespaces := []string{"ns1", "notmatched"}
	for _, namespace := range namespaces {
		req := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace}}
		_, err := auth.Reconcile(context.Background(), req)
		assert.NoError(t, err, "reconciliation should not have failed")
	}

	assert.NotNil(t, auth.Creds.Map["ns1"], "reconcile loop should set a map for namespace \"ns1\"")
	assert.True(t, auth.Match("example1", "example1", "ns1/example1"))
	assert.False(t, auth.Match("example1", "example1", "ns1/example2"))
	assert.True(t, auth.Match("example2", "example2", "ns1/example2"))
	assert.False(t, auth.Match("example2", "example2", "ns1/example1"))
	assert.False(t, auth.Match("notmatched", "notmatched", "notmatched/notmatched-label"))
	assert.False(t, auth.Match("notmatched", "notmatched", "notmatched/notmatched-annotation"))

	// Check an unauthorized response.
	response, err := auth.Check(context.TODO(), &Request{
		Request: http.Request{
			Header: http.Header{},
			URL:    &url.URL{},
		},
	})
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, http.StatusUnauthorized, response.Response.StatusCode)
	assert.NotEmpty(t, response.Response.Header.Get("WWW-Authenticate"))

	// Check an authorized response.
	response, err = auth.Check(context.TODO(), &Request{
		Request: http.Request{
			Header: http.Header{
				"Authorization": {"Basic ZXhhbXBsZTE6ZXhhbXBsZTE="},
			},
			URL: &url.URL{},
		},
		Context: map[string]string{
			secretRefKey: "ns1/example1",
		},
	})
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, http.StatusOK, response.Response.StatusCode)
	assert.Equal(t, "example1", response.Response.Header.Get("Auth-Username"))
	assert.Equal(t, "default", response.Response.Header.Get("Auth-Realm"))
}

func TestHtpasswd_Match_InvalidSecretRef(t *testing.T) {
	auth := newTestHtpasswd(t)

	tests := []struct {
		name      string
		secretRef string
	}{
		{"empty", ""},
		{"no separator", "ns1example1"},
		{"too many separators", "ns1/example1/extra"},
		{"missing namespace", "/example1"},
		{"missing name", "ns1/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := auth.Match("user", "pass", tt.secretRef)
			assert.False(t, result)
		})
	}
}

func TestHtpasswd_Match_NonexistentSecret(t *testing.T) {
	auth := newTestHtpasswd(t)

	result := auth.Match("user", "pass", "nonexistent/secret")
	assert.False(t, result)
}

func TestHtpasswd_Check_MissingSecretRefContext(t *testing.T) {
	auth := newTestHtpasswd(t)

	response, err := auth.Check(context.TODO(), &Request{
		Request: http.Request{
			Header: http.Header{
				"Authorization": {"Basic dXNlcjpwYXNz"}, // user:pass
			},
			URL: &url.URL{},
		},
		Context: map[string]string{}, // missing secretRef
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, response.Response.StatusCode)
}

func TestHtpasswd_Check_WrongPassword(t *testing.T) {
	auth := newTestHtpasswd(t,
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-secret",
				Namespace: "test-ns",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=testuser, pass=testpass
				"auth": []byte("testuser:$apr1$tVsjy2r7$67D.nLwdd6EKKQR5z3lJS0"),
			},
		},
	)

	// Reconcile to load the secret
	_, err := auth.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "test-ns"},
	})
	require.NoError(t, err)

	// Try with wrong password
	response, err := auth.Check(context.TODO(), &Request{
		Request: http.Request{
			Header: http.Header{
				"Authorization": {"Basic dGVzdHVzZXI6d3JvbmdwYXNz"}, // testuser:wrongpass
			},
			URL: &url.URL{},
		},
		Context: map[string]string{
			secretRefKey: "test-ns/test-secret",
		},
	})

	require.NoError(t, err)
	assert.Equal(t, http.StatusUnauthorized, response.Response.StatusCode)
}

func TestHtpasswd_Reconcile_SecretWithoutAuthKey(t *testing.T) {
	auth := newTestHtpasswd(t,
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "no-auth-key",
				Namespace: "test-ns",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				"other-key": []byte("some data"),
			},
		},
	)

	_, err := auth.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "test-ns"},
	})
	require.NoError(t, err)

	// Should not find the secret since it doesn't have "auth" key
	result := auth.Match("user", "pass", "test-ns/no-auth-key")
	assert.False(t, result)
}

func TestHtpasswd_Reconcile_MalformedHtpasswd(t *testing.T) {
	auth := newTestHtpasswd(t,
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "malformed",
				Namespace: "test-ns",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				"auth": []byte("this is not valid htpasswd format"),
			},
		},
	)

	_, err := auth.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "test-ns"},
	})
	require.NoError(t, err)

	// Ensure malformed secret is not stored
	nsCreds, ok := auth.Creds.Map["test-ns"]
	require.True(t, ok)
	_, exists := nsCreds["malformed"]
	assert.False(t, exists)

	// Should not find the secret since it's malformed
	result := auth.Match("this", "is", "test-ns/malformed")
	assert.False(t, result)
}

func TestHtpasswd_ConcurrentAccess(t *testing.T) {
	auth := newTestHtpasswd(t,
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "concurrent-test",
				Namespace: "test-ns",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// user=testuser, pass=testpass
				"auth": []byte("testuser:$apr1$WBCC5B.w$fUu8qiKG/rLdMs3OTy9gc0"),
			},
		},
	)

	// Initial reconcile
	_, err := auth.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "test-ns"},
	})
	require.NoError(t, err)

	// Run concurrent Match and Reconcile operations
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			auth.Match("testuser", "testuser", "test-ns/concurrent-test")
		}()

		go func() {
			defer wg.Done()
			_, _ = auth.Reconcile(context.Background(), ctrl.Request{
				NamespacedName: types.NamespacedName{Namespace: "test-ns"},
			})
		}()
	}

	wg.Wait()
}

func TestHtpasswd_MultipleUsersInSecret(t *testing.T) {
	auth := newTestHtpasswd(t,
		v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "multi-user",
				Namespace: "test-ns",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "*",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				// Multiple users in htpasswd format
				"auth": []byte("user1:$apr1$WBCC5B.w$fUu8qiKG/rLdMs3OTy9gc0\nuser2:$apr1$tVsjy2r7$67D.nLwdd6EKKQR5z3lJS0"),
			},
		},
	)

	_, err := auth.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "test-ns"},
	})
	require.NoError(t, err)

	// Both users should work with correct passwords
	assert.True(t, auth.Match("user1", "example1", "test-ns/multi-user"))
	assert.True(t, auth.Match("user2", "example2", "test-ns/multi-user"))

	// Wrong passwords should fail
	assert.False(t, auth.Match("user1", "example2", "test-ns/multi-user"))
	assert.False(t, auth.Match("user2", "example1", "test-ns/multi-user"))
}

func TestHtpasswd_RealmMatching(t *testing.T) {
	client := fake.NewClientBuilder().WithRuntimeObjects(
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "realm-specific",
				Namespace: "test-ns",
				Labels:    map[string]string{"auth.contour.snappcloud.io/type": "basic"},
				Annotations: map[string]string{
					AnnotationAuthRealm: "specific-realm",
				},
			},
			Type: v1.SecretTypeOpaque,
			Data: map[string][]byte{
				"auth": []byte("user:$apr1$WBCC5B.w$fUu8qiKG/rLdMs3OTy9gc0"),
			},
		},
	).Build()

	selector, _ := labels.Parse("auth.contour.snappcloud.io/type=basic")

	// Create auth with different realm
	auth := &Htpasswd{
		Log:    logr.New(log.NullLogSink{}),
		Realm:  "different-realm",
		Client: client,
		Creds: &Creds{
			Map: make(map[string]map[string]*htpasswd.File),
			Mu:  &sync.RWMutex{},
		},
		Mu:       &sync.Mutex{},
		Selector: selector,
	}

	_, err := auth.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "test-ns"},
	})
	require.NoError(t, err)

	// Should not find the secret since realm doesn't match
	result := auth.Match("user", "example1", "test-ns/realm-specific")
	assert.False(t, result)

	// Now with matching realm
	auth.Realm = "specific-realm"
	_, err = auth.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "test-ns"},
	})
	require.NoError(t, err)

	result = auth.Match("user", "example1", "test-ns/realm-specific")
	assert.True(t, result)
}
