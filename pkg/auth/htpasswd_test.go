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
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

func TestHtpasswdAuth(t *testing.T) {
	client := fake.NewClientBuilder().WithRuntimeObjects(
		// filtered by label selector
		&v1.Secret{
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
		&v1.Secret{
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
		&v1.Secret{
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
		&v1.Secret{
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

	selector, err := labels.Parse("auth.contour.snappcloud.io/type=basic")
	if err != nil {
		t.Fatalf("failed to parse selector: %s", err)
	}

	creds := &Creds{
		Map: make(map[string]map[string]*htpasswd.File),
		Mu:  &sync.RWMutex{},
	}

	auth := Htpasswd{
		Log:      logr.New(log.NullLogSink{}),
		Realm:    "default",
		Creds:    creds,
		Client:   client.Build(),
		Mu:       &sync.Mutex{},
		Selector: selector,
	}

	var namespaces = []string{"ns1", "notmatched"}
	for _, namespace := range namespaces {
		// only the namespace of the object being reconciled is used in reconcile loop.
		//nolint:lll
		_, err = auth.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: namespace}})
		assert.NoError(t, err, "reconciliation should not have failed")
	}

	assert.NotNil(t, auth.Creds.Map["ns1"], "reconcile loop should set a map for namespace \"ns1\"")
	//nolint:lll
	assert.True(t, auth.Match("example1", "example1", "ns1/example1"), "auth for \"example1:example1\" with secretRef \"ns1/example1\" should succeed")
	//nolint:lll
	assert.False(t, auth.Match("example1", "example1", "ns1/example2"), "auth for \"example1:example1\" with secretRef \"ns1/example2\" should fail")
	//nolint:lll
	assert.True(t, auth.Match("example2", "example2", "ns1/example2"), "auth for \"example2:example2\" with secretRef \"ns1/example2\" should succeed")
	//nolint:lll
	assert.False(t, auth.Match("example2", "example2", "ns1/example1"), "auth for \"example2:example2\" with secretRef \"ns1/example1\" should fail")
	//nolint:lll
	assert.False(t, auth.Match("notmatched", "notmatched", "notmatched/notmatched-label"), "auth for notmatched:notmatched should fail (filtered by label selector)")
	//nolint:lll
	assert.False(t, auth.Match("notmatched", "notmatched", "notmatched/notmatched-annotation"), "auth for notmatched:notmatched should fail (filtered by wrong annotation)")

	// Check an unauthorized response.
	response, err := auth.Check(context.TODO(), &Request{
		Request: http.Request{
			Header: http.Header{},
			URL:    &url.URL{},
		},
	})
	require.NoError(t, err, "check should not have failed")
	assert.Equal(t, http.StatusUnauthorized, response.Response.StatusCode)
	// Note that this isn't canonical as per CanonicalMIMEHeaderKey :-(
	assert.NotEmpty(t, response.Response.Header["WWW-Authenticate"]) //nolint:staticcheck

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
