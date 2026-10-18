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
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"github.com/tg123/go-htpasswd"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

const (
	// AnnotationAuthRealm marks Secrets that match our authentication realm.
	AnnotationAuthRealm = "auth.contour.snappcloud.io/realm"
	secretRefKey        = "secretRef"
)

// Htpasswd watches Secrets for htpasswd files and uses them for HTTP Basic Authentication.
type Htpasswd struct {
	Log           logr.Logger
	Realm         string
	Client        client.Client
	Creds         *Creds
	Mu            *sync.Mutex
	Selector      labels.Selector
	HealthChecker *HealthChecker
}

type Creds struct {
	Map map[string]map[string]*htpasswd.File
	Mu  *sync.RWMutex
}

// Match authenticates the credential against the htpasswd file.
func (h *Htpasswd) Match(user, pass, secretRef string) bool {
	return h.MatchContext(context.Background(), user, pass, secretRef)
}

// MatchContext authenticates the credential against the htpasswd file with context support.
// If the secret is not found in the local cache, it attempts to fetch and cache it dynamically.
func (h *Htpasswd) MatchContext(ctx context.Context, user, pass, secretRef string) bool {
	secretRef = strings.TrimSpace(secretRef)
	secretRefSlice := strings.Split(secretRef, "/")
	if len(secretRefSlice) != 2 {
		//nolint:lll
		h.Log.Info(fmt.Sprintf("secret reference \"%s\" in HTTPProxy auth context is invalid, it must be in the form of \"namespace/secretName\"", secretRef))
		return false
	}

	namespace := secretRefSlice[0]
	secretName := secretRefSlice[1]

	h.Creds.Mu.RLock()
	var passwd *htpasswd.File
	var found bool
	if nsMap, ok := h.Creds.Map[namespace]; ok {
		passwd, found = nsMap[secretName]
	}
	h.Creds.Mu.RUnlock()

	if !found && h.Client != nil {
		var err error
		passwd, err = h.fetchAndCacheSecret(ctx, namespace, secretName)
		if err == nil && passwd != nil {
			found = true
		}
	}

	if !found {
		//nolint:lll
		h.Log.Info(fmt.Sprintf("no HTTP basic authentication credential found for Secret reference \"%s\", make sure the Secret has compatible annotations and labels.", secretRef))
		return false
	}

	return passwd.Match(user, pass)
}

func (h *Htpasswd) fetchAndCacheSecret(ctx context.Context, namespace, name string) (*htpasswd.File, error) {
	if h.Client == nil {
		return nil, fmt.Errorf("k8s client is nil")
	}

	secret := &v1.Secret{}
	if err := h.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret); err != nil {
		return nil, err
	}

	if h.Selector != nil && !h.Selector.Matches(labels.Set(secret.GetLabels())) {
		return nil, fmt.Errorf("secret does not match selector")
	}

	isVerified, authData := h.verifyFetchSecretData(secret)
	if !isVerified {
		return nil, fmt.Errorf("secret verification failed")
	}

	hasBadLine := false
	passwd, err := htpasswd.NewFromReader(
		bytes.NewBuffer(authData),
		htpasswd.DefaultSystems,
		htpasswd.BadLineHandler(func(_ error) {
			hasBadLine = true
			h.Log.Info("skipping Secret with malformed htpasswd line syntax",
				"name", secret.Name, "namespace", secret.Namespace)
		}),
	)
	if err != nil {
		h.Log.Info("skipping Secret due to htpasswd scan error",
			"name", secret.Name, "namespace", secret.Namespace)
		return nil, err
	}
	if hasBadLine || passwd == nil {
		return nil, fmt.Errorf("malformed or empty htpasswd data")
	}

	h.Creds.Mu.Lock()
	if h.Creds.Map[namespace] == nil {
		h.Creds.Map[namespace] = make(map[string]*htpasswd.File)
	}
	h.Creds.Map[namespace][name] = passwd
	h.Creds.Mu.Unlock()

	h.Log.Info("dynamically loaded secret", "namespace", namespace, "name", name)
	return passwd, nil
}

// Check manages the HTTP basic authentication flow and return a response based on the authentication result.
func (h *Htpasswd) Check(ctx context.Context, request *Request) (*Response, error) {
	user, pass, ok := request.Request.BasicAuth()

	secretRef, found := request.Context[secretRefKey]
	if !found {
		//nolint:lll
		h.Log.Info(fmt.Sprintf("failed to find Secret reference key in HTTPProxy auth context of request with host=\"%s\" and path=\"%s\"", request.Request.URL.Host, request.Request.URL.Path))
	}

	// If there's an "Authorization" header and we can verify
	// it, succeed and inject some headers to tell the origin
	// what we did.
	if ok && found && h.MatchContext(ctx, user, pass, secretRef) {
		authorized := http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Auth-Handler":  {"htpasswd"},
				"Auth-Username": {user},
				"Auth-Realm":    {h.Realm},
			},
		}

		// // Reflect the authorization check context into the response headers.
		// for k, v := range request.Context {
		// 	key := fmt.Sprintf("Auth-Context-%s", k)
		// 	key = http.CanonicalHeaderKey(key) // XXX(jpeach) this will not transform invalid characters

		// 	authorized.Header.Add(key, v)
		// }

		return &Response{
			Allow:    true,
			Response: authorized,
		}, nil
	}

	// If there's no "Authorization" header, or the authentication
	// failed, send an authenticate request.
	unauthorizedHeader := make(http.Header)
	unauthorizedHeader.Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s", charset="UTF-8"`, h.Realm))

	return &Response{
		Allow: false,
		Response: http.Response{
			StatusCode: http.StatusUnauthorized,
			Header:     unauthorizedHeader,
		},
	}, nil
}

func (h *Htpasswd) verifyFetchSecretData(secret *v1.Secret) (bool, []byte) {
	// Accept the secret if it is for our realm or for any realm.
	if realm := secret.Annotations[AnnotationAuthRealm]; realm != "" {
		if realm != h.Realm && realm != "*" {
			return false, nil
		}
	}

	// Check for the "auth" key, which is the format used by ingress-nginx.
	authData, ok := secret.Data["auth"]
	if !ok {
		h.Log.Info("skipping Secret without \"auth\" key in data", "name", secret.Name, "namespace", secret.Namespace)
		return false, nil
	}

	return true, authData
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (h *Htpasswd) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var opts []client.ListOption

	// restricts the list operation to the given namespace
	if req.Namespace != "" {
		opts = append(opts, client.InNamespace(req.Namespace))
	}

	if h.Selector != nil {
		opts = append(opts, client.MatchingLabelsSelector{Selector: h.Selector})
	}

	secrets := &v1.SecretList{}
	if err := h.Client.List(ctx, secrets, opts...); err != nil {
		return ctrl.Result{}, err
	}

	newSecretPasswdMap := make(map[string]*htpasswd.File)

	for _, secret := range secrets.Items {
		// avoid implicit memory aliasing in for loop
		s := secret

		isVerified, authData := h.verifyFetchSecretData(&s)
		if !isVerified {
			continue
		}

		hasBadLine := false

		passwd, err := htpasswd.NewFromReader(
			bytes.NewBuffer(authData),
			htpasswd.DefaultSystems,
			htpasswd.BadLineHandler(func(_ error) {
				hasBadLine = true
				h.Log.Info("skipping Secret with malformed htpasswd line syntax",
					"name", s.Name, "namespace", s.Namespace)
			}),
		)
		if err != nil {
			h.Log.Info("skipping Secret due to htpasswd scan error",
				"name", s.Name, "namespace", s.Namespace)
			continue
		}

		if hasBadLine {
			continue
		}

		if passwd == nil {
			h.Log.Info("skipping Secret with empty credentials",
				"name", s.Name, "namespace", s.Namespace)
			continue
		}

		newSecretPasswdMap[s.Name] = passwd
	}

	h.Creds.Mu.Lock()
	if req.Namespace != "" {
		h.Creds.Map[req.Namespace] = newSecretPasswdMap
	} else {
		for _, s := range secrets.Items {
			if passwd, ok := newSecretPasswdMap[s.Name]; ok {
				if h.Creds.Map[s.Namespace] == nil {
					h.Creds.Map[s.Namespace] = make(map[string]*htpasswd.File)
				}
				h.Creds.Map[s.Namespace][s.Name] = passwd
			}
		}
	}
	h.Creds.Mu.Unlock()

	// Mark as ready after successful reconciliation
	if h.HealthChecker != nil && !h.HealthChecker.IsReady() {
		h.Log.Info("initial secret reconciliation complete, marking service as ready")
		h.HealthChecker.SetReady()
	}

	return ctrl.Result{Requeue: false}, nil
}

// RegisterWithManager sets up the controller with the manager.
func (h *Htpasswd) RegisterWithManager(mgr ctrl.Manager) error {
	labelPredicate := predicate.Funcs{
		UpdateFunc: func(e event.UpdateEvent) bool {
			if h.Selector != nil {
				return h.Selector.Matches(labels.Set(e.ObjectNew.GetLabels())) ||
					h.Selector.Matches(labels.Set(e.ObjectOld.GetLabels()))
			}
			return true
		},
		CreateFunc: func(e event.CreateEvent) bool {
			if h.Selector != nil {
				return h.Selector.Matches(labels.Set(e.Object.GetLabels()))
			}
			return true
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if h.Selector != nil {
				return h.Selector.Matches(labels.Set(e.Object.GetLabels()))
			}
			return true
		},
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&v1.Secret{}, builder.WithPredicates(labelPredicate)).
		Complete(h)
}
