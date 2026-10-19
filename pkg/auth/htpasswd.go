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

	namespace, secretName := secretRefSlice[0], secretRefSlice[1]

	passwd, found := h.lookup(namespace, secretName)
	if !found && h.Client != nil {
		var err error
		if passwd, err = h.fetchAndCacheSecret(ctx, namespace, secretName); err != nil {
			h.Log.V(1).Info("on-demand Secret lookup failed",
				"namespace", namespace, "name", secretName, "reason", err.Error())
		} else {
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

// lookup returns the cached htpasswd file for the given Secret.
func (h *Htpasswd) lookup(namespace, name string) (*htpasswd.File, bool) {
	h.Creds.Mu.RLock()
	defer h.Creds.Mu.RUnlock()

	passwd, found := h.Creds.Map[namespace][name]
	return passwd, found
}

// fetchAndCacheSecret loads a single Secret from the informer cache and stores it in Creds.
// It holds h.Mu so it cannot interleave with Reconcile: otherwise a copy fetched here could be
// written back after Reconcile dropped a deleted or rotated Secret, keeping revoked credentials valid.
func (h *Htpasswd) fetchAndCacheSecret(ctx context.Context, namespace, name string) (*htpasswd.File, error) {
	h.Mu.Lock()
	defer h.Mu.Unlock()

	// Another request or Reconcile may have loaded it while we waited for the lock.
	if passwd, found := h.lookup(namespace, name); found {
		return passwd, nil
	}

	secret := &v1.Secret{}
	if err := h.Client.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, secret); err != nil {
		return nil, err
	}

	if h.Selector != nil && !h.Selector.Matches(labels.Set(secret.GetLabels())) {
		return nil, fmt.Errorf("secret does not match selector")
	}

	passwd, ok := h.parseSecret(secret)
	if !ok {
		return nil, fmt.Errorf("secret has no usable htpasswd data")
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

// parseSecret checks the Secret against our realm and parses its htpasswd data.
// Parse errors are not logged since they may echo credential lines.
func (h *Htpasswd) parseSecret(s *v1.Secret) (*htpasswd.File, bool) {
	isVerified, authData := h.verifyFetchSecretData(s)
	if !isVerified {
		return nil, false
	}

	hasBadLine := false

	passwd, err := htpasswd.NewFromReader(
		bytes.NewBuffer(authData),
		htpasswd.DefaultSystems,
		htpasswd.BadLineHandler(func(_ error) {
			hasBadLine = true
		}),
	)
	if err != nil {
		h.Log.Info("skipping Secret due to htpasswd scan error",
			"name", s.Name, "namespace", s.Namespace)
		return nil, false
	}

	if hasBadLine {
		h.Log.Info("skipping Secret with malformed htpasswd line syntax",
			"name", s.Name, "namespace", s.Namespace)
		return nil, false
	}

	if passwd == nil {
		h.Log.Info("skipping Secret with empty credentials",
			"name", s.Name, "namespace", s.Namespace)
		return nil, false
	}

	return passwd, true
}

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (h *Htpasswd) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	// restricts the list operation to the given namespace
	opts := []client.ListOption{client.InNamespace(req.Namespace)}

	if h.Selector != nil {
		opts = append(opts, client.MatchingLabelsSelector{Selector: h.Selector})
	}

	// Serialize with fetchAndCacheSecret, see there.
	h.Mu.Lock()
	defer h.Mu.Unlock()

	secrets := &v1.SecretList{}
	if err := h.Client.List(ctx, secrets, opts...); err != nil {
		return ctrl.Result{}, err
	}

	newSecretPasswdMap := make(map[string]*htpasswd.File)

	for i := range secrets.Items {
		s := &secrets.Items[i]

		if passwd, ok := h.parseSecret(s); ok {
			newSecretPasswdMap[s.Name] = passwd
		}
	}

	h.Creds.Mu.Lock()
	h.Creds.Map[req.Namespace] = newSecretPasswdMap
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
