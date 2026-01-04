# Testing Contour Auth Multi-Tenant on OpenShift OKD4

This document provides comprehensive test cases for validating the contour-auth-multi-tenant service on OpenShift OKD4 clusters.

## Prerequisites

1. An OKD4 cluster (v4.12+)
2. Contour ingress controller installed
3. `oc` CLI configured with cluster access
4. `htpasswd` utility for generating credentials

## Setup

### 1. Deploy the Auth Server

```bash
# Create namespace
oc new-project contour-auth

# Apply the kustomization
oc apply -k config/htpasswd/
```

### 2. Create Test Secret with htpasswd Credentials

```bash
# Generate htpasswd file
htpasswd -bc auth testuser testpass123
htpasswd -b auth admin adminpass456

# Create secret with proper labels and annotations
oc create secret generic test-htpasswd \
  --from-file=auth \
  -n test-app \
  --dry-run=client -o yaml | \
oc label --local -f - auth.contour.snappcloud.io/type=basic --dry-run=client -o yaml | \
oc annotate --local -f - auth.contour.snappcloud.io/realm="*" --dry-run=client -o yaml | \
oc apply -f -
```

---

## Test Cases

### TC-01: Basic Authentication - Valid Credentials

**Objective:** Verify that valid credentials are accepted.

**Steps:**
1. Deploy a test application behind Contour HTTPProxy with external auth
2. Send a request with valid Basic auth credentials
3. Verify access is granted

**Commands:**
```bash
# Create test namespace and app
oc new-project test-app
oc create deployment nginx --image=nginx:alpine -n test-app
oc expose deployment nginx --port=80 -n test-app

# Create HTTPProxy with auth (replace YOUR_DOMAIN)
cat <<EOF | oc apply -f -
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: test-proxy
  namespace: test-app
spec:
  virtualhost:
    fqdn: test-app.apps.YOUR_DOMAIN
  routes:
  - conditions:
    - prefix: /
    services:
    - name: nginx
      port: 80
    authPolicy:
      context:
        secretRef: test-app/test-htpasswd
EOF

# Test with valid credentials
curl -v -u testuser:testpass123 https://test-app.apps.YOUR_DOMAIN/
```

**Expected Result:** HTTP 200 OK with Auth-Username header set to "testuser"

---

### TC-02: Basic Authentication - Invalid Credentials

**Objective:** Verify that invalid credentials are rejected.

**Commands:**
```bash
# Test with wrong password
curl -v -u testuser:wrongpassword https://test-app.apps.YOUR_DOMAIN/

# Test with non-existent user
curl -v -u fakeuser:anypassword https://test-app.apps.YOUR_DOMAIN/
```

**Expected Result:** HTTP 401 Unauthorized with WWW-Authenticate header

---

### TC-03: Basic Authentication - No Credentials

**Objective:** Verify that missing credentials trigger authentication request.

**Commands:**
```bash
# Test without credentials
curl -v https://test-app.apps.YOUR_DOMAIN/
```

**Expected Result:** HTTP 401 Unauthorized with WWW-Authenticate header containing realm

---

### TC-04: Secret Reference Validation

**Objective:** Verify proper handling of invalid secret references.

**Steps:**
1. Create HTTPProxy with non-existent secret reference
2. Attempt authentication

**Commands:**
```bash
cat <<EOF | oc apply -f -
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: bad-ref-proxy
  namespace: test-app
spec:
  virtualhost:
    fqdn: bad-ref.apps.YOUR_DOMAIN
  routes:
  - conditions:
    - prefix: /
    services:
    - name: nginx
      port: 80
    authPolicy:
      context:
        secretRef: nonexistent/secret
EOF

curl -v -u testuser:testpass123 https://bad-ref.apps.YOUR_DOMAIN/
```

**Expected Result:** HTTP 401 Unauthorized (secret not found)

---

### TC-05: Multi-Namespace Isolation

**Objective:** Verify secrets are isolated by namespace.

**Steps:**
1. Create secrets with same name in different namespaces
2. Verify users can only authenticate against their namespace's secret

**Commands:**
```bash
# Create second namespace
oc new-project test-app-2

# Create secret in test-app-2 with different user
htpasswd -bc auth user2 user2pass
oc create secret generic test-htpasswd \
  --from-file=auth \
  -n test-app-2

oc label secret test-htpasswd auth.contour.snappcloud.io/type=basic -n test-app-2
oc annotate secret test-htpasswd auth.contour.snappcloud.io/realm="*" -n test-app-2

# Try test-app credentials on test-app-2 route
curl -v -u testuser:testpass123 https://test-app-2-route.apps.YOUR_DOMAIN/
```

**Expected Result:** HTTP 401 (test-app credentials not valid for test-app-2 namespace)

---

### TC-06: Realm-Based Filtering

**Objective:** Verify realm-based secret filtering.

**Commands:**
```bash
# Create secret with specific realm
htpasswd -bc auth realmuser realmpass
oc create secret generic realm-secret \
  --from-file=auth \
  -n test-app

oc label secret realm-secret auth.contour.snappcloud.io/type=basic -n test-app
oc annotate secret realm-secret auth.contour.snappcloud.io/realm=specific-realm -n test-app

# Deploy auth server with different realm
# The secret should be ignored by auth server with "default" realm
```

**Expected Result:** Secret with specific realm is only used when auth server realm matches

---

### TC-07: Secret Update Propagation

**Objective:** Verify that secret updates are detected and applied.

**Commands:**
```bash
# Update the secret with new user
htpasswd -bc auth newuser newpass123
oc create secret generic test-htpasswd \
  --from-file=auth \
  -n test-app \
  --dry-run=client -o yaml | oc apply -f -

# Wait for reconciliation (controller watches secrets)
sleep 5

# Test with new user
curl -v -u newuser:newpass123 https://test-app.apps.YOUR_DOMAIN/
```

**Expected Result:** New credentials are accepted after secret update

---

### TC-08: Secret Deletion Handling

**Objective:** Verify that deleted secrets are removed from cache.

**Commands:**
```bash
# Delete the secret
oc delete secret test-htpasswd -n test-app

# Wait for reconciliation
sleep 5

# Attempt authentication
curl -v -u testuser:testpass123 https://test-app.apps.YOUR_DOMAIN/
```

**Expected Result:** HTTP 401 (secret no longer available)

---

### TC-09: TLS/mTLS Configuration

**Objective:** Verify TLS termination works correctly.

**Commands:**
```bash
# Check if auth server is running with TLS
oc get pods -n contour-auth -o jsonpath='{.items[*].spec.containers[*].args}'

# Verify certificate is valid
oc get secret -n contour-auth -o jsonpath='{.items[*].data.tls\.crt}' | base64 -d | openssl x509 -text -noout
```

**Expected Result:** Valid TLS certificate with proper subject and expiry

---

### TC-10: High Availability - Pod Restart

**Objective:** Verify service continuity during pod restart.

**Commands:**
```bash
# Start continuous requests in background
while true; do curl -s -o /dev/null -w "%{http_code}\n" -u testuser:testpass123 https://test-app.apps.YOUR_DOMAIN/; sleep 0.5; done &

# Delete auth pod
oc delete pod -l app=contour-auth -n contour-auth

# Watch for errors in background job
```

**Expected Result:** Brief interruption (< 30s) then service resumes

---

### TC-11: Concurrent Authentication Requests

**Objective:** Verify handling of concurrent authentication requests.

**Commands:**
```bash
# Run 100 concurrent requests
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}" -u testuser:testpass123 https://test-app.apps.YOUR_DOMAIN/ &
done
wait

# Check auth server logs for errors
oc logs -l app=contour-auth -n contour-auth --tail=100
```

**Expected Result:** All requests return 200, no errors in logs

---

### TC-12: Label Selector Filtering

**Objective:** Verify that only secrets matching the label selector are processed.

**Commands:**
```bash
# Create secret without required label
oc create secret generic unlabeled-secret \
  --from-literal=auth="$(htpasswd -nb unlabeled unlabeledpass)" \
  -n test-app

oc annotate secret unlabeled-secret auth.contour.snappcloud.io/realm="*" -n test-app
# Note: NOT adding the label

# Try to authenticate
curl -v -u unlabeled:unlabeledpass https://test-app.apps.YOUR_DOMAIN/
```

**Expected Result:** HTTP 401 (secret not processed due to missing label)

---

### TC-13: Malformed htpasswd File

**Objective:** Verify graceful handling of malformed htpasswd data.

**Commands:**
```bash
# Create secret with invalid htpasswd content
oc create secret generic malformed-htpasswd \
  --from-literal=auth="this is not valid htpasswd format" \
  -n test-app

oc label secret malformed-htpasswd auth.contour.snappcloud.io/type=basic -n test-app
oc annotate secret malformed-htpasswd auth.contour.snappcloud.io/realm="*" -n test-app

# Check logs for error handling
oc logs -l app=contour-auth -n contour-auth | grep -i malformed
```

**Expected Result:** Error logged, malformed secret skipped, service continues operating

---

### TC-14: Resource Limits and OOM

**Objective:** Verify auth server operates within resource limits.

**Commands:**
```bash
# Check current resource usage
oc adm top pod -n contour-auth

# Check resource limits
oc get deployment contour-auth -n contour-auth -o jsonpath='{.spec.template.spec.containers[*].resources}'

# Generate load and monitor
for i in {1..1000}; do
  curl -s -o /dev/null -u testuser:testpass123 https://test-app.apps.YOUR_DOMAIN/ &
done
wait

oc adm top pod -n contour-auth
```

**Expected Result:** Memory and CPU stay within limits

---

### TC-15: Metrics Endpoint

**Objective:** Verify metrics are exposed correctly.

**Commands:**
```bash
# Port-forward to metrics endpoint
oc port-forward -n contour-auth svc/contour-auth-metrics 8080:8080 &

# Fetch metrics
curl http://localhost:8080/metrics | grep -E "^(go_|process_|workqueue_)"
```

**Expected Result:** Prometheus metrics exposed

---

## OIDC Test Cases (if using OIDC mode)

### TC-OIDC-01: OIDC Provider Configuration

**Objective:** Verify OIDC provider is correctly configured.

**Steps:**
1. Create OIDC config file
2. Deploy auth server in OIDC mode
3. Verify redirect to IDP

**Config Example:**
```yaml
issuerURL: https://keycloak.apps.YOUR_DOMAIN/realms/master
clientID: contour-auth
clientSecret: your-client-secret
redirectURL: https://app.apps.YOUR_DOMAIN
redirectPath: /callback
scopes:
  - openid
  - profile
  - email
```

---

### TC-OIDC-02: OAuth Flow - Login Redirect

**Commands:**
```bash
# Access protected resource
curl -v https://app.apps.YOUR_DOMAIN/protected
```

**Expected Result:** HTTP 302 redirect to OIDC provider login page

---

### TC-OIDC-03: OAuth Callback Handling

**Objective:** Verify callback handling after IDP authentication.

**Expected Result:** User redirected back to original URL with state token

---

## Cleanup

```bash
# Remove test resources
oc delete project test-app test-app-2

# Remove auth server (if needed)
oc delete -k config/htpasswd/
```

## Troubleshooting

### Common Issues

1. **401 on all requests**
   - Check secret has correct labels and annotations
   - Verify auth server logs for reconciliation errors
   - Confirm HTTPProxy authPolicy.context.secretRef format

2. **Connection refused**
   - Check auth server pod is running
   - Verify service is correctly configured
   - Check Envoy cluster configuration for ext_authz

3. **Slow authentication**
   - Check resource limits
   - Verify network policies allow traffic
   - Check for high reconciliation frequency

### Useful Debug Commands

```bash
# Check auth server logs
oc logs -f -l app=contour-auth -n contour-auth

# Check Envoy configuration
oc exec -n projectcontour deploy/envoy -- curl -s localhost:9001/config_dump | jq '.configs[] | select(.["@type"] | contains("ext_authz"))'

# Check secret reconciliation
oc describe secret test-htpasswd -n test-app
```

