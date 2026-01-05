# Testing contour-auth-multi-tenant on OpenShift OKD4

This document provides step-by-step test cases to verify the functionality of the contour-auth-multi-tenant application deployed on OpenShift OKD4.

---

## Configuration (Set These First!)

**Copy and customize these variables before running any commands:**

```bash
#############################################
# REQUIRED: Customize these for your cluster
#############################################

# Your cluster's apps domain (e.g., apps.okd4.example.com)
export APPS_DOMAIN="apps.okd4.example.com"

# Auth server instance name (from Helm values)
export INSTANCE_NAME="private"

# Auth server namespace (where authserver is deployed)
export AUTH_NAMESPACE="snappcloud-ingress"

# Test application namespace (will be created)
export TEST_NAMESPACE="authserver-test"

# Test application hostname prefix
export TEST_HOST_PREFIX="echo-auth-test"

# TLS secret for HTTPProxy (namespace/name format)
export TLS_SECRET="openshift-ingress/letsencrypt"

# Ingress class name
export INGRESS_CLASS="private"

# Secret label selector (must match authserver --selector flag)
export SECRET_LABEL="auth.contour.snappcloud.io/type=basic"

#############################################
# OPTIONAL: Test credentials (change if desired)
#############################################

export TEST_USER="testuser"
export TEST_PASS="testpass123"
export ADMIN_USER="admin"
export ADMIN_PASS="adminpass456"

#############################################
# DERIVED: Auto-calculated (don't change)
#############################################

export DEPLOYMENT_NAME="${INSTANCE_NAME}-authserver-htpasswd"
export SERVICE_NAME="${INSTANCE_NAME}-authserver-htpasswd"
export TLS_SECRET_NAME="${INSTANCE_NAME}-authserver-htpasswd-cert"
export APP_HOST="${TEST_HOST_PREFIX}.${APPS_DOMAIN}"
export PROTO="https"
```

### Verify Configuration

```bash
echo "========================================="
echo "Configuration Summary:"
echo "========================================="
echo "Apps Domain:      ${APPS_DOMAIN}"
echo "Instance Name:    ${INSTANCE_NAME}"
echo "Auth Namespace:   ${AUTH_NAMESPACE}"
echo "Test Namespace:   ${TEST_NAMESPACE}"
echo "Test Host:        ${APP_HOST}"
echo "TLS Secret:       ${TLS_SECRET}"
echo "Ingress Class:    ${INGRESS_CLASS}"
echo "Secret Label:     ${SECRET_LABEL}"
echo "Deployment:       ${DEPLOYMENT_NAME}"
echo "========================================="
```

---

## Deployment Overview

The auth server is deployed via Helm chart with the following naming convention:
- **Namespace:** `${AUTH_NAMESPACE}`
- **Deployment:** `${INSTANCE_NAME}-authserver-htpasswd`
- **Service:** `${INSTANCE_NAME}-authserver-htpasswd`
- **TLS Secret:** `${INSTANCE_NAME}-authserver-htpasswd-cert`

Each instance uses a label selector (`--selector`) to filter which Secrets it watches.

## Prerequisites

- OpenShift OKD4 cluster access with `oc` CLI configured
- Contour/Envoy deployed and configured for external authorization
- The auth server deployed via Helm chart
- `htpasswd` command available (from `httpd-tools` or `apache2-utils` package)

---

## Part 0: Deploy Sample Test Application

### 0.1 Create Test Namespace

```bash
# Create dedicated test namespace
oc create namespace ${TEST_NAMESPACE}

# Verify namespace created
oc get namespace ${TEST_NAMESPACE}
```

### 0.2 Deploy Echo Server Application

We'll use a simple echo server that returns request information. Note: OpenShift runs containers as non-root, so we use port 8080.

```bash
# Deploy echo server (using port 8080 for OpenShift compatibility)
cat <<EOF | oc apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-server
  namespace: ${TEST_NAMESPACE}
  labels:
    app: echo-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo-server
  template:
    metadata:
      labels:
        app: echo-server
    spec:
      containers:
      - name: echo-server
        image: ealen/echo-server:latest
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: PORT
          value: "8080"
        resources:
          limits:
            cpu: 100m
            memory: 128Mi
          requests:
            cpu: 50m
            memory: 64Mi
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          seccompProfile:
            type: RuntimeDefault
          capabilities:
            drop:
            - ALL
---
apiVersion: v1
kind: Service
metadata:
  name: echo-server
  namespace: ${TEST_NAMESPACE}
  labels:
    app: echo-server
spec:
  ports:
  - port: 80
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: echo-server
  type: ClusterIP
EOF

# Wait for deployment to be ready
oc rollout status deployment/echo-server -n ${TEST_NAMESPACE} --timeout=60s

# Verify pod is running
oc get pods -n ${TEST_NAMESPACE} -l app=echo-server
```

### 0.3 Create htpasswd Secret for Testing

```bash
# Create htpasswd file with test users
htpasswd -cbB /tmp/htpasswd ${TEST_USER} ${TEST_PASS}
htpasswd -bB /tmp/htpasswd ${ADMIN_USER} ${ADMIN_PASS}

# Create secret from file
oc create secret generic echo-server-basic-auth \
  --from-file=auth=/tmp/htpasswd \
  -n ${TEST_NAMESPACE}

# Add required labels and annotations
oc label secret echo-server-basic-auth -n ${TEST_NAMESPACE} \
  ${SECRET_LABEL}

oc annotate secret echo-server-basic-auth -n ${TEST_NAMESPACE} \
  auth.contour.snappcloud.io/realm="*"

# Verify secret
oc get secret echo-server-basic-auth -n ${TEST_NAMESPACE} --show-labels

# Clean up temp file
rm /tmp/htpasswd
```

### 0.4 Create HTTPProxy with External Authorization

> **Note:** Contour requires TLS termination for HTTPProxy with External Authorization.

```bash
# Create HTTPProxy with TLS and External Auth
cat <<EOF | oc apply -f -
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: echo-server-auth
  namespace: ${TEST_NAMESPACE}
spec:
  virtualhost:
    fqdn: ${APP_HOST}
    tls:
      secretName: ${TLS_SECRET}
    authorization:
      extensionRef:
        name: ${DEPLOYMENT_NAME}
        namespace: ${AUTH_NAMESPACE}
      authPolicy:
        context:
          secretRef: ${TEST_NAMESPACE}/echo-server-basic-auth
  ingressClassName: ${INGRESS_CLASS}
  routes:
  - conditions:
    - prefix: /
    services:
    - name: echo-server
      port: 80
EOF

# Verify HTTPProxy status
oc get httpproxy echo-server-auth -n ${TEST_NAMESPACE}

# Check HTTPProxy is valid
oc get httpproxy echo-server-auth -n ${TEST_NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Valid")].status}'
echo  # newline
# Expected: True
```

### 0.5 Verify Setup

```bash
# Check all resources are created
oc get all -n ${TEST_NAMESPACE}

# Check HTTPProxy status
oc get httpproxy -n ${TEST_NAMESPACE} echo-server-auth

# Check HTTPProxy conditions
oc get httpproxy echo-server-auth -n ${TEST_NAMESPACE} -o jsonpath='{range .status.conditions[*]}{.type}: {.status}{"\n"}{end}'

# Check secret exists with correct labels
oc get secret echo-server-basic-auth -n ${TEST_NAMESPACE} --show-labels

# Quick test
curl -v ${PROTO}://${APP_HOST}/
# Expected: 401 Unauthorized

curl -v -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/
# Expected: 200 OK
```

---

## Part 1: Deployment Health Checks

### 1.1 Verify Auth Server Pod Status

**Objective:** Confirm the auth server pod is running.

```bash
# Check pod status
oc get pods -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME}

# Expected output:
# NAME                                            READY   STATUS    RESTARTS   AGE
# ${DEPLOYMENT_NAME}-xxxxxxxx-xxxxx               1/1     Running   0          5m

# Check pod details if not running
oc describe pod -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME}
```

### 1.2 Verify Startup Logs

**Objective:** Confirm the auth server started correctly.

```bash
# Check startup logs
oc logs -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME} --tail=30

# Expected log messages:
# - "started authorization server" with address=:9443
# - "started controller"
# - No error messages about TLS or configuration
```

### 1.3 Verify Service Endpoint

**Objective:** Confirm the service has healthy endpoints.

```bash
# Check service
oc get svc ${SERVICE_NAME} -n ${AUTH_NAMESPACE}

# Check endpoints (should have pod IP)
oc get endpoints ${SERVICE_NAME} -n ${AUTH_NAMESPACE}

# Expected: Should show pod IP:9443
```

### 1.4 Verify Secret Reconciliation

**Objective:** Confirm controller picked up the test secret.

```bash
# Check logs for secret reconciliation
oc logs -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME} --tail=50 | \
  grep -i "${TEST_NAMESPACE}\|echo-server"

# No errors should appear for our test secret
```

---

## Part 2: Authentication Flow Tests

### 2.1 Test Unauthenticated Request (Expect 401)

**Objective:** Verify requests without credentials receive 401.

```bash
# Make request without credentials
curl -v ${PROTO}://${APP_HOST}/

# Expected Response:
# < HTTP/1.1 401 Unauthorized
# < www-authenticate: Basic realm="default", charset="UTF-8"

# Quick check (just status code)
echo "Status: $(curl -s -o /dev/null -w '%{http_code}' ${PROTO}://${APP_HOST}/)"
# Expected: Status: 401
```

### 2.2 Test Valid Credentials - testuser (Expect 200)

**Objective:** Verify correct credentials allow access.

```bash
# Make request with valid testuser credentials
curl -v -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/

# Expected Response:
# < HTTP/1.1 200 OK
# < auth-handler: htpasswd
# < auth-username: testuser
# < auth-realm: default

# Quick check
echo "Status: $(curl -s -o /dev/null -w '%{http_code}' -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/)"
# Expected: Status: 200
```

### 2.3 Test Valid Credentials - admin (Expect 200)

**Objective:** Verify second user works.

```bash
# Make request with admin credentials
curl -s -o /dev/null -w "Status: %{http_code}\n" -u ${ADMIN_USER}:${ADMIN_PASS} ${PROTO}://${APP_HOST}/

# Expected: Status: 200
```

### 2.4 Test Invalid Password (Expect 401)

**Objective:** Verify wrong passwords are rejected.

```bash
# Make request with wrong password
curl -s -o /dev/null -w "Status: %{http_code}\n" -u ${TEST_USER}:wrongpassword ${PROTO}://${APP_HOST}/

# Expected: Status: 401
```

### 2.5 Test Non-existent User (Expect 401)

**Objective:** Verify unknown users are rejected.

```bash
# Make request with non-existent user
curl -s -o /dev/null -w "Status: %{http_code}\n" -u fakeuser:anypassword ${PROTO}://${APP_HOST}/

# Expected: Status: 401
```

### 2.6 Test Cross-User Password (Expect 401)

**Objective:** Verify user A's password doesn't work for user B.

```bash
# Use testuser's password with admin username
curl -s -o /dev/null -w "Status: %{http_code}\n" -u ${ADMIN_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/

# Expected: Status: 401
```

### 2.7 Verify Auth Headers in Response

**Objective:** Check auth server injects correct headers.

```bash
# Get response headers with valid auth
curl -s -u ${TEST_USER}:${TEST_PASS} -D - ${PROTO}://${APP_HOST}/ -o /dev/null | \
  grep -iE "auth-handler|auth-username|auth-realm"

# Expected:
# auth-handler: htpasswd
# auth-username: testuser
# auth-realm: default
```

---

## Part 3: Hot Reload Tests

### 3.1 Add New User Without Restart

**Objective:** Verify new users are recognized without pod restart.

```bash
# Get current pod name for later comparison
OLD_POD=$(oc get pods -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME} -o jsonpath='{.items[0].metadata.name}')
echo "Current pod: ${OLD_POD}"

# Create updated htpasswd with new user
htpasswd -cbB /tmp/htpasswd ${TEST_USER} ${TEST_PASS}
htpasswd -bB /tmp/htpasswd ${ADMIN_USER} ${ADMIN_PASS}
htpasswd -bB /tmp/htpasswd newuser newpass789

# Update the secret
oc create secret generic echo-server-basic-auth \
  --from-file=auth=/tmp/htpasswd \
  -n ${TEST_NAMESPACE} \
  --dry-run=client -o yaml | oc apply -f -

# Re-apply labels and annotations
oc label secret echo-server-basic-auth -n ${TEST_NAMESPACE} \
  ${SECRET_LABEL} --overwrite
oc annotate secret echo-server-basic-auth -n ${TEST_NAMESPACE} \
  auth.contour.snappcloud.io/realm="*" --overwrite

# Wait for reconciliation
sleep 5

# Verify pod was NOT restarted
NEW_POD=$(oc get pods -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME} -o jsonpath='{.items[0].metadata.name}')
echo "Pod after update: ${NEW_POD}"
if [ "${OLD_POD}" = "${NEW_POD}" ]; then
  echo "✅ Pod was NOT restarted (hot reload worked)"
else
  echo "⚠️  Pod was restarted"
fi

# Test new user
echo "New user test: $(curl -s -o /dev/null -w '%{http_code}' -u newuser:newpass789 ${PROTO}://${APP_HOST}/)"
# Expected: 200

# Verify original users still work
echo "testuser test: $(curl -s -o /dev/null -w '%{http_code}' -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/)"
# Expected: 200

rm /tmp/htpasswd
```

### 3.2 Change Password Without Restart

**Objective:** Verify password changes take effect.

```bash
# Create htpasswd with changed password for testuser
htpasswd -cbB /tmp/htpasswd ${TEST_USER} changedpass999
htpasswd -bB /tmp/htpasswd ${ADMIN_USER} ${ADMIN_PASS}
htpasswd -bB /tmp/htpasswd newuser newpass789

# Update secret
oc create secret generic echo-server-basic-auth \
  --from-file=auth=/tmp/htpasswd \
  -n ${TEST_NAMESPACE} \
  --dry-run=client -o yaml | oc apply -f -

oc label secret echo-server-basic-auth -n ${TEST_NAMESPACE} \
  ${SECRET_LABEL} --overwrite
oc annotate secret echo-server-basic-auth -n ${TEST_NAMESPACE} \
  auth.contour.snappcloud.io/realm="*" --overwrite

sleep 5

# Test old password fails
echo "Old password: $(curl -s -o /dev/null -w '%{http_code}' -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/)"
# Expected: 401

# Test new password works
echo "New password: $(curl -s -o /dev/null -w '%{http_code}' -u ${TEST_USER}:changedpass999 ${PROTO}://${APP_HOST}/)"
# Expected: 200

rm /tmp/htpasswd
```

### 3.3 Restore Original Credentials

```bash
# Restore original test credentials
htpasswd -cbB /tmp/htpasswd ${TEST_USER} ${TEST_PASS}
htpasswd -bB /tmp/htpasswd ${ADMIN_USER} ${ADMIN_PASS}

oc create secret generic echo-server-basic-auth \
  --from-file=auth=/tmp/htpasswd \
  -n ${TEST_NAMESPACE} \
  --dry-run=client -o yaml | oc apply -f -

oc label secret echo-server-basic-auth -n ${TEST_NAMESPACE} \
  ${SECRET_LABEL} --overwrite
oc annotate secret echo-server-basic-auth -n ${TEST_NAMESPACE} \
  auth.contour.snappcloud.io/realm="*" --overwrite

sleep 3

echo "Restored testuser: $(curl -s -o /dev/null -w '%{http_code}' -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/)"
# Expected: 200

rm /tmp/htpasswd
```

---

## Part 4: Error Handling Tests

### 4.1 Malformed htpasswd Format

**Objective:** Verify malformed secrets are skipped gracefully.

```bash
# Create secret with invalid htpasswd format
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: malformed-auth-test
  namespace: ${TEST_NAMESPACE}
  labels:
    ${SECRET_LABEL%%=*}: ${SECRET_LABEL##*=}
  annotations:
    auth.contour.snappcloud.io/realm: "*"
type: Opaque
stringData:
  auth: "this is completely invalid htpasswd format!!!"
EOF

sleep 3

# Check logs - should see warning about malformed secret
oc logs -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME} --tail=20 | \
  grep -i "malformed\|skipping\|error"

# Verify pod is still running
oc get pods -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME}
# Expected: 1/1 Running

# Verify original auth still works
echo "Auth still works: $(curl -s -o /dev/null -w '%{http_code}' -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/)"
# Expected: 200

# Cleanup
oc delete secret malformed-auth-test -n ${TEST_NAMESPACE}
```

### 4.2 Secret Missing "auth" Key

**Objective:** Verify secrets without "auth" key are skipped.

```bash
# Create secret with wrong key name
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: wrong-key-test
  namespace: ${TEST_NAMESPACE}
  labels:
    ${SECRET_LABEL%%=*}: ${SECRET_LABEL##*=}
  annotations:
    auth.contour.snappcloud.io/realm: "*"
type: Opaque
stringData:
  htpasswd: "user:\\\$apr1\\\$xyz\\\$hash"  # Wrong key! Should be "auth"
EOF

sleep 3

# Check logs
oc logs -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME} --tail=10 | \
  grep -i "without.*auth"

# Expected: Log message about skipping secret without "auth" key

# Cleanup
oc delete secret wrong-key-test -n ${TEST_NAMESPACE}
```

### 4.3 Secret Without Matching Labels

**Objective:** Verify secrets without correct labels are ignored.

```bash
# Create secret WITHOUT the required label
cat <<EOF | oc apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: unlabeled-auth-test
  namespace: ${TEST_NAMESPACE}
  # NO labels!
  annotations:
    auth.contour.snappcloud.io/realm: "*"
type: Opaque
stringData:
  auth: "unlabeled:\\\$apr1\\\$test\\\$hash"
EOF

sleep 3

# This user should NOT work (secret not picked up)
echo "Unlabeled secret user: $(curl -s -o /dev/null -w '%{http_code}' -u unlabeled:anypass ${PROTO}://${APP_HOST}/)"
# Expected: 401

# Cleanup
oc delete secret unlabeled-auth-test -n ${TEST_NAMESPACE}
```

---

## Part 5: Performance Tests

### 5.1 Concurrent Request Test

**Objective:** Verify auth server handles concurrent load.

```bash
# Run load test with curl (if ab not available)
echo "Running 100 concurrent requests..."
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/ &
done | sort | uniq -c

wait
# Expected: 100 requests with status 200

# Alternative with Apache Bench (if available)
# ab -n 500 -c 20 -A ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/
```

### 5.2 Resource Usage Check

**Objective:** Verify resource usage is within limits.

```bash
# Check current resource usage
oc adm top pod -n ${AUTH_NAMESPACE} -l app.kubernetes.io/name=${DEPLOYMENT_NAME}

# Expected: CPU and memory within configured limits
```

---

## Part 6: Cleanup

### 6.1 Remove Test Resources

```bash
# Delete test namespace and all resources
oc delete namespace ${TEST_NAMESPACE}

# Verify cleanup
oc get namespace ${TEST_NAMESPACE}
# Expected: Error from server (NotFound)
```

### 6.2 Keep Test Environment (Optional)

If you want to keep the test environment for future testing:

```bash
# Just remove test secrets, keep the app
oc delete secret malformed-auth-test wrong-key-test unlabeled-auth-test \
  -n ${TEST_NAMESPACE} --ignore-not-found

echo "Test environment preserved in namespace: ${TEST_NAMESPACE}"
```

---

## Quick Test Script

Save this as `quick-test.sh` for rapid validation:

```bash
#!/bin/bash
set -e

# Load configuration (source your env vars first!)
: "${APP_HOST:?APP_HOST not set}"
: "${TEST_USER:?TEST_USER not set}"
: "${TEST_PASS:?TEST_PASS not set}"
: "${PROTO:=https}"

echo "Testing auth server at: ${PROTO}://${APP_HOST}"
echo "========================================"

# Test 1: No auth (expect 401)
STATUS=$(curl -s -o /dev/null -w '%{http_code}' ${PROTO}://${APP_HOST}/)
if [ "$STATUS" = "401" ]; then
  echo "✅ Test 1 PASS: No auth returns 401"
else
  echo "❌ Test 1 FAIL: Expected 401, got $STATUS"
fi

# Test 2: Valid auth (expect 200)
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -u ${TEST_USER}:${TEST_PASS} ${PROTO}://${APP_HOST}/)
if [ "$STATUS" = "200" ]; then
  echo "✅ Test 2 PASS: Valid auth returns 200"
else
  echo "❌ Test 2 FAIL: Expected 200, got $STATUS"
fi

# Test 3: Wrong password (expect 401)
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -u ${TEST_USER}:wrongpass ${PROTO}://${APP_HOST}/)
if [ "$STATUS" = "401" ]; then
  echo "✅ Test 3 PASS: Wrong password returns 401"
else
  echo "❌ Test 3 FAIL: Expected 401, got $STATUS"
fi

# Test 4: Unknown user (expect 401)
STATUS=$(curl -s -o /dev/null -w '%{http_code}' -u unknownuser:anypass ${PROTO}://${APP_HOST}/)
if [ "$STATUS" = "401" ]; then
  echo "✅ Test 4 PASS: Unknown user returns 401"
else
  echo "❌ Test 4 FAIL: Expected 401, got $STATUS"
fi

# Test 5: Check auth headers
HEADERS=$(curl -s -u ${TEST_USER}:${TEST_PASS} -D - ${PROTO}://${APP_HOST}/ -o /dev/null | grep -i "auth-username")
if echo "$HEADERS" | grep -q "${TEST_USER}"; then
  echo "✅ Test 5 PASS: Auth-Username header present"
else
  echo "❌ Test 5 FAIL: Auth-Username header missing"
fi

echo "========================================"
echo "Tests complete!"
```

---

## Troubleshooting

| Symptom | Possible Cause | Solution |
|---------|---------------|----------|
| Pod CrashLoopBackOff | TLS secret missing | `oc get secret ${TLS_SECRET_NAME} -n ${AUTH_NAMESPACE}` |
| 401 with correct creds | Secret missing label | Add label: `oc label secret <name> ${SECRET_LABEL}` |
| 401 with correct creds | HTTPProxy secretRef wrong | Check `authPolicy.context.secretRef` format: `namespace/name` |
| 401 with correct creds | Realm mismatch | Set annotation `auth.contour.snappcloud.io/realm: "*"` |
| Secret not picked up | Label doesn't match selector | Verify `--selector` arg matches secret labels |
| HTTPProxy not valid | ExtensionRef service not found | Verify service name: `${DEPLOYMENT_NAME}` in `${AUTH_NAMESPACE}` |
| Connection refused | Service not ready | Check `oc get endpoints ${SERVICE_NAME} -n ${AUTH_NAMESPACE}` |
| TLS error | Wrong TLS secret | Verify `${TLS_SECRET}` exists and is accessible |
