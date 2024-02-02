# contour-auth-multi-tenant

`contour-auth-multi-tenant` is an Envoy-compatible authorization server that builds upon the foundation of [contour-authserver](https://github.com/projectcontour/contour-authserver).

`contour-authserver` implements the Envoy [external authorization][4]
GRPC protocol (both v2 and v3). `contour-authserver` has two authorization
backends that are selected by subcommands.

`contour-auth-multi-tenant` adds multi-tenancy feature to `contour-authserver` and improves its performance to make it production-ready.

## Key Features:
- **Multi-Tenancy Support**: One of the standout features of contour-auth-multi-tenant is its built-in support for multi-tenancy. This allows us to securely manage and isolate authorization scopes for different tenants within a single instance.

- **Enhanced Performance**: 
contour-auth-multi-tenant has meticulously been optimized to deliver outstanding performance under heavy loads. This ensures that your application's authorization layer can handle requests efficiently, without introducing bottlenecks or delays.

# htpasswd

Usage:

```
Run a htpasswd basic authentication server

Usage:
  contour-authserver htpasswd [OPTIONS]

Flags:
      --address string             The address the authentication endpoint binds to. (default ":9090")
      --auth-realm string          Basic authentication realm. (default "default")
  -h, --help                       help for htpasswd
      --metrics-address string     The address the metrics endpoint binds to. (default ":8080")
      --selector string            Selector (label-query) to filter Secrets, supports '=', '==', and '!='.
      --tls-ca-path string         Path to the TLS CA certificate bundle.
      --tls-cert-path string       Path to the TLS server certificate.
      --tls-key-path string        Path to the TLS server key.
      --watch-namespaces strings   The list of namespaces to watch for Secrets.
```

## htpasswd Secrets

The `htpasswd` backend implements [HTTP basic authentication][3]
against a set of Secrets that contain [htpasswd][1] formatted data.
The htpasswd data must be stored in the `auth` key, which is compatible
with ingress-nginx [`auth-file` Secrets][2].

The `htpasswd` backend only accesses Secrets that are
annotated with `auth.contour.snappcloud.io/type: basic`.

Secrets that are annotated with the `auth.contour.snappcloud.io/realm`
will only be used if the annotation value matches the value of the
`--auth-realm` flag.
The `auth.contour.snappcloud.io/realm: *` annotation explicitly marks
a Secret as being valid for all realms.
This is equivalent to omitting the annotation.

When it authenticates a request, the `htpasswd` backend injects the
`Auth-Username` and  `Auth-Realm` headers, which contain the
authenticated user name and the basic authentication realm respectively.

The `--watch-namespaces` flag specifies the namespaces where the
`htpasswd` backend will discover Secrets.
If this flag is empty, Secrets from all namespaces will be used.

The `--selector` flag accepts a [label selector][5] that can be
used to further restrict which Secrets the `htpasswd` backend will consume. (Use it for lower resource consumption and better performance as it reduce reconcile loops dramatically if there are lots of secrets)

## htpasswd Multi-Tenancy Support

While `contour-authserver` matches the provided credential in the `Authorization` header against all the Secrets, `contour-auth-multi-tenant` offers a more refined approach. It matches the provided credential against a user-defined Secret, enabling precise control over authorization scopes.

To leverage the multi-tenancy feature of `contour-auth-multi-tenant`, include a secret reference in your Envoy [CheckRequest](https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto#service-auth-v3-checkrequest). Specify the reference in the request's context, using `secretRef` as the key and the `namespace/secretName` format for the value.

Here is a sample HTTPProxy instance in which htpasswd is supported. Please notice that defining an `authPolicy` is a necessity in order to be able to use the specified secret. 

example:
```
apiVersion: projectcontour.io/v1
kind: HTTPProxy
metadata:
  name: SAMPLE_NAME
  namespace: SAMPLE_NAMESPACE
spec:
  ingressClassName: INGRESS_CLASS_NAME
  routes:
    - conditions:
        - prefix: /
      services:
        - name: SERVICE_NAME
          port: 80
  virtualhost:
    authorization:
      authPolicy:
        context:
          secretRef: NAMESPACE/SECRET_NAME
      extensionRef:
        name: EXTENSION_SERVICE_NAME
        namespace: EXTENSION_SERVICE_NAMESPACE
    fqdn: SAMPLE_FQDN
    tls:
      enableFallbackCertificate: false
      secretName: NAMESPACE/TLS_CERT_NAME
```
The ExtensionService does not necessarily need to be in the same namespace as the configuration provides the namespace option.
It has been supposed that the service listens on root path `/` and port `80`. 

### htpasswd Secret Configuration
It is important to note that the procedure of matching Secrets occures by comparing the existing Secrets' labels with Contour Authserver's secretSelector. In addition, it is worth mentioning that the key `auth` should be present while using the label. 
The default value for secretSelector is `auth.contour.snappcloud.io/type=basic` which can be modified to a desirable one following the mentioned format. 

example:
```
auth.contour.sample.label/type=basic
```

# OIDC

Usage:

```
Run a oidc authentication server

Usage:
  contour-authserver oidc [OPTIONS]

Flags:
      --config string              Path to config file ( yaml format )
  -h, --help                       help for htpasswd
      --tls-ca-path string         Path to the TLS CA certificate bundle.
      --tls-cert-path string       Path to the TLS server certificate.
      --tls-key-path string        Path to the TLS server key.

```
Oidc configuration can be specified with configmaps. 
Please visit [DexIDP](https://github.com/dexidp/dex) for more detail.

```
## The following entries are the variables  accepted by the Contour OIDC module.
## server address and port 
address: ":9443"

## OIDC issuer URL 
issuerURL: "http://<path to your SSO server>"

## App redirect path ( usually point back to app url)
redirectURL: "https://<path to your applications>"
redirectPath: "/callback"
allowEmptyClientSecret: false
scopes:
- openid
- profile
- email
- offline_access
usernameClaim: "nickname"
emailClaim: ""
serveTLS: false
clientID: "<your client id>"
clientSecret: "<your client secret>"
```


# Request Headers

Both authorization backends emit the `Auth-Handler` header, which
publishes the name of the backend that approved or rejected the
authorization.

<del>The authorization context is also reflected into HTTP headers
prefixed with `Auth-Context-`. Note that This can generate malformed
HTTP headers. The `testserver` backend always creates the context
headers, but the `htpasswd` backend only does so for authenticated
requests (i.e. the origin server gets them bu the client never
does.)</del>

# Deploying `contour-auth-multi-tenant`

The recommended way to deploy `contour-auth-multi-tenant` is to use the Kustomize
[deployment YAML](./config/default). This will deploy services for `htpasswd` and `oidc` backends. For developer deployments,
[Skaffold](https://skaffold.dev/) seems to work reasonably well.

# Releasing `contour-auth-multi-tenant`

Maintainers who need to release a new version of `contour-auth-multi-tenant`
can follow the following steps:

```bash
# Ensure that you have a Github token either in $GITHUB_TOKEN or in ~/.config/goreleaser/github_token.
# Ensure that goreleaser is installed.

# Tag the release.
$ ./hack/make-release-tag.sh $OLDVERS $NEWVERS

# Push the release tag to Github.
$ git push origin $NEWVERS

# Build and release binaries and Docker images.
$ make release

# Log in with your GitHub account and token to push the images.
$ docker login -u <GitHub username>
$ docker push ghcr.io/projectcontour/contour-authserver:$NEWVERS
$ docker push ghcr.io/projectcontour/contour-authserver:latest

# Log out.
$ docker logout
```

[1]: https://httpd.apache.org/docs/current/programs/htpasswd.html
[2]: https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#authentication
[3]: https://tools.ietf.org/html/rfc7617
[4]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/security/ext_authz_filter
[5]: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors
