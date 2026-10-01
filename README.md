# ExternalDNS - Vultr Webhook

ExternalDNS is a Kubernetes add-on for automatically managing
Domain Name System (DNS) records for Kubernetes services by using different DNS providers.
By default, Kubernetes manages DNS records internally,
but ExternalDNS takes this functionality a step further by delegating the management of DNS records to an external DNS
provider such as this one.
The Vultr webhook manages Vultr DNS zones from a Kubernetes cluster with
[ExternalDNS](https://github.com/kubernetes-sigs/external-dns).

To use ExternalDNS with Vultr, you need your Vultr API token of the account managing
your domains.
For detailed technical instructions on how the Vultr webhook is deployed using the Bitnami Helm charts for ExternalDNS,
see the [deployment instructions](#kubernetes-deployment).

Supported record types are `A`, `AAAA`, `CAA`, `CNAME`, `MX`, `NS`, `SRV`,
`SSHFP`, and `TXT`. MX and SRV priorities are translated between ExternalDNS's
target format and Vultr's dedicated priority field.

## Kubernetes Deployment

The deployment can be performed in every way Kubernetes supports.
The following example shows the deployment as
a [sidecar container](https://kubernetes.io/docs/concepts/workloads/pods/#workload-resources-for-managing-pods) in the
ExternalDNS pod
using the [Bitnami Helm charts for ExternalDNS](https://github.com/bitnami/charts/tree/main/bitnami/external-dns).

This release is tested with ExternalDNS v0.23.0.

The webhook can be installed using either the Bitnami chart or the ExternalDNS one.

First, create the namespace and Vultr secret:

```shell
kubectl create namespace external-dns
kubectl create secret generic vultr-credentials --from-literal=api-key='<EXAMPLE_PLEASE_REPLACE>' -n external-dns
```

### Using the Bitnami chart

Skip this if you already have the Bitnami repository added:

```shell
helm repo add bitnami https://charts.bitnami.com/bitnami
```

You can then create the helm values file, for example
`external-dns-vultr-values.yaml`:

```yaml
image:
  registry: registry.k8s.io
  repository: external-dns/external-dns
  tag: v0.23.0

provider: webhook

extraArgs:
  webhook-provider-url: http://localhost:8888
  txt-prefix: reg-

sidecars:
  - name: vultr-webhook
    image: vultr/external-dns-vultr-webhook:v0.2.0
    ports:
      - containerPort: 8888
        name: webhook
      - containerPort: 8080
        name: http
    livenessProbe:
      httpGet:
        path: /health
        port: http
      initialDelaySeconds: 10
      timeoutSeconds: 5
    readinessProbe:
      httpGet:
        path: /ready
        port: http
      initialDelaySeconds: 10
      timeoutSeconds: 5
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
      runAsNonRoot: true
    resources:
      requests:
        cpu: 10m
        memory: 32Mi
      limits:
        memory: 128Mi
    env:
      - name: VULTR_API_KEY
        valueFrom:
          secretKeyRef:
            name: vultr-credentials
            key: api-key
```

And then:

```shell
# install external-dns with helm
helm install external-dns-vultr bitnami/external-dns -f external-dns-vultr-values.yaml -n external-dns
```

### Using the ExternalDNS chart

Skip this if you already have the ExternalDNS repository added:

```shell
helm repo add external-dns https://kubernetes-sigs.github.io/external-dns/
```

You can then create the helm values file, for example
`external-dns-vultr-values.yaml`:

```yaml
namespace: external-dns
policy: upsert-only
provider:
  name: webhook
  webhook:
    image:
      repository: vultr/external-dns-vultr-webhook
      tag: v0.2.0
    env:
      - name: VULTR_API_KEY
        valueFrom:
          secretKeyRef:
            name: vultr-credentials
            key: api-key
    livenessProbe:
      httpGet:
        path: /health
        port: http-wh-metrics
      initialDelaySeconds: 10
      timeoutSeconds: 5
    readinessProbe:
      httpGet:
        path: /ready
        port: http-wh-metrics
      initialDelaySeconds: 10
      timeoutSeconds: 5
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
      runAsNonRoot: true
    resources:
      requests:
        cpu: 10m
        memory: 32Mi
      limits:
        memory: 128Mi

extraArgs:
  - --txt-prefix=reg-
```

And then:

```shell
# install external-dns with helm
helm install external-dns-vultr external-dns/external-dns -f external-dns-vultr-values.yaml -n external-dns
```

## Environment variables

The following environment variables are available:

| Variable            | Description                         | Notes                |
| ------------------- | ----------------------------------- | -------------------- |
| VULTR_API_KEY       | Vultr API token                     | Mandatory            |
| DRY_RUN             | Validate and log without API writes | Default: `false`     |
| WEBHOOK_HOST        | Webhook hostname or IP address      | Default: `localhost` |
| WEBHOOK_PORT        | Webhook port                        | Default: `8888`      |
| HEALTH_HOST         | Liveness and readiness hostname     | Default: `0.0.0.0`   |
| HEALTH_PORT         | Liveness and readiness port         | Default: `8080`      |
| READ_TIMEOUT        | Server read timeout in ms           | Default: `60000`     |
| WRITE_TIMEOUT       | Server write timeout in ms          | Default: `60000`     |
| READ_HEADER_TIMEOUT | Server header timeout in ms         | Default: `5000`      |
| IDLE_TIMEOUT        | Server idle timeout in ms           | Default: `60000`     |
| MAX_BODY_SIZE       | Maximum webhook body in bytes       | Default: `1048576`   |

Additional environment variables for domain filtering:

| Environment variable           | Description                        |
| ------------------------------ | ---------------------------------- |
| DOMAIN_FILTER                  | Filtered domains                   |
| EXCLUDE_DOMAIN_FILTER          | Excluded domains                   |
| REGEXP_DOMAIN_FILTER           | Regex for filtered domains         |
| REGEXP_DOMAIN_FILTER_EXCLUSION | Regex for excluded domains         |

If the `REGEXP_DOMAIN_FILTER` is set, the following variables will be used to
build the filter:

- REGEXP_DOMAIN_FILTER
- REGEXP_DOMAIN_FILTER_EXCLUSION

otherwise, the filter will be built using:

- DOMAIN_FILTER
- EXCLUDE_DOMAIN_FILTER

## Tweaking the configuration

While tweaking the configuration, there are some points to take into
consideration:

- if `WEBHOOK_HOST` and `HEALTH_HOST` are set to the same address/hostname or
  one of them is set to `0.0.0.0` remember to use different ports.
- if your records do not get deleted when applications are uninstalled, you
  might want to verify the policy in use for ExternalDNS: if it's `upsert-only`
  no deletion will occur. Set it to `sync` only when ExternalDNS should delete
  records it owns. Verify TXT ownership records before enabling this strategy:

  ```yaml
  policy: sync
  ```

## Development

The basic development tasks are provided by make. Run `make help` to see the
available targets.

Use `make unit-test`, `make static-analysis`, and `make build` before opening a
pull request. The project follows the Go version declared in `go.mod`.
