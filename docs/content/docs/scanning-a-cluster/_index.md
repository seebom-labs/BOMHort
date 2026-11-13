---
title: "Scanning a Cluster"
linkTitle: "Scanning a Cluster"
type: docs
weight: 7
description: >
  How a Kubernetes cluster scanner should upload SBOMs so the fleet tree fills
  itself, and the conformance list a third-party scanner can claim.
---

A **cluster scanner** is a job that runs inside a Kubernetes cluster, finds the
images that are actually running, produces an SBOM for each one and pushes it
to [`POST /api/v1/sboms/upload`]({{< relref "/docs/api-reference#post-apiv1sbomsupload" >}}).
BOMHort itself never talks to a Kubernetes API (see
[Fleet Views]({{< relref "/docs/ownership" >}})): the scanner knows where each
image runs, and states it on the upload.

This page is the contract between the two. It has two parts:

1. **What a scanner does**: the loop, the RBAC it needs, and a minimal script
   you can run today.
2. **The conformance list**: every parameter a scanner sends, and whether it is
   required. A scanner that sends every *required* row correctly may describe
   itself as *BOMHort-conformant*.

{{% alert title="The reference scanner lives in its own repository" color="info" %}}
A small reference scanner (a CronJob plus a Helm chart) is planned as a separate
repository under the `seebom-labs` organisation. It generates SBOMs with an
existing generator (syft or trivy), so BOMHort never ships SBOM generation
code. Until it exists, the script below is the reference.
{{% /alert %}}

## What ends up where

The fleet tree (`GET /api/v1/fleet`, the **Fleet** page) is
`cluster → namespace → project`. A scanner fills it by mapping what it sees in
Kubernetes onto the upload parameters:

| Kubernetes | BOMHort | How the scanner gets it |
|------------|---------|-------------------------|
| The cluster the scanner runs in | `cluster` | Configured on the scanner (there is no cluster name in the Kubernetes API) |
| `metadata.namespace` of the pod | `namespace` | The pod |
| The application the pod belongs to | `project` | A pod label (default `app.kubernetes.io/name`, configurable), falling back to the name of the owning workload |
| A larger product the application is part of | `parent` | A pod label such as `app.kubernetes.io/part-of`, if set |
| `status.containerStatuses[].imageID` | the SBOM itself | One SBOM per image digest |

`project` falls back to the owning workload, not the pod name: pod names change
on every rollout, and a project per pod would make the fleet tree useless after
a week.

## The scan loop

Every run:

1. **List running pods**, in all namespaces or in a configured set.
2. **Collect `(digest, image, cluster, namespace, project, workload)`** for every
   container, init container included. Use the digest from
   `status.containerStatuses[].imageID`, not `spec.containers[].image`: a tag
   names whatever was pushed last, the digest names what is actually running.
3. **Deduplicate by digest.** Twenty replicas of one Deployment are one image;
   generate its SBOM once.
4. **Get an SBOM for each digest.** Generate it with an existing tool, e.g.
   `syft <image>@<digest> -o spdx-json` or
   `trivy image --format cyclonedx <image>@<digest>`.
5. **Upload once per ownership tuple** with the parameters in the
   [conformance list](#conformance-list). One image running in two namespaces
   is two uploads (see [Known limitations](#known-limitations-today) for why
   the two documents must not be byte-identical yet).
6. **Remember what you uploaded.** Keep the set of
   `(digest, cluster, namespace, project)` tuples already sent, for example in a
   ConfigMap, and skip them on the next run. Without it every run re-uploads
   every image, and generators such as syft stamp a fresh timestamp and
   document ID into each SBOM, so BOMHort cannot tell the re-upload is the same
   document and stores it again.

### RBAC

The scanner only reads. List pods, plus `get` on every owner kind it walks
through to find the workload:

- a pod owned by a ReplicaSet belongs to a Deployment: `get` the ReplicaSet to
  read its owner, then `get` the Deployment;
- a pod owned by a Job may belong to a CronJob: `get` the Job, then `get` the
  CronJob.

StatefulSets and DaemonSets own their pods directly, so the pod's
`ownerReferences` already name them and no extra permission is needed. A
scanner that walks further, for example into an operator's custom resources,
needs `get` on those kinds as well, or the lookup fails with `Forbidden`.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: bomhort-scanner
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["list"]
  - apiGroups: ["apps"]
    resources: ["replicasets", "deployments"]
    verbs: ["get"]
  - apiGroups: ["batch"]
    resources: ["jobs", "cronjobs"]
    verbs: ["get"]
```

Bind it to the scanner's ServiceAccount with a `ClusterRoleBinding`, or with a
`RoleBinding` per namespace if the scanner should only see some of them. The
scanner needs no access to Secrets, and no write access to anything.

### Authentication

Uploads require `AUTH_ENABLED=true` on the API gateway. The scanner sends an
API key from `API_KEYS` in the `X-API-Key` header (`Authorization: Bearer` with
the `SERVICE_TOKEN` also works); mount it from a Secret, never bake it into the
image. Authentication with the scanner's own ServiceAccount token, so no static
key needs distributing, is planned.

### A minimal scanner

Readable rather than robust: no retries, no owner walk beyond one level, no
upload cache. It needs `kubectl`, `jq`, `syft` and `curl`.

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${BOMHORT_URL:?}" "${BOMHORT_API_KEY:?}" "${CLUSTER_NAME:?}"
PROJECT_LABEL="${PROJECT_LABEL:-app.kubernetes.io/name}"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# One line per running container:
#   digest-ref <TAB> namespace <TAB> project <TAB> owner-kind <TAB> owner-name
kubectl get pods --all-namespaces --field-selector=status.phase=Running -o json |
  jq -r --arg label "$PROJECT_LABEL" '
    .items[] as $pod
    | ($pod.metadata.ownerReferences // [] | first) as $owner
    | ($pod.status.containerStatuses // []) + ($pod.status.initContainerStatuses // [])
    | .[]
    | select((.imageID // "") | contains("@sha256:"))
    | [ (.imageID | sub("^[a-z-]+://"; "")),
        $pod.metadata.namespace,
        ($pod.metadata.labels[$label] // $owner.name // $pod.metadata.name),
        ($owner.kind // "Pod"),
        ($owner.name // $pod.metadata.name) ]
    | @tsv' |
  sort -u > "$WORK/containers.tsv"

while IFS=$'\t' read -r ref namespace project kind name; do
  digest="${ref#*@}"
  sbom="$WORK/${digest#sha256:}.spdx.json"
  # Generate once per digest.
  [[ -f "$sbom" ]] || syft "$ref" -q -o spdx-json > "$sbom"

  # Make the document unique per ownership tuple (see Known limitations).
  doc="$WORK/upload.spdx.json"
  jq --arg ns "https://bomhort.local/scan/$CLUSTER_NAME/$namespace/$project/$digest" \
     '.documentNamespace = $ns' "$sbom" > "$doc"

  curl -fsS -X POST "$BOMHORT_URL/api/v1/sboms/upload" \
    -H "X-API-Key: $BOMHORT_API_KEY" \
    -H "X-Filename: ${digest#sha256:}.spdx.json" \
    --url-query "cluster=$CLUSTER_NAME" \
    --url-query "namespace=$namespace" \
    --url-query "project=$project" \
    --url-query "origin=cluster-scan" \
    --url-query "image=$ref" \
    --url-query "workload_kind=$kind" \
    --url-query "workload_name=$name" \
    --data-binary @"$doc" \
    -o /dev/null -w "%{http_code} $namespace/$project $ref\n"
done < "$WORK/containers.tsv"
```

`--url-query` (curl 7.87 or later) URL-encodes each value into the query
string while `--data-binary` still sends the document as the body.
For a ReplicaSet, `$owner.name` is the ReplicaSet (`payment-api-7d9f8c6b5`);
a production scanner walks one level further to the Deployment.

## Conformance list

What a scanner sends on every `POST /api/v1/sboms/upload`. The authoritative
description of each parameter, including validation and error codes, is the
[API reference]({{< relref "/docs/api-reference#post-apiv1sbomsupload" >}});
this list says which of them a *scanner* is expected to send.

Status:

- **required**: a conformant scanner always sends it.
- **recommended**: send it whenever the scanner knows the value.
- **optional**: send it if the deployment uses it.
- **planned**: not accepted by BOMHort yet. Unknown parameters are ignored
  today, so a scanner can and should already send them: the value starts being
  stored the day the feature lands, with no scanner change. Send well-formed
  values only; once a parameter is supported, a malformed one is a `400`.
- **not-applicable**: part of the upload contract, but not for a scanner.

<!-- scanner-conformance:start -->
| Name | Sent as | Status | What a cluster scanner sends |
|------|---------|--------|------------------------------|
| `X-API-Key` | credential | required | An API key from `API_KEYS`, mounted from a Secret |
| `X-Filename` | header | required | `<digest-hex>.spdx.json` or `<digest-hex>.cdx.json`: the extension tells BOMHort the format |
| `cluster` | query | required | The cluster name the scanner is configured with |
| `namespace` | query | required | The pod's namespace |
| `project` | query | required | The project label's value, else the owning workload's name |
| `parent` | query | optional | A product grouping, e.g. the `app.kubernetes.io/part-of` label |
| `tags` | query | optional | Comma-separated grouping labels, e.g. `runtime` |
| `X-Source-Repo` | header | recommended | The image's `org.opencontainers.image.source` label, when set |
| `X-Source-Ref` | header | recommended | The image's `org.opencontainers.image.revision` label, when set |
| `origin` | query | planned | `cluster-scan` |
| `image` | query | planned | The running image as `<repository>@sha256:<digest>` |
| `workload_kind` | query | planned | The owning workload's kind, e.g. `Deployment` |
| `workload_name` | query | planned | The owning workload's name |
| `workload_uid` | query | planned | The owning workload's `metadata.uid` |
| `sbom_id` | query | not-applicable | VEX uploads only |
<!-- scanner-conformance:end -->

The table is checked against the upload handler by
`TestDocsScannerConformanceInSync`
(`backend/cmd/api-gateway/scanner_conformance_test.go`): every parameter the
handler reads must be listed here, every listed parameter that is not
*planned* must reach the ingestion job, and a *planned* parameter that the
handler starts reading fails the test until its row is updated.

### Beyond the parameters

A conformant scanner also:

- uploads **one SBOM per image digest and ownership tuple**, never one per pod
  or per replica;
- takes the digest from the **running container status**, not from the pod
  spec's tag;
- treats `200 {"status":"duplicate"}` as success, not as an error to retry;
- treats `400` as a bug in the scanner (a malformed value), not as a transient
  failure, and does not retry it unchanged;
- runs with a **read-only** ServiceAccount and reads the API key from a Secret.

## Known limitations today

These are the gaps between what a cluster scanner wants and what BOMHort
accepts right now. Each one is covered by planned work and the conformance list
above already accounts for it.

- **Identity is the document's content hash.** `sbom_id` is derived from the
  SHA-256 of the uploaded bytes. Uploading the *same bytes* for a second
  namespace is answered with `200 duplicate`, and the second ownership tuple is
  not recorded. That is why the minimal scanner rewrites `documentNamespace`
  (CycloneDX: `serialNumber`) per tuple: both fields are meant to be unique per
  document anyway. Image-digest identity, where one document can belong to
  several workloads, is planned.
- **No digest lookup.** A scanner cannot yet ask BOMHort whether it already
  holds an SBOM for a digest, so it keeps its own record of what it uploaded.
- **No `origin`, image or workload columns yet.** Sent today, ignored today
  (see *planned* above). Until they land, the fleet tree is complete but
  `?workload=` style lookups are not possible; the workload is only visible
  through `project`.
- **No attestation fetch.** When an image already carries a signed SBOM
  attestation in its registry, the scanner has to download it itself (for
  example with `cosign download attestation`) and upload the predicate. Asking
  BOMHort to fetch it by digest is planned.

## Checking the result

After a scan run:

```bash
curl -s "$BOMHORT_URL/api/v1/fleet" -H "X-API-Key: $BOMHORT_API_KEY" | jq .
```

should list the scanner's cluster with one namespace per scanned namespace and
one project per workload. In the UI it is the **Fleet** page. Jobs that are
still being parsed show up in `make dev-status` (Docker Compose) or the
parsing worker's log.
