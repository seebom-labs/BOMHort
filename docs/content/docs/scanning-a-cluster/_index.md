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
BOMHort does not discover pod images itself (see
[Fleet Views]({{< relref "/docs/ownership" >}})): the scanner knows where each
image runs, and states it on the upload. Workers may still use the Kubernetes
API for Lease-based coordination.

This page is the contract between the two. It has two parts:

1. **What a scanner does**: the loop, the RBAC it needs, and a minimal script
   you can run today.
2. **The conformance list**: every parameter a scanner sends, and whether it is
   required. A scanner that sends every *required* row correctly may describe
   itself as *BOMHort-conformant*.

{{% alert title="Reference scanner planned" color="info" %}}
A reference scanner (a CronJob with Helm support) is planned in the BOMHort
monorepo. It will use an existing SBOM generator such as syft or trivy.
The script below is a limited example, not a complete scanner.
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
| `status.containerStatuses[].imageID` | `image`, and the SBOM itself | One SBOM per image digest |

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
   Some runtimes report only a local image ID instead of a repository digest.
   Resolve those through the runtime or report them as unsupported; do not
   guess a digest from a mutable tag.
3. **Deduplicate by digest.** Twenty replicas of one Deployment are one image;
   generate its SBOM once.
4. **Get an SBOM for each digest.** Generate it with an existing tool, e.g.
   `syft <image>@<digest> -o spdx-json` or
   `trivy image --format cyclonedx <image>@<digest>`.
5. **Upload once per ownership tuple** with the parameters in the
   [conformance list](#conformance-list). One image running in two namespaces
   is two uploads, each with its own ownership and the same `image`.
6. **Don't re-upload a completed ownership.** Generators such as syft stamp a
   fresh timestamp and document ID into each SBOM, so without a check every
   run can store it again. `HEAD /api/v1/images/{digest}` only reports whether
   the digest exists anywhere; it cannot tell whether this ownership was
   recorded. Check every page of `GET /api/v1/images/{digest}` for the image
   reference, origin and ownership tuple, or keep a confirmed upload cache.
   For a new tuple, still upload a valid SBOM even if `HEAD` returned `200`.
   Reuse a cached document or generate one if no document is available.

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

Readable rather than robust: no retries, owner walk or upload cache. It needs
`kubectl`, `jq`, `syft` and `curl`. Every scanned pod must carry the configured
project label, and each running container or completed init container must have
an `imageID` containing a `repository@sha256:…` reference. The example fails
rather than silently skipping an unsupported image ID or using an unstable
pod/ReplicaSet name.

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${BOMHORT_URL:?}" "${BOMHORT_API_KEY:?}" "${CLUSTER_NAME:?}"
PROJECT_LABEL="${PROJECT_LABEL:-app.kubernetes.io/name}"
WORK="$(mktemp -d)"
trap 'rm -f -- "$WORK"/*.spdx.json "$WORK/containers.tsv"; rmdir -- "$WORK"' EXIT

# One line per running container or completed init container:
#   digest-ref <TAB> digest <TAB> namespace <TAB> project
kubectl get pods --all-namespaces --field-selector=status.phase=Running -o json |
  jq -r --arg label "$PROJECT_LABEL" '
    .items[] as $pod
    | (($pod.status.containerStatuses // []) | map(select(.state.running != null))) +
      (($pod.status.initContainerStatuses // []) | map(select(.state.running != null or .state.terminated != null)))
    | .[]
    | .imageID as $id
    | ($pod.metadata.labels[$label] // "") as $project
    | if ($project | type) != "string" or $project == "" then
        error("missing project label on \($pod.metadata.namespace)/\($pod.metadata.name)")
      else . end
    | if (($id // "") | test("^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?[^@[:space:]]+@sha256:[a-f0-9]{64}$")) then .
      else error("unsupported imageID on \($pod.metadata.namespace)/\($pod.metadata.name): \($id)") end
    | ($id | sub("^[a-zA-Z][a-zA-Z0-9+.-]*://"; "")) as $ref
    | [$ref, ($ref | split("@")[-1]), $pod.metadata.namespace, $project]
    | @tsv' |
  LC_ALL=C sort -t $'\t' -u -k2,2 -k3,3 -k4,4 > "$WORK/containers.tsv"

while IFS=$'\t' read -r ref digest namespace project; do
  sbom="$WORK/${digest#sha256:}.spdx.json"
  # Generate once per digest.
  [[ -f "$sbom" ]] || syft "$ref" -q -o spdx-json > "$sbom"

  # Only needed with DEDUP_BY_IMAGE_DIGEST=false: keeps the document unique
  # per ownership tuple (see Known limitations).
  doc="$WORK/upload.spdx.json"
  jq --arg cluster "$CLUSTER_NAME" --arg namespace "$namespace" --arg project "$project" '
    if (.documentNamespace | type) != "string" or .documentNamespace == "" then
      error("generated SPDX has no documentNamespace")
    else
      .documentNamespace += "/" + ([$cluster, $namespace, $project] | map(@uri) | join("/"))
    end' "$sbom" > "$doc"

  status="$(curl -fsS -X POST "$BOMHORT_URL/api/v1/sboms/upload" \
    -H "X-API-Key: $BOMHORT_API_KEY" \
    -H "X-Filename: ${digest#sha256:}.spdx.json" \
    --url-query "cluster=$CLUSTER_NAME" \
    --url-query "namespace=$namespace" \
    --url-query "project=$project" \
    --url-query "origin=cluster-scan" \
    --url-query "image=$ref" \
    --data-binary @"$doc" \
    -o /dev/null -w "%{http_code}")"
  case "$status" in
    200|202) printf '%s %s/%s %s\n' "$status" "$namespace" "$project" "$ref" ;;
    *) printf 'unexpected HTTP status %s for %s/%s %s\n' "$status" "$namespace" "$project" "$ref" >&2; exit 1 ;;
  esac
done < "$WORK/containers.tsv"
```

`--url-query` (curl 7.87 or later) URL-encodes each value into the query
string while `--data-binary` still sends the document as the body.
Without the label, a production scanner must resolve the owning workload
before choosing a project; a ReplicaSet name alone changes on every rollout.

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
  today; their future validation and meaning are not a current API contract.
  Do not depend on them until they are supported.
- **not-applicable**: part of the upload contract, but not for a scanner.

<!-- scanner-conformance:start -->
| Name | Sent as | Status | What a cluster scanner sends |
|------|---------|--------|------------------------------|
| `X-API-Key` | credential | required | An API key from `API_KEYS`, mounted from a Secret |
| `X-Filename` | header | required | `<digest-hex>.spdx.json` or `<digest-hex>.cdx.json`: the filename identifies an SBOM; its contents determine the format |
| `cluster` | query | required | The cluster name the scanner is configured with |
| `namespace` | query | required | The pod's namespace |
| `project` | query | required | The project label's value, else the owning workload's name |
| `parent` | query | optional | A product grouping, e.g. the `app.kubernetes.io/part-of` label |
| `tags` | query | optional | Comma-separated grouping labels, e.g. `runtime` |
| `X-Source-Repo` | header | recommended | The image's `org.opencontainers.image.source` label, when set |
| `X-Source-Ref` | header | recommended | The image's `org.opencontainers.image.revision` label, when set |
| `origin` | query | required | `cluster-scan` |
| `image` | query | required | The running image as `<repository>@sha256:<digest>` |
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
- treats `200 {"status":"duplicate"}` and `200` with `"reused": true` as
  success, not as an error to retry;
- treats `202` as pending, not as proof that parsing succeeded, and confirms
  the image and ownership before marking the upload complete;
- treats `409` as "the same content is still being ingested" and retries that
  upload on a later run;
- treats `400` as a bug in the scanner (a malformed value), not as a transient
  failure, and does not retry it unchanged;
- runs with a **read-only** ServiceAccount and reads the API key from a Secret.

## Image digests and deduplication

`?image=` makes the image digest part of the SBOM's identity. What happens when
the same digest arrives twice depends on `DEDUP_BY_IMAGE_DIGEST` on the API
gateway (Helm: `apiGateway.dedupByImageDigest`, default `false`):

- **`true` (recommended for cluster scanning):** once the digest is fully
  ingested, another upload with the same image reference, origin, cluster,
  namespace and project is a `200` duplicate. For a different reference,
  origin or ownership, BOMHort copies the parsed SBOM and answers `200` with
  `"reused": true`. While the first upload is still pending, a different
  ownership may instead be enqueued for parsing separately.
- **`false`:** deduplication is by the document's content hash. Uploading the
  *same bytes* for a second namespace is a `200` duplicate and the second
  ownership is not recorded. That is why the minimal scanner rewrites
  `documentNamespace` (CycloneDX: `serialNumber`) per ownership tuple: both
  are meant to be unique per document anyway.

## Known limitations today

What a cluster scanner wants but BOMHort does not accept yet. The conformance
list already accounts for each one.

- **No workload columns yet.** `workload_kind`, `workload_name` and
  `workload_uid` are ignored if sent (see *planned* above). Until they land,
  the workload is only visible through `project`, and `?workload=` style
  lookups are not possible.
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
