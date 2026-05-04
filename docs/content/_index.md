---
title: "SeeBOM"
linkTitle: "SeeBOM"
description: "SeeBOM is a Kubernetes-native SBOM visualization and governance platform. Ingest SPDX SBOMs from S3, detect CVEs via OSV, enforce license compliance, and apply VEX statements."
---

{{< blocks/cover title="" image_anchor="top" height="med" color="dark" >}}
<img src="/images/logo-with-text.svg" alt="SeeBOM" style="max-width: 420px; width: 100%; margin-bottom: 1rem;">
<p class="lead mt-4">Kubernetes-native Software Bill of Materials (SBOM) Visualization &amp; Governance Platform</p>
<a class="btn btn-lg btn-seebom me-3 mb-4" href="/docs/">
  <img class="fb-icon" src="/images/flowbite/book-open.svg" alt="" loading="lazy">
  Documentation
</a>
<a class="btn btn-lg btn-secondary me-3 mb-4" href="https://github.com/seebom-labs/seebom">
  <img class="fb-icon" src="/images/flowbite/github.svg" alt="" loading="lazy">
  GitHub
</a>
{{< /blocks/cover >}}

{{% blocks/lead color="primary" %}}

Ingest thousands of SPDX SBOMs, scan for vulnerabilities via OSV, enforce license compliance,
and apply VEX statements — all visualized in a fast Angular dashboard backed by ClickHouse analytics.

{{% /blocks/lead %}}

{{< blocks/section color="dark" >}}
<div class="col-12 text-center">
  <img src="/images/dashboard-screenshot.png" alt="SeeBOM Dashboard" style="width: 100%; max-width: 1100px; border-radius: 8px; box-shadow: 0 4px 24px rgba(0,0,0,0.4);">
</div>
{{< /blocks/section >}}

{{< blocks/section color="dark" type="row" >}}

{{% blocks/feature icon="fa-bolt" title="High Performance" url="/docs/architecture/" %}}
<img class="fb-icon-lg me-1" src="/images/flowbite/database.svg" alt="">
ClickHouse MergeTree tables handle millions of dependency records.
Virtual scrolling and OnPush change detection keep the UI responsive.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-shield-alt" title="Vulnerability Intelligence" url="/docs/architecture/#osv-integration" %}}
<img class="fb-icon-lg me-1" src="/images/flowbite/shield-check.svg" alt="">
Automatic OSV API lookups for every package URL.
Daily CVE Refresher finds newly disclosed vulnerabilities without re-scanning.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-balance-scale" title="License Governance" url="/docs/deployment/#2-license-exceptions" %}}
<img class="fb-icon-lg me-1" src="/images/flowbite/scale-balanced.svg" alt="">
Externalized license policy and exceptions.
CNCF Allowed Third-Party License Policy enforced out of the box.
{{% /blocks/feature %}}

{{< /blocks/section >}}

{{< blocks/section color="white" type="row" >}}

{{% blocks/feature icon="fa-cloud" title="S3 Ingestion" url="/docs/deployment/#option-a-s3-buckets-default-recommended" %}}
<img class="fb-icon-lg me-1" src="/images/flowbite/folder-open.svg" alt="">
Stream SBOMs from any S3-compatible bucket — AWS, MinIO, GCS, Oracle Cloud.
No PVCs, no git-sync, scales to any repo size.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-file-code" title="API &amp; UI" url="/docs/architecture/#api-endpoints" %}}
<img class="fb-icon-lg me-1" src="/images/flowbite/code-branch.svg" alt="">
REST endpoints power a modern Angular interface with search, virtual scrolling,
and configurable theming.
{{% /blocks/feature %}}

{{% blocks/feature icon="fa-server" title="Cloud Native" url="/docs/deployment/" %}}
<img class="fb-icon-lg me-1" src="/images/flowbite/rocket.svg" alt="">
Helm chart with 19 templates. ClickHouse Operator for stateful lifecycle.
Docker Compose for local development.
{{% /blocks/feature %}}

{{< /blocks/section >}}
