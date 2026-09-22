# Organization-managed license exceptions

BOMHort starts with **no license exceptions**. Neither Helm nor Docker Compose
automatically imports CNCF approvals. The default license **classification policy**
is separate and is unchanged.

`license-exceptions.example.json` demonstrates the structure, not recommended
approvals. It is outside the scanned SBOM directory and every example rule is
`pending`, so copying it alone does not exempt anything.

## Configure

1. Copy the example to `my-exceptions.json`.
2. Remove unused rules (especially the blanket example), replace placeholders,
   and review the actual package, project, and license scope with your organization.
3. Record the approval date and decision reference. Only explicitly approved rules
   should have `status: "approved"`.
4. Configure the file through Helm:

   ```bash
   helm upgrade --install bomhort deploy/helm/bomhort -n bomhort \
     -f my-values.yaml --set-file licenseExceptions.custom=./my-exceptions.json
   ```

Keep this file/setting in your deployment configuration for subsequent upgrades.
Helm accepts `licenseExceptions.custom` as either a JSON string (`--set-file`) or
a YAML object. Template expressions inside comments are treated as literal data,
not evaluated using `tpl`.

An explicitly empty values template is:

```yaml
licenseExceptions:
  enabled: true
  custom:
    version: "1.0.0"
    blanketExceptions: []
    exceptions: []
```

For Docker Compose, put your reviewed configuration in
`sboms/license-exceptions.json` and recreate/restart both `api-gateway` and
`parsing-worker`. For standalone binaries, point `EXCEPTIONS_FILE` to the file.

### Argo CD

Use Git-backed `helm.valueFiles` or `helm.valuesObject.licenseExceptions.custom`
in your Application instead of a local `helm upgrade --set-file` command.
The [Argo CD example and checklist](../../docs/content/docs/deployment/_index.md#argo-cd-gitops)
show an inactive `valuesObject` example and explain the required chart/image revisions.

An exception change updates the ConfigMap and both Deployment pod-template
checksums. Sync all three resources so API and worker pods receive the new file;
unchanged values do not trigger extra rollouts. Manage approvals in Git, not by
editing the live ConfigMap. An Argo sync does not re-process existing SBOMs;
the migration and re-scan requirements below still apply.

## Matching contract

- Both `blanketExceptions` and `exceptions` must be JSON arrays, including when
  empty. Unknown fields are rejected; use `blanketExceptions`, not
  `blanket_exceptions`, and `package`, not `purl_prefix`. The provenance fields
  `results`, `issueUrl` and `packageUrl` are accepted and carried through as
  audit metadata, so files exported from a published exception registry load
  without editing.
- Only `approved` and `allowlisted` rules are active (case-insensitive status
  comparison). `allowlisted` means approved in bulk under a standing allowlist
  policy rather than case by case, which is identical in effect. Everything
  else — `pending`, `revoked`, `denied`, `not-eligible`, a permissive-license
  marker such as `apache-2.0`, or a typo — is inactive. An unrecognised status
  never becomes an approval.
- `blanketExceptions` intentionally exempts an entire license for **all packages
  and projects**. Existing SPDX modifier-prefix matching is retained, e.g.
  `MPL-2.0` also covers `MPL-2.0-no-copyleft-exception`.
- An `exceptions` rule always requires a package. Names match case-sensitively,
  exactly or as a complete slash-delimited suffix: `team/library` can match
  `example.org/team/library`, but not `notteam/library`, `team/library-evil`,
  or `team/library/submodule`. Prefer fully qualified names to avoid ambiguity.
  Package PURL/glob patterns are **not** supported.
- `project` matches the **exact SBOM `document_name`**, not the UI's grouped project
  label. Omit it or use `"*"` for all projects. A scope phrased as
  `all <qualifier> projects` — `"All Projects"`, `"All CNCF Projects"`,
  `"all internal projects"` — is also a wildcard, because that is how published
  registries spell a global scope; compared literally it would match no document
  name at all and the rule would silently exempt nothing. The qualifier must be a
  single word, so a real project named `"All Things Open Projects WG"` stays a
  literal name. No project value removes a rule's package restriction.

- `license` matches exact SPDX IDs. Comma-, ` OR `-, and ` AND `-separated rule
  values expand into individual license IDs; this is not a full SPDX expression
  evaluator. Omitting `license` grants **any license** for the named package, so
  prefer specifying it explicitly.
- Multiple rules for the same package/license retain their separate project
  scopes. Matching is deterministic: exact package/license, suffix package/license,
  exact package-only, then suffix package-only; ties use file order.
- `scope`, `approvedDate`, `results`, and `comment` are audit metadata, **not**
  executable conditions. Linkage, modifications, expiry, and deployment cluster
  are not inferred or enforced.

## Loading and upgrades

The first existing file wins, even if both lists are empty. Only a **missing**
primary file allows fallback to `SBOM_DIR/license-exceptions.json`. Invalid JSON,
incorrect structure, or an unreadable file is an error, not permission to load
another list. The worker stops on invalid configuration; exception-related API
requests return HTTP 500 instead of pretending there are no configured rules.
Missing optional files still mean no exceptions.

To disable all approvals, keep the ConfigMap enabled and supply empty lists.
`licenseExceptions.enabled: false` only disables the Helm mount; a deliberately
supplied file in `SBOM_DIR` can still be loaded by the legacy fallback.

Migration from older versions:

1. Remove `seedJob.cncfExceptionsURL` from your values (also clear retained Helm
   values if using `--reuse-values`). The chart rejects the old download option
   with a migration hint rather than silently changing your approvals.
2. Review any imported approvals and their package/project restrictions; provide
   only your intended rules through `licenseExceptions.custom`.
3. Helm changes now update checksums on **both** API Gateway and worker pod
   templates. This is necessary because `subPath` ConfigMap mounts do not update
   in running pods. Direct `kubectl edit configmap` still requires manually
   restarting both deployments and will be overwritten by Helm upgrades.
4. **Re-process existing SBOMs** to refresh stored compliance results, especially
   when revoking/removing previously broad approvals. Ingestion writes exempted
   and violating packages separately; query-time filtering cannot restore
   packages omitted by an old approval. Merely restarting services or running
   the watcher is insufficient because unchanged SBOMs are hash-deduplicated.

Plan and back up a full re-scan for existing installations. The development
helpers `make re-scan` and `make kind-reingest` are **destructive full rebuilds of
ingested data**, not license-only refresh commands; do not run them blindly in
production. This change does not modify or delete deployed data automatically.

## Regression checks

```bash
cd backend && go test ./internal/license ./cmd/api-gateway -count=1
# From repository root:
helm lint deploy/helm/bomhort
python3 -B -m unittest discover -s deploy/helm/tests -v
```
