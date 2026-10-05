---
title: "License Resolution"
linkTitle: "License Resolution"
type: docs
weight: 6
description: >
  How BOMHort turns NOASSERTION into a license, which heuristics it applies, what
  it deliberately refuses to guess, and how every decision is tested.
---

SBOM generators frequently write `NOASSERTION` instead of a license: container
scanners cannot see a package's metadata, lockfile-based generators never read
it, and some ecosystems have no license field at all. BOMHort fills these gaps at
ingest time from public sources. Every rule it applies is listed on this page,
including the ones it **deliberately does not apply** because guessing would turn
an unknown license into an approved one without anyone having decided so.

Two principles hold throughout:

1. **A declared license always wins.** Resolution only touches packages whose
   license is `NOASSERTION`, `NONE` or empty. It never overrides what the SBOM
   states. Free-text normalization rewrites how a declared license is spelled,
   not which license it is.
2. **Every package says where its license came from, or why it has none.** The
   parsing worker stores a *license source* next to each package license
   (`sbom_packages.package_license_sources`, migration `024`,
   [#439](https://github.com/seebom-labs/bomhort/issues/439)). An unknown
   license is no longer a dead end: it carries a reason, so you can tell an
   actionable gap from one where looking further makes no sense.

## Pipeline

The parsing worker runs these steps for every SBOM, **before** the ClickHouse
insert, so the stored package licenses are already final
(`backend/cmd/parsing-worker/license_provenance.go`):

| Step | What happens | Source recorded |
|------|--------------|-----------------|
| 1. Parse | Declared licenses are read from the SBOM. Broken Yarn Berry PURLs are repaired here (see [D7](#d7-repair-yarn-berry-purls)). | `declared` |
| 2. GitHub | For unknown licenses whose PURL maps to a GitHub repository, the repository license is used. | `github` |
| 3. Registries | Still-unknown packages are offered to the registry resolvers, **in this order**: npm → NuGet → deps.dev → Packagist → PyPI. The first resolver that returns a license wins. | `npm`, `nuget`, `depsdev`, `packagist`, `pypi` |
| 4. Normalize | Every license (declared or resolved) is rewritten to its SPDX form (see [D2](#d2-normalize-only-unambiguous-free-text)). If that changed it, `+normalized` is appended. | `…+normalized` |
| 5. Explain | Every package that is *still* unknown gets the reason why (see the vocabulary below). | a reason |
| 6. Compliance | First-party packages are excluded; everything else is categorized against the license policy. | – |

Registry results, positive and negative, are cached in `registry_license_cache`
and GitHub results in `github_license_cache`, so each package version is looked
up at most once across all workers and restarts.

## License source vocabulary

<!-- license-sources:start -->
| Value | Kind | Meaning |
|-------|------|---------|
| `declared` | origin | The SBOM itself stated the license. |
| `github` | origin | The GitHub repository license (`/repos/{owner}/{repo}` and `/license` API). |
| `npm` | origin | registry.npmjs.org version manifest. |
| `nuget` | origin | NuGet V3 catalog entry (`licenseExpression`, well-known `licenseUrl`). |
| `depsdev` | origin | deps.dev version batch API (Maven, PyPI, Cargo, Go, npm, NuGet). |
| `packagist` | origin | repo.packagist.org (Composer). |
| `pypi` | origin | pypi.org JSON API. |
| `latest` | modifier | The exact version had no license (or the SBOM gave no usable version), so the newest release's license was used. |
| `normalized` | modifier | Free text such as `Apache License 2.0` was rewritten to an SPDX ID. |
| `first-party` | reason | The project's own code (SBOM root, Yarn workspace, Maven `${project.*}` module). Excluded from the compliance check. |
| `no-purl` | reason | The SBOM gives no package URL, so there is nothing to look up. |
| `unsupported-ecosystem` | reason | No resolver covers the PURL type (`generic`, `deb`, `apk`, `oci`, …). |
| `not-published` | reason | The registry does not know the package or version: private, internal, or deleted. |
| `no-license-upstream` | reason | The registry knows the package, but its author declared no license. Legally that means *all rights reserved*. |
| `unresolved` | reason | A resolver covers the package but gave no answer: disabled, rate-limited, network error, or a negative result cached before reasons were recorded. Usually worth a re-scan. |
<!-- license-sources:end -->

Modifiers are joined with `+`: `depsdev+latest+normalized`. SBOMs ingested
before BOMHort recorded sources have no value; the API reports them as
`unrecorded` until the next re-scan.

### Where you see it

- **License Compliance page → License Resolution** (open by default; clicking the
  *Unknown* card jumps there):
  - a summary: how many packages the SBOMs left without a license, how many of
    them BOMHort resolved from public registries (and what share), and how many
    remain unknown;
  - packages per source, with example package names on hover;
  - a table of the remaining unknowns per reason with package and SBOM counts,
    example packages and what you can do about each reason. First-party
    components are listed separately as *not counted*, because they are excluded
    from license compliance ([D8](#d8-first-party-code-is-not-a-dependency)).
    The table's package total equals the plain `NOASSERTION` entry of the
    license list; the *Unknown* card can be slightly higher because it also
    counts expressions that are only partly unknown, e.g.
    `GPL-2.0-only AND NOASSERTION`.
- **SBOM → Dependencies tab**: hover a license to see where it came from.
- **API**: `GET /api/v1/licenses/sources` and the `license_source` field of
  `GET /api/v1/sboms/{id}/dependencies` (see the [API Reference](/docs/api-reference/)).

## Decision log

Each entry states the decision, why it was taken, what can go wrong, how to turn
it off, and which test pins it.

### D1. Declared licenses are never overridden

- **Decision:** Resolvers only run for `NOASSERTION`, `NONE` and empty licenses.
- **Why:** The SBOM author knows the artifact; a registry may describe a
  different build of the package.
- **Risk:** A wrong declared license stays wrong. Fix it in the SBOM or with an
  exception.
- **Test:** `TestLicensePipelineGolden` (`declared-*` rows).

### D2. Normalize only unambiguous free text

- **Decision:** Free-text names are rewritten to SPDX IDs only when the spelling
  names one license unambiguously, usually by including an explicit version
  (`Apache License, Version 2.0`, `MPL 2.0`, `GNU General Public License v2 or later`).
  This also applies inside expressions and to raw names returned by registries.
- **Why:** An SPDX ID can be matched against the policy; free text cannot.
- **Risk:** A spelling that looks unambiguous could hide a modified license
  text. The rules are deliberately narrow; see the
  [normalization examples](#normalization-examples).
- **Switch:** None. The stored license changes spelling only.
- **Test:** `internal/license/normalize_test.go`, `TestDocsLicenseResolutionInSync`.

### D3. Ambiguous names are not guessed

- **Decision:** `BSD` (which clause count?), `Apache Software License` (1.1 or
  2.0?), `Public Domain` (no SPDX ID) and similar are kept as declared and
  categorized **unapproved**. The same goes for the ambiguous PyPI classifiers
  `License :: OSI Approved :: BSD License` and `… :: Apache Software License`.
- **Why:** Mapping them would approve a license nobody approved.
- **Resolve it by:** fixing the SBOM, adding the exact ID to the policy, or adding
  a license exception (see the [deployment guide](/docs/deployment/)).

### D4. Unrecognised names become a LicenseRef, not NOASSERTION

- **Decision:** A license name that is not SPDX and not mappable is stored as
  `LicenseRef-<name>` (`Remix Icon License 1.0` → `LicenseRef-Remix-Icon-License-1.0`).
  Composer's `proprietary` becomes `LicenseRef-proprietary`.
- **Why:** The package *has* a declared license; reporting it as unknown would
  hide that. As a LicenseRef it is **unapproved** and can be approved by that
  exact ID.
- **Not a license:** URLs and `NOASSERTION`/`NONE` are never turned into a
  LicenseRef. They carry no license name.
- **Test:** `internal/license/normalize_test.go`.

### D5. Deprecated SPDX IDs map to their current form

- **Decision:** `GPL-2.0` → `GPL-2.0-only`, `GPL-2.0+` → `GPL-2.0-or-later`,
  `GPL-2.0-with-classpath-exception` → `GPL-2.0-only WITH Classpath-exception-2.0`
  for categorization (and the LGPL/AGPL equivalents).
- **Why:** The SPDX list deprecated them; the policy lists only the current IDs.
- **Test:** `internal/license/expression_test.go`, golden row `declared-deprecated`.

### D6. Expressions fold into one category

- **Decision:** `AND`, `OR` and `WITH` are parsed and folded according to
  `LICENSE_EXPRESSION_MODE` (`strict` by default). See
  [Compound SPDX expressions](/docs/deployment/#compound-spdx-expressions).
- **Test:** golden rows `declared-or`, `declared-and`.

### D7. Repair Yarn Berry PURLs

- **Decision:** Lockfile keys copied verbatim into PURLs
  (`pkg:npm/ws@npm:^8.18.0, ws@8.20.0`, `fsevents@patch:…`) are reduced to the
  resolved name and version at parse time.
- **Why:** Neither npm nor OSV can match the raw key, so licenses stayed unknown
  and vulnerabilities were missed.
- **Test:** golden row `fsevents`.

### D8. First-party code is not a dependency

- **Decision:** These packages get the reason `first-party` and are excluded from
  the compliance check (they stay in the package list):
  - the SBOM's root package(s);
  - Yarn workspace packages (`pkg:npm/…@0.0.0-use.local`);
  - Maven modules whose coordinates are unresolved `${project.*}` placeholders.
- **Not first-party:** other unresolved placeholders such as
  `scalatest_${scala.compat.version}`. That is a third-party artifact whose
  coordinates the generator failed to expand.
- **Why:** The project's own license is not a third-party compliance question,
  and nobody can look it up in a registry.
- **Test:** `cmd/parsing-worker/first_party_test.go`, golden rows `golden-app`,
  `@golden/web`, `golden-core`.

### D9. Missing versions fall back to the latest release

- **Decision:** When the SBOM gives no usable version (`pkg:pypi/requests`,
  `…@unknown`, `${project.version}`) or the registry has no license for a Composer
  dev branch (`dev-main`), the license of the newest stable release is used and
  the source gets `+latest`.
- **Why:** Licenses rarely change between releases, and without a version there
  is nothing more precise to ask.
- **Risk:** A project that relicensed (for example from Apache-2.0 to BSL) is
  reported with its *current* license. Check `+latest` entries if this matters.
- **Exception:** PyPI does **not** fall back when a concrete version is missing
  on PyPI. PyPI names are global, so a missing version usually means a
  different, private package with the same name.
- **Test:** `npm`, `depsdev`, `packagist` and `pypi` resolver tests, golden rows
  `npm-versionless`, `monolog/monolog`.

### D10. Resolver order and precedence

- **Decision:** GitHub first, then npm → NuGet → deps.dev → Packagist → PyPI. The
  first license found wins. Native registries run before deps.dev for their own
  ecosystem. PyPI runs last, so it only sees what deps.dev could not map.
- **Why:** The ecosystem's own registry is authoritative. deps.dev covers several
  ecosystems with one batch call. PyPI's free-text fields need the most
  heuristics, so they are only consulted when nothing better exists.
- **Test:** `TestLicensePipelineGolden` (row `typing-extensions`: deps.dev had
  nothing, PyPI did), `TestDocsLicenseResolutionInSync` (resolver order).

### D11. PyPI field precedence

- **Decision:** `license_expression` (PEP 639) → an explicit classifier → SPDX
  table → a *short* free-text `license` field via
  [D2](#d2-normalize-only-unambiguous-free-text) / [D4](#d4-unrecognised-names-become-a-licenseref-not-noassertion)
  → the first unmapped classifier as a LicenseRef. Long `license` fields (full
  license texts pasted into metadata) are ignored.
- **Test:** `internal/pypi/resolver_test.go`.

### D12. Multiple licenses: AND vs OR

- **Decision:** Packagist's `license` array is joined with `OR`, because Composer
  defines it as a choice. deps.dev's list is joined with `AND`, because it lists
  every license the package declares.
- **Test:** `packagist` and `depsdev` resolver tests.

### D13. Negative results are cached with their reason

- **Decision:** A package that a registry does not know, or that declares no
  license, is cached as a negative result *with its reason*, so it is not looked
  up again on every ingest and the reason survives restarts.
- **Risk:** A package that gets published or licensed later stays negative until
  its cache row is removed (see [Operations](#operations)).
- **Test:** `npm`, `depsdev`, `packagist`, `pypi` resolver tests.

### D14. gopkg.in import paths map to their GitHub repository

- **Decision:** Besides the well-known table, `gopkg.in/pkg.vN` →
  `github.com/go-pkg/pkg` and `gopkg.in/user/pkg.vN` → `github.com/user/pkg`,
  following gopkg.in's documented redirect rule.
- **Test:** `internal/github/purl_test.go`.

## Deliberately not guessed

| Input | Stays | Why |
|-------|-------|-----|
| `BSD`, `BSD License` | unapproved | 2-clause, 3-clause and 4-clause differ legally |
| `Apache Software License` | unapproved | Apache-1.1 or Apache-2.0 |
| `Public Domain` | unapproved | No SPDX ID; jurisdictions differ |
| `GPL`, `LGPL` without a version | unapproved | -only vs -or-later, version 2 vs 3 |
| A license URL | unknown | A URL can point anywhere and change over time |
| The latest release's license for a missing PyPI version | unknown | Probably a private package with the same name |
| A Maven parent POM's license | unknown | Not implemented, see below |

## Known limitations

- **Maven parent POM inheritance.** Many Maven artifacts inherit their license
  from a parent POM, and deps.dev reports no license for them
  (`org.apache.commons:commons-pool2:2.13.1`). Resolving parent chains would need
  a Maven-specific resolver. Such packages show `no-license-upstream`.
- **Artifacts outside Maven Central** (for example Confluent's repository) are
  `not-published` from deps.dev's point of view.
- **NuGet** does not report reasons yet; unresolved NuGet packages show
  `unresolved`.
- **Archived-repository view.** `GET /api/v1/packages/archived` maps
  repositories back to packages using the well-known module table only, not the
  generic gopkg.in rule from [D14](#d14-gopkgin-import-paths-map-to-their-github-repository).
- **Cache entries never expire.** Licenses can change upstream; see
  [Operations](#operations) for how to refresh them.

## Normalization examples

How a license name returned by a registry is stored (`license.Recover`). Each
row is checked by `TestDocsLicenseResolutionInSync` against the code and the
built-in default policy in `strict` mode. Change the code and this table
together.

A license *declared in the SBOM* goes through the same spelling rules
(`license.Normalize`) with one difference: a name that matches no rule is kept
verbatim (`Public Domain`) instead of becoming a LicenseRef. The category is the
same either way, which the test also checks.

<!-- normalize-examples:start -->
| Registry text | Stored as | Category |
|--------------------------|-----------|----------|
| `Apache License, Version 2.0` | `Apache-2.0` | permissive |
| `The Apache Software License, Version 2.0` | `Apache-2.0` | permissive |
| `The MIT License` | `MIT` | permissive |
| `Expat` | `MIT` | permissive |
| `New BSD License` | `BSD-3-Clause` | permissive |
| `Simplified BSD License` | `BSD-2-Clause` | permissive |
| `Eclipse Distribution License - v 1.0` | `BSD-3-Clause` | permissive |
| `Go License` | `BSD-3-Clause` | permissive |
| `Bouncy Castle Licence` | `MIT` | permissive |
| `Python Software Foundation License` | `PSF-2.0` | permissive |
| `MPL 2.0` | `MPL-2.0` | copyleft |
| `EPL 2.0` | `EPL-2.0` | copyleft |
| `GNU General Public License v2 or later` | `GPL-2.0-or-later` | copyleft |
| `GPL-2.0` | `GPL-2.0-only` | copyleft |
| `GPL-2.0+` | `GPL-2.0-or-later` | copyleft |
| `GNU General Public License, version 2 with the GNU Classpath Exception` | `GPL-2.0-only WITH Classpath-exception-2.0` | copyleft |
| `MIT OR GPL-3.0-only` | `MIT OR GPL-3.0-only` | permissive |
| `MIT AND GPL-3.0-only` | `MIT AND GPL-3.0-only` | copyleft |
| `CC BY-SA 4.0` | `CC-BY-SA-4.0` | unapproved |
| `CDDL 1.1` | `CDDL-1.1` | unapproved |
| `BSD` | `BSD` | unapproved |
| `Apache Software License` | `LicenseRef-Apache-Software-License` | unapproved |
| `Public Domain` | `LicenseRef-Public-Domain` | unapproved |
| `Remix Icon License 1.0` | `LicenseRef-Remix-Icon-License-1.0` | unapproved |
| `proprietary` | `LicenseRef-proprietary` | unapproved |
| `https://example.com/LICENSE` | `NOASSERTION` | unknown |
<!-- normalize-examples:end -->

Categories depend on your license policy. The table uses the built-in default,
so `CC-BY-SA-4.0` or `CDDL-1.1` may well be approved in yours.

## Worked examples

One synthetic SBOM covers every path through the pipeline:
`backend/cmd/parsing-worker/testdata/license_golden.spdx.json`.
`TestLicensePipelineGolden` runs it through the real parser, the real pipeline
(with recorded registry answers) and the real policy. The table below must match
that test's expectations exactly; `TestDocsLicenseResolutionInSync` fails
otherwise.

<!-- golden:start -->
| Package | Case | License | Source | Category | Compliance check |
|---------|------|---------|--------|----------|------------------|
| `golden-app` | SBOM root | `NOASSERTION` | `first-party` | unknown | excluded |
| `declared-mit` | Declared SPDX ID | `MIT` | `declared` | permissive | checked |
| `declared-freetext` | Declared `Apache License 2.0` | `Apache-2.0` | `declared+normalized` | permissive | checked |
| `declared-deprecated` | Declared `GPL-2.0+` | `GPL-2.0-or-later` | `declared+normalized` | copyleft | checked |
| `declared-or` | Choice | `MIT OR GPL-3.0-only` | `declared` | permissive | checked |
| `declared-and` | Conjunction | `MIT AND GPL-3.0-only` | `declared` | copyleft | checked |
| `declared-custom` | Custom license | `LicenseRef-Remix-Icon-License-1.0` | `declared` | unapproved | checked |
| `github.com/acme/lib` | Go module on GitHub | `MIT` | `github` | permissive | checked |
| `npm-pkg` | npm, exact version | `ISC` | `npm` | permissive | checked |
| `npm-versionless` | npm, no version | `MIT` | `npm+latest` | permissive | checked |
| `fsevents` | Yarn `patch:` PURL | `MIT` | `npm` | permissive | checked |
| `commons-lang3` | Maven via deps.dev | `Apache-2.0` | `depsdev` | permissive | checked |
| `jakarta.xml.bind-api` | Raw POM license name | `BSD-3-Clause` | `depsdev+normalized` | permissive | checked |
| `monolog/monolog` | Composer `dev-main` | `MIT` | `packagist+latest` | permissive | checked |
| `typing-extensions` | deps.dev empty, PyPI has it | `PSF-2.0` | `pypi` | permissive | checked |
| `internal-ui` | Private npm package | `NOASSERTION` | `not-published` | unknown | checked |
| `@golden/web` | Yarn workspace | `NOASSERTION` | `first-party` | unknown | excluded |
| `golden-core` | Maven `${project.groupId}` module | `NOASSERTION` | `first-party` | unknown | excluded |
| `legacy-tool` | Published without a license | `NOASSERTION` | `no-license-upstream` | unknown | checked |
| `libc.so.6` | `pkg:generic` | `NOASSERTION` | `unsupported-ecosystem` | unknown | checked |
| `vendored-blob` | No PURL | `NOASSERTION` | `no-purl` | unknown | checked |
| `flaky-crate` | Registry error | `NOASSERTION` | `unresolved` | unknown | checked |
<!-- golden:end -->

## Operations

| Setting | Effect |
|---------|--------|
| `SKIP_GITHUB_RESOLVE=true` | Disable step 2 |
| `SKIP_NPM_RESOLVE`, `SKIP_NUGET_RESOLVE`, `SKIP_DEPSDEV_RESOLVE`, `SKIP_PACKAGIST_RESOLVE`, `SKIP_PYPI_RESOLVE` | Disable one registry resolver |
| `LICENSE_EXPRESSION_MODE` | How expressions fold ([D6](#d6-expressions-fold-into-one-category)) |

Resolution happens at ingest. After changing settings or upgrading, re-process
the SBOMs (`make re-scan` locally, or a re-ingest on Kubernetes, see the
[deployment guide](/docs/deployment/)).

To re-check packages that were negative, delete their cache rows before the
re-scan:

```sql
-- negatives cached before reasons were recorded
ALTER TABLE registry_license_cache DELETE WHERE spdx_id = '';
-- all negatives of one registry
ALTER TABLE registry_license_cache DELETE WHERE registry = 'pypi' AND startsWith(spdx_id, '!');
```

## Tests

| Test | Covers |
|------|--------|
| `cmd/parsing-worker/golden_test.go` | End-to-end: parser → resolvers → normalization → reasons → policy → compliance exclusion |
| `cmd/parsing-worker/docs_sync_test.go` | This page's vocabulary, resolver order, normalization and worked-example tables match the code |
| `cmd/parsing-worker/first_party_test.go` | First-party detection ([D8](#d8-first-party-code-is-not-a-dependency)) |
| `internal/license/normalize_test.go`, `expression_test.go` | Normalization, deprecated IDs, expression folding |
| `internal/{npm,nuget,depsdev,packagist,pypi}/*_test.go` | Each registry's parsing, version fallback and negative reasons (recorded HTTP responses) |
| `internal/github/purl_test.go` | PURL → repository mapping |
