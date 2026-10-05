/**
 * Human-readable labels for package license provenance (`license_source`).
 *
 * The vocabulary is defined in backend/internal/license/source.go and
 * documented on the "License Resolution" docs page; keep all three in sync.
 */

const ORIGIN_LABELS: Record<string, string> = {
  declared: 'Declared in the SBOM',
  github: 'GitHub repository license',
  npm: 'npm registry',
  nuget: 'NuGet registry',
  depsdev: 'deps.dev',
  packagist: 'Packagist',
  pypi: 'PyPI',
};

const REASON_LABELS: Record<string, string> = {
  'first-party': 'First-party component (the project itself or one of its own modules)',
  'not-published': 'Not published on a public registry (private or internal package)',
  'no-license-upstream': 'The registry has the package, but no license is declared upstream',
  'no-purl': 'No package URL, so there is nothing to look up',
  'unsupported-ecosystem': 'No license resolver exists for this ecosystem',
  unresolved: 'All lookups failed or returned no result',
  unrecorded: 'Ingested before BOMHort recorded license sources; re-scan to fill in',
};

/** What an operator can do about each unresolved reason. */
const REASON_HINTS: Record<string, string> = {
  'first-party': 'A project\'s own code is not a third-party dependency, so it is excluded from license compliance.',
  'not-published':
    'Internal packages are not on any public registry. Declare the license in the SBOM generator, or add a license exception.',
  'no-license-upstream':
    'Ask the upstream project to declare a license (Maven artifacts often inherit it from a parent POM), or add an exception after review.',
  'no-purl': 'Configure the SBOM generator to emit package URLs.',
  'unsupported-ecosystem':
    'Usually pkg:generic files or system libraries. Scan the image with a tool that reads OS package metadata, or add an exception.',
  unresolved:
    'Lookups failed or matched nothing, e.g. unresolved build variables in the coordinates. Re-scan later or fix the SBOM.',
  unrecorded: 'Re-scan the SBOM to record where its licenses come from.',
};

/** Reasons that do not count as an open compliance gap. */
const EXCLUDED_FROM_COMPLIANCE = new Set(['first-party']);

export function licenseReasonHint(origin: string): string {
  return REASON_HINTS[origin] ?? '';
}

export function isExcludedFromCompliance(origin: string): boolean {
  return EXCLUDED_FROM_COMPLIANCE.has(origin);
}

const MODIFIER_LABELS: Record<string, string> = {
  latest: 'taken from the latest release, not the exact version',
  normalized: 'normalized to an SPDX identifier',
};

export interface LicenseSourceInfo {
  origin: string;
  modifiers: string[];
  resolved: boolean;
  label: string;
}

export function describeLicenseSource(source?: string | null): LicenseSourceInfo | null {
  if (!source) {
    return null;
  }
  const [origin, ...modifiers] = source.split('+');
  const resolved = !(origin in REASON_LABELS);
  const base = ORIGIN_LABELS[origin] ?? REASON_LABELS[origin] ?? origin;
  const extras = modifiers.map((m) => MODIFIER_LABELS[m] ?? m);
  const label = extras.length ? `${base} (${extras.join('; ')})` : base;
  return { origin, modifiers, resolved, label };
}

/** Tooltip text for a dependency's license cell; empty when nothing was recorded. */
export function licenseSourceTooltip(source?: string | null): string {
  const info = describeLicenseSource(source);
  if (!info) {
    return '';
  }
  return info.resolved ? `Source: ${info.label}` : `Unknown: ${info.label}`;
}
