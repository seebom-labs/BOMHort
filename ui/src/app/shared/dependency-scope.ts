import type { DependencyScope } from '../core/api.models';

/**
 * Labels and explanations for how a package is pulled into a product
 * (`dependency_scope`). Vocabulary: backend/internal/depgraph.
 */

const LABELS: Record<DependencyScope, string> = {
  root: 'ROOT',
  direct: 'DIRECT',
  transitive: 'TRANSITIVE',
  unknown: 'UNKNOWN',
};

const TITLES: Record<DependencyScope, string> = {
  root: 'The product the SBOM describes',
  direct: 'Declared directly by the product',
  transitive: 'Pulled in by another dependency',
  unknown: 'The SBOM carries no dependency graph for this package, or it was ingested before BOMHort recorded depths (re-scan to fill in)',
};

export function scopeLabel(scope: DependencyScope | undefined): string {
  return LABELS[scope ?? 'unknown'] ?? LABELS.unknown;
}

export function scopeTitle(scope: DependencyScope | undefined, depth?: number, reason?: string): string {
  if (scope === 'unknown' && reason === 'no-dependency-graph') {
    return 'The SBOM contains a flat component list with no dependency graph relationships (generator limitation)';
  }
  const base = TITLES[scope ?? 'unknown'] ?? TITLES.unknown;
  return depth !== undefined && scope === 'transitive' ? `${base} (depth ${depth})` : base;
}

/** CSS modifier class for the scope badge. */
export function scopeClass(scope: DependencyScope | undefined): string {
  return `scope-${scope ?? 'unknown'}`;
}

/** Scope for a package name from a `package_scopes` map. */
export function scopeOf(
  scopes: Record<string, DependencyScope> | undefined,
  name: string,
): DependencyScope {
  return scopes?.[name] ?? 'unknown';
}

/** Filter options offered on findings lists. '' = no filter. */
export const SCOPE_FILTERS: { value: '' | DependencyScope; label: string }[] = [
  { value: '', label: 'All dependencies' },
  { value: 'direct', label: 'Direct only' },
  { value: 'transitive', label: 'Transitive only' },
  { value: 'unknown', label: 'Unknown scope' },
];
