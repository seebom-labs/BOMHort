/**
 * purlEcosystem extracts the ecosystem identifier from a Package URL (PURL),
 * e.g. "pkg:npm/crossenv@1.0.0" -> "npm", "pkg:pypi/requests" -> "pypi".
 */
export function purlEcosystem(purl?: string): string {
  if (!purl || !purl.startsWith('pkg:')) return '';
  const rest = purl.substring(4);
  const slash = rest.indexOf('/');
  if (slash <= 0) return '';
  return rest.substring(0, slash).toLowerCase();
}

