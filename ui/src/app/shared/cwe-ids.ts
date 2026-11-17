// CWE weakness-class helpers for the register views (#409).
//
// A register row names the weakness class next to the CVE: small chips in
// the list rows, a "top weakness classes" breakdown on the project overview.
// Findings without CWEs (NVD-sourced OSV entries often list none) never
// render a chip and are not counted.

export const CWE_BASE_URL = 'https://cwe.mitre.org/data/definitions/';

/** Definition URL for a stored CWE id like "CWE-79". */
export function cweUrl(cwe: string): string {
  return CWE_BASE_URL + cwe.replace(/^CWE-/i, '') + '.html';
}

/** Top weakness classes across findings: total occurrences per id, most
 *  common first, ties alphabetical, capped at `max`. */
export function topCwes(
  vulns: Array<{ cwe_ids?: string[] }>,
  max = 5,
): Array<{ label: string; value: number }> {
  const counts = new Map<string, number>();
  for (const v of vulns) {
    for (const cwe of v.cwe_ids ?? []) {
      counts.set(cwe, (counts.get(cwe) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, max)
    .map(([label, value]) => ({ label, value }));
}
