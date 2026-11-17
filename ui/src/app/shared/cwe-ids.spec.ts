import { describe, expect, it } from 'vitest';
import { cweUrl, topCwes } from './cwe-ids';

describe('cwe-ids', () => {
  it('builds the MITRE definition URL for a CWE id', () => {
    expect(cweUrl('CWE-79')).toBe('https://cwe.mitre.org/data/definitions/79.html');
  });

  it('counts weakness classes across findings, most common first', () => {
    const vulns = [
      { cwe_ids: ['CWE-79', 'CWE-80'] },
      { cwe_ids: ['CWE-79'] },
      { cwe_ids: undefined },
      {},
    ];
    expect(topCwes(vulns)).toEqual([
      { label: 'CWE-79', value: 2 },
      { label: 'CWE-80', value: 1 },
    ]);
  });

  it('breaks count ties alphabetically and caps the list', () => {
    const vulns = [
      { cwe_ids: ['CWE-200', 'CWE-79'] },
      { cwe_ids: ['CWE-79', 'CWE-200'] },
      { cwe_ids: ['CWE-80'] },
    ];
    const got = topCwes(vulns, 2);
    expect(got.map((s) => s.label)).toEqual(['CWE-200', 'CWE-79']);
  });

  it('returns an empty list when no finding carries CWEs', () => {
    expect(topCwes([{ cwe_ids: [] }, {}])).toEqual([]);
  });
});
