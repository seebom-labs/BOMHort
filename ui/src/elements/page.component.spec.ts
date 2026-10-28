import { describe, expect, it } from 'vitest';
import { MemoryLocationStrategy } from './page.component';

describe('MemoryLocationStrategy', () => {
  it('joins path and query whether or not the query already starts with ?', () => {
    const loc = new MemoryLocationStrategy();
    loc.pushState(null, '', '/cve-impact', '?vuln=x');
    expect(loc.path()).toBe('/cve-impact?vuln=x');
    loc.replaceState(null, '', '/cve-impact', 'vuln=y');
    expect(loc.path()).toBe('/cve-impact?vuln=y');
    loc.pushState(null, '', '/projects', '');
    expect(loc.path()).toBe('/projects');
  });
});
