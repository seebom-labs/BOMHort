import { describe, it, expect } from 'vitest';
import { purlEcosystem } from './purl';

describe('purlEcosystem', () => {
  it('extracts ecosystem from valid PURLs', () => {
    expect(purlEcosystem('pkg:npm/crossenv@1.0.0')).toBe('npm');
    expect(purlEcosystem('pkg:pypi/requests@2.28.0')).toBe('pypi');
    expect(purlEcosystem('pkg:golang/github.com/gin-gonic/gin@v1.9.0')).toBe('golang');
    expect(purlEcosystem('pkg:maven/org.apache.commons/commons-lang3@3.12.0')).toBe('maven');
    expect(purlEcosystem('pkg:cargo/serde@1.0.104')).toBe('cargo');
  });

  it('handles empty or malformed inputs', () => {
    expect(purlEcosystem('')).toBe('');
    expect(purlEcosystem(undefined)).toBe('');
    expect(purlEcosystem('invalid-purl')).toBe('');
    expect(purlEcosystem('pkg:')).toBe('');
    expect(purlEcosystem('pkg:nonamespace')).toBe('');
  });
});
