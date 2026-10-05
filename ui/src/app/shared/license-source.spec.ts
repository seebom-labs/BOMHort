import { describeLicenseSource, isExcludedFromCompliance, licenseReasonHint, licenseSourceTooltip } from './license-source';

describe('license-source', () => {
  it('returns null for missing sources (pre-migration rows)', () => {
    expect(describeLicenseSource('')).toBeNull();
    expect(describeLicenseSource(undefined)).toBeNull();
    expect(licenseSourceTooltip(null)).toBe('');
  });

  it('labels resolved sources with their modifiers', () => {
    const info = describeLicenseSource('depsdev+latest+normalized')!;
    expect(info.origin).toBe('depsdev');
    expect(info.modifiers).toEqual(['latest', 'normalized']);
    expect(info.resolved).toBe(true);
    expect(info.label).toBe(
      'deps.dev (taken from the latest release, not the exact version; normalized to an SPDX identifier)',
    );
    expect(licenseSourceTooltip('declared')).toBe('Source: Declared in the SBOM');
  });

  it('marks unresolved reasons as unresolved', () => {
    for (const reason of ['first-party', 'not-published', 'no-license-upstream', 'no-purl',
      'unsupported-ecosystem', 'unresolved', 'unrecorded']) {
      expect(describeLicenseSource(reason)!.resolved).toBe(false);
    }
    expect(licenseSourceTooltip('not-published')).toContain('Unknown: Not published');
  });

  it('gives every unresolved reason a hint and excludes only first-party', () => {
    for (const reason of ['first-party', 'not-published', 'no-license-upstream', 'no-purl',
      'unsupported-ecosystem', 'unresolved', 'unrecorded']) {
      expect(licenseReasonHint(reason)).not.toBe('');
      expect(isExcludedFromCompliance(reason)).toBe(reason === 'first-party');
    }
    expect(licenseReasonHint('npm')).toBe('');
  });

  it('falls back to the raw value for unknown vocabulary', () => {
    expect(describeLicenseSource('conan')!.label).toBe('conan');
  });
});
