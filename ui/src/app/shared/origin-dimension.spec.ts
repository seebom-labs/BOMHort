import { describe, it, expect } from 'vitest';
import { VALID_ORIGINS, ORIGIN_LABELS, ORIGIN_FILTERS } from './origin-dimension';

describe('origin-dimension', () => {
  it('defines the 5 fixed vocabulary origins', () => {
    expect(VALID_ORIGINS).toEqual(['cluster-scan', 'ci', 'registry', 'vendor', 'manual']);
  });

  it('provides human labels for all origins', () => {
    for (const origin of VALID_ORIGINS) {
      expect(ORIGIN_LABELS[origin]).toBeDefined();
    }
  });

  it('includes an all-origins option in filters', () => {
    expect(ORIGIN_FILTERS[0]).toEqual({ value: '', label: 'All origins' });
    expect(ORIGIN_FILTERS.length).toBe(6);
  });
});
