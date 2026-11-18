/**
 * Origin vocabulary for recording how an SBOM was produced (#455).
 * Matches backend/internal/origin.
 */

export const VALID_ORIGINS = [
  'cluster-scan',
  'ci',
  'registry',
  'vendor',
  'manual',
] as const;

export type Origin = (typeof VALID_ORIGINS)[number];

export const ORIGIN_LABELS: Record<Origin, string> = {
  'cluster-scan': 'Cluster Scan',
  'ci': 'CI Pipeline',
  'registry': 'OCI Registry',
  'vendor': 'Vendor Delivery',
  'manual': 'Manual Upload',
};

export const ORIGIN_FILTERS: { value: '' | Origin; label: string }[] = [
  { value: '', label: 'All origins' },
  { value: 'cluster-scan', label: 'Cluster scan' },
  { value: 'ci', label: 'CI' },
  { value: 'registry', label: 'Registry' },
  { value: 'vendor', label: 'Vendor' },
  { value: 'manual', label: 'Manual' },
];
