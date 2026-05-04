import { describe, it, expect } from 'vitest';
import { VersionSkewItem, VersionSkewResponse, VersionSkewDetail } from '../../core/api.models';

describe('VersionSkew Models', () => {
  it('should parse a version skew response', () => {
    const response: VersionSkewResponse = {
      total_skewed_packages: 42,
      page: 1,
      page_size: 50,
      items: [
        {
          package_name: 'golang.org/x/net',
          purl: 'pkg:golang/golang.org/x/net@v0.17.0',
          version_count: 3,
          project_count: 5,
          is_direct_in_count: 2,
          versions: [
            { version: 'v0.17.0', project_count: 3, projects: ['etcd-io/raft', 'kubernetes/kubernetes'] },
            { version: 'v0.21.0', project_count: 2, projects: ['prometheus/prometheus'] },
          ],
        },
      ],
    };

    expect(response.total_skewed_packages).toBe(42);
    expect(response.items).toHaveLength(1);
    expect(response.items[0].package_name).toBe('golang.org/x/net');
    expect(response.items[0].versions[0].projects).toContain('etcd-io/raft');
  });

  it('should handle empty items array', () => {
    const response: VersionSkewResponse = {
      total_skewed_packages: 0,
      page: 1,
      page_size: 50,
      items: [],
    };

    expect(response.items).toHaveLength(0);
  });

  it('should support sorting by version_count', () => {
    const items: VersionSkewItem[] = [
      { package_name: 'a', purl: '', version_count: 2, project_count: 10, is_direct_in_count: 0, versions: [] },
      { package_name: 'b', purl: '', version_count: 5, project_count: 3, is_direct_in_count: 0, versions: [] },
      { package_name: 'c', purl: '', version_count: 3, project_count: 7, is_direct_in_count: 0, versions: [] },
    ];

    const sorted = [...items].sort((a, b) => b.version_count - a.version_count);
    expect(sorted[0].package_name).toBe('b');
    expect(sorted[1].package_name).toBe('c');
    expect(sorted[2].package_name).toBe('a');
  });
});

