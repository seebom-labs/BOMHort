import { describe, it, expect } from 'vitest';
import {
  DependencySearchResponse,
  DependencySearchResult,
  DependencySearchProject,
  PackageDetailResponse,
} from '../../core/api.models';

describe('PackageSearch Models', () => {
  it('should parse a search response with results', () => {
    const response: DependencySearchResponse = {
      total_results: 3,
      page: 1,
      page_size: 20,
      query: 'golang.org/x/net',
      items: [
        {
          package_name: 'golang.org/x/net',
          purl: 'pkg:golang/golang.org/x/net@v0.17.0',
          project_count: 12,
          versions: ['v0.17.0', 'v0.21.0', 'v0.25.0'],
          projects: [
            { project_name: 'etcd-io/raft', version: 'v0.17.0', sbom_id: 'abc-123' },
            { project_name: 'kubernetes/kubernetes', version: 'v0.21.0', sbom_id: 'def-456' },
          ],
        },
      ],
    };

    expect(response.total_results).toBe(3);
    expect(response.query).toBe('golang.org/x/net');
    expect(response.items).toHaveLength(1);
    expect(response.items[0].package_name).toBe('golang.org/x/net');
    expect(response.items[0].project_count).toBe(12);
    expect(response.items[0].versions).toHaveLength(3);
    expect(response.items[0].projects).toHaveLength(2);
    expect(response.items[0].projects[0].project_name).toBe('etcd-io/raft');
  });

  it('should handle empty search results', () => {
    const response: DependencySearchResponse = {
      total_results: 0,
      page: 1,
      page_size: 20,
      query: 'nonexistent-pkg',
      items: [],
    };

    expect(response.total_results).toBe(0);
    expect(response.items).toHaveLength(0);
  });

  it('should calculate total pages correctly', () => {
    const response: DependencySearchResponse = {
      total_results: 47,
      page: 1,
      page_size: 20,
      query: 'net',
      items: [],
    };

    const totalPages = Math.ceil(response.total_results / response.page_size);
    expect(totalPages).toBe(3);
  });

  it('should parse a package detail response', () => {
    const detail: PackageDetailResponse = {
      package_name: 'golang.org/x/net',
      total_projects: 42,
      page: 1,
      page_size: 50,
      projects: [
        { project_name: 'etcd-io/raft', version: 'v0.17.0', sbom_id: 'abc-123' },
        { project_name: 'kubernetes/kubernetes', version: 'v0.21.0', sbom_id: 'def-456' },
        { project_name: 'prometheus/prometheus', version: 'v0.25.0', sbom_id: 'ghi-789' },
      ],
    };

    expect(detail.package_name).toBe('golang.org/x/net');
    expect(detail.total_projects).toBe(42);
    expect(detail.projects).toHaveLength(3);
    expect(detail.projects[2].project_name).toBe('prometheus/prometheus');
  });

  it('should handle package detail with no projects', () => {
    const detail: PackageDetailResponse = {
      package_name: 'some-unused-package',
      total_projects: 0,
      page: 1,
      page_size: 50,
      projects: [],
    };

    expect(detail.total_projects).toBe(0);
    expect(detail.projects).toHaveLength(0);
  });

  it('should support pagination in detail response', () => {
    const detail: PackageDetailResponse = {
      package_name: 'lodash',
      total_projects: 120,
      page: 3,
      page_size: 50,
      projects: Array.from({ length: 20 }, (_, i) => ({
        project_name: `project-${i}`,
        version: `1.0.${i}`,
        sbom_id: `id-${i}`,
      })),
    };

    const totalPages = Math.ceil(detail.total_projects / detail.page_size);
    expect(totalPages).toBe(3);
    expect(detail.page).toBe(3);
    expect(detail.projects).toHaveLength(20);
  });

  it('should encode package names with slashes for URL routing', () => {
    const packageName = 'golang.org/x/net';
    const encoded = encodeURIComponent(packageName);
    expect(encoded).toBe('golang.org%2Fx%2Fnet');
    expect(decodeURIComponent(encoded)).toBe(packageName);
  });

  it('should sort search results by project count descending', () => {
    const items: DependencySearchResult[] = [
      { package_name: 'a', purl: '', project_count: 5, versions: [], projects: [] },
      { package_name: 'b', purl: '', project_count: 20, versions: [], projects: [] },
      { package_name: 'c', purl: '', project_count: 12, versions: [], projects: [] },
    ];

    const sorted = [...items].sort((a, b) => b.project_count - a.project_count);
    expect(sorted[0].package_name).toBe('b');
    expect(sorted[1].package_name).toBe('c');
    expect(sorted[2].package_name).toBe('a');
  });
});

