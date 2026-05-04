import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    loadComponent: () =>
      import('./features/dashboard/dashboard.component').then((m) => m.DashboardComponent),
  },
  {
    path: 'sboms',
    loadComponent: () =>
      import('./features/sbom-explorer/sbom-list.component').then((m) => m.SbomListComponent),
  },
  {
    path: 'sboms/:id',
    loadComponent: () =>
      import('./features/sbom-explorer/sbom-detail.component').then((m) => m.SbomDetailComponent),
  },
  {
    path: 'vulnerabilities',
    loadComponent: () =>
      import('./features/vulnerability/vulnerability-list.component').then(
        (m) => m.VulnerabilityListComponent
      ),
  },
  {
    path: 'cve-impact',
    loadComponent: () =>
      import('./features/search/cve-impact.component').then((m) => m.CVEImpactComponent),
  },
  {
    path: 'licenses',
    loadComponent: () =>
      import('./features/license-compliance/license-overview.component').then(
        (m) => m.LicenseOverviewComponent
      ),
  },
  {
    path: 'license-compliance',
    loadComponent: () =>
      import('./features/search/license-violations.component').then(
        (m) => m.LicenseViolationsComponent
      ),
  },
  {
    path: 'dependencies',
    loadComponent: () =>
      import('./features/search/dependency-stats.component').then(
        (m) => m.DependencyStatsComponent
      ),
  },
  {
    path: 'version-skew',
    loadComponent: () =>
      import('./features/search/version-skew.component').then(
        (m) => m.VersionSkewComponent
      ),
  },
  {
    path: 'vex',
    loadComponent: () =>
      import('./features/vex/vex-list.component').then((m) => m.VEXListComponent),
  },
  {
    path: 'archived-packages',
    loadComponent: () =>
      import('./features/archived-packages/archived-packages.component').then(
        (m) => m.ArchivedPackagesComponent
      ),
  },
  { path: '**', redirectTo: '' },
];
