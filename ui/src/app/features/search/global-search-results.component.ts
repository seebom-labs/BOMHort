import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink, ActivatedRoute, Router } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { GlobalSearchResponse } from '../../core/api.models';

@Component({
  selector: 'app-global-search-results',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="search-page">
      <h1>Global Search</h1>
      <p class="subtitle">Search across packages, projects, vulnerabilities, and licenses.</p>

      <div class="search-bar">
        <form (submit)="onSearchSubmit($event)">
          <input
            type="text"
            [(ngModel)]="searchInput"
            name="searchInput"
            placeholder="Search all components..."
            class="search-input"
            autofocus
          />
        </form>
      </div>

      <div class="loading" *ngIf="loading">Searching...</div>

      <div class="empty-state" *ngIf="!loading && !data && !query">
        <p>Type a query to begin searching.</p>
      </div>

      <div class="empty-state" *ngIf="!loading && data && isAllEmpty()">
        <p>No results found for "{{ query }}"</p>
      </div>

      <div class="results" *ngIf="!loading && data && !isAllEmpty()">
        <!-- Packages -->
        <div class="facet-section" *ngIf="data.packages.length > 0">
          <h2>Packages ({{ data.total_packages }})</h2>
          <div class="result-card" *ngFor="let pkg of data.packages" [routerLink]="['/package-search', pkg.package_name]">
            <div class="pkg-info">
              <span class="pkg-name">{{ pkg.package_name }}</span>
              <span class="pkg-meta">{{ pkg.project_count }} {{ pkg.project_count === 1 ? 'project' : 'projects' }}</span>
            </div>
            <span class="expand-icon">▸</span>
          </div>
          <p class="limit-note" *ngIf="data.total_packages > data.packages.length">Showing top {{ data.packages.length }} results. Refine your query for more.</p>
        </div>

        <!-- Projects -->
        <div class="facet-section" *ngIf="data.projects.length > 0">
          <h2>Projects ({{ data.total_projects }})</h2>
          <div class="result-card" *ngFor="let proj of data.projects" [routerLink]="['/sboms', proj.latest_sbom_id]">
            <div class="pkg-info">
              <span class="pkg-name">{{ proj.project_name }}</span>
              <span class="pkg-meta">{{ proj.sbom_count }} {{ proj.sbom_count === 1 ? 'sbom' : 'sboms' }}</span>
            </div>
            <span class="expand-icon">▸</span>
          </div>
          <p class="limit-note" *ngIf="data.total_projects > data.projects.length">Showing top {{ data.projects.length }} results. Refine your query for more.</p>
        </div>

        <!-- Vulnerabilities -->
        <div class="facet-section" *ngIf="data.vulnerabilities.length > 0">
          <h2>Vulnerabilities ({{ data.total_vulnerabilities }})</h2>
          <div class="result-card" *ngFor="let vuln of data.vulnerabilities" [routerLink]="['/cve-impact']" [queryParams]="{ cve: vuln.vuln_id }">
            <div class="pkg-info">
              <div class="pkg-name flex-center">
                <span class="severity-badge" [ngClass]="'severity-' + vuln.severity.toLowerCase()">{{ vuln.severity }}</span>
                {{ vuln.vuln_id }}
              </div>
              <span class="pkg-meta">{{ vuln.affected_sboms }} {{ vuln.affected_sboms === 1 ? 'sbom' : 'sboms' }} affected</span>
            </div>
            <span class="expand-icon">▸</span>
          </div>
          <p class="limit-note" *ngIf="data.total_vulnerabilities > data.vulnerabilities.length">Showing top {{ data.vulnerabilities.length }} results. Refine your query for more.</p>
        </div>

        <!-- Licenses -->
        <div class="facet-section" *ngIf="data.licenses.length > 0">
          <h2>Licenses ({{ data.total_licenses }})</h2>
          <div class="result-card" *ngFor="let lic of data.licenses" [routerLink]="['/licenses']">
            <div class="pkg-info">
              <div class="pkg-name flex-center">
                <span class="license-cat" [ngClass]="'license-' + lic.category.toLowerCase()"></span>
                {{ lic.license_id }}
              </div>
              <span class="pkg-meta">{{ lic.sbom_count }} {{ lic.sbom_count === 1 ? 'sbom' : 'sboms' }}</span>
            </div>
            <span class="expand-icon">▸</span>
          </div>
          <p class="limit-note" *ngIf="data.total_licenses > data.licenses.length">Showing top {{ data.licenses.length }} results. Refine your query for more.</p>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .search-page { padding: 32px; max-width: 900px; margin: 0 auto; }
    h1 { font-size: 1.5rem; font-weight: 700; color: var(--text); margin: 0 0 4px; }
    .subtitle { color: var(--text-secondary); font-size: 0.85rem; margin: 0 0 24px; }

    .search-bar { margin-bottom: 20px; }
    .search-input {
      width: 100%;
      padding: 12px 16px;
      font-size: 0.95rem;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: var(--card-bg);
      color: var(--text);
      outline: none;
      transition: border-color 0.2s;
    }
    .search-input:focus { border-color: var(--accent); }
    .search-input::placeholder { color: var(--text-muted); }

    .facet-section { margin-bottom: 32px; }
    .facet-section h2 {
      font-size: 1.1rem;
      font-weight: 600;
      color: var(--text);
      margin-bottom: 12px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }

    .result-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 8px;
      cursor: pointer;
      transition: border-color 0.15s;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .result-card:hover { border-color: var(--accent); }

    .pkg-info { display: flex; flex-direction: column; gap: 4px; }
    .pkg-name { font-weight: 600; font-size: 0.9rem; color: var(--text); }
    .pkg-meta { font-size: 0.75rem; color: var(--text-secondary); }
    .expand-icon { color: var(--text-muted); font-size: 0.9rem; }

    .flex-center { display: flex; align-items: center; gap: 6px; }

    .severity-badge {
      font-size: 0.65rem;
      font-weight: 700;
      padding: 1px 4px;
      border-radius: 2px;
      text-transform: uppercase;
    }
    .severity-critical { background: var(--severity-critical-bg); color: var(--severity-critical); border: 1px solid var(--severity-critical); }
    .severity-high { background: var(--severity-high-bg); color: var(--severity-high); border: 1px solid var(--severity-high); }
    .severity-medium { background: var(--severity-medium-bg); color: var(--severity-medium); border: 1px solid var(--severity-medium); }
    .severity-low { background: var(--severity-low-bg); color: var(--severity-low); border: 1px solid var(--severity-low); }

    .license-cat {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
    }
    .license-permissive { background: var(--license-permissive); }
    .license-copyleft { background: var(--license-copyleft); }
    .license-unknown { background: var(--license-unknown); }

    .limit-note {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 8px;
      text-align: right;
    }

    .empty-state {
      text-align: center;
      padding: 48px 0;
      color: var(--text-muted);
      font-size: 0.9rem;
    }
    .loading {
      text-align: center;
      padding: 24px;
      color: var(--text-secondary);
      font-size: 0.85rem;
    }
  `]
})
export class GlobalSearchResultsComponent implements OnInit {
  query = '';
  searchInput = '';
  data: GlobalSearchResponse | null = null;
  loading = false;

  constructor(
    private readonly route: ActivatedRoute,
    private readonly router: Router,
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.route.queryParamMap.subscribe(params => {
      const q = params.get('q');
      if (q && q.length >= 2) {
        this.query = q;
        this.searchInput = q;
        this.doSearch(q);
      } else {
        this.query = '';
        this.searchInput = '';
        this.data = null;
        this.cdr.markForCheck();
      }
    });
  }

  onSearchSubmit(event: Event): void {
    event.preventDefault();
    if (this.searchInput.length >= 2) {
      this.router.navigate([], {
        relativeTo: this.route,
        queryParams: { q: this.searchInput },
        queryParamsHandling: 'merge'
      });
    }
  }

  isAllEmpty(): boolean {
    if (!this.data) return true;
    return this.data.total_packages === 0 &&
           this.data.total_projects === 0 &&
           this.data.total_vulnerabilities === 0 &&
           this.data.total_licenses === 0;
  }

  private doSearch(q: string): void {
    this.loading = true;
    this.cdr.markForCheck();

    this.api.globalSearch(q, 50).subscribe({
      next: (resp) => {
        this.data = resp;
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: () => {
        this.data = null;
        this.loading = false;
        this.cdr.markForCheck();
      }
    });
  }
}
