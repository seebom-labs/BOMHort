import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { ApiService } from '../../core/api.service';
import { LicenseComplianceItem, LicenseAffectedSBOM } from '../../core/api.models';

type SortField = 'severity' | 'usages' | 'name' | 'projects' | 'non-compliant';

interface GroupedProject {
  project_name: string;
  versions: { sbom_id: string; label: string; document_name: string }[];
}

@Component({
  selector: 'app-license-overview',
  standalone: true,
  imports: [CommonModule, RouterModule, ScrollingModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="license-overview">
      <h1>License Compliance</h1>

      <div class="categories">
        <div class="category-card permissive">
          <h3>Permissive</h3>
          <span class="count">{{ getCategoryCount('permissive') | number }}</span>
        </div>
        <div class="category-card copyleft">
          <h3>Copyleft</h3>
          <span class="count">{{ getCategoryCount('copyleft') | number }}</span>
        </div>
        <div class="category-card unknown">
          <h3>Unknown</h3>
          <span class="count">{{ getCategoryCount('unknown') | number }}</span>
        </div>
        <div class="category-card exempted">
          <h3>Exempted</h3>
          <span class="count">{{ getExemptedCount() | number }}</span>
        </div>
      </div>

      <div class="list-header">
        <h2>All Licenses</h2>
        <div class="sort-controls">
          <span class="sort-label">Sort by</span>
          <button *ngFor="let opt of sortOptions"
                  class="sort-btn"
                  [class.active]="sortField === opt.field"
                  (click)="toggleSort(opt.field)">
            {{ opt.label }}
            <span class="sort-arrow" *ngIf="sortField === opt.field">{{ sortAsc ? '↑' : '↓' }}</span>
          </button>
        </div>
      </div>

      <div class="license-list">
        <div *ngFor="let item of licenses; trackBy: trackByLicense"
             class="license-card"
             [class.expanded]="expandedLicense === item.license_id">

          <!-- Card Header – always visible -->
          <div class="card-header" (click)="toggle(item.license_id)">
            <span class="category-badge" [class]="getCategoryClass(item)">{{ item.category }}</span>
            <div class="header-main">
              <span class="license-id">{{ item.license_id }}</span>
              <span class="exception-badge" *ngIf="item.exempted_packages?.length"
                    [title]="item.exemption_reason || 'Approved exception'">
                ✓ Exempted
              </span>
            </div>
            <div class="header-stats">
              <span class="stat">{{ item.package_count | number }} <small>usages</small></span>
              <span class="stat">{{ item.sbom_count | number }} <small>{{ item.sbom_count === 1 ? 'project' : 'projects' }}</small></span>
              <span class="stat warn" *ngIf="item.non_compliant_packages?.length && item.category !== 'permissive' && !item.exempted_packages?.length">
                {{ item.non_compliant_packages!.length | number }} <small>non-compliant</small>
              </span>
              <span class="stat ok" *ngIf="item.exempted_packages?.length">
                {{ item.exempted_packages!.length | number }} <small>exempted</small>
              </span>
            </div>
            <span class="toggle-icon">{{ expandedLicense === item.license_id ? '▾' : '▸' }}</span>
          </div>

          <!-- Expanded Details -->
          <div class="card-body" *ngIf="expandedLicense === item.license_id">
            <!-- Exemption Reason -->
            <div class="detail-section reason" *ngIf="item.exemption_reason">
              <span class="section-icon">✓</span>
              <span class="reason-text">{{ item.exemption_reason }}</span>
            </div>

            <!-- Affected Projects grouped by name with version tags -->
            <div class="detail-section" *ngIf="item.affected_sboms?.length">
              <h4>Affected Projects</h4>
              <div class="project-groups">
                <div *ngFor="let group of getGroupedProjects(item)" class="project-group">
                  <span class="project-name">{{ group.project_name }}</span>
                  <a *ngFor="let v of group.versions"
                     [routerLink]="['/sboms', v.sbom_id]"
                     class="version-tag"
                     [title]="v.document_name">
                    {{ v.label }}
                  </a>
                </div>
              </div>
            </div>

            <!-- Non-Compliant Packages -->
            <div class="detail-section" *ngIf="item.non_compliant_packages?.length && item.category !== 'permissive' && !item.exempted_packages?.length">
              <h4>Non-Compliant Packages ({{ item.non_compliant_packages!.length | number }})</h4>
              <div class="pkg-list">
                <span *ngFor="let pkg of item.non_compliant_packages" class="pkg-tag violation">{{ pkg }}</span>
              </div>
            </div>

            <!-- Exempted Packages -->
            <div class="detail-section" *ngIf="item.exempted_packages?.length">
              <h4>Exempted Packages ({{ item.exempted_packages!.length }})</h4>
              <div class="pkg-list">
                <span *ngFor="let pkg of item.exempted_packages" class="pkg-tag exempted">{{ pkg }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .license-overview { padding: 24px; height: 100%; display: flex; flex-direction: column; overflow-y: auto; }
    h1 { margin: 0 0 16px; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    h2 { margin: 0; font-size: 0.9rem; font-weight: 600; }

    .categories { display: flex; gap: 8px; margin-bottom: 20px; }
    .category-card {
      flex: 1; padding: 16px; border-radius: 4px; text-align: center;
      border: 1px solid var(--border);
    }
    .category-card h3 { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-secondary); margin: 0 0 4px; font-weight: 600; }
    .permissive { background: var(--surface-alt); }
    .copyleft { background: var(--severity-critical-bg); }
    .unknown { background: var(--surface-alt); }
    .exempted { background: var(--status-success-bg); }
    .count { font-size: 1.5rem; font-weight: 700; letter-spacing: -0.02em; }

    .list-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 12px; flex-wrap: wrap; gap: 8px;
    }
    .sort-controls { display: flex; align-items: center; gap: 4px; }
    .sort-label { font-size: 0.72rem; color: var(--text-muted); margin-right: 4px; }
    .sort-btn {
      background: var(--surface); border: 1px solid var(--border); color: var(--text-secondary);
      padding: 3px 10px; border-radius: 2px; font-size: 0.72rem; cursor: pointer;
      font-family: inherit; transition: all 0.15s;
    }
    .sort-btn:hover { border-color: var(--accent); color: var(--text); }
    .sort-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
    .sort-arrow { margin-left: 2px; font-size: 0.68rem; }

    /* License Cards */
    .license-list { display: flex; flex-direction: column; gap: 4px; }
    .license-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; overflow: hidden; transition: box-shadow 0.15s;
    }
    .license-card:hover { box-shadow: 0 1px 4px rgba(0,0,0,0.06); }
    .license-card.expanded { border-color: var(--accent); }

    /* Card Header */
    .card-header {
      display: flex; align-items: center; gap: 12px;
      padding: 10px 14px; cursor: pointer; transition: background 0.1s;
    }
    .card-header:hover { background: var(--surface-alt); }
    .category-badge {
      padding: 3px 8px; border-radius: 2px; font-size: 0.65rem; font-weight: 600;
      min-width: 80px; text-align: center; text-transform: uppercase; letter-spacing: 0.03em;
      flex-shrink: 0;
    }
    .cat-permissive { background: var(--status-success-bg); color: var(--status-success); }
    .cat-copyleft { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .cat-copyleft-exempted { background: var(--status-success-bg); color: var(--status-success); }
    .cat-unknown { background: var(--bg); color: var(--text-secondary); }

    .header-main { display: flex; align-items: center; gap: 8px; min-width: 280px; }
    .license-id { font-weight: 600; font-size: 0.85rem; }
    .exception-badge {
      padding: 2px 6px; border-radius: 2px; font-size: 0.6rem; font-weight: 600;
      background: var(--status-success-bg); color: var(--status-success);
      text-transform: uppercase; letter-spacing: 0.03em; white-space: nowrap;
    }

    .header-stats { display: flex; gap: 16px; flex: 1; }
    .stat { font-size: 0.82rem; font-weight: 600; color: var(--text); white-space: nowrap; }
    .stat small { font-weight: 400; color: var(--text-secondary); font-size: 0.72rem; }
    .stat.warn { color: var(--severity-critical); }
    .stat.warn small { color: var(--severity-critical); opacity: 0.7; }
    .stat.ok { color: var(--status-success); }
    .stat.ok small { color: var(--status-success); opacity: 0.7; }

    .toggle-icon { color: var(--text-muted); font-size: 0.75rem; flex-shrink: 0; margin-left: auto; }

    /* Card Body – expanded details */
    .card-body { border-top: 1px solid var(--border); padding: 12px 14px; }
    .detail-section { margin-bottom: 12px; }
    .detail-section:last-child { margin-bottom: 0; }
    .detail-section h4 {
      font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.03em; color: var(--text-secondary); margin: 0 0 6px;
    }

    .reason {
      display: flex; align-items: flex-start; gap: 6px;
      background: var(--status-success-bg); padding: 8px 12px; border-radius: 2px;
      margin-bottom: 12px;
    }
    .section-icon { color: var(--status-success); font-weight: 700; font-size: 0.8rem; }
    .reason-text { font-size: 0.78rem; color: var(--text); line-height: 1.4; }

    /* Project Groups – version tags */
    .project-groups { display: flex; flex-direction: column; gap: 6px; }
    .project-group { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
    .project-name { font-size: 0.78rem; font-weight: 600; color: var(--text); min-width: 180px; }
    .version-tag {
      font-size: 0.65rem; color: var(--accent); text-decoration: none;
      background: var(--bg); padding: 2px 7px; border-radius: 2px;
      white-space: nowrap; font-family: monospace; font-weight: 500;
      border: 1px solid var(--border); transition: all 0.15s;
    }
    .version-tag:hover { background: var(--accent); color: #fff; border-color: var(--accent); }

    /* Package Tags */
    .pkg-list { display: flex; flex-wrap: wrap; gap: 4px; max-height: 200px; overflow-y: auto; }
    .pkg-tag {
      font-size: 0.7rem; padding: 2px 8px; border-radius: 2px; white-space: nowrap;
      font-family: monospace;
    }
    .pkg-tag.violation {
      background: var(--severity-critical-bg); color: var(--severity-critical);
      border: 1px solid var(--severity-critical);
    }
    .pkg-tag.exempted {
      background: var(--status-success-bg); color: var(--status-success);
      border: 1px solid var(--status-success);
    }
  `],
})
export class LicenseOverviewComponent implements OnInit {
  licenses: LicenseComplianceItem[] = [];
  expandedLicense: string | null = null;
  private rawLicenses: LicenseComplianceItem[] = [];
  private groupedCache = new Map<string, GroupedProject[]>();

  sortField: SortField = 'severity';
  sortAsc = false;

  readonly sortOptions: { field: SortField; label: string }[] = [
    { field: 'severity', label: 'Most Severe' },
    { field: 'usages', label: 'Most Usages' },
    { field: 'projects', label: 'Most Projects' },
    { field: 'non-compliant', label: 'Non-Compliant' },
    { field: 'name', label: 'Name' },
  ];

  private readonly severityOrder: Record<string, number> = {
    copyleft: 0,
    unknown: 1,
    permissive: 2,
  };

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.api.getLicenseCompliance().subscribe((data) => {
      this.rawLicenses = data;
      this.buildGroupedCache();
      this.applySort();
      this.cdr.markForCheck();
    });
  }

  toggle(licenseId: string): void {
    this.expandedLicense = this.expandedLicense === licenseId ? null : licenseId;
    this.cdr.markForCheck();
  }

  getCategoryClass(item: LicenseComplianceItem): string {
    if (item.category === 'copyleft' && item.exempted_packages?.length) {
      return 'cat-copyleft-exempted';
    }
    return 'cat-' + item.category;
  }

  getGroupedProjects(item: LicenseComplianceItem): GroupedProject[] {
    return this.groupedCache.get(item.license_id) ?? [];
  }

  toggleSort(field: SortField): void {
    if (this.sortField === field) {
      this.sortAsc = !this.sortAsc;
    } else {
      this.sortField = field;
      this.sortAsc = field === 'name';
    }
    this.applySort();
    this.cdr.markForCheck();
  }

  private applySort(): void {
    const dir = this.sortAsc ? 1 : -1;
    this.licenses = [...this.rawLicenses].sort((a, b) => {
      switch (this.sortField) {
        case 'severity': {
          const sa = this.severityOrder[a.category] ?? 1;
          const sb = this.severityOrder[b.category] ?? 1;
          // exempted copyleft should sort between copyleft and unknown
          const ea = a.exempted_packages?.length ? 0.5 : 0;
          const eb = b.exempted_packages?.length ? 0.5 : 0;
          const da = sa + ea;
          const db = sb + eb;
          return da !== db ? (da - db) * dir : (b.package_count - a.package_count);
        }
        case 'usages':
          return (a.package_count - b.package_count) * dir;
        case 'projects':
          return (a.sbom_count - b.sbom_count) * dir;
        case 'non-compliant': {
          const na = a.non_compliant_packages?.length ?? 0;
          const nb = b.non_compliant_packages?.length ?? 0;
          return (na - nb) * dir;
        }
        case 'name':
          return a.license_id.localeCompare(b.license_id) * dir;
        default:
          return 0;
      }
    });
  }

  private buildGroupedCache(): void {
    this.groupedCache.clear();
    for (const lic of this.rawLicenses) {
      if (lic.affected_sboms?.length) {
        this.groupedCache.set(lic.license_id, this.groupSBOMs(lic.affected_sboms));
      }
    }
  }

  private groupSBOMs(sboms: LicenseAffectedSBOM[]): GroupedProject[] {
    const map = new Map<string, GroupedProject>();
    for (const sbom of sboms) {
      const name = sbom.document_name || sbom.sbom_id;
      const projectKey = this.extractProjectKey(name);
      const versionLabel = this.extractVersionLabel(name);
      let group = map.get(projectKey);
      if (!group) {
        group = { project_name: projectKey, versions: [] };
        map.set(projectKey, group);
      }
      group.versions.push({ sbom_id: sbom.sbom_id, label: versionLabel, document_name: name });
    }
    for (const g of map.values()) {
      g.versions.sort((a, b) => b.label.localeCompare(a.label, undefined, { numeric: true }));
    }
    return Array.from(map.values());
  }

  private extractProjectKey(name: string): string {
    return name.replace(/\s+v?\d+(\.\d+){1,}(-[\w.]+)?$/i, '').replace(/\s+$/, '');
  }

  private extractVersionLabel(name: string): string {
    const match = name.match(/(v?\d+(\.\d+){1,}(-[\w.]+)?)$/i);
    return match ? match[1] : name;
  }

  getCategoryCount(category: string): number {
    return this.rawLicenses
      .filter((l) => l.category === category)
      .reduce((sum, l) => sum + l.package_count, 0);
  }

  getExemptedCount(): number {
    return this.rawLicenses
      .reduce((sum, l) => sum + (l.exempted_packages?.length ?? 0), 0);
  }

  trackByLicense(_index: number, item: LicenseComplianceItem): string {
    return item.license_id;
  }
}
