import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterModule } from '@angular/router';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { ApiService } from '../../core/api.service';
import {
  SBOMDetail,
  VulnerabilityListItem,
  SBOMLicenseBreakdownItem,
  DependencyNode,
  ArchivedPackageInfo,
} from '../../core/api.models';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';

type Tab = 'vulns' | 'licenses' | 'deps';

@Component({
  selector: 'app-sbom-detail',
  standalone: true,
  imports: [CommonModule, ScrollingModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="sbom-detail" *ngIf="detail">
      <div class="header">
        <a routerLink="/sboms" class="back">← Back</a>
        <h1>{{ detail.document_name || detail.source_file }}</h1>
        <span class="badge">{{ detail.spdx_version }}</span>
        <button class="download-btn" title="Download original SBOM" (click)="downloadSbom()">⬇ Download</button>
      </div>

      <div class="stats-row">
        <div class="stat"><strong>{{ detail.package_count | number }}</strong> packages</div>
        <div class="stat"><strong>{{ detail.vuln_count | number }}</strong> vulnerabilities</div>
        <div class="stat critical" *ngIf="detail.critical_vulns">{{ detail.critical_vulns | number }} critical</div>
        <div class="stat high" *ngIf="detail.high_vulns">{{ detail.high_vulns | number }} high</div>
        <div class="stat medium" *ngIf="detail.medium_vulns">{{ detail.medium_vulns | number }} medium</div>
        <div class="stat low" *ngIf="detail.low_vulns">{{ detail.low_vulns | number }} low</div>
      </div>

      <div class="tabs">
        <button [class.active]="activeTab === 'vulns'" (click)="activeTab = 'vulns'">
          Vulnerabilities ({{ vulns.length | number }})
        </button>
        <button [class.active]="activeTab === 'licenses'" (click)="activeTab = 'licenses'">
          Licenses ({{ licenses.length | number }})
        </button>
        <button [class.active]="activeTab === 'deps'" (click)="activeTab = 'deps'">
          Dependencies
        </button>
      </div>

      <!-- Vulnerabilities Tab -->
      <div *ngIf="activeTab === 'vulns'" class="tab-content">
        <cdk-virtual-scroll-viewport itemSize="56" class="viewport">
          <div *cdkVirtualFor="let vuln of vulns; trackBy: trackByVuln" class="vuln-row">
            <span class="severity-badge" [class]="'sev-' + vuln.severity.toLowerCase()">{{ vuln.severity }}</span>
            <div class="vuln-info">
              <a [routerLink]="['/cve-impact']" [queryParams]="{vuln: vuln.vuln_id}" class="vuln-id">
                {{ vuln.vuln_id }}
              </a>
              <span class="summary">{{ vuln.summary }}</span>
            </div>
            <span class="vex-badge" *ngIf="vuln.vex_status" [class]="'vex-' + vuln.vex_status">
              {{ vuln.vex_status | titlecase }}
            </span>
            <span class="purl">{{ vuln.purl }}</span>
          </div>
        </cdk-virtual-scroll-viewport>
      </div>

      <!-- Licenses Tab -->
      <div *ngIf="activeTab === 'licenses'" class="tab-content">
        <div class="license-summary">
          <div class="license-summary-item permissive-bg">
            <span class="license-summary-count">{{ getLicenseCategoryCount('permissive') }}</span>
            <span class="license-summary-label">Permissive</span>
          </div>
          <div class="license-summary-item copyleft-bg">
            <span class="license-summary-count">{{ getLicenseCategoryCount('copyleft') }}</span>
            <span class="license-summary-label">Copyleft</span>
          </div>
          <div class="license-summary-item unknown-bg">
            <span class="license-summary-count">{{ getLicenseCategoryCount('unknown') }}</span>
            <span class="license-summary-label">Unknown</span>
          </div>
        </div>

        <div class="license-list">
          <div *ngFor="let lic of licenses; trackBy: trackByLicense"
               class="license-row"
               [class]="getLicenseCardClass(lic)"
               [class.expanded]="expandedLicense === lic.license_id">

            <div class="lic-header" (click)="toggleLicense(lic.license_id)">
              <span class="lic-toggle">{{ expandedLicense === lic.license_id ? '▾' : '▸' }}</span>
              <span class="lic-id" *ngIf="!isUrl(lic.license_id)">{{ lic.license_id || 'Unknown' }}</span>
              <a *ngIf="isUrl(lic.license_id)"
                 [href]="lic.license_id" target="_blank" rel="noopener"
                 class="lic-id lic-id-link"
                 (click)="$event.stopPropagation()">
                {{ extractLicenseLabel(lic.license_id) }}
                <span class="link-icon">↗</span>
              </a>
              <span class="lic-cat-badge" [class]="'cat-badge-' + lic.category">{{ lic.category }}</span>
              <span class="lic-exempted-badge" *ngIf="lic.exempted_packages?.length"
                    [title]="lic.exemption_reason || 'Approved exception'">
                ✓ Exempted
              </span>
              <span class="lic-count">{{ lic.package_count | number }} {{ lic.package_count === 1 ? 'package' : 'packages' }}</span>
            </div>

            <div class="lic-body" *ngIf="expandedLicense === lic.license_id">
              <div class="lic-exemption-note" *ngIf="lic.exemption_reason">
                <span class="exemption-icon">✓</span>
                {{ lic.exemption_reason }}
              </div>

              <div class="lic-url-row" *ngIf="isUrl(lic.license_id)">
                <span class="lic-url-label">License URL:</span>
                <a [href]="lic.license_id" target="_blank" rel="noopener" class="lic-url-link">
                  {{ lic.license_id }}
                </a>
              </div>

              <div class="lic-pkg-section" *ngIf="lic.packages?.length">
                <h4 class="lic-pkg-title">Packages ({{ lic.packages.length | number }})</h4>
                <div class="lic-pkg-list">
                  <div *ngFor="let pkg of lic.packages" class="lic-pkg-item">
                    <a *ngIf="isUrl(pkg)" [href]="pkg" target="_blank" rel="noopener" class="lic-pkg-link">
                      {{ extractPackageLabel(pkg) }} <span class="link-icon">↗</span>
                    </a>
                    <span *ngIf="!isUrl(pkg)" class="lic-pkg-name">{{ pkg }}</span>
                  </div>
                </div>
              </div>

              <div class="lic-pkg-section" *ngIf="lic.exempted_packages?.length">
                <h4 class="lic-pkg-title exempted-title">Exempted Packages ({{ lic.exempted_packages!.length | number }})</h4>
                <div class="lic-pkg-list">
                  <div *ngFor="let pkg of lic.exempted_packages" class="lic-pkg-item exempted">
                    <a *ngIf="isUrl(pkg)" [href]="pkg" target="_blank" rel="noopener" class="lic-pkg-link exempted-link">
                      {{ extractPackageLabel(pkg) }} <span class="link-icon">↗</span>
                    </a>
                    <span *ngIf="!isUrl(pkg)" class="lic-pkg-name">{{ pkg }}</span>
                  </div>
                </div>
              </div>

              <p class="lic-no-packages" *ngIf="!lic.packages?.length && !lic.exempted_packages?.length">
                No individual package details available.
              </p>
            </div>
          </div>
        </div>
      </div>

      <!-- Dependencies Tab -->
      <div *ngIf="activeTab === 'deps'" class="tab-content">
        <div class="dep-table-header">
          <span class="dep-col-name">Package</span>
          <span class="dep-col-version">Version</span>
          <span class="dep-col-license">License</span>
        </div>
        <cdk-virtual-scroll-viewport itemSize="44" class="viewport">
          <div *cdkVirtualFor="let node of flatDeps; trackBy: trackByDep" class="dep-row"
               [style.padding-left.px]="12 + node.level * 24">
            <span class="dep-name" [title]="node.purl || node.name">
              {{ node.name }}
              <span class="archived-tag" *ngIf="isArchivedPurl(node.purl)" title="This package uses an archived GitHub repository"> ARCHIVED</span>
            </span>
            <span class="dep-version">{{ node.version }}</span>
            <span class="dep-license"
                  [class.copyleft]="isCopyleft(node.license) && !isExemptedLicense(node.license)"
                  [class.exempted]="isCopyleft(node.license) && isExemptedLicense(node.license)">
              {{ node.license || '—' }}
              <span class="dep-exempted-tag" *ngIf="isCopyleft(node.license) && isExemptedLicense(node.license)">✓</span>
            </span>
          </div>
        </cdk-virtual-scroll-viewport>
      </div>
    </div>

    <p *ngIf="!detail" class="loading">Loading SBOM details...</p>
  `,
  styles: [`
    .sbom-detail { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; }
    .back { color: var(--accent); text-decoration: none; font-size: 0.8rem; font-weight: 500; }
    h1 { margin: 0; flex: 1; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .badge { background: var(--bg); color: var(--text-secondary); padding: 3px 8px; border-radius: 2px; font-size: 0.7rem; font-weight: 500; }
    .download-btn {
      background: none; border: 1px solid var(--border); border-radius: 4px;
      cursor: pointer; padding: 5px 12px; font-size: 0.75rem; color: var(--text-secondary);
      font-family: inherit; font-weight: 500; transition: all 0.15s;
    }
    .download-btn:hover { border-color: var(--accent); color: var(--accent); }
    .stats-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
    .stat { background: var(--surface-alt); padding: 6px 14px; border-radius: 2px; font-size: 0.8rem; border: 1px solid var(--border); }
    .critical { color: var(--severity-critical); }
    .high { color: var(--severity-high); }
    .medium { color: var(--status-warning); }
    .low { color: var(--text-secondary); }
    .tabs { display: flex; gap: 2px; margin-bottom: 16px; border-bottom: 1px solid var(--border); }
    .tabs button {
      padding: 8px 18px; border: none; background: transparent; cursor: pointer;
      font-size: 0.8rem; border-radius: 0; transition: all 0.15s;
      font-family: inherit; color: var(--text-secondary); font-weight: 500;
      border-bottom: 2px solid transparent; margin-bottom: -1px;
    }
    .tabs button.active { color: var(--text); border-bottom-color: var(--accent); }
    .tab-content { flex: 1; min-height: 0; }
    .viewport { height: 100%; min-height: 400px; }
    .vuln-row {
      height: 52px; display: flex; align-items: center; gap: 12px; padding: 0 12px;
      border-bottom: 1px solid var(--border);
    }
    .severity-badge, .sev-critical, .sev-high, .sev-medium, .sev-low {
      padding: 2px 7px; border-radius: 2px; font-size: 0.65rem; font-weight: 600;
      text-transform: uppercase; min-width: 64px; text-align: center; letter-spacing: 0.03em;
    }
    .sev-critical { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .sev-high { background: var(--severity-high-bg); color: var(--severity-high); }
    .sev-medium { background: var(--severity-high-bg); color: var(--status-warning); }
    .sev-low { background: var(--bg); color: var(--text-secondary); }
    .vuln-info { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
    .vuln-id { font-weight: 600; font-size: 0.8rem; color: var(--accent); text-decoration: none; }
    .summary { color: var(--text-secondary); font-size: 0.75rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .vex-badge { padding: 2px 6px; border-radius: 2px; font-size: 0.6rem; font-weight: 600; }
    .vex-not_affected { background: var(--status-success-bg); color: var(--status-success); }
    .vex-fixed { background: var(--status-info-bg); color: var(--accent-hover); }
    .purl { color: var(--text-secondary); font-size: 0.7rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis; }
    .license-summary { display: flex; gap: 8px; margin-bottom: 16px; }
    .license-summary-item {
      flex: 1; display: flex; flex-direction: column; align-items: center; gap: 2px;
      padding: 12px; border-radius: 4px; border: 1px solid var(--border);
    }
    .license-summary-count { font-size: 1.25rem; font-weight: 700; color: var(--text); }
    .license-summary-label { font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-secondary); font-weight: 500; }
    .permissive-bg { background: var(--surface-alt); }
    .copyleft-bg { background: var(--severity-critical-bg); }
    .unknown-bg { background: var(--surface-alt); }

    .license-list { display: flex; flex-direction: column; gap: 4px; overflow-y: auto; }
    .license-row {
      border-radius: 4px; overflow: hidden; transition: box-shadow 0.15s;
    }
    .license-row:hover { box-shadow: 0 1px 4px rgba(0,0,0,0.06); }
    .license-row.expanded { border-color: var(--accent); }
    .cat-permissive { background: var(--surface); border: 1px solid var(--border); }
    .cat-copyleft { background: var(--severity-critical-bg); border: 1px solid #fecaca; }
    .cat-copyleft-exempted { background: var(--status-success-bg); border: 1px solid var(--status-success); }
    .cat-unknown { background: var(--surface); border: 1px solid var(--border); }
    .lic-header {
      display: flex; align-items: center; gap: 10px; padding: 10px 14px; cursor: pointer;
      transition: background 0.1s;
    }
    .lic-header:hover { background: rgba(0,0,0,0.02); }
    .lic-toggle { font-size: 0.7rem; color: var(--text-muted); width: 14px; flex-shrink: 0; }
    .lic-id { font-weight: 600; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .lic-id-link { color: var(--accent); text-decoration: none; display: inline-flex; align-items: center; gap: 4px; }
    .lic-id-link:hover { text-decoration: underline; }
    .link-icon { font-size: 0.65rem; opacity: 0.6; }
    .lic-cat-badge {
      padding: 2px 7px; border-radius: 2px; font-size: 0.6rem; font-weight: 600;
      text-transform: uppercase; letter-spacing: 0.03em; flex-shrink: 0;
    }
    .cat-badge-permissive { background: var(--status-success-bg); color: var(--status-success); }
    .cat-badge-copyleft { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .cat-badge-unknown { background: var(--bg); color: var(--text-secondary); }
    .lic-exempted-badge {
      padding: 2px 6px; border-radius: 2px; font-size: 0.6rem; font-weight: 600;
      background: var(--status-success-bg); color: var(--status-success);
      text-transform: uppercase; letter-spacing: 0.03em; cursor: help; flex-shrink: 0;
    }
    .lic-count { font-size: 0.78rem; color: var(--text-secondary); margin-left: auto; white-space: nowrap; }

    .lic-body { border-top: 1px solid var(--border); padding: 12px 14px 14px; }
    .lic-exemption-note {
      display: flex; align-items: flex-start; gap: 6px;
      font-size: 0.75rem; color: var(--text); line-height: 1.4;
      background: var(--status-success-bg); padding: 8px 12px; border-radius: 3px;
      margin-bottom: 12px;
    }
    .exemption-icon { color: var(--status-success); font-weight: 700; flex-shrink: 0; }
    .lic-url-row {
      display: flex; align-items: center; gap: 8px; margin-bottom: 12px;
      font-size: 0.75rem;
    }
    .lic-url-label { color: var(--text-secondary); font-weight: 500; flex-shrink: 0; }
    .lic-url-link {
      color: var(--accent); text-decoration: none; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 0.72rem;
    }
    .lic-url-link:hover { text-decoration: underline; }

    .lic-pkg-section { margin-bottom: 10px; }
    .lic-pkg-section:last-child { margin-bottom: 0; }
    .lic-pkg-title {
      font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.03em; color: var(--text-secondary); margin: 0 0 8px;
    }
    .lic-pkg-title.exempted-title { color: var(--status-success); }
    .lic-pkg-list {
      display: flex; flex-direction: column; gap: 2px;
      max-height: 300px; overflow-y: auto;
    }
    .lic-pkg-item {
      padding: 5px 10px; border-radius: 3px; font-size: 0.75rem;
      background: var(--bg); border: 1px solid var(--border);
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .lic-pkg-item.exempted {
      background: var(--status-success-bg); border-color: var(--status-success);
    }
    .lic-pkg-name { color: var(--text); font-family: monospace; font-size: 0.72rem; }
    .lic-pkg-link {
      color: var(--accent); text-decoration: none; font-family: monospace; font-size: 0.72rem;
      display: inline-flex; align-items: center; gap: 4px;
    }
    .lic-pkg-link:hover { text-decoration: underline; }
    .lic-pkg-link.exempted-link { color: var(--status-success); }
    .lic-no-packages { font-size: 0.75rem; color: var(--text-muted); margin: 0; font-style: italic; }
    .dep-table-header {
      display: flex; align-items: center; gap: 16px; padding: 8px 12px;
      background: var(--bg); border-radius: 2px; font-weight: 600; font-size: 0.7rem;
      color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em;
      margin-bottom: 2px; border-bottom: 1px solid var(--border);
    }
    .dep-col-name { flex: 1; min-width: 0; }
    .dep-col-version { width: 140px; flex-shrink: 0; }
    .dep-col-license { width: 180px; flex-shrink: 0; }
    .dep-row {
      height: 42px; display: flex; align-items: center; gap: 16px;
      padding: 0 12px; border-bottom: 1px solid var(--border); font-size: 0.82rem;
      transition: background 0.1s;
    }
    .dep-row:hover { background: var(--surface-alt); }
    .dep-name {
      font-weight: 500; flex: 1; min-width: 0;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
      display: flex; align-items: center; gap: 8px;
    }
    .archived-tag {
      background: var(--severity-high); color: #fff;
      padding: 1px 6px; border-radius: 2px; font-size: 0.6rem; font-weight: 600;
      flex-shrink: 0;
    }
    .dep-version {
      color: var(--text-secondary); width: 140px; flex-shrink: 0;
      font-family: monospace; font-size: 0.78rem;
    }
    .dep-license {
      color: var(--status-success); font-size: 0.75rem;
      width: 180px; flex-shrink: 0; display: flex; align-items: center; gap: 4px;
    }
    .copyleft { color: var(--severity-critical); }
    .exempted { color: var(--status-warning); }
    .dep-exempted-tag {
      font-size: 0.6rem; font-weight: 700; color: var(--status-success);
      background: var(--status-success-bg); padding: 0 3px; border-radius: 2px;
    }
    .loading { padding: 24px; color: var(--text-muted); }
  `],
})
export class SbomDetailComponent implements OnInit {
  detail: SBOMDetail | null = null;
  vulns: VulnerabilityListItem[] = [];
  licenses: SBOMLicenseBreakdownItem[] = [];
  flatDeps: FlatDep[] = [];
  activeTab: Tab = 'vulns';
  expandedLicense: string | null = null;
  private archivedRepos = new Set<string>();

  constructor(
    private readonly route: ActivatedRoute,
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    const sbomId = this.route.snapshot.paramMap.get('id');
    if (!sbomId) return;

    forkJoin({
      detail: this.api.getSbomDetail(sbomId),
      vulns: this.api.getSbomVulnerabilities(sbomId),
      licenses: this.api.getSbomLicenses(sbomId),
      deps: this.api.getSbomDependencies(sbomId),
      archived: this.api.getArchivedPackages().pipe(catchError(() => of([] as ArchivedPackageInfo[]))),
    }).subscribe(({ detail, vulns, licenses, deps, archived }) => {
      this.detail = detail;
      this.vulns = vulns;
      this.licenses = licenses;
      this.buildExemptedSet();
      this.buildArchivedSet(archived || []);
      this.flatDeps = this.flattenTree(deps);
      this.cdr.markForCheck();
    });
  }

  trackByVuln(_i: number, v: VulnerabilityListItem): string { return v.vuln_id + v.purl; }
  trackByDep(_i: number, d: FlatDep): number { return d.index; }
  trackByLicense(_i: number, lic: SBOMLicenseBreakdownItem): string { return lic.license_id; }

  downloadSbom(): void {
    if (!this.detail) return;
    const url = this.api.getSbomDownloadUrl(this.detail.sbom_id);
    const a = document.createElement('a');
    a.href = url;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }

  toggleLicense(licenseId: string): void {
    this.expandedLicense = this.expandedLicense === licenseId ? null : licenseId;
    this.cdr.markForCheck();
  }

  isUrl(value: string): boolean {
    if (!value) return false;
    return value.startsWith('http://') || value.startsWith('https://');
  }

  extractLicenseLabel(url: string): string {
    try {
      const u = new URL(url);
      // Use last meaningful path segment as label
      const segments = u.pathname.split('/').filter(Boolean);
      return segments.length > 0 ? segments[segments.length - 1] : u.hostname;
    } catch {
      return url;
    }
  }

  extractPackageLabel(pkg: string): string {
    if (!this.isUrl(pkg)) return pkg;
    try {
      const u = new URL(pkg);
      // For package URLs, show path without leading slash
      return u.pathname.replace(/^\//, '') || u.hostname;
    } catch {
      return pkg;
    }
  }

  getLicenseCategoryCount(category: string): number {
    return this.licenses
      .filter(l => l.category === category)
      .reduce((sum, l) => sum + l.package_count, 0);
  }

  isCopyleft(license: string): boolean {
    return ['GPL', 'LGPL', 'AGPL', 'MPL', 'EPL', 'EUPL'].some((l) => license.toUpperCase().includes(l));
  }

  isExemptedLicense(license: string): boolean {
    return this.exemptedLicenseIds.has(license);
  }

  isArchivedPurl(purl: string): boolean {
    if (!purl) return false;
    const lower = purl.toLowerCase();
    for (const repo of this.archivedRepos) {
      if (lower.includes(repo)) return true;
    }
    return false;
  }

  getLicenseCardClass(lic: SBOMLicenseBreakdownItem): string {
    if (lic.exempted_packages?.length && lic.category === 'copyleft') {
      return 'cat-copyleft-exempted';
    }
    return 'cat-' + lic.category;
  }

  private buildExemptedSet(): void {
    this.exemptedLicenseIds.clear();
    for (const lic of this.licenses) {
      if (lic.exempted_packages?.length) {
        this.exemptedLicenseIds.add(lic.license_id);
      }
    }
  }

  private buildArchivedSet(archived: ArchivedPackageInfo[]): void {
    this.archivedRepos.clear();
    for (const pkg of archived) {
      if (pkg.repo) {
        this.archivedRepos.add(pkg.repo.toLowerCase());
      }
    }
  }

  private exemptedLicenseIds = new Set<string>();

  private flattenTree(nodes: DependencyNode[], level = 0): FlatDep[] {
    const result: FlatDep[] = [];
    for (const node of nodes) {
      result.push({
        name: node.name, version: node.version, license: node.license,
        purl: node.purl, level, index: node.index,
      });
    }
    return result;
  }
}

interface FlatDep {
  name: string;
  version: string;
  license: string;
  purl: string;
  level: number;
  index: number;
}

