import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { RouterModule, ActivatedRoute } from '@angular/router';
import { Subject, forkJoin, of } from 'rxjs';
import { catchError, debounceTime, distinctUntilChanged, switchMap, takeUntil } from 'rxjs/operators';
import { ApiService } from '../../core/api.service';
import {
  ProjectDetail,
  ProjectListItem,
  ProjectPackageItem,
  SBOMListItem,
  VulnerabilityListItem,
} from '../../core/api.models';
import { DonutChartComponent, DonutSegment } from '../../shared/charts/donut-chart.component';
import { HorizontalBarChartComponent, BarItem } from '../../shared/charts/horizontal-bar-chart.component';
import { parentSourceLabel } from '../../shared/parent-source';

type Tab = 'overview' | 'versions' | 'vulns' | 'packages' | 'subprojects';

type VulnRow = VulnerabilityListItem & { pkg_name: string; pkg_version: string };

/**
 * Splits a PURL into a display name (namespace/name) and version.
 * Qualifiers and subpath are dropped; an unparseable value is returned as the name.
 */
export function splitPurl(purl: string): { pkg_name: string; pkg_version: string } {
  if (!purl) return { pkg_name: '', pkg_version: '' };
  const core = purl.split(/[?#]/)[0];
  const at = core.lastIndexOf('@');
  const path = at >= 0 ? core.slice(0, at) : core;
  const version = at >= 0 ? core.slice(at + 1) : '';
  const slash = path.indexOf('/');
  const name = path.startsWith('pkg:') && slash >= 0 ? path.slice(slash + 1) : path;
  const decode = (s: string) => {
    try { return decodeURIComponent(s); } catch { return s; }
  };
  return { pkg_name: decode(name), pkg_version: decode(version) };
}

/**
 * One project as a unit (#398).
 *
 * Before this page existed, clicking a project ran a substring search over
 * the SBOM list — "kubernetes" returned 1 368 documents, eleven of which were
 * Kubernetes. This page is scoped by project identity, aggregates across all
 * of the project's versions with de-duplicated counts, and — through tags
 * that are themselves project names — shows the way up to a parent and down
 * to sub-projects.
 *
 * The Overview tab is the global dashboard narrowed to this project: the
 * same KPI cards and charts, fed from the project read model instead of the
 * instance-wide stats, so a maintainer reads one project the way an operator
 * reads the fleet.
 */
@Component({
  selector: 'app-project-detail',
  standalone: true,
  imports: [CommonModule, FormsModule, ScrollingModule, RouterModule, DonutChartComponent, HorizontalBarChartComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="project-detail" *ngIf="detail">
      <div class="header">
        <a routerLink="/projects" class="back">← Projects</a>
        <h1>{{ detail.project_name }}</h1>
        <span class="product-version" *ngIf="detail.latest_version" [title]="'Latest version: ' + detail.latest_version">{{ detail.latest_version }}</span>
        <span class="badge">{{ detail.sbom_count }} {{ detail.sbom_count === 1 ? 'version' : 'versions' }}</span>
      </div>

      <!--
        Hierarchy row. Parents are tags that are also projects; the parent's
        page is where its own SBOMs live. Sub-projects are the projects tagged
        with this name — that listing already exists as /projects?tag=.
        Plain groupings (tier, org) are shown as filter links.
      -->
      <div class="context-row" *ngIf="detail.parents.length || detail.related_project_count || otherTags.length || resolvedParent || children.length">
        <ng-container *ngIf="detail.parents.length || resolvedParent">
          <span class="ctx-label">Part of</span>
          <a *ngFor="let p of detail.parents" [routerLink]="['/projects', p]" class="ctx-chip parent" [title]="'Open parent project ' + p">↑ {{ p }}</a>
          <!--
            The resolved parent (repository owner, mapping file, bucket
            config…). Only shown when the tag hierarchy above does not
            already name it; the title says how it was resolved.
          -->
          <a *ngIf="resolvedParent" [routerLink]="['/projects', resolvedParent]" class="ctx-chip parent resolved"
             [title]="parentSourceLabel(detail.parent_source, detail.parent_owner)">↑ {{ resolvedParent }}</a>
        </ng-container>
        <ng-container *ngIf="children.length">
          <span class="ctx-label">Subprojects</span>
          <a *ngFor="let c of children" [routerLink]="['/projects', c]" class="ctx-chip children" [title]="'Open subproject ' + c">↓ {{ c }}</a>
        </ng-container>
        <ng-container *ngIf="detail.related_project_count">
          <span class="ctx-label">Has</span>
          <a routerLink="/projects" [queryParams]="{tag: detail.project_name}" class="ctx-chip children"
             [title]="'List projects tagged with ' + detail.project_name">
            ↓ {{ detail.related_project_count | number }} {{ detail.related_project_count === 1 ? 'sub-project' : 'sub-projects' }}
          </a>
        </ng-container>
        <ng-container *ngIf="otherTags.length">
          <span class="ctx-label">In</span>
          <a *ngFor="let t of otherTags" routerLink="/projects" [queryParams]="{tag: t}" class="ctx-chip" [title]="'Grouping: ' + t">{{ t }}</a>
        </ng-container>
      </div>

      <div class="source-row" *ngIf="detail.source_repo || detail.clusters.length">
        <ng-container *ngIf="detail.source_repo">
          <span class="source-label">Source:</span>
          <a *ngIf="isUrl(detail.source_repo)" [href]="detail.source_repo" target="_blank" rel="noopener" class="source-link">
            {{ detail.source_repo }} <span class="link-icon">↗</span>
          </a>
          <span *ngIf="!isUrl(detail.source_repo)" class="source-value">{{ detail.source_repo }}</span>
        </ng-container>
        <ng-container *ngIf="detail.clusters.length">
          <span class="source-label deployed">Deployed:</span>
          <span *ngFor="let c of detail.clusters" class="owner-badge cluster-badge" [title]="'Cluster'">{{ c }}</span>
          <span *ngFor="let n of detail.namespaces" class="owner-badge" [title]="'Namespace'">{{ n }}</span>
        </ng-container>
      </div>

      <!--
        The numbers are de-duplicated across versions — the title spells it
        out because the same page used to show a sum and readers will compare.
      -->
      <div class="stats-row">
        <div class="stat" title="Distinct components across all versions"><strong>{{ detail.package_count | number }}</strong> packages</div>
        <div class="stat" title="Distinct (vulnerability, package) pairs across all versions"><strong>{{ detail.vuln_count | number }}</strong> vulnerabilities</div>
        <button type="button" class="stat distinct-ids" *ngIf="distinctVulnIds && distinctVulnIds !== vulns.length"
                (click)="activeTab = 'vulns'"
                title="Distinct vulnerability IDs — one ID can affect several packages, or several versions of the same package. Click to open the list.">
          {{ distinctVulnIds | number }} distinct IDs
        </button>
        <div class="stat critical" *ngIf="detail.critical_vulns">{{ detail.critical_vulns | number }} critical</div>
        <div class="stat high" *ngIf="detail.high_vulns">{{ detail.high_vulns | number }} high</div>
        <div class="stat medium" *ngIf="detail.medium_vulns">{{ detail.medium_vulns | number }} medium</div>
        <div class="stat low" *ngIf="detail.low_vulns">{{ detail.low_vulns | number }} low</div>
        <div class="stat date" *ngIf="detail.latest_ingested" [title]="'Latest SBOM ingested'">{{ detail.latest_ingested | date:'mediumDate' }}</div>
      </div>

      <div class="tabs">
        <button [class.active]="activeTab === 'overview'" (click)="activeTab = 'overview'">
          Overview
        </button>
        <button [class.active]="activeTab === 'versions'" (click)="activeTab = 'versions'">
          Versions ({{ sboms.length | number }})
        </button>
        <button [class.active]="activeTab === 'vulns'" (click)="activeTab = 'vulns'">
          Vulnerabilities ({{ vulns.length | number }})
        </button>
        <button [class.active]="activeTab === 'packages'" (click)="selectPackages()">
          Packages ({{ packagesTotal | number }})
        </button>
        <button *ngIf="detail.related_project_count" [class.active]="activeTab === 'subprojects'" (click)="selectSubprojects()">
          Sub-projects ({{ detail.related_project_count | number }})
        </button>
      </div>

      <!-- Overview: the dashboard, scoped to this project -->
      <div *ngIf="activeTab === 'overview'" class="tab-content overview">
        <div class="kpi-row">
          <div class="kpi-card">
            <span class="kpi-value">{{ detail.sbom_count | number }}</span>
            <span class="kpi-label">{{ detail.sbom_count === 1 ? 'Version' : 'Versions' }}</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-value">{{ detail.package_count | number }}</span>
            <span class="kpi-label">Distinct Packages</span>
          </div>
          <div class="kpi-card warn">
            <span class="kpi-value">{{ effectiveVulns | number }}</span>
            <span class="kpi-label">{{ suppressedVulns > 0 ? 'Effective Vulns' : 'Vulnerabilities' }}</span>
          </div>
          <div class="kpi-card ok" *ngIf="suppressedVulns > 0">
            <span class="kpi-value">{{ suppressedVulns | number }}</span>
            <span class="kpi-label">Suppressed by VEX</span>
          </div>
          <div class="kpi-card" [class.warn]="licenseViolations > 0" [class.ok]="licenseViolations === 0">
            <span class="kpi-value">{{ licenseViolations | number }}</span>
            <span class="kpi-label">License Findings</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-value">{{ inEveryVersion | number }}</span>
            <span class="kpi-label">Vulns in every version</span>
          </div>
        </div>

        <div class="charts-row">
          <div class="chart-card">
            <h3>Vulnerability Severity</h3>
            <app-donut-chart [segments]="severitySegments" centerLabel="Vulnerabilities" />
          </div>
          <div class="chart-card">
            <h3>License Breakdown</h3>
            <app-donut-chart [segments]="licenseSegments" centerLabel="Packages" />
          </div>
          <div class="chart-card">
            <h3>VEX Effectiveness</h3>
            @if (suppressedVulns > 0) {
              <app-donut-chart [segments]="vexSegments" centerLabel="Total" />
            } @else {
              <div class="empty-vex">
                <p class="empty-vex-title">No VEX suppressions</p>
                <p class="empty-vex-hint">No <code>not_affected</code> statement covers a finding of this project.</p>
              </div>
            }
          </div>
        </div>

        <div class="charts-row two-col">
          <div class="chart-card">
            <h3>Vulnerabilities by Severity</h3>
            <app-horizontal-bar-chart [bars]="severityBars" />
          </div>
          <div class="chart-card">
            <h3>Packages by License Category</h3>
            <app-horizontal-bar-chart [bars]="licenseBars" />
          </div>
        </div>

        <div class="quick-links">
          <button class="quick-link" (click)="activeTab = 'vulns'">Vulnerabilities <span class="arrow">→</span></button>
          <button class="quick-link" (click)="selectPackages()">Packages <span class="arrow">→</span></button>
          <a *ngIf="detail.latest_sbom_id" [routerLink]="['/sboms', detail.latest_sbom_id]" class="quick-link">
            Latest SBOM<span *ngIf="detail.latest_version"> ({{ detail.latest_version }})</span> <span class="arrow">→</span>
          </a>
          <a routerLink="/license-compliance" [queryParams]="{search: detail.project_name}" class="quick-link">License Compliance <span class="arrow">→</span></a>
        </div>
      </div>

      <!-- Versions -->
      <div *ngIf="activeTab === 'versions'" class="tab-content">
        <cdk-virtual-scroll-viewport itemSize="56" class="viewport">
          <div *cdkVirtualFor="let sbom of sboms; trackBy: trackBySbom" class="row">
            <a [routerLink]="['/sboms', sbom.sbom_id]" class="row-link">
              <div class="row-main">
                <span class="row-title">
                  {{ sbom.document_name }}
                  <span class="product-version" *ngIf="sbom.document_version">{{ sbom.document_version }}</span>
                </span>
                <span class="row-meta">
                  <span class="owner-badge cluster-badge" *ngIf="sbom.cluster">{{ sbom.cluster }}</span>
                  <span class="owner-badge" *ngIf="sbom.namespace">{{ sbom.namespace }}</span>
                  <span class="mono">{{ sbom.source_file }}</span>
                </span>
              </div>
              <div class="row-stats">
                <span class="stat-inline">{{ sbom.package_count | number }} pkgs</span>
                <span class="stat-inline" [class.has-vulns]="sbom.vuln_count > 0">{{ sbom.vuln_count | number }} vulns</span>
                <span class="date">{{ sbom.ingested_at | date:'mediumDate' }}</span>
              </div>
            </a>
          </div>
        </cdk-virtual-scroll-viewport>
        <div *ngIf="sboms.length < sbomsTotal" class="load-more">
          <button (click)="loadMoreSboms()" class="load-more-btn">Load more ({{ sboms.length }} / {{ sbomsTotal }})</button>
        </div>
      </div>

      <!-- Vulnerabilities: one row per (vuln, package), with reach across versions -->
      <div *ngIf="activeTab === 'vulns'" class="tab-content">
        <div *ngIf="vulns.length === 0" class="empty">No vulnerabilities across any version.</div>
        <p *ngIf="distinctVulnIds && distinctVulnIds !== vulns.length" class="vuln-hint">
          {{ vulns.length | number }} findings across {{ distinctVulnIds | number }} distinct vulnerability IDs —
          one row per affected package version, so the same ID appears once for every version that carries it.
        </p>
        <cdk-virtual-scroll-viewport *ngIf="vulns.length > 0" itemSize="56" class="viewport">
          <div *cdkVirtualFor="let vuln of vulnRows; trackBy: trackByVuln" class="vuln-row">
            <span class="severity-badge" [class]="'sev-' + vuln.severity.toLowerCase()">{{ vuln.severity }}</span>
            <div class="vuln-info">
              <a [routerLink]="['/cve-impact']" [queryParams]="{vuln: vuln.vuln_id}" class="vuln-id">{{ vuln.vuln_id }}</a>
              <span class="summary">{{ vuln.summary }}</span>
            </div>
            <span class="vex-badge" *ngIf="vuln.vex_status" [class]="'vex-' + vuln.vex_status">{{ vuln.vex_status | titlecase }}</span>
            <span class="reach" *ngIf="vuln.affected_sboms"
                  [class.all]="vuln.affected_sboms === detail.sbom_count"
                  [title]="'Present in ' + vuln.affected_sboms + ' of ' + detail.sbom_count + ' versions'">
              {{ vuln.affected_sboms }}/{{ detail.sbom_count }}
            </span>
            <!-- Name and version separately: a truncated PURL cuts exactly the
                 version off, and two versions of one module then read as a duplicate. -->
            <span class="vuln-pkg" [title]="vuln.purl">
              <span class="vuln-pkg-name">{{ vuln.pkg_name }}</span>
              <span class="pkg-version" *ngIf="vuln.pkg_version">{{ vuln.pkg_version }}</span>
            </span>
          </div>
        </cdk-virtual-scroll-viewport>
      </div>

      <!-- Packages: distinct components, most exposed first -->
      <div *ngIf="activeTab === 'packages'" class="tab-content">
        <div class="search-bar">
          <input type="text" [(ngModel)]="packageSearch" (ngModelChange)="onPackageSearch($event)"
                 placeholder="Filter components by name or PURL…" class="search-input" />
          <span class="search-loading" *ngIf="packagesLoading">⏳</span>
        </div>
        <div *ngIf="!packagesLoading && packages.length === 0" class="empty">
          No components<span *ngIf="packageSearch"> matching "{{ packageSearch }}"</span>.
        </div>
        <cdk-virtual-scroll-viewport *ngIf="packages.length > 0" itemSize="48" class="viewport">
          <div *cdkVirtualFor="let pkg of packages; trackBy: trackByPackage" class="pkg-row">
            <div class="pkg-info">
              <a [routerLink]="['/package-search', pkg.name]" class="pkg-name">{{ pkg.name }}</a>
              <span class="pkg-version">{{ pkg.version }}</span>
            </div>
            <span class="reach" [class.all]="pkg.sbom_count === detail.sbom_count"
                  [title]="'Shipped in ' + pkg.sbom_count + ' of ' + detail.sbom_count + ' versions'">
              {{ pkg.sbom_count }}/{{ detail.sbom_count }}
            </span>
            <span class="stat-inline vulns" [class.has-vulns]="pkg.vuln_count > 0" [title]="'Distinct vulnerability ids on this component'">
              {{ pkg.vuln_count | number }} vulns
            </span>
            <span class="purl">{{ pkg.purl }}</span>
          </div>
        </cdk-virtual-scroll-viewport>
        <div *ngIf="packages.length < packagesTotal" class="load-more">
          <button (click)="loadMorePackages()" class="load-more-btn">Load more ({{ packages.length }} / {{ packagesTotal }})</button>
        </div>
      </div>

      <!-- Sub-projects: projects tagged with this project's name -->
      <div *ngIf="activeTab === 'subprojects'" class="tab-content">
        <cdk-virtual-scroll-viewport itemSize="56" class="viewport">
          <div *cdkVirtualFor="let p of subprojects; trackBy: trackByProject" class="row">
            <a [routerLink]="['/projects', p.project_name]" class="row-link">
              <div class="row-main">
                <span class="row-title">{{ p.project_name }}</span>
                <span class="row-meta">{{ p.sbom_count }} {{ p.sbom_count === 1 ? 'version' : 'versions' }}</span>
              </div>
              <div class="row-stats">
                <span class="stat-inline">{{ p.package_count | number }} pkgs</span>
                <span class="stat-inline" [class.has-vulns]="p.vuln_count > 0">{{ p.vuln_count | number }} vulns</span>
                <span class="date">{{ p.latest_ingested | date:'mediumDate' }}</span>
              </div>
            </a>
          </div>
        </cdk-virtual-scroll-viewport>
        <div *ngIf="subprojects.length < (detail.related_project_count || 0)" class="load-more">
          <a routerLink="/projects" [queryParams]="{tag: detail.project_name}" class="load-more-btn">
            See all {{ detail.related_project_count | number }} in the project list →
          </a>
        </div>
      </div>
    </div>

    <div class="not-found" *ngIf="notFound">
      <a routerLink="/projects" class="back">← Projects</a>
      <h1>Project not found</h1>
      <p>No SBOM resolves to <code>{{ requestedName }}</code>.</p>
    </div>
  `,
  styles: [`
    .project-detail, .not-found { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    .header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; flex-wrap: wrap; }
    .back { color: var(--text-secondary); text-decoration: none; font-size: 0.8rem; }
    .back:hover { color: var(--accent); }
    h1 { margin: 0; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .badge { background: var(--surface-alt); padding: 2px 8px; border-radius: 2px; font-size: 0.7rem; color: var(--text-secondary); border: 1px solid var(--border); }
    .product-version {
      font-family: monospace; font-size: 0.75rem; color: var(--accent-hover);
      background: var(--status-info-bg); border: 1px solid var(--accent); border-radius: 2px;
      padding: 1px 6px; margin-left: 6px;
    }

    .context-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-bottom: 8px; font-size: 0.75rem; }
    .ctx-label { color: var(--text-muted); margin-left: 6px; }
    .ctx-label:first-child { margin-left: 0; }
    .ctx-chip {
      display: inline-block; padding: 2px 8px; border-radius: 12px; text-decoration: none;
      background: var(--surface); color: var(--text-secondary); border: 1px solid var(--border);
      font-size: 0.72rem; transition: all 0.15s;
    }
    .ctx-chip:hover { border-color: var(--accent); color: var(--accent); }
    .ctx-chip.parent { border-style: dashed; color: var(--accent-hover); font-weight: 600; }
    .ctx-chip.children { background: var(--status-info-bg); color: var(--accent-hover); border-color: var(--accent); font-weight: 600; }

    .source-row { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 0.78rem; flex-wrap: wrap; }
    .source-label { color: var(--text-secondary); font-weight: 500; flex-shrink: 0; }
    .source-label.deployed { margin-left: 12px; }
    .source-link { color: var(--accent); text-decoration: none; font-family: monospace; font-size: 0.72rem; display: inline-flex; align-items: center; gap: 4px; }
    .source-link:hover { text-decoration: underline; }
    .source-value { font-family: monospace; font-size: 0.72rem; }
    .owner-badge {
      display: inline-block; padding: 1px 6px; border-radius: 2px; font-size: 0.65rem; font-weight: 500;
      background: var(--surface-alt); color: var(--text-secondary); border: 1px solid var(--border);
    }
    .cluster-badge { background: var(--status-info-bg); color: var(--accent-hover); border-color: var(--accent); }

    .stats-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
    .stat { background: var(--surface-alt); padding: 6px 14px; border-radius: 2px; font-size: 0.8rem; border: 1px solid var(--border); }
    .stat.date { color: var(--text-muted); margin-left: auto; }
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
    .tab-content { flex: 1; min-height: 0; display: flex; flex-direction: column; }
    .tab-content.overview { overflow-y: auto; gap: 12px; }
    .viewport { flex: 1; min-height: 400px; }
    .empty { padding: 32px; text-align: center; color: var(--text-muted); font-size: 0.85rem; }

    /* Overview: same vocabulary as the global dashboard, scoped to one project. */
    .kpi-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
    .kpi-card {
      display: flex; flex-direction: column; gap: 2px; padding: 14px 16px;
      background: var(--surface); border: 1px solid var(--border); border-radius: 4px;
    }
    .kpi-value { font-size: 1.4rem; font-weight: 700; color: var(--text); line-height: 1.2; letter-spacing: -0.02em; }
    .kpi-label { font-size: 0.68rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; font-weight: 500; }
    .kpi-card.warn .kpi-value { color: var(--severity-critical); }
    .kpi-card.ok .kpi-value { color: var(--status-success); }
    .charts-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; }
    .charts-row.two-col { grid-template-columns: repeat(2, 1fr); }
    .chart-card { background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 16px 20px; }
    .chart-card h3 { margin: 0 0 12px; font-size: 0.78rem; font-weight: 600; color: var(--dark); text-transform: uppercase; letter-spacing: 0.03em; }
    .empty-vex { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 180px; text-align: center; }
    .empty-vex-title { margin: 0; font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); }
    .empty-vex-hint { margin: 4px 0 0; font-size: 0.72rem; color: var(--text-muted); }
    .empty-vex-hint code { font-family: monospace; background: var(--surface-alt); padding: 1px 4px; border-radius: 2px; }
    .quick-links { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; }
    .quick-link {
      display: flex; align-items: center; justify-content: space-between;
      padding: 10px 14px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; text-decoration: none; color: var(--dark); cursor: pointer;
      font-size: 0.78rem; font-weight: 500; font-family: inherit; transition: border-color 0.15s; text-align: left;
    }
    .quick-link:hover { border-color: var(--accent); color: var(--accent); }
    .arrow { color: var(--text-muted); }
    .quick-link:hover .arrow { color: var(--accent); }

    .row { height: 52px; display: flex; align-items: center; border-bottom: 1px solid var(--border); }
    .row-link { display: flex; align-items: center; justify-content: space-between; width: 100%; padding: 0 12px; text-decoration: none; color: inherit; height: 100%; }
    .row-link:hover { background: var(--surface-alt); }
    .row-main { display: flex; flex-direction: column; gap: 2px; flex: 1; min-width: 0; }
    .row-title { font-weight: 600; font-size: 0.82rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-meta { font-size: 0.7rem; color: var(--text-muted); display: flex; gap: 6px; align-items: center; overflow: hidden; }
    .mono { font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-stats { display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
    .stat-inline { font-size: 0.78rem; color: var(--text-secondary); }
    .stat-inline.vulns { width: 80px; text-align: right; }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }
    .date { color: var(--text-muted); font-size: 0.72rem; width: 100px; text-align: right; }

    .vuln-row { height: 52px; display: flex; align-items: center; gap: 12px; padding: 0 12px; border-bottom: 1px solid var(--border); }
    .severity-badge {
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
    .vex-affected { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .vex-under_investigation { background: var(--severity-high-bg); color: var(--status-warning); }
    .purl { color: var(--text-secondary); font-size: 0.7rem; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .vuln-pkg { display: flex; align-items: baseline; gap: 6px; max-width: 420px; min-width: 0; flex-shrink: 1; }
    .vuln-pkg-name { color: var(--text-secondary); font-size: 0.72rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
    .vuln-pkg .pkg-version { flex-shrink: 0; white-space: nowrap; }
    .vuln-hint { margin: 0 0 8px; font-size: 0.75rem; color: var(--text-secondary); }
    .stat.distinct-ids { color: var(--text-secondary); cursor: pointer; font-family: inherit; }
    .stat.distinct-ids:hover { border-color: var(--accent); color: var(--accent); }

    /* Reach: in how many of the project's versions. Full reach is emphasised —
       a finding in every version is a project problem, not a version problem. */
    .reach {
      font-family: monospace; font-size: 0.7rem; padding: 1px 6px; border-radius: 2px;
      background: var(--bg); color: var(--text-secondary); border: 1px solid var(--border);
      min-width: 44px; text-align: center; cursor: help;
    }
    .reach.all { color: var(--text); font-weight: 600; border-color: var(--text-secondary); }

    .pkg-row { height: 44px; display: flex; align-items: center; gap: 12px; padding: 0 12px; border-bottom: 1px solid var(--border); }
    .pkg-info { flex: 1; display: flex; align-items: baseline; gap: 8px; min-width: 0; }
    .pkg-name { font-weight: 600; font-size: 0.8rem; color: var(--accent); text-decoration: none; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .pkg-name:hover { text-decoration: underline; }
    .pkg-version { font-family: monospace; font-size: 0.72rem; color: var(--text-secondary); }

    .search-bar { position: relative; margin-bottom: 8px; }
    .search-input {
      width: 100%; padding: 8px 36px 8px 12px; font-size: 0.82rem; box-sizing: border-box;
      border: 1px solid var(--border); border-radius: 4px; background: var(--surface); color: var(--text);
      font-family: inherit; outline: none;
    }
    .search-input:focus { border-color: var(--accent); }
    .search-loading { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); font-size: 0.8rem; }

    .load-more { padding: 12px; text-align: center; }
    .load-more-btn {
      display: inline-block; padding: 8px 24px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-family: inherit;
      color: var(--text-secondary); text-decoration: none; transition: all 0.15s;
    }
    .load-more-btn:hover { border-color: var(--accent); color: var(--accent); }

    .not-found h1 { margin-top: 12px; }
    .not-found code { font-family: monospace; background: var(--surface-alt); padding: 1px 6px; border-radius: 2px; }
  `],
})
export class ProjectDetailComponent implements OnInit, OnDestroy {
  detail: ProjectDetail | null = null;
  notFound = false;
  requestedName = '';

  sboms: SBOMListItem[] = [];
  sbomsTotal = 0;
  vulns: VulnerabilityListItem[] = [];
  vulnRows: VulnRow[] = [];
  distinctVulnIds = 0;
  packages: ProjectPackageItem[] = [];
  packagesTotal = 0;
  packagesLoading = false;
  packageSearch = '';
  subprojects: ProjectListItem[] = [];

  activeTab: Tab = 'overview';

  // Overview tab. Severity and license come from the read model; the VEX
  // split is derived from the vulnerability rows, which already carry the
  // latest-wins statement per (vuln, package) across the project's versions.
  severitySegments: DonutSegment[] = [];
  severityBars: BarItem[] = [];
  licenseSegments: DonutSegment[] = [];
  licenseBars: BarItem[] = [];
  vexSegments: DonutSegment[] = [];
  suppressedVulns = 0;
  effectiveVulns = 0;
  licenseViolations = 0;
  inEveryVersion = 0;

  private sbomPage = 1;
  private packagePage = 1;
  private packagesLoaded = false;
  private subprojectsLoaded = false;
  private readonly pageSize = 100;
  private readonly packageSearch$ = new Subject<string>();
  private readonly destroy$ = new Subject<void>();

  constructor(
    private readonly api: ApiService,
    private readonly route: ActivatedRoute,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    // Package filtering is server-side; debounce so typing does not fire a
    // request per keystroke against an arrayJoin over the project's SBOMs.
    this.packageSearch$.pipe(
      debounceTime(300),
      distinctUntilChanged(),
      takeUntil(this.destroy$),
    ).subscribe(() => {
      this.packagePage = 1;
      this.packages = [];
      this.loadPackages();
    });

    // The route param is the identity. switchMap so navigating between two
    // project pages cancels the first load instead of racing it.
    this.route.paramMap.pipe(
      switchMap((params) => {
        const name = params.get('name') ?? '';
        this.requestedName = name;
        this.reset();
        this.cdr.markForCheck();
        return forkJoin({
          detail: this.api.getProjectDetail(name),
          sboms: this.api.getProjectSboms(name, 1, this.pageSize),
          vulns: this.api.getProjectVulnerabilities(name).pipe(catchError(() => of([] as VulnerabilityListItem[]))),
        }).pipe(catchError(() => of(null)));
      }),
      takeUntil(this.destroy$),
    ).subscribe((res) => {
      if (!res) {
        this.notFound = true;
        this.cdr.markForCheck();
        return;
      }
      this.detail = res.detail;
      this.sboms = res.sboms.data;
      this.sbomsTotal = res.sboms.total;
      this.vulns = res.vulns;
      this.vulnRows = res.vulns.map((v) => ({ ...v, ...splitPurl(v.purl) }));
      this.distinctVulnIds = new Set(res.vulns.map((v) => v.vuln_id)).size;
      // Packages total is known from the header without loading the list;
      // the list itself loads on first tab open.
      this.packagesTotal = res.detail.package_count;
      this.buildOverview(res.detail, res.vulns);
      this.cdr.markForCheck();
    });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  /** Same palette and order as the global dashboard so the two read alike. */
  private buildOverview(d: ProjectDetail, vulns: VulnerabilityListItem[]): void {
    this.severitySegments = [
      { label: 'Critical', value: d.critical_vulns, color: '#C43030' },
      { label: 'High', value: d.high_vulns, color: '#E8871E' },
      { label: 'Medium', value: d.medium_vulns, color: '#C07012' },
      { label: 'Low', value: d.low_vulns, color: '#4b5563' },
    ];
    this.severityBars = [...this.severitySegments];

    const lb = d.license_breakdown || {};
    this.licenseSegments = [
      { label: 'Permissive', value: lb['permissive'] || 0, color: '#0D6B5E' },
      { label: 'Copyleft', value: lb['copyleft'] || 0, color: '#C43030' },
      { label: 'Not Approved', value: lb['unapproved'] || 0, color: '#C07012' },
      { label: 'Unknown', value: lb['unknown'] || 0, color: '#9ca3af' },
    ];
    this.licenseBars = [...this.licenseSegments];
    this.licenseViolations = (lb['copyleft'] || 0) + (lb['unapproved'] || 0) + (lb['unknown'] || 0);

    this.suppressedVulns = vulns.filter((v) => v.vex_status === 'not_affected').length;
    this.effectiveVulns = Math.max(0, vulns.length - this.suppressedVulns);
    this.inEveryVersion = d.sbom_count > 0
      ? vulns.filter((v) => v.affected_sboms === d.sbom_count).length
      : 0;
    this.vexSegments = this.suppressedVulns > 0
      ? [
          { label: 'Effective', value: this.effectiveVulns, color: '#E8871E' },
          { label: 'Suppressed', value: this.suppressedVulns, color: '#0D6B5E' },
        ]
      : [];
  }

  /** Tags that are groupings rather than parents. */
  get otherTags(): string[] {
    if (!this.detail) return [];
    const parents = new Set(this.detail.parents);
    return this.detail.tags.filter((t) => !parents.has(t));
  }

  /**
   * The resolved parent, unless the tag hierarchy already shows it as a
   * "Part of" chip — the same parent twice would read as two parents.
   */
  get resolvedParent(): string {
    const p = this.detail?.parent;
    if (!p || this.detail!.parents.includes(p)) return '';
    return p;
  }

  /** Subprojects resolved by the API (repository owner, mapping file, …). */
  get children(): string[] {
    return this.detail?.children ?? [];
  }

  parentSourceLabel = parentSourceLabel;

  isUrl(s: string): boolean {
    return /^https?:\/\//i.test(s);
  }

  selectPackages(): void {
    this.activeTab = 'packages';
    if (!this.packagesLoaded) {
      this.loadPackages();
    }
  }

  selectSubprojects(): void {
    this.activeTab = 'subprojects';
    if (!this.subprojectsLoaded && this.detail) {
      this.subprojectsLoaded = true;
      this.api.getProjects(1, this.pageSize, '', this.detail.project_name)
        .pipe(takeUntil(this.destroy$))
        .subscribe((resp) => {
          // The tag listing can include the project itself if it was
          // self-tagged; the count from the header already excludes it.
          this.subprojects = resp.data.filter((p) => p.project_name !== this.detail?.project_name);
          this.cdr.markForCheck();
        });
    }
  }

  onPackageSearch(term: string): void {
    this.packageSearch$.next(term.trim());
  }

  loadMoreSboms(): void {
    if (!this.detail) return;
    this.sbomPage++;
    this.api.getProjectSboms(this.detail.project_name, this.sbomPage, this.pageSize)
      .pipe(takeUntil(this.destroy$))
      .subscribe((resp) => {
        this.sboms = [...this.sboms, ...resp.data];
        this.sbomsTotal = resp.total;
        this.cdr.markForCheck();
      });
  }

  loadMorePackages(): void {
    this.packagePage++;
    this.loadPackages(true);
  }

  private loadPackages(append = false): void {
    if (!this.detail) return;
    this.packagesLoading = true;
    this.packagesLoaded = true;
    this.cdr.markForCheck();
    this.api.getProjectPackages(this.detail.project_name, this.packagePage, this.pageSize, this.packageSearch)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (resp) => {
          this.packages = append ? [...this.packages, ...resp.data] : resp.data;
          this.packagesTotal = resp.total;
          this.packagesLoading = false;
          this.cdr.markForCheck();
        },
        error: () => {
          this.packagesLoading = false;
          this.cdr.markForCheck();
        },
      });
  }

  private reset(): void {
    this.detail = null;
    this.notFound = false;
    this.sboms = [];
    this.sbomsTotal = 0;
    this.vulns = [];
    this.vulnRows = [];
    this.distinctVulnIds = 0;
    this.packages = [];
    this.packagesTotal = 0;
    this.packageSearch = '';
    this.subprojects = [];
    this.activeTab = 'overview';
    this.severitySegments = [];
    this.severityBars = [];
    this.licenseSegments = [];
    this.licenseBars = [];
    this.vexSegments = [];
    this.suppressedVulns = 0;
    this.effectiveVulns = 0;
    this.licenseViolations = 0;
    this.inEveryVersion = 0;
    this.sbomPage = 1;
    this.packagePage = 1;
    this.packagesLoaded = false;
    this.subprojectsLoaded = false;
  }

  trackBySbom(_i: number, s: SBOMListItem): string { return s.sbom_id; }
  trackByVuln(_i: number, v: VulnerabilityListItem): string { return v.vuln_id + '|' + v.purl; }
  trackByPackage(_i: number, p: ProjectPackageItem): string { return p.purl || p.name + '@' + p.version; }
  trackByProject(_i: number, p: ProjectListItem): string { return p.project_name; }
}








