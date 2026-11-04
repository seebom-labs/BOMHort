import { Component, Input, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { ApiService } from '../../core/api.service';
import { SBOMListItem, ProjectListItem } from '../../core/api.models';

/**
 * The aggregated half of the SBOM Explorer (#58): one expandable row per
 * project instead of one per document.
 *
 * Its own component rather than a second branch inside SbomListComponent,
 * because the two modes share nothing but the row layout — separate state
 * (expansion, per-project version caches), separate data source and separate
 * empty states. Keeping them in one class also pushed that class's styles
 * past the 4 kB component budget, which was the signal that they were two
 * things.
 */
@Component({
  selector: 'app-project-group-list',
  standalone: true,
  imports: [CommonModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="project-list" [class.embedded]="embedded">
      <div *ngFor="let project of projects; trackBy: trackByProject" class="project-group">
        <div class="project-row">
          <button
            type="button"
            class="expander"
            [attr.aria-expanded]="isExpanded(project.project_name)"
            [attr.aria-label]="(isExpanded(project.project_name) ? 'Collapse ' : 'Expand ') + project.project_name"
            (click)="toggleProject(project.project_name)"
          >{{ isExpanded(project.project_name) ? '▾' : '▸' }}</button>

          <a [routerLink]="['/projects', project.project_name]" class="row-link project-link">
            <span class="name">{{ project.project_name }}</span>
            <span class="badge tag-badge" *ngFor="let tag of project.tags" [title]="'Tag: ' + tag">{{ tag }}</span>
            <span class="badge" [title]="project.sbom_count + ' ingested version(s)'">
              {{ project.sbom_count | number }} {{ project.sbom_count === 1 ? 'version' : 'versions' }}
            </span>
            <!--
              These come from the project read model (#398) and are
              de-duplicated across versions: a package shipped in every version
              counts once. They are deliberately not the sum of the rows below,
              and the tooltip says so — a reader who adds the expanded rows up
              gets a larger number and would otherwise assume this one is wrong.
            -->
            <span class="packages" title="Distinct components across all versions (de-duplicated)">
              {{ project.package_count | number }} packages
            </span>
            <span class="vulns" [class.has-vulns]="project.vuln_count > 0" title="Distinct findings across all versions (de-duplicated)">
              {{ project.vuln_count | number }} vulns
            </span>
            <span class="date">{{ project.latest_ingested | date:'short' }}</span>
          </a>
        </div>

        <div class="versions-panel" *ngIf="isExpanded(project.project_name)">
          <div class="muted-line" *ngIf="isLoadingVersions(project.project_name)">Loading versions…</div>

          <div *ngFor="let sbom of versionsOf(project.project_name); trackBy: trackBySbom" class="version-row">
            <a [routerLink]="['/sboms', sbom.sbom_id]" class="row-link">
              <span class="name">{{ sbom.document_name || sbom.source_file }}</span>
              <span class="product-version" *ngIf="sbom.document_version" [title]="'Product version: ' + sbom.document_version">{{ sbom.document_version }}</span>
              <span class="badge">{{ sbom.spdx_version }}</span>
              <span class="badge cluster-badge" *ngIf="sbom.cluster" [title]="'Cluster: ' + sbom.cluster">{{ sbom.cluster }}</span>
              <span class="badge" *ngIf="sbom.namespace" [title]="'Namespace: ' + sbom.namespace">{{ sbom.namespace }}</span>
              <span class="badge origin-badge" *ngIf="sbom.origin" [title]="'Origin: ' + sbom.origin">{{ sbom.origin }}</span>
              <span class="packages">{{ sbom.package_count | number }} packages</span>
              <span class="vulns" [class.has-vulns]="sbom.vuln_count > 0">{{ sbom.vuln_count | number }} vulns</span>
              <span class="date">{{ sbom.ingested_at | date:'short' }}</span>
            </a>
          </div>

          <!--
            A project with more versions than one page holds gets a way out
            rather than a silently truncated list.
          -->
          <a
            *ngIf="hasMoreVersions(project.project_name)"
            routerLink="/sboms"
            [queryParams]="{ project: project.project_name }"
            class="all-versions-link"
          >
            Showing {{ versionsOf(project.project_name).length | number }} of
            {{ versionTotalOf(project.project_name) | number }} versions — show all →
          </a>
        </div>
      </div>
    </div>
  `,
  styles: [`
    .project-list { flex: 1; min-height: 400px; overflow-y: auto; }
    /* Nested inside a parent group: the outer list scrolls, not this one. */
    .project-list.embedded { flex: none; min-height: 0; overflow: visible; }
    .project-row, .version-row { display: flex; align-items: center; border-bottom: 1px solid var(--border); }
    .project-row { height: 52px; }
    .version-row { height: 46px; padding-left: 28px; }
    .version-row:last-of-type { border-bottom: none; }
    .expander {
      background: none; border: none; cursor: pointer; color: var(--text-muted);
      font-size: 0.8rem; width: 28px; flex-shrink: 0; padding: 4px; line-height: 1;
    }
    .expander:hover { color: var(--accent); }
    .row-link {
      display: flex; align-items: center; gap: 16px; width: 100%;
      padding: 0 12px; text-decoration: none; color: inherit; transition: background 0.1s;
    }
    .row-link:hover { background: var(--surface-alt); }
    .project-link { padding-left: 0; }
    .project-link .name { font-weight: 600; }
    .name { flex: 1; font-weight: 500; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .product-version { color: var(--text-secondary); font-size: 0.8rem; font-weight: 600; }
    .badge {
      background: var(--bg); color: var(--text-secondary); padding: 2px 6px; border-radius: 2px;
      font-size: 0.7rem; font-weight: 500; white-space: nowrap; flex-shrink: 0;
      max-width: 140px; overflow: hidden; text-overflow: ellipsis;
    }
    .badge.tag-badge { border-radius: 10px; cursor: help; }
    .badge.cluster-badge { background: var(--status-info-bg); color: var(--accent-hover); }
    .badge.origin-badge { background: rgba(147, 51, 234, 0.12); color: #a855f7; }
    .packages { color: var(--text-secondary); font-size: 0.8rem; width: 110px; }
    .vulns { font-size: 0.8rem; width: 80px; color: var(--text-secondary); }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }
    .date { color: var(--text-muted); font-size: 0.75rem; width: 110px; }
    .versions-panel { background: var(--surface-alt); border-bottom: 1px solid var(--border); }
    .muted-line, .all-versions-link { padding: 11px 40px; font-size: 0.75rem; }
    .muted-line { color: var(--text-muted); }
    .all-versions-link { display: block; color: var(--accent-hover); text-decoration: none; }
    .all-versions-link:hover { text-decoration: underline; }
  `],
})
export class ProjectGroupListComponent implements OnDestroy {
  /**
   * One page of the project listing, loaded and paged by the parent. The
   * counts on each item are the read model's de-duplicated ones; nothing here
   * recomputes them.
   */
  @Input() projects: ProjectListItem[] = [];

  /**
   * Rendered inside a parent group (ParentGroupListComponent): no own scroll
   * container and no minimum height, so a group of two projects is two rows
   * tall instead of 400px.
   */
  @Input() embedded = false;

  private readonly expanded = new Set<string>();
  private readonly versions = new Map<string, SBOMListItem[]>();
  private readonly versionTotals = new Map<string, number>();
  private readonly versionsLoading = new Set<string>();
  private readonly destroy$ = new Subject<void>();

  /** One page of versions per expanded row; beyond that, link to the scope. */
  private readonly versionPageSize = 50;

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  /** Called by the parent when the underlying listing changes. */
  reset(): void {
    this.expanded.clear();
    this.versions.clear();
    this.versionTotals.clear();
    this.versionsLoading.clear();
    this.cdr.markForCheck();
  }

  isExpanded(project: string): boolean {
    return this.expanded.has(project);
  }

  isLoadingVersions(project: string): boolean {
    return this.versionsLoading.has(project);
  }

  versionsOf(project: string): SBOMListItem[] {
    return this.versions.get(project) ?? [];
  }

  versionTotalOf(project: string): number {
    return this.versionTotals.get(project) ?? 0;
  }

  hasMoreVersions(project: string): boolean {
    return this.versionTotalOf(project) > this.versionsOf(project).length;
  }

  /**
   * Expands a project and fetches its versions once.
   *
   * The versions are never derived from the flat document list: that list is
   * one page of documents, so a project's rows may sit on pages nobody
   * loaded, and grouping whatever happens to be in memory would show "2
   * versions" for a project that has eleven.
   */
  toggleProject(project: string): void {
    if (this.expanded.has(project)) {
      this.expanded.delete(project);
      this.cdr.markForCheck();
      return;
    }

    this.expanded.add(project);
    this.cdr.markForCheck();

    if (this.versions.has(project)) {
      return; // already fetched; collapsing does not discard it
    }

    this.versionsLoading.add(project);
    this.api.getProjectSboms(project, 1, this.versionPageSize)
      .pipe(takeUntil(this.destroy$))
      .subscribe({
        next: (response) => {
          this.versions.set(project, response.data);
          this.versionTotals.set(project, response.total);
          this.versionsLoading.delete(project);
          this.cdr.markForCheck();
        },
        error: () => {
          // An empty panel with the row still expanded is the honest state:
          // it says "no versions shown", not "this project has none".
          this.versionsLoading.delete(project);
          this.cdr.markForCheck();
        },
      });
  }

  trackBySbom(_index: number, item: SBOMListItem): string {
    return item.sbom_id;
  }

  trackByProject(_index: number, item: ProjectListItem): string {
    return item.project_name;
  }
}

