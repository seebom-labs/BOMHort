import { Component, OnInit, OnDestroy, ViewChild, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { RouterModule, ActivatedRoute, Router } from '@angular/router';
import { Subject } from 'rxjs';
import { debounceTime, distinctUntilChanged, takeUntil } from 'rxjs/operators';
import { ApiService } from '../../core/api.service';
import { SBOMListItem, ProjectGroupItem } from '../../core/api.models';
import { ParentGroupListComponent } from './parent-group-list.component';

/** Flat lists one row per document; grouped lists one row per project (#58). */
export type SbomViewMode = 'flat' | 'grouped';

@Component({
  selector: 'app-sbom-list',
  standalone: true,
  imports: [CommonModule, FormsModule, ScrollingModule, RouterModule, ParentGroupListComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="sbom-list">
      <div class="list-header">
        <h1>SBOM Explorer</h1>
        <span class="result-count" *ngIf="total > 0">
          <ng-container *ngIf="viewMode === 'flat'">
            {{ sboms.length | number }} of {{ total | number }} SBOMs
          </ng-container>
          <ng-container *ngIf="viewMode === 'grouped'">
            {{ groups.length | number }} of {{ total | number }} {{ total === 1 ? 'entry' : 'entries' }}
          </ng-container>
          <span *ngIf="searchTerm" class="search-hint">matching "{{ searchTerm }}"</span>
        </span>

        <!--
          #58. The toggle is hidden inside a project scope: there the list is
          already one project's versions, so grouping it into a single row
          would collapse the page into the thing you clicked to get here.
        -->
        <div class="view-toggle" *ngIf="!projectScope" role="group" aria-label="View mode">
          <button
            type="button"
            class="toggle-btn"
            [class.active]="viewMode === 'flat'"
            [attr.aria-pressed]="viewMode === 'flat'"
            (click)="setViewMode('flat')"
          >Documents</button>
          <button
            type="button"
            class="toggle-btn"
            [class.active]="viewMode === 'grouped'"
            [attr.aria-pressed]="viewMode === 'grouped'"
            (click)="setViewMode('grouped')"
          >By project</button>
        </div>
      </div>

      <!--
        Project scope (#398). ?project= is an identity filter, not a search:
        it lists exactly this project's versions. Named explicitly so the
        reader knows why the list is short, with the way to the project page
        and the way out.
      -->
      <div class="scope-banner" *ngIf="projectScope">
        Versions of
        <a [routerLink]="['/projects', projectScope]" class="scope-link">{{ projectScope }}</a>
        <a routerLink="/sboms" class="scope-clear" title="Show all SBOMs">✕ clear</a>
      </div>

      <div class="search-bar">
        <input
          type="text"
          [(ngModel)]="searchTerm"
          (ngModelChange)="onSearchChange($event)"
          [placeholder]="searchPlaceholder"
          class="search-input"
        />
        <select
          *ngIf="viewMode === 'flat'"
          [(ngModel)]="minQuality"
          (ngModelChange)="onMinQualityChange($event)"
          class="quality-select"
          aria-label="Filter by minimum quality"
        >
          <option [ngValue]="0">All Quality</option>
          <option [ngValue]="80">High Quality (≥80)</option>
          <option [ngValue]="60">Acceptable (≥60)</option>
          <option [ngValue]="40">Basic (≥40)</option>
        </select>
        <span class="search-loading" *ngIf="loading">⏳</span>
        <button *ngIf="searchTerm && !loading" class="clear-btn" (click)="clearSearch()">✕</button>
      </div>

      <!--
        The two modes search different things, because they list different
        things: documents are matched on name or path, projects on the project
        name. Saying so is cheaper than explaining why a path fragment finds
        nothing here.
      -->
      <div class="mode-hint" *ngIf="viewMode === 'grouped' && searchTerm">
        Matching project and parent names. Switch to <strong>Documents</strong> to search by file path.
      </div>

      <!-- Flat: one row per document -->
      <cdk-virtual-scroll-viewport
        *ngIf="viewMode === 'flat'"
        itemSize="56"
        class="viewport"
        (scrolledIndexChange)="onScroll()"
      >
        <div *cdkVirtualFor="let sbom of sboms; trackBy: trackBySbom" class="sbom-row">
          <a [routerLink]="['/sboms', sbom.sbom_id]" class="sbom-link">
            <span class="name">{{ sbom.document_name || sbom.source_file }}</span>
            <span class="product-version" *ngIf="sbom.document_version" [title]="'Product version: ' + sbom.document_version">{{ sbom.document_version }}</span>
            <span class="version badge">{{ sbom.spdx_version }}</span>
            <span class="owner-badge cluster-badge" *ngIf="sbom.cluster" [title]="'Cluster: ' + sbom.cluster">
              {{ sbom.cluster }}
            </span>
            <span class="owner-badge" *ngIf="sbom.namespace" [title]="'Namespace: ' + sbom.namespace">
              {{ sbom.namespace }}
            </span>
            <!-- The project badge is redundant inside a project scope. -->
            <span class="owner-badge" *ngIf="sbom.project && sbom.project !== projectScope" [title]="'Project: ' + sbom.project">
              {{ sbom.project }}
            </span>
            <span class="packages">{{ sbom.package_count | number }} packages</span>
            <span class="vulns" [class.has-vulns]="sbom.vuln_count > 0">
              {{ sbom.vuln_count | number }} vulns
            </span>
            <span
              class="quality-badge"
              *ngIf="sbom.quality_score !== undefined"
              [class.good]="sbom.quality_score >= 80"
              [class.fair]="sbom.quality_score >= 60 && sbom.quality_score < 80"
              [class.poor]="sbom.quality_score < 60"
              [title]="'Quality: ' + sbom.quality_score + '/100' + (sbom.quality_flags && sbom.quality_flags.length ? ' (' + sbom.quality_flags.join(', ') + ')' : '')"
            >
              Q: {{ sbom.quality_score }}
            </span>
            <span class="date">{{ sbom.ingested_at | date:'short' }}</span>
          </a>
          <button class="download-btn" title="Download SBOM" (click)="downloadSbom(sbom.sbom_id, $event)">⬇</button>
        </div>
      </cdk-virtual-scroll-viewport>

      <!--
        Grouped: parents (products) → projects → versions (#58), in their own
        components. Projects are grouped under the parent the API resolved
        (mapping file, bucket config, repository owner, …); a project without
        a parent is a plain row.

        Not virtual-scrolled, unlike the flat list. An expanded row is taller
        than a collapsed one, and cdk-virtual-scroll-viewport's fixed itemSize
        cannot represent that — it would place rows at the wrong offsets the
        moment one opens. The list is bounded instead: one page is 100
        entries, and projects are the low-cardinality dimension (50-5000 per
        instance) rather than the document count.
      -->
      <app-parent-group-list *ngIf="viewMode === 'grouped'" [groups]="groups" />

      <div *ngIf="!loading && total > 0 && loadedCount < total" class="load-more">
        <button (click)="loadMore()" class="load-more-btn">
          Load more ({{ loadedCount | number }} / {{ total | number }})
        </button>
      </div>

      <div *ngIf="!loading && total === 0 && searchTerm" class="empty-search">
        No {{ viewMode === 'grouped' ? 'projects' : 'SBOMs' }} matching "{{ searchTerm }}"<span *ngIf="projectScope"> in {{ projectScope }}</span>
      </div>
      <div *ngIf="!loading && total === 0 && !searchTerm && projectScope" class="empty-search">
        No SBOMs resolve to project "{{ projectScope }}"
      </div>
    </div>
  `,
  styles: [`
    .sbom-list { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    .list-header { display: flex; align-items: baseline; gap: 12px; margin-bottom: 12px; }
    h1 { margin: 0; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .result-count { font-size: 0.75rem; color: var(--text-muted); }
    .search-hint { font-style: italic; }
    .mode-hint { font-size: 0.72rem; color: var(--text-muted); margin: -6px 0 10px 2px; }

    .view-toggle { margin-left: auto; display: flex; border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }
    .toggle-btn, .load-more-btn {
      background: var(--surface); border: none; cursor: pointer; font-family: inherit;
      padding: 5px 12px; font-size: 0.74rem; color: var(--text-secondary); transition: all 0.12s;
    }
    .toggle-btn + .toggle-btn { border-left: 1px solid var(--border); }
    .toggle-btn:hover { color: var(--text); }
    .toggle-btn.active { background: var(--accent); color: var(--surface); font-weight: 600; }

    .scope-banner {
      display: flex; align-items: baseline; gap: 8px; margin-bottom: 12px;
      padding: 8px 12px; font-size: 0.78rem; color: var(--text-secondary);
      background: var(--status-info-bg); border: 1px solid var(--accent); border-radius: 4px;
    }
    .scope-link { font-weight: 700; color: var(--accent-hover); text-decoration: none; }
    .scope-clear { margin-left: auto; color: var(--text-muted); text-decoration: none; font-size: 0.72rem; }
    .scope-clear:hover { color: var(--text); }
    .scope-link:hover, .all-versions-link:hover { text-decoration: underline; }

    .search-bar { position: relative; margin-bottom: 12px; }
    .search-input {
      width: 100%; padding: 8px 36px 8px 12px; font-size: 0.82rem; box-sizing: border-box;
      border: 1px solid var(--border); border-radius: 4px; outline: none;
      background: var(--surface); color: var(--text); font-family: inherit; transition: border-color 0.15s;
    }
    .search-input::placeholder { color: var(--text-muted); }
    .search-input:focus { border-color: var(--accent); }
    .search-loading { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); font-size: 0.8rem; line-height: 1; }
    .clear-btn { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); }
    .clear-btn, .expander {
      background: none; border: none; cursor: pointer; color: var(--text-muted);
      font-size: 0.8rem; padding: 4px; line-height: 1;
    }
    .clear-btn:hover { color: var(--text); }
    .expander:hover { color: var(--accent); }
    .expander { width: 28px; flex-shrink: 0; }

    .viewport { flex: 1; min-height: 400px; }
    .sbom-row { height: 52px; display: flex; align-items: center; border-bottom: 1px solid var(--border); }
    .sbom-link {
      display: flex; align-items: center; gap: 16px; width: 100%;
      padding: 0 12px; text-decoration: none; color: inherit; transition: background 0.1s;
    }
    .sbom-link:hover { background: var(--surface-alt); }
    .download-btn {
      background: none; border: 1px solid var(--border); border-radius: 4px; cursor: pointer;
      padding: 4px 8px; font-size: 0.75rem; color: var(--text-secondary); margin-right: 12px;
      flex-shrink: 0; transition: all 0.15s;
    }
    .download-btn:hover, .load-more-btn:hover { border-color: var(--accent); color: var(--accent); }
    .name { flex: 1; font-weight: 500; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .badge { background: var(--bg); color: var(--text-secondary); padding: 2px 6px; border-radius: 2px; font-size: 0.7rem; font-weight: 500; }
    .product-version { color: var(--text-secondary); font-size: 0.8rem; font-weight: 600; }
    .owner-badge {
      background: var(--surface-alt); color: var(--text-secondary); cursor: help;
      border: 1px solid var(--border); padding: 1px 6px; border-radius: 2px;
      font-size: 0.65rem; font-weight: 500; white-space: nowrap; flex-shrink: 0;
      max-width: 140px; overflow: hidden; text-overflow: ellipsis;
    }
    .owner-badge.cluster-badge { background: var(--status-info-bg); color: var(--accent-hover); border-color: transparent; }
    .packages { color: var(--text-secondary); font-size: 0.8rem; width: 110px; }
    .vulns { font-size: 0.8rem; width: 80px; color: var(--text-secondary); }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }
    .quality-select {
      font-size: 0.78rem; padding: 4px 8px; border: 1px solid var(--border);
      border-radius: 4px; background: var(--surface); color: var(--text);
      cursor: pointer;
    }
    .quality-badge {
      padding: 1px 6px; border-radius: 2px; font-size: 0.65rem; font-weight: 600;
      white-space: nowrap; flex-shrink: 0; text-align: center; border: 1px solid var(--border);
    }
    .quality-badge.good { background: var(--status-success-bg); color: var(--status-success); border-color: transparent; }
    .quality-badge.fair { background: var(--severity-high-bg); color: var(--status-warning); border-color: transparent; }
    .quality-badge.poor { background: var(--severity-critical-bg); color: var(--severity-critical); border-color: transparent; }
    .date { color: var(--text-muted); font-size: 0.75rem; width: 110px; }

    .load-more { padding: 12px; text-align: center; }
    .load-more-btn { padding: 8px 24px; border: 1px solid var(--border); border-radius: 4px; font-size: 0.8rem; }
    .empty-search { padding: 32px; text-align: center; color: var(--text-muted); font-size: 0.85rem; }
  `],
})
export class SbomListComponent implements OnInit, OnDestroy {
  @ViewChild(ParentGroupListComponent) private groupList?: ParentGroupListComponent;

  sboms: SBOMListItem[] = [];
  /** Grouped mode: parents with their projects, and parentless projects. */
  groups: ProjectGroupItem[] = [];
  total = 0;
  searchTerm = '';
  loading = false;
  /** Exact project identity from ?project= (#398); '' = unscoped. */
  projectScope = '';
  /** Minimum quality score filter (#537). 0 = all. */
  minQuality = 0;
  /** #58. Linkable via ?view=grouped so a grouped list can be shared. */
  viewMode: SbomViewMode = 'flat';

  private page = 1;
  private loadedOnce = false;
  private readonly pageSize = 100;
  private readonly searchSubject = new Subject<string>();
  private readonly destroy$ = new Subject<void>();

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
    private readonly route: ActivatedRoute,
    private readonly router: Router,
  ) {}

  ngOnInit(): void {
    this.searchSubject.pipe(
      debounceTime(300),
      distinctUntilChanged(),
      takeUntil(this.destroy$),
    ).subscribe((term) => {
      this.resetRows();
      this.load(term);
    });

    // The URL carries all three filters. Subscribed rather than snapshotted so
    // a navigation from one project scope to another (or to none), or a view
    // switch, reloads. Rows are only discarded on an actual filter change —
    // the first emit must not blank out rows a caller has already placed.
    this.route.queryParamMap.pipe(takeUntil(this.destroy$)).subscribe((params) => {
      const project = params.get('project') || '';
      const search = params.get('search') || '';
      const minQualityRaw = parseInt(params.get('min_quality') || '0', 10);
      const minQuality = isNaN(minQualityRaw) || minQualityRaw < 0 ? 0 : minQualityRaw;
      // A project scope is a list of that project's versions; grouping it
      // would collapse the page into the row that was clicked to open it.
      const view: SbomViewMode = !project && params.get('view') === 'grouped' ? 'grouped' : 'flat';

      const changed = project !== this.projectScope || search !== this.searchTerm || view !== this.viewMode || minQuality !== this.minQuality;
      if (this.loadedOnce && !changed) {
        return;
      }
      if (changed) {
        this.resetRows();
      }
      this.projectScope = project;
      this.searchTerm = search;
      this.minQuality = minQuality;
      this.viewMode = view;
      this.loadedOnce = true;
      this.load(search);
    });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  get searchPlaceholder(): string {
    if (this.projectScope) {
      return `Search within ${this.projectScope}…`;
    }
    return this.viewMode === 'grouped'
      ? 'Search projects and parents by name…'
      : 'Search SBOMs by document name or path…';
  }

  /** Rows currently held, for the "load more" counter of either mode. */
  get loadedCount(): number {
    return this.viewMode === 'grouped' ? this.groups.length : this.sboms.length;
  }

  setViewMode(mode: SbomViewMode): void {
    if (mode === this.viewMode) {
      return;
    }
    // Through the URL rather than by assignment, so the mode survives a
    // reload and can be linked to. The queryParamMap subscription does the
    // actual reload.
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { view: mode === 'grouped' ? 'grouped' : null },
      queryParamsHandling: 'merge',
    });
  }

  onMinQualityChange(val: number): void {
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { min_quality: val > 0 ? val : null },
      queryParamsHandling: 'merge',
    });
  }

  onSearchChange(term: string): void {
    this.searchSubject.next(term.trim());
  }

  clearSearch(): void {
    this.searchTerm = '';
    this.searchSubject.next('');
  }

  loadMore(): void {
    this.page++;
    this.load(this.searchTerm, true);
  }

  onScroll(): void {
    // Could implement infinite scroll here in the future
  }

  // Loading

  private resetRows(): void {
    this.page = 1;
    this.sboms = [];
    this.groups = [];
    // The grouped child owns its expansion state; a new listing invalidates
    // it, otherwise a panel stays open under a project that left the page.
    this.groupList?.reset();
  }

  private load(search: string, append = false): void {
    this.loading = true;
    this.cdr.markForCheck();

    if (this.viewMode === 'grouped') {
      this.api.getProjectGroups(this.page, this.pageSize, search).subscribe((response) => {
        this.groups = append ? [...this.groups, ...response.data] : response.data;
        this.total = response.total;
        this.loading = false;
        this.cdr.markForCheck();
      });
      return;
    }

    this.api.getSboms(this.page, this.pageSize, search, this.projectScope, this.minQuality).subscribe((response) => {
      this.sboms = append ? [...this.sboms, ...response.data] : response.data;
      this.total = response.total;
      this.loading = false;
      this.cdr.markForCheck();
    });
  }

  trackBySbom(_index: number, item: SBOMListItem): string {
    return item.sbom_id;
  }

  downloadSbom(sbomId: string, event: Event): void {
    event.stopPropagation();
    event.preventDefault();
    const url = this.api.getSbomDownloadUrl(sbomId);
    const a = document.createElement('a');
    a.href = url;
    a.download = '';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
}











