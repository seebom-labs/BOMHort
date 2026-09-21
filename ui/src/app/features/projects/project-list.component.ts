import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { RouterModule, ActivatedRoute, Router } from '@angular/router';
import { Subject } from 'rxjs';
import { debounceTime, distinctUntilChanged, takeUntil } from 'rxjs/operators';
import { ApiService } from '../../core/api.service';
import { ProjectListItem, TagListItem } from '../../core/api.models';

@Component({
  selector: 'app-project-list',
  standalone: true,
  imports: [CommonModule, FormsModule, ScrollingModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="project-list">
      <div class="list-header">
        <h1>Projects</h1>
        <span class="result-count" *ngIf="total > 0">
          {{ projects.length | number }} of {{ total | number }} projects
          <span *ngIf="searchTerm" class="search-hint">matching "{{ searchTerm }}"</span>
          <span *ngIf="activeTag" class="search-hint">in {{ activeTag }}</span>
        </span>
      </div>

      <!--
        Grouping filter. Rendered only when the instance actually tags its
        SBOMs: a deployment that groups nothing gets no control at all rather
        than an empty dropdown implying a feature that does not apply to it.
        The tags themselves come from the data, so this works for any grouping
        scheme without a UI change.
      -->
      <div class="tag-bar" *ngIf="tags.length > 0">
        <button
          class="tag-chip"
          [class.selected]="!activeTag"
          (click)="selectTag('')"
        >All</button>
        <button
          *ngFor="let t of tags; trackBy: trackByTag"
          class="tag-chip"
          [class.selected]="activeTag === t.tag"
          [title]="t.project_count + ' projects, ' + t.sbom_count + ' SBOMs'"
          (click)="selectTag(t.tag)"
        >
          {{ t.tag }}
          <span class="tag-count">{{ t.project_count | number }}</span>
        </button>
      </div>

      <div class="search-bar">
        <input
          type="text"
          [(ngModel)]="searchTerm"
          (ngModelChange)="onSearchChange($event)"
          placeholder="Search projects…"
          class="search-input"
        />
        <span class="search-loading" *ngIf="loading">⏳</span>
        <button *ngIf="searchTerm && !loading" class="clear-btn" (click)="clearSearch()">✕</button>
      </div>

      <cdk-virtual-scroll-viewport itemSize="64" class="viewport" (scrolledIndexChange)="onScroll()">
        <div *cdkVirtualFor="let project of projects; trackBy: trackByProject" class="project-row">
          <a [routerLink]="['/sboms']" [queryParams]="{search: project.project_name}" class="project-link">
            <div class="project-info">
              <span class="name">{{ project.project_name }}</span>
              <span class="meta">
                {{ project.sbom_count }} {{ project.sbom_count === 1 ? 'version' : 'versions' }}
                <!--
                  A project's groupings, shown inline. Only tags other than the
                  active filter are listed: repeating the tag every row was
                  filtered by adds noise without information.
                -->
                <span
                  class="tag-badge"
                  *ngFor="let t of otherTags(project)"
                  [title]="'Grouping: ' + t"
                >{{ t }}</span>
              </span>
            </div>
            <div class="project-stats">
              <span class="stat packages">{{ project.package_count | number }} packages</span>
              <span class="stat vulns" [class.has-vulns]="project.vuln_count > 0">
                {{ project.vuln_count | number }} vulns
              </span>
              <span class="date">{{ project.latest_ingested | date:'mediumDate' }}</span>
            </div>
          </a>
        </div>
      </cdk-virtual-scroll-viewport>

      <div *ngIf="!loading && total > 0 && projects.length < total" class="load-more">
        <button (click)="loadMore()" class="load-more-btn">
          Load more ({{ projects.length | number }} / {{ total | number }})
        </button>
      </div>

      <div *ngIf="!loading && total === 0 && searchTerm" class="empty-search">
        No projects matching "{{ searchTerm }}"<span *ngIf="activeTag"> in {{ activeTag }}</span>
      </div>

      <!--
        A tag filter that matches nothing is named explicitly: without it the
        generic "ingest SBOMs" message would suggest the instance is empty
        when it is merely filtered.
      -->
      <div *ngIf="!loading && total === 0 && !searchTerm && activeTag" class="empty-search">
        No projects in {{ activeTag }}
      </div>

      <div *ngIf="!loading && total === 0 && !searchTerm && !activeTag" class="empty-state">
        No projects found. Ingest SBOMs to see projects here.
      </div>
    </div>
  `,
  styles: [`
    .project-list { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    .list-header { display: flex; align-items: baseline; gap: 12px; margin-bottom: 12px; }
    h1 { margin: 0; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .result-count { font-size: 0.75rem; color: var(--text-muted); }
    .search-hint { font-style: italic; }

    .search-bar { position: relative; margin-bottom: 12px; }
    .tag-bar { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
    .tag-chip {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 4px 10px; font-size: 0.72rem; font-family: inherit;
      background: var(--surface); color: var(--text-secondary);
      border: 1px solid var(--border); border-radius: 12px;
      cursor: pointer; transition: all 0.15s;
    }
    .tag-chip:hover { border-color: var(--accent); color: var(--accent); }
    .tag-chip.selected {
      background: var(--status-info-bg); color: var(--accent-hover);
      border-color: var(--accent); font-weight: 600;
    }
    .tag-count { font-size: 0.65rem; opacity: 0.7; }
    .tag-badge {
      display: inline-block; margin-left: 6px; padding: 1px 6px;
      background: var(--surface-alt); color: var(--text-secondary);
      border: 1px solid var(--border); border-radius: 2px;
      font-size: 0.65rem; font-weight: 500;
    }
    .search-input {
      width: 100%; padding: 8px 36px 8px 12px; font-size: 0.82rem;
      border: 1px solid var(--border); border-radius: 4px;
      background: var(--surface); color: var(--text);
      font-family: inherit; outline: none; transition: border-color 0.15s;
      box-sizing: border-box;
    }
    .search-input::placeholder { color: var(--text-muted); }
    .search-input:focus { border-color: var(--accent); }
    .search-loading {
      position: absolute; right: 10px; top: 50%; transform: translateY(-50%);
      font-size: 0.8rem; line-height: 1;
    }
    .clear-btn {
      position: absolute; right: 8px; top: 50%; transform: translateY(-50%);
      background: none; border: none; color: var(--text-muted); cursor: pointer;
      font-size: 0.8rem; padding: 4px; line-height: 1;
    }
    .clear-btn:hover { color: var(--text); }

    .viewport { flex: 1; min-height: 400px; }
    .project-row { height: 60px; display: flex; align-items: center; border-bottom: 1px solid var(--border); }
    .project-link {
      display: flex; align-items: center; justify-content: space-between;
      width: 100%; padding: 0 16px; text-decoration: none; color: inherit;
      transition: background 0.1s; height: 100%;
    }
    .project-link:hover { background: var(--surface-alt); }
    .project-info { display: flex; flex-direction: column; gap: 2px; flex: 1; min-width: 0; }
    .name {
      font-weight: 600; font-size: 0.85rem;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
    }
    .meta { font-size: 0.72rem; color: var(--text-muted); }
    .project-stats { display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
    .stat { font-size: 0.8rem; color: var(--text-secondary); }
    .stat.vulns { width: 80px; }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }
    .stat.packages { width: 120px; }
    .date { color: var(--text-muted); font-size: 0.72rem; width: 100px; text-align: right; }

    .load-more { padding: 12px; text-align: center; }
    .load-more-btn {
      padding: 8px 24px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-family: inherit;
      color: var(--text-secondary); transition: all 0.15s;
    }
    .load-more-btn:hover { border-color: var(--accent); color: var(--accent); }

    .empty-search, .empty-state {
      padding: 32px; text-align: center; color: var(--text-muted); font-size: 0.85rem;
    }
  `],
})
export class ProjectListComponent implements OnInit, OnDestroy {
  projects: ProjectListItem[] = [];
  total = 0;
  searchTerm = '';
  loading = false;

  /**
   * Groupings this instance uses, from the API. Empty means "this deployment
   * does not group projects" and the filter bar is not rendered at all.
   */
  tags: TagListItem[] = [];
  /** Currently filtered grouping; '' = no grouping filter. */
  activeTag = '';

  /**
   * The filter state the current rows were loaded with. Distinct from
   * activeTag/searchTerm, which track the *controls* — searchTerm in
   * particular moves ahead of the data via ngModel while typing.
   *
   * `null` means "nothing loaded yet", which is what makes the initial
   * navigation pass the guard below: on first load the URL's empty filter
   * would otherwise compare equal to the empty state and skip the fetch.
   */
  private loadedTag: string | null = null;
  private loadedSearch: string | null = null;

  private page = 1;
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
      // Only the URL is written here; the reload happens in the queryParams
      // subscription below, so there is exactly one path into loadProjects()
      // and typing cannot race a back-navigation.
      this.syncUrl(term, this.activeTag, true);
    });

    // Tags load independently of the listing: a failure here must not hide
    // the projects themselves, so an error just leaves the filter bar off.
    this.api.getTags().pipe(takeUntil(this.destroy$)).subscribe({
      next: (tags) => {
        this.tags = tags;
        this.cdr.markForCheck();
      },
      error: () => {
        this.tags = [];
        this.cdr.markForCheck();
      },
    });

    // The URL is the single source of truth for the filter state. That makes
    // a grouping shareable and bookmarkable ("send me all sandbox
    // applications" is a link, not a click path), makes browser back/forward
    // step through filters, and survives a reload. It also means deep links
    // like /projects?tag=sandbox-applications work as an entry point.
    this.route.queryParams.pipe(takeUntil(this.destroy$)).subscribe((params) => {
      const tag = params['tag'] ?? '';
      const search = params['search'] ?? '';

      // Compared against what was last *loaded*, not against searchTerm:
      // searchTerm is bound to the input via ngModel and already holds the
      // new value while the user types, so comparing it would make this
      // guard swallow the very reload the typing asked for.
      if (tag === this.loadedTag && search === this.loadedSearch) {
        return;
      }

      this.activeTag = tag;
      this.searchTerm = search;
      this.resetPaging();
      this.loadProjects(search);
    });
  }

  ngOnDestroy(): void {
    this.destroy$.next();
    this.destroy$.complete();
  }

  onSearchChange(term: string): void {
    this.searchSubject.next(term.trim());
  }

  clearSearch(): void {
    this.searchTerm = '';
    this.searchSubject.next('');
  }

  /**
   * Switches the grouping filter. Clicking the active tag clears it, so the
   * chip doubles as its own off switch and there is no dead click.
   *
   * Writes the URL rather than the state directly — the queryParams
   * subscription applies it, so a chip click and a pasted link take the
   * identical code path.
   */
  selectTag(tag: string): void {
    this.syncUrl(this.searchTerm, this.activeTag === tag ? '' : tag, false);
  }

  /**
   * Reflects the filter state in the URL.
   *
   * Empty values are written as `null` so Angular drops the parameter
   * entirely: an unfiltered list should be a clean /projects, not
   * /projects?tag=&search=.
   *
   * `replace` is passed in rather than derived: search typing replaces the
   * history entry, because otherwise a single back press would walk back one
   * character at a time. Choosing a grouping is a deliberate act and gets its
   * own entry, so back returns to the previous grouping.
   */
  private syncUrl(search: string, tag: string, replace: boolean): void {
    this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { tag: tag || null, search: search || null },
      queryParamsHandling: 'merge',
      replaceUrl: replace,
    });
  }

  /**
   * A project's groupings minus the one being filtered on, which every
   * visible row would otherwise repeat identically.
   */
  otherTags(project: ProjectListItem): string[] {
    return (project.tags ?? []).filter((t) => t !== this.activeTag);
  }

  loadMore(): void {
    this.page++;
    this.loadProjects(this.searchTerm, true);
  }

  onScroll(): void {}

  private resetPaging(): void {
    this.page = 1;
    this.projects = [];
  }

  private loadProjects(search: string, append = false): void {
    this.loading = true;
    this.loadedTag = this.activeTag;
    this.loadedSearch = search;
    this.cdr.markForCheck();

    this.api.getProjects(this.page, this.pageSize, search, this.activeTag).subscribe((response) => {
      if (append) {
        this.projects = [...this.projects, ...response.data];
      } else {
        this.projects = response.data;
      }
      this.total = response.total;
      this.loading = false;
      this.cdr.markForCheck();
    });
  }

  trackByProject(_index: number, item: ProjectListItem): string {
    return item.project_name;
  }

  trackByTag(_index: number, item: TagListItem): string {
    return item.tag;
  }
}

