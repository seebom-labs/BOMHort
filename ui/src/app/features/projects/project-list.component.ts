import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { RouterModule } from '@angular/router';
import { Subject } from 'rxjs';
import { debounceTime, distinctUntilChanged, takeUntil } from 'rxjs/operators';
import { ApiService } from '../../core/api.service';
import { ProjectListItem } from '../../core/api.models';

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
        </span>
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
        No projects matching "{{ searchTerm }}"
      </div>

      <div *ngIf="!loading && total === 0 && !searchTerm" class="empty-state">
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

  private page = 1;
  private readonly pageSize = 100;
  private readonly searchSubject = new Subject<string>();
  private readonly destroy$ = new Subject<void>();

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.searchSubject.pipe(
      debounceTime(300),
      distinctUntilChanged(),
      takeUntil(this.destroy$),
    ).subscribe((term) => {
      this.page = 1;
      this.projects = [];
      this.loadProjects(term);
    });

    this.loadProjects('');
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

  loadMore(): void {
    this.page++;
    this.loadProjects(this.searchTerm, true);
  }

  onScroll(): void {}

  private loadProjects(search: string, append = false): void {
    this.loading = true;
    this.cdr.markForCheck();

    this.api.getProjects(this.page, this.pageSize, search).subscribe((response) => {
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
}

