import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { DependencySearchResponse, DependencySearchResult } from '../../core/api.models';
import { Subject } from 'rxjs';
import { debounceTime, distinctUntilChanged } from 'rxjs/operators';

@Component({
  selector: 'app-package-search',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="search-page">
      <h1>Package Search</h1>
      <p class="subtitle">Search for a dependency by name and see which projects use it.</p>

      <div class="search-bar">
        <input
          type="text"
          [(ngModel)]="searchQuery"
          (ngModelChange)="onSearchChange($event)"
          placeholder="Search package name (e.g. golang.org/x/net, lodash, react)..."
          class="search-input"
          autofocus
        />
      </div>

      <div class="results-summary" *ngIf="data && searchQuery">
        <span class="result-count">{{ data.total_results | number }} packages found</span>
        <span class="page-info" *ngIf="data.total_results > data.page_size">
          Page {{ data.page }} of {{ totalPages }}
        </span>
      </div>

      <div class="results" *ngIf="data && data.items.length > 0">
        <div class="result-card" *ngFor="let item of data.items" (click)="toggleExpand(item)">
          <div class="result-header">
            <div class="pkg-info">
              <span class="pkg-name">{{ item.package_name }}</span>
              <span class="pkg-meta">
                {{ item.project_count }} {{ item.project_count === 1 ? 'project' : 'projects' }}
                · {{ item.versions.length }} {{ item.versions.length === 1 ? 'version' : 'versions' }}
              </span>
            </div>
            <span class="expand-icon">{{ expandedPkg === item.package_name ? '▾' : '▸' }}</span>
          </div>

          <div class="version-tags" *ngIf="item.versions.length > 0">
            <span class="version-tag" *ngFor="let v of item.versions.slice(0, 8)">{{ v }}</span>
            <span class="version-tag more" *ngIf="item.versions.length > 8">+{{ item.versions.length - 8 }}</span>
          </div>

          <div class="projects-list" *ngIf="expandedPkg === item.package_name && item.projects.length > 0">
            <div class="project-row" *ngFor="let proj of item.projects">
              <a [routerLink]="['/sboms', proj.sbom_id]" class="project-link">{{ proj.project_name }}</a>
              <span class="project-version">{{ proj.version }}</span>
            </div>
            <a *ngIf="item.project_count > 5"
               [routerLink]="['/package-search', encodePackageName(item.package_name)]"
               class="view-all-link">
              View all {{ item.project_count }} projects →
            </a>
          </div>
        </div>
      </div>

      <div class="empty-state" *ngIf="data && data.items.length === 0 && searchQuery">
        <p>No packages found matching "{{ searchQuery }}"</p>
      </div>

      <div class="empty-state" *ngIf="!data && !loading && !searchQuery">
        <p>Start typing to search for packages across all projects.</p>
      </div>

      <div class="loading" *ngIf="loading">Searching...</div>

      <div class="pagination" *ngIf="data && data.total_results > data.page_size">
        <button (click)="goToPage(currentPage - 1)" [disabled]="currentPage <= 1">← Previous</button>
        <span>Page {{ currentPage }} of {{ totalPages }}</span>
        <button (click)="goToPage(currentPage + 1)" [disabled]="currentPage >= totalPages">Next →</button>
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

    .results-summary {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
      font-size: 0.8rem;
      color: var(--text-secondary);
    }
    .result-count { font-weight: 600; }

    .result-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
      cursor: pointer;
      transition: border-color 0.15s;
    }
    .result-card:hover { border-color: var(--accent); }

    .result-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .pkg-info { display: flex; flex-direction: column; gap: 4px; }
    .pkg-name { font-weight: 600; font-size: 0.9rem; color: var(--text); }
    .pkg-meta { font-size: 0.75rem; color: var(--text-secondary); }
    .expand-icon { color: var(--text-muted); font-size: 0.9rem; }

    .version-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
    .version-tag {
      background: var(--tag-bg, #f0f0f0);
      color: var(--text-secondary);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.7rem;
      font-family: monospace;
    }
    .version-tag.more { font-style: italic; }

    .projects-list {
      margin-top: 12px;
      border-top: 1px solid var(--border);
      padding-top: 12px;
    }
    .project-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 6px 0;
      font-size: 0.8rem;
    }
    .project-link {
      color: var(--accent);
      text-decoration: none;
      font-weight: 500;
    }
    .project-link:hover { text-decoration: underline; }
    .project-version {
      font-family: monospace;
      font-size: 0.75rem;
      color: var(--text-muted);
    }
    .view-all-link {
      display: block;
      margin-top: 10px;
      padding-top: 8px;
      border-top: 1px dashed var(--border);
      color: var(--accent);
      text-decoration: none;
      font-size: 0.8rem;
      font-weight: 500;
    }
    .view-all-link:hover { text-decoration: underline; }

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

    .pagination {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 16px;
      margin-top: 24px;
      font-size: 0.8rem;
      color: var(--text-secondary);
    }
    .pagination button {
      padding: 6px 12px;
      border: 1px solid var(--border);
      border-radius: 4px;
      background: var(--card-bg);
      color: var(--text);
      cursor: pointer;
      font-size: 0.8rem;
    }
    .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
    .pagination button:not(:disabled):hover { border-color: var(--accent); }
  `]
})
export class PackageSearchComponent implements OnInit {
  searchQuery = '';
  data: DependencySearchResponse | null = null;
  loading = false;
  expandedPkg: string | null = null;
  currentPage = 1;

  private searchSubject = new Subject<string>();

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.searchSubject.pipe(
      debounceTime(300),
      distinctUntilChanged()
    ).subscribe(query => {
      this.currentPage = 1;
      this.doSearch(query);
    });
  }

  onSearchChange(value: string): void {
    this.searchSubject.next(value);
  }

  get totalPages(): number {
    if (!this.data) return 1;
    return Math.ceil(this.data.total_results / this.data.page_size);
  }

  goToPage(page: number): void {
    if (page < 1 || page > this.totalPages) return;
    this.currentPage = page;
    this.doSearch(this.searchQuery);
  }

  toggleExpand(item: DependencySearchResult): void {
    this.expandedPkg = this.expandedPkg === item.package_name ? null : item.package_name;
  }

  encodePackageName(name: string): string {
    return encodeURIComponent(name);
  }

  private doSearch(query: string): void {
    if (!query || query.length < 2) {
      this.data = null;
      this.loading = false;
      this.cdr.markForCheck();
      return;
    }
    this.loading = true;
    this.cdr.markForCheck();

    this.api.searchPackages(query, this.currentPage, 20).subscribe({
      next: (resp) => {
        this.data = resp;
        this.loading = false;
        this.expandedPkg = null;
        this.cdr.markForCheck();
      },
      error: () => {
        this.loading = false;
        this.cdr.markForCheck();
      }
    });
  }
}

