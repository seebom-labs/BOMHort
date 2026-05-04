import { Component, OnInit, OnDestroy, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ScrollingModule } from '@angular/cdk/scrolling';
import { RouterModule, ActivatedRoute } from '@angular/router';
import { Subject } from 'rxjs';
import { debounceTime, distinctUntilChanged, takeUntil } from 'rxjs/operators';
import { ApiService } from '../../core/api.service';
import { SBOMListItem } from '../../core/api.models';

@Component({
  selector: 'app-sbom-list',
  standalone: true,
  imports: [CommonModule, FormsModule, ScrollingModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="sbom-list">
      <div class="list-header">
        <h1>SBOM Explorer</h1>
        <span class="result-count" *ngIf="total > 0">
          {{ sboms.length | number }} of {{ total | number }} SBOMs
          <span *ngIf="searchTerm" class="search-hint">matching "{{ searchTerm }}"</span>
        </span>
      </div>

      <div class="search-bar">
        <input
          type="text"
          [(ngModel)]="searchTerm"
          (ngModelChange)="onSearchChange($event)"
          placeholder="Search projects by name…"
          class="search-input"
        />
        <span class="search-loading" *ngIf="loading">⏳</span>
        <button *ngIf="searchTerm && !loading" class="clear-btn" (click)="clearSearch()">✕</button>
      </div>

      <cdk-virtual-scroll-viewport itemSize="56" class="viewport" (scrolledIndexChange)="onScroll()">
        <div *cdkVirtualFor="let sbom of sboms; trackBy: trackBySbom" class="sbom-row">
          <a [routerLink]="['/sboms', sbom.sbom_id]" class="sbom-link">
            <span class="name">{{ sbom.document_name || sbom.source_file }}</span>
            <span class="version badge">{{ sbom.spdx_version }}</span>
            <span class="packages">{{ sbom.package_count | number }} packages</span>
            <span class="vulns" [class.has-vulns]="sbom.vuln_count > 0">
              {{ sbom.vuln_count | number }} vulns
            </span>
            <span class="date">{{ sbom.ingested_at | date:'short' }}</span>
          </a>
        </div>
      </cdk-virtual-scroll-viewport>

      <div *ngIf="!loading && total > 0 && sboms.length < total" class="load-more">
        <button (click)="loadMore()" class="load-more-btn">
          Load more ({{ sboms.length | number }} / {{ total | number }})
        </button>
      </div>

      <div *ngIf="!loading && total === 0 && searchTerm" class="empty-search">
        No SBOMs matching "{{ searchTerm }}"
      </div>
    </div>
  `,
  styles: [`
    .sbom-list { padding: 24px; height: 100%; display: flex; flex-direction: column; }
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
    .sbom-row { height: 52px; display: flex; align-items: center; border-bottom: 1px solid var(--border); }
    .sbom-link {
      display: flex; align-items: center; gap: 16px; width: 100%;
      padding: 0 12px; text-decoration: none; color: inherit; transition: background 0.1s;
    }
    .sbom-link:hover { background: var(--surface-alt); }
    .name { flex: 1; font-weight: 500; font-size: 0.85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .badge { background: var(--bg); color: var(--text-secondary); padding: 2px 6px; border-radius: 2px; font-size: 0.7rem; font-weight: 500; }
    .packages { color: var(--text-secondary); font-size: 0.8rem; width: 110px; }
    .vulns { font-size: 0.8rem; width: 80px; color: var(--text-secondary); }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }
    .date { color: var(--text-muted); font-size: 0.75rem; width: 110px; }

    .load-more {
      padding: 12px; text-align: center;
    }
    .load-more-btn {
      padding: 8px 24px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-family: inherit;
      color: var(--text-secondary); transition: all 0.15s;
    }
    .load-more-btn:hover { border-color: var(--accent); color: var(--accent); }

    .empty-search {
      padding: 32px; text-align: center; color: var(--text-muted); font-size: 0.85rem;
    }
  `],
})
export class SbomListComponent implements OnInit, OnDestroy {
  sboms: SBOMListItem[] = [];
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
    private readonly route: ActivatedRoute,
  ) {}

  ngOnInit(): void {
    this.searchSubject.pipe(
      debounceTime(300),
      distinctUntilChanged(),
      takeUntil(this.destroy$),
    ).subscribe((term) => {
      this.page = 1;
      this.sboms = [];
      this.loadSboms(term);
    });

    // Read initial search from URL query parameter.
    const initialSearch = this.route.snapshot.queryParamMap.get('search') || '';
    this.searchTerm = initialSearch;
    this.loadSboms(initialSearch);
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
    this.loadSboms(this.searchTerm, true);
  }

  onScroll(): void {
    // Could implement infinite scroll here in the future
  }

  private loadSboms(search: string, append = false): void {
    this.loading = true;
    this.cdr.markForCheck();

    this.api.getSboms(this.page, this.pageSize, search).subscribe((response) => {
      if (append) {
        this.sboms = [...this.sboms, ...response.data];
      } else {
        this.sboms = response.data;
      }
      this.total = response.total;
      this.loading = false;
      this.cdr.markForCheck();
    });
  }

  trackBySbom(_index: number, item: SBOMListItem): string {
    return item.sbom_id;
  }
}
