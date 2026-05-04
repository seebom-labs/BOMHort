import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { VersionSkewResponse, VersionSkewItem } from '../../core/api.models';
import { Subject } from 'rxjs';
import { debounceTime, distinctUntilChanged } from 'rxjs/operators';

type SortField = 'projects' | 'name' | 'versions';

@Component({
  selector: 'app-version-skew',
  standalone: true,
  imports: [CommonModule, FormsModule, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="skew-page">
      <h1>Version Consistency</h1>
      <p class="subtitle">Packages with inconsistent versions across projects, ranked by impact.</p>

      <div class="toolbar">
        <div class="summary-card" *ngIf="data">
          <span class="big-number">{{ data.total_skewed_packages | number }}</span>
          <span class="label">Skewed Packages</span>
        </div>
        <input
          type="text"
          class="search-input"
          placeholder="Search packages..."
          [ngModel]="searchTerm"
          (ngModelChange)="onSearch($event)"
        >
      </div>

      <div class="table-container" *ngIf="data">
        <table class="skew-table">
          <thead>
            <tr>
              <th class="col-rank">#</th>
              <th class="col-name sortable" (click)="toggleSort('name')" [class.active]="sortField === 'name'">
                Package {{ sortField === 'name' ? (sortAsc ? '↑' : '↓') : '' }}
              </th>
              <th class="col-versions sortable" (click)="toggleSort('versions')" [class.active]="sortField === 'versions'">
                Versions {{ sortField === 'versions' ? (sortAsc ? '↑' : '↓') : '' }}
              </th>
              <th class="col-projects sortable" (click)="toggleSort('projects')" [class.active]="sortField === 'projects'">
                Projects {{ sortField === 'projects' ? (sortAsc ? '↑' : '↓') : '' }}
              </th>
            </tr>
          </thead>
          <tbody>
            <ng-container *ngFor="let item of sortedItems; let i = index; trackBy: trackBy">
              <tr class="skew-row" (click)="toggle(item.package_name)" [class.expanded]="expandedPkg === item.package_name">
                <td class="col-rank">{{ (page - 1) * pageSize + i + 1 }}</td>
                <td class="col-name">
                  <span class="pkg-name">{{ item.package_name }}</span>
                  <span class="pkg-purl" *ngIf="item.purl">{{ item.purl }}</span>
                </td>
                <td class="col-versions">
                  <span class="version-badge">{{ item.version_count }}</span>
                </td>
                <td class="col-projects">{{ item.project_count | number }}</td>
              </tr>
              <tr *ngIf="expandedPkg === item.package_name" class="detail-row">
                <td colspan="4">
                  <div class="version-breakdown">
                    <div class="version-entry" *ngFor="let v of item.versions">
                      <div class="ver-header">
                        <span class="ver-pill">{{ v.version }}</span>
                        <span class="ver-count">{{ v.project_count | number }} project{{ v.project_count !== 1 ? 's' : '' }}</span>
                      </div>
                      <div class="ver-projects">
                        <a class="project-tag" *ngFor="let p of v.projects"
                           [routerLink]="['/sboms']"
                           [queryParams]="{search: p}">{{ p }}</a>
                      </div>
                    </div>
                  </div>
                </td>
              </tr>
            </ng-container>
          </tbody>
        </table>
      </div>

      <div class="pagination" *ngIf="data && data.total_skewed_packages > pageSize">
        <button [disabled]="page <= 1" (click)="goToPage(page - 1)">← Prev</button>
        <span class="page-info">Page {{ page }} of {{ totalPages }}</span>
        <button [disabled]="page >= totalPages" (click)="goToPage(page + 1)">Next →</button>
      </div>

      <p *ngIf="!data" class="loading">Loading version skew data...</p>
    </div>
  `,
  styles: [`
    .skew-page { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    h1 { margin: 0; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .subtitle { color: var(--text-secondary); margin: 4px 0 16px; font-size: 0.8rem; }
    .toolbar { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; }
    .summary-card {
      display: inline-flex; flex-direction: column; align-items: center;
      background: var(--surface-alt); padding: 10px 20px; border-radius: 4px;
      border: 1px solid var(--border);
    }
    .big-number { font-size: 1.3rem; font-weight: 700; color: var(--text); letter-spacing: -0.02em; }
    .label { font-size: 0.65rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em; }
    .search-input {
      flex: 1; max-width: 320px; padding: 8px 12px; border: 1px solid var(--border);
      border-radius: 4px; background: var(--surface-alt); color: var(--text);
      font-size: 0.85rem; outline: none;
    }
    .search-input:focus { border-color: var(--accent); }
    .table-container { flex: 1; overflow: auto; }
    .skew-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    .skew-table th {
      text-align: left; padding: 8px 12px; font-size: 0.7rem; font-weight: 600;
      color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em;
      border-bottom: 2px solid var(--border); background: var(--bg);
      position: sticky; top: 0; z-index: 1;
    }
    .sortable { cursor: pointer; user-select: none; }
    .sortable:hover { color: var(--accent); }
    .sortable.active { color: var(--accent); }
    .skew-row { cursor: pointer; transition: background 0.1s; }
    .skew-row:hover { background: var(--surface-alt); }
    .skew-row.expanded { background: var(--surface-alt); }
    .skew-table td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    .col-rank { width: 40px; color: var(--text-muted); font-variant-numeric: tabular-nums; text-align: center; }
    .col-name .pkg-name { font-weight: 600; display: block; }
    .col-name .pkg-purl { color: var(--text-muted); font-size: 0.7rem; display: block; overflow: hidden; text-overflow: ellipsis; max-width: 400px; }
    .col-versions { width: 80px; text-align: center; }
    .version-badge {
      background: var(--severity-medium-bg, #fff3cd); color: var(--severity-medium, #856404);
      padding: 2px 8px; border-radius: 10px; font-weight: 700; font-size: 0.8rem;
    }
    .col-projects { width: 80px; text-align: center; font-weight: 600; font-variant-numeric: tabular-nums; }
    .detail-row td { padding: 12px 12px 16px 52px; background: var(--surface-alt); border-bottom: 2px solid var(--border); }
    .version-breakdown { display: flex; flex-direction: column; gap: 12px; }
    .version-entry { display: flex; flex-direction: column; gap: 4px; }
    .ver-header { display: flex; align-items: center; gap: 12px; }
    .ver-pill {
      background: var(--bg); color: var(--text); padding: 4px 12px; border-radius: 3px;
      font-size: 0.78rem; font-family: monospace; border: 1px solid var(--border);
      min-width: 100px; display: inline-block;
    }
    .ver-count { font-size: 0.75rem; color: var(--text-muted); font-weight: 600; }
    .ver-projects { display: flex; flex-wrap: wrap; gap: 4px; padding-left: 4px; }
    .project-tag {
      background: var(--bg); color: var(--accent); padding: 2px 8px; border-radius: 2px;
      font-size: 0.7rem; border: 1px solid var(--border); text-decoration: none;
      cursor: pointer; transition: background 0.15s, border-color 0.15s;
    }
    .project-tag:hover { border-color: var(--accent); background: var(--surface-alt); }
    .pagination {
      display: flex; align-items: center; justify-content: center; gap: 16px;
      padding: 16px 0; border-top: 1px solid var(--border); margin-top: auto;
    }
    .pagination button {
      background: var(--surface-alt); border: 1px solid var(--border); color: var(--text);
      padding: 6px 14px; border-radius: 4px; cursor: pointer; font-size: 0.8rem;
    }
    .pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
    .pagination button:not(:disabled):hover { background: var(--accent); color: #fff; }
    .page-info { font-size: 0.8rem; color: var(--text-secondary); }
    .loading { color: var(--text-muted); }
  `],
})
export class VersionSkewComponent implements OnInit {
  data: VersionSkewResponse | null = null;
  sortedItems: VersionSkewItem[] = [];
  sortField: SortField = 'projects';
  sortAsc = false;
  expandedPkg: string | null = null;
  page = 1;
  pageSize = 50;
  searchTerm = '';

  private readonly searchSubject = new Subject<string>();

  get totalPages(): number {
    return this.data ? Math.ceil(this.data.total_skewed_packages / this.pageSize) : 0;
  }

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.searchSubject.pipe(
      debounceTime(300),
      distinctUntilChanged(),
    ).subscribe((term) => {
      this.searchTerm = term;
      this.page = 1;
      this.loadPage();
    });
    this.loadPage();
  }

  onSearch(term: string): void {
    this.searchSubject.next(term);
  }

  loadPage(): void {
    this.api.getVersionSkew(this.page, this.pageSize, this.searchTerm).subscribe((data) => {
      this.data = data;
      this.applySort();
      this.cdr.markForCheck();
    });
  }

  goToPage(p: number): void {
    this.page = p;
    this.expandedPkg = null;
    this.loadPage();
  }

  toggle(pkgName: string): void {
    this.expandedPkg = this.expandedPkg === pkgName ? null : pkgName;
    this.cdr.markForCheck();
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
    if (!this.data) return;
    const dir = this.sortAsc ? 1 : -1;
    this.sortedItems = [...this.data.items].sort((a, b) => {
      switch (this.sortField) {
        case 'projects': return (a.project_count - b.project_count) * dir;
        case 'name': return a.package_name.localeCompare(b.package_name) * dir;
        case 'versions': return (a.version_count - b.version_count) * dir;
        default: return 0;
      }
    });
  }

  trackBy(_i: number, item: VersionSkewItem): string { return item.package_name; }
}






