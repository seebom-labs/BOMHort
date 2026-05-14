import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { PackageDetailResponse } from '../../core/api.models';

@Component({
  selector: 'app-package-detail',
  standalone: true,
  imports: [CommonModule, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="detail-page">
      <div class="breadcrumb">
        <a routerLink="/package-search" class="back-link">← Package Search</a>
      </div>

      <h1>{{ packageName }}</h1>
      <p class="subtitle" *ngIf="data">
        Used in <strong>{{ data.total_projects }}</strong>
        {{ data.total_projects === 1 ? 'project' : 'projects' }}
      </p>

      <div class="loading" *ngIf="loading">Loading projects...</div>

      <div class="projects-table" *ngIf="data && data.projects.length > 0">
        <div class="table-header">
          <span class="col-project">Project</span>
          <span class="col-version">Version</span>
        </div>
        <div class="table-row" *ngFor="let proj of data.projects">
          <a [routerLink]="['/sboms', proj.sbom_id]" class="col-project project-link">{{ proj.project_name }}</a>
          <span class="col-version version-mono">{{ proj.version }}</span>
        </div>
      </div>

      <div class="empty-state" *ngIf="data && data.projects.length === 0">
        <p>No projects found using this package.</p>
      </div>

      <div class="pagination" *ngIf="data && data.total_projects > data.page_size">
        <button (click)="goToPage(currentPage - 1)" [disabled]="currentPage <= 1">← Previous</button>
        <span>Page {{ currentPage }} of {{ totalPages }}</span>
        <button (click)="goToPage(currentPage + 1)" [disabled]="currentPage >= totalPages">Next →</button>
      </div>
    </div>
  `,
  styles: [`
    .detail-page { padding: 32px; max-width: 900px; margin: 0 auto; }
    .breadcrumb { margin-bottom: 16px; }
    .back-link {
      color: var(--accent);
      text-decoration: none;
      font-size: 0.85rem;
    }
    .back-link:hover { text-decoration: underline; }

    h1 {
      font-size: 1.4rem;
      font-weight: 700;
      color: var(--text);
      margin: 0 0 4px;
      word-break: break-all;
      font-family: monospace;
    }
    .subtitle { color: var(--text-secondary); font-size: 0.85rem; margin: 0 0 24px; }

    .projects-table {
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .table-header {
      display: flex;
      padding: 10px 16px;
      background: var(--table-header-bg, #f8f9fa);
      font-size: 0.75rem;
      font-weight: 600;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .table-row {
      display: flex;
      padding: 10px 16px;
      border-top: 1px solid var(--border);
      align-items: center;
      font-size: 0.85rem;
    }
    .table-row:hover { background: var(--row-hover-bg, #f8f9fa); }

    .col-project { flex: 1; }
    .col-version { width: 180px; text-align: right; }

    .project-link {
      color: var(--accent);
      text-decoration: none;
      font-weight: 500;
    }
    .project-link:hover { text-decoration: underline; }
    .version-mono {
      font-family: monospace;
      font-size: 0.8rem;
      color: var(--text-muted);
    }

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
export class PackageDetailComponent implements OnInit {
  packageName = '';
  data: PackageDetailResponse | null = null;
  loading = false;
  currentPage = 1;

  constructor(
    private readonly route: ActivatedRoute,
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef
  ) {}

  ngOnInit(): void {
    this.route.paramMap.subscribe(params => {
      this.packageName = decodeURIComponent(params.get('name') || '');
      this.currentPage = 1;
      this.loadData();
    });
  }

  get totalPages(): number {
    if (!this.data) return 1;
    return Math.ceil(this.data.total_projects / this.data.page_size);
  }

  goToPage(page: number): void {
    if (page < 1 || page > this.totalPages) return;
    this.currentPage = page;
    this.loadData();
  }

  private loadData(): void {
    if (!this.packageName) return;
    this.loading = true;
    this.cdr.markForCheck();

    this.api.getPackageDetail(this.packageName, this.currentPage, 50).subscribe({
      next: (resp) => {
        this.data = resp;
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: () => {
        this.loading = false;
        this.cdr.markForCheck();
      }
    });
  }
}

