import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ArchivedRepoGroup } from '../../core/api.models';

interface VersionInfo {
  version: string;
  sbomId: string;
}

interface AggregatedProject {
  projectName: string;
  versions: VersionInfo[];
}

interface GroupedArchived {
  repo: string;
  stars: number;
  lastPushed: string;
  projects: AggregatedProject[];
}

@Component({
  selector: 'app-archived-packages',
  standalone: true,
  imports: [CommonModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="container">
      <header class="page-header">
        <h1>⚠️ Archived Repositories</h1>
        <p class="subtitle">
          These dependencies use GitHub repositories that have been archived.
          Archived repos no longer receive updates or security patches.
        </p>
      </header>

      @if (loading) {
        <div class="loading">Loading archived packages...</div>
      } @else if (grouped.length === 0) {
        <div class="empty-state">
          <span class="check-icon">✓</span>
          <p>No archived repositories detected in your dependencies.</p>
        </div>
      } @else {
        <div class="summary-bar">
          <span class="summary-count">{{ total | number }} archived repo(s)</span>
          <span class="summary-projects">affecting {{ totalProjects | number }} project(s) on this page</span>
        </div>

        <div class="repo-list">
          @for (item of grouped; track item.repo) {
            <div class="repo-card">
              <div class="repo-header">
                <a [href]="'https://github.com/' + item.repo" target="_blank" class="repo-name">
                  📦 {{ item.repo }}
                </a>
                <span class="archived-badge">ARCHIVED</span>
                <span class="stars">⭐ {{ item.stars | number }}</span>
              </div>
              <div class="repo-meta">
                Last pushed: {{ item.lastPushed | date:'mediumDate' }}
              </div>
              <div class="affected-projects">
                <strong>Affected Projects ({{ item.projects.length }}):</strong>
                <div class="project-list">
                  @for (proj of item.projects; track proj.projectName) {
                    <div class="project-row">
                      <span class="project-name">{{ proj.projectName }}</span>
                      <div class="version-tags">
                        @for (v of proj.versions; track v.sbomId) {
                          <a [routerLink]="['/sboms', v.sbomId]" class="version-tag">
                            {{ v.version || 'latest' }}
                          </a>
                        }
                      </div>
                    </div>
                  }
                </div>
              </div>
            </div>
          }
        </div>

        @if (grouped.length < total) {
          <div class="load-more">
            <button (click)="loadMore()" [disabled]="loadingMore" class="load-more-btn">
              {{ loadingMore ? 'Loading…' : 'Load more (' + (grouped.length | number) + ' / ' + (total | number) + ')' }}
            </button>
          </div>
        }
      }
    </div>
  `,
  styles: [`
    .container { padding: 24px; max-width: 1200px; margin: 0 auto; }
    .page-header { margin-bottom: 24px; }
    .page-header h1 { margin: 0 0 8px 0; font-size: 1.5rem; color: var(--text); }
    .subtitle { color: var(--text-secondary); margin: 0; line-height: 1.5; }

    .loading { padding: 40px; text-align: center; color: var(--text-muted); }

    .empty-state {
      display: flex; flex-direction: column; align-items: center; gap: 12px;
      padding: 60px 20px; background: var(--surface); border-radius: 4px;
      border: 1px solid var(--border); text-align: center;
    }
    .check-icon { font-size: 2.5rem; color: var(--status-success); }
    .empty-state p { color: var(--text-secondary); margin: 0; }

    .summary-bar {
      display: flex; gap: 16px; padding: 12px 16px;
      background: color-mix(in srgb, var(--severity-high) 10%, transparent);
      border: 1px solid var(--severity-high); border-radius: 4px;
      margin-bottom: 16px; font-size: 0.9rem;
    }
    .summary-count { font-weight: 600; color: var(--severity-high); }
    .summary-projects { color: var(--text-secondary); }

    .repo-list { display: flex; flex-direction: column; gap: 12px; }

    .repo-card {
      background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; padding: 16px;
    }
    .repo-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
    .repo-name {
      font-weight: 600; font-size: 1rem; color: var(--accent);
      text-decoration: none;
    }
    .repo-name:hover { text-decoration: underline; }
    .archived-badge {
      background: var(--severity-high); color: #fff;
      padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600;
    }
    .stars { color: var(--text-muted); font-size: 0.85rem; }
    .repo-meta { color: var(--text-secondary); font-size: 0.8rem; margin-bottom: 12px; }

    .affected-projects strong { display: block; margin-bottom: 12px; font-size: 0.85rem; color: var(--text-secondary); }
    .project-list { display: flex; flex-direction: column; gap: 8px; }
    .project-row {
      display: flex; align-items: center; gap: 12px;
      padding: 8px 12px; background: var(--bg); border-radius: 4px;
    }
    .project-name {
      font-weight: 500; font-size: 0.9rem; color: var(--text);
      min-width: 200px; flex-shrink: 0;
    }
    .version-tags { display: flex; flex-wrap: wrap; gap: 6px; }
    .version-tag {
      background: var(--surface); border: 1px solid var(--border);
      padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;
      color: var(--accent); text-decoration: none; transition: all 0.15s;
      font-family: monospace;
    }
    .version-tag:hover { border-color: var(--accent); background: var(--accent); color: #fff; }

    .load-more { display: flex; justify-content: center; padding: 16px; }
    .load-more-btn {
      padding: 8px 24px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; cursor: pointer; font-size: 0.8rem; font-family: inherit;
      color: var(--text-secondary); transition: all 0.15s;
    }
    .load-more-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent); }
  `]
})
export class ArchivedPackagesComponent implements OnInit {
  loading = true;
  loadingMore = false;
  grouped: GroupedArchived[] = [];
  total = 0;
  totalProjects = 0;
  private page = 1;
  private readonly pageSize = 20;

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.load();
  }

  loadMore(): void {
    this.page++;
    this.loadingMore = true;
    this.load();
  }

  private load(): void {
    this.api.getArchivedRepos(this.page, this.pageSize).subscribe({
      next: (resp) => {
        this.grouped = [...this.grouped, ...(resp?.data ?? []).map(g => this.toGroup(g))];
        this.total = resp?.total ?? 0;
        this.totalProjects = this.countUniqueProjects();
        this.loading = false;
        this.loadingMore = false;
        this.cdr.markForCheck();
      },
      error: () => {
        this.loading = false;
        this.loadingMore = false;
        this.cdr.markForCheck();
      }
    });
  }

  private countUniqueProjects(): number {
    const uniqueProjects = new Set<string>();
    for (const group of this.grouped) {
      for (const proj of group.projects) {
        uniqueProjects.add(proj.projectName);
      }
    }
    return uniqueProjects.size;
  }

  private toGroup(g: ArchivedRepoGroup): GroupedArchived {
    const projects: AggregatedProject[] = [];
    for (const sbom of g.sboms ?? []) {
      // The API reports the described product's version in its own field
      // (document_version, migration 021). Guessing it from the display name
      // is the fallback for SBOMs ingested before that column existed —
      // "k2s" carries no version to guess, so those rows rendered as
      // "latest" even though the SBOM states 0.3.0.
      const baseProjectName = this.extractBaseProjectName(sbom.project_name);
      const version = sbom.project_version || this.extractVersion(sbom.project_name);
      let project = projects.find(p => p.projectName === baseProjectName);
      if (!project) {
        project = { projectName: baseProjectName, versions: [] };
        projects.push(project);
      }
      if (!project.versions.some(v => v.sbomId === sbom.sbom_id)) {
        project.versions.push({ version, sbomId: sbom.sbom_id });
      }
    }
    projects.sort((a, b) => a.projectName.localeCompare(b.projectName));
    for (const proj of projects) {
      proj.versions.sort((a, b) => this.compareVersions(a.version, b.version));
    }
    return { repo: g.repo, stars: g.stars, lastPushed: g.last_pushed, projects };
  }

  private extractBaseProjectName(fullName: string): string {
    // Strip a trailing version from the display name so two versions of the
    // same product group into one project.
    // "Cilium - cilium v1.17.13" -> "Cilium - cilium"
    return fullName.replace(/\s+v?\d+\.\d+(\.\d+)?(-\w+)?$/i, '').trim();
  }

  private extractVersion(fullName: string): string {
    // Fallback only — see groupByRepo. Used when project_version is empty,
    // i.e. SBOMs ingested before migration 021.
    const match = fullName.match(/v?(\d+\.\d+(?:\.\d+)?(?:-\w+)?)\s*$/i);
    return match ? match[1] : '';
  }

  private compareVersions(a: string, b: string): number {
    const parseVersion = (v: string) => v.split(/[.-]/).map(p => parseInt(p, 10) || 0);
    const va = parseVersion(a);
    const vb = parseVersion(b);
    for (let i = 0; i < Math.max(va.length, vb.length); i++) {
      const diff = (vb[i] || 0) - (va[i] || 0);
      if (diff !== 0) return diff;
    }
    return 0;
  }
}

