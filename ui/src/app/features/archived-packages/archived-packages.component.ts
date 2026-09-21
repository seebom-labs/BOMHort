import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { ArchivedPackageInfo } from '../../core/api.models';

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
          <span class="summary-count">{{ grouped.length | number }} archived repo(s)</span>
          <span class="summary-projects">affecting {{ totalProjects | number }} project(s)</span>
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
  `]
})
export class ArchivedPackagesComponent implements OnInit {
  loading = true;
  grouped: GroupedArchived[] = [];
  totalProjects = 0;

  constructor(private api: ApiService, private cdr: ChangeDetectorRef) {}

  ngOnInit(): void {
    this.api.getArchivedPackages().subscribe({
      next: (data) => {
        this.grouped = this.groupByRepo(data || []);
        this.totalProjects = this.countUniqueProjects();
        this.loading = false;
        this.cdr.markForCheck();
      },
      error: () => {
        this.loading = false;
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

  private groupByRepo(packages: ArchivedPackageInfo[]): GroupedArchived[] {
    const repoMap = new Map<string, GroupedArchived>();

    for (const pkg of packages) {
      // Get or create repo group
      let repoGroup = repoMap.get(pkg.repo);
      if (!repoGroup) {
        repoGroup = {
          repo: pkg.repo,
          stars: pkg.stars,
          lastPushed: pkg.last_pushed,
          projects: []
        };
        repoMap.set(pkg.repo, repoGroup);
      }

      // The API reports the described product's version in its own field
      // (document_version, migration 021). Guessing it from the display name
      // is the fallback for SBOMs ingested before that column existed —
      // "k2s" carries no version to guess, so those rows rendered as
      // "latest" even though the SBOM states 0.3.0.
      const baseProjectName = this.extractBaseProjectName(pkg.project_name);
      const version = pkg.project_version || this.extractVersion(pkg.project_name);

      // Find or create project in this repo group
      let project = repoGroup.projects.find(p => p.projectName === baseProjectName);
      if (!project) {
        project = { projectName: baseProjectName, versions: [] };
        repoGroup.projects.push(project);
      }

      // Add version if not already present
      const versionExists = project.versions.some(v => v.sbomId === pkg.sbom_id);
      if (!versionExists) {
        project.versions.push({ version, sbomId: pkg.sbom_id });
      }
    }

    // Sort versions within each project and sort projects alphabetically
    for (const group of repoMap.values()) {
      group.projects.sort((a, b) => a.projectName.localeCompare(b.projectName));
      for (const proj of group.projects) {
        proj.versions.sort((a, b) => this.compareVersions(a.version, b.version));
      }
    }

    // Sort repos by stars descending
    return Array.from(repoMap.values()).sort((a, b) => b.stars - a.stars);
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

