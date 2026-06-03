import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef, SecurityContext } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { DomSanitizer } from '@angular/platform-browser';
import { ApiService } from '../../core/api.service';
import { DashboardStats } from '../../core/api.models';
import { SiteConfigService } from '../../core/site-config.service';
import { DonutChartComponent, DonutSegment } from '../../shared/charts/donut-chart.component';
import { HorizontalBarChartComponent, BarItem } from '../../shared/charts/horizontal-bar-chart.component';

@Component({
  selector: 'app-dashboard',
  standalone: true,
  imports: [CommonModule, RouterModule, DonutChartComponent, HorizontalBarChartComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="dashboard">
      <header class="dash-header">
        <h1>{{ dashTitle }}</h1>
        <p class="subtitle">{{ dashSubtitle }}</p>
      </header>

      <section class="description-banner">
        <p class="description-text" [innerHTML]="dashDescription"></p>
      </section>

      @if (stats) {
        <div class="kpi-row">
          <div class="kpi-card">
            <span class="kpi-value">{{ stats.total_sboms | number }}</span>
            <span class="kpi-label">SBOMs</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-value">{{ stats.total_packages | number }}</span>
            <span class="kpi-label">Packages</span>
          </div>
          <div class="kpi-card warn">
            @if (stats.total_vex_statements > 0) {
              <span class="kpi-value">{{ stats.effective_vulnerabilities | number }}</span>
              <span class="kpi-label">Effective Vulns</span>
            } @else {
              <span class="kpi-value">{{ stats.total_vulnerabilities | number }}</span>
              <span class="kpi-label">Total Vulns</span>
            }
          </div>
          <div class="kpi-card ok">
            <span class="kpi-value">{{ stats.suppressed_by_vex | number }}</span>
            <span class="kpi-label">Suppressed by VEX</span>
          </div>
          <div class="kpi-card ok">
            <span class="kpi-value">{{ stats.exempted_packages | number }}</span>
            <span class="kpi-label">Exempted Licenses</span>
          </div>
          <div class="kpi-card">
            <span class="kpi-value">{{ stats.total_vex_statements | number }}</span>
            <span class="kpi-label">VEX Statements</span>
          </div>
        </div>

        <div class="charts-row">
          <div class="chart-card">
            <h3>Vulnerability Severity</h3>
            <app-donut-chart [segments]="severitySegments" centerLabel="Vulnerabilities" />
          </div>
          <div class="chart-card">
            <h3>License Breakdown</h3>
            <app-donut-chart [segments]="licenseSegments" centerLabel="Licenses" />
          </div>
          <div class="chart-card">
            <h3>VEX Effectiveness</h3>
            @if (stats.total_vex_statements > 0) {
              <app-donut-chart [segments]="vexSegments" centerLabel="Total" />
            } @else {
              <div class="empty-vex">
                <span class="empty-vex-icon">📄</span>
                <p class="empty-vex-title">No VEX Data</p>
                <p class="empty-vex-hint">Add <code>.openvex.json</code> files to suppress non-applicable vulnerabilities.</p>
              </div>
            }
          </div>
        </div>

        <div class="charts-row two-col">
          <div class="chart-card">
            <h3>Vulnerabilities by Severity</h3>
            <app-horizontal-bar-chart [bars]="severityBars" />
          </div>
          <div class="chart-card">
            <h3>Packages by License Category</h3>
            <app-horizontal-bar-chart [bars]="licenseBars" />
          </div>
        </div>

        <div class="refresh-banner" *ngIf="stats.last_cve_refresh">
          <span class="refresh-label">Last CVE Refresh:</span>
          <span class="refresh-time">{{ stats.last_cve_refresh | date:'medium' }}</span>
          <span class="refresh-vulns" *ngIf="stats.new_vulns_since_refresh">
            {{ stats.new_vulns_since_refresh | number }} new vulns found
          </span>
          <span class="refresh-ok" *ngIf="!stats.new_vulns_since_refresh">
            ✓ No new vulnerabilities
          </span>
        </div>

        <div class="warning-banner" *ngIf="stats.archived_repos_count && stats.archived_repos_count > 0">
          <span class="warning-icon">⚠️</span>
          <span class="warning-text">
            <strong>{{ stats.archived_repos_count | number }}</strong> archived GitHub repositories detected in your dependencies.
            <a routerLink="/archived-packages">View Details →</a>
          </span>
        </div>

        <div class="quick-links">
          <a routerLink="/sboms" class="quick-link">Browse SBOMs <span class="arrow">→</span></a>
          <a routerLink="/vulnerabilities" class="quick-link">View Vulnerabilities <span class="arrow">→</span></a>
          <a routerLink="/license-compliance" class="quick-link">License Compliance <span class="arrow">→</span></a>
          <a routerLink="/cve-impact" class="quick-link">CVE Impact Search <span class="arrow">→</span></a>
        </div>

        <section class="disclaimer">
          <p [innerHTML]="dashDisclaimer"></p>
        </section>
      } @else if (error) {
        <div class="error-state">
          <span class="error-icon">⚠️</span>
          <p class="error-title">Unable to load dashboard data</p>
          <p class="error-hint">Make sure the API Gateway is running and accessible.</p>
          <button class="retry-btn" (click)="loadData()">Retry</button>
        </div>
      } @else {
        <div class="loading-state">
          <div class="spinner"></div>
          <p>Loading…</p>
        </div>
      }
    </div>
  `,
  styles: [`
    .dashboard { padding: 24px; max-width: 1400px; margin: 0 auto; }
    .dash-header { margin-bottom: 24px; }
    .dash-header h1 { font-size: 1.25rem; font-weight: 700; letter-spacing: -0.02em; color: var(--text); }
    .subtitle { margin-top: 2px; color: var(--text-secondary); font-size: 0.8rem; }

    .description-banner {
      background: var(--surface); border: 1px solid var(--border); border-radius: 4px;
      padding: 16px 20px; margin-bottom: 24px;
    }
    .description-text {
      margin: 0; font-size: 0.82rem; line-height: 1.65; color: var(--text-secondary);
    }
    .description-text strong { color: var(--text); }
    .description-text a { color: var(--accent); text-decoration: none; font-weight: 500; }
    .description-text a:hover { text-decoration: underline; }

    .kpi-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 24px; }
    .kpi-card {
      display: flex; flex-direction: column; gap: 2px;
      padding: 16px 18px; background: var(--surface);
      border: 1px solid var(--border); border-radius: 4px;
    }
    .kpi-value { font-size: 1.5rem; font-weight: 700; color: var(--text); line-height: 1.2; letter-spacing: -0.02em; }
    .kpi-label { font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.04em; font-weight: 500; }
    .kpi-card.warn .kpi-value { color: var(--severity-critical); }
    .kpi-card.ok .kpi-value { color: var(--status-success); }

    .charts-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 16px; }
    .charts-row.two-col { grid-template-columns: repeat(2, 1fr); }
    .chart-card {
      background: var(--surface); border: 1px solid var(--border); border-radius: 4px; padding: 20px;
    }
    .chart-card h3 { margin: 0 0 14px; font-size: 0.8rem; font-weight: 600; color: var(--dark); text-transform: uppercase; letter-spacing: 0.03em; }

    .quick-links { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; margin-top: 8px; }
    .quick-link {
      display: flex; align-items: center; justify-content: space-between;
      padding: 12px 16px; background: var(--surface); border: 1px solid var(--border);
      border-radius: 4px; text-decoration: none; color: var(--dark);
      font-size: 0.8rem; font-weight: 500; transition: border-color 0.15s;
    }
    .quick-link:hover { border-color: var(--accent); color: var(--accent); }
    .arrow { color: var(--text-muted); }
    .quick-link:hover .arrow { color: var(--accent); }

    .refresh-banner {
      display: flex; align-items: center; gap: 10px; padding: 10px 16px;
      background: var(--surface); border: 1px solid var(--border); border-radius: 4px;
      margin-bottom: 12px; font-size: 0.78rem;
    }
    .refresh-label { color: var(--text-secondary); font-weight: 500; }
    .refresh-time { color: var(--text); font-weight: 600; }
    .refresh-vulns { color: var(--severity-critical); font-weight: 600; }
    .refresh-ok { color: var(--status-success); font-weight: 600; }

    .warning-banner {
      display: flex; align-items: center; gap: 10px; padding: 12px 16px;
      background: color-mix(in srgb, var(--severity-high) 15%, transparent);
      border: 1px solid var(--severity-high); border-radius: 4px;
      margin-bottom: 12px; font-size: 0.85rem;
    }
    .warning-icon { font-size: 1.2rem; }
    .warning-text { color: var(--text); }
    .warning-text a { color: var(--accent); font-weight: 600; margin-left: 8px; }
    .warning-text a:hover { text-decoration: underline; }

    .empty-vex { display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 6px; padding: 32px 16px; text-align: center; }
    .empty-vex-icon { font-size: 2rem; opacity: 0.5; }
    .empty-vex-title { font-size: 0.85rem; font-weight: 600; color: var(--text-secondary); margin: 0; }
    .empty-vex-hint { font-size: 0.72rem; color: var(--text-muted); margin: 0; line-height: 1.5; }
    .empty-vex-hint code { background: var(--border); padding: 1px 5px; border-radius: 3px; font-size: 0.7rem; }

    .disclaimer {
      margin-top: 24px; padding: 14px 18px;
      background: color-mix(in srgb, var(--text-muted) 8%, transparent);
      border: 1px solid var(--border); border-radius: 4px;
    }
    .disclaimer p {
      margin: 0; font-size: 0.72rem; line-height: 1.6; color: var(--text-muted);
    }
    .disclaimer strong { color: var(--text-secondary); }

    .loading-state { display: flex; flex-direction: column; align-items: center; gap: 12px; padding: 80px 0; color: var(--text-muted); }
    .spinner {
      width: 28px; height: 28px; border: 2px solid #e5e7eb; border-top-color: var(--accent);
      border-radius: 50%; animation: spin 0.7s linear infinite;
    }
    @keyframes spin { to { transform: rotate(360deg); } }

    .error-state { display: flex; flex-direction: column; align-items: center; gap: 8px; padding: 80px 0; text-align: center; }
    .error-icon { font-size: 2rem; }
    .error-title { font-size: 0.9rem; font-weight: 600; color: var(--text); margin: 0; }
    .error-hint { font-size: 0.78rem; color: var(--text-muted); margin: 0; }
    .retry-btn {
      margin-top: 12px; padding: 8px 20px; font-size: 0.8rem; font-weight: 500;
      background: var(--accent); color: #fff; border: none; border-radius: 4px;
      cursor: pointer; transition: opacity 0.15s;
    }
    .retry-btn:hover { opacity: 0.85; }
  `],
})
export class DashboardComponent implements OnInit {
  stats: DashboardStats | null = null;
  error = false;
  severitySegments: DonutSegment[] = [];
  licenseSegments: DonutSegment[] = [];
  vexSegments: DonutSegment[] = [];
  severityBars: BarItem[] = [];
  licenseBars: BarItem[] = [];

  dashTitle = '';
  dashSubtitle = '';
  dashDescription = '';
  dashDisclaimer = '';

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
    private readonly siteConfig: SiteConfigService,
    private readonly sanitizer: DomSanitizer,
  ) {}

  ngOnInit(): void {
    const dc = this.siteConfig.dashboard;
    this.dashTitle = dc.title;
    this.dashSubtitle = dc.subtitle;
    // Use Angular's built-in sanitizer: strips <script>, event handlers, etc.
    // but preserves safe formatting tags (<strong>, <a>, <em>, <code>).
    this.dashDescription = this.sanitizer.sanitize(SecurityContext.HTML, dc.description) ?? '';
    this.dashDisclaimer = this.sanitizer.sanitize(SecurityContext.HTML, dc.disclaimer) ?? '';

    this.loadData();
  }

  loadData(): void {
    this.error = false;
    this.stats = null;
    this.cdr.markForCheck();

    this.api.getDashboardStats().subscribe({
      next: (data) => {
        this.stats = data;
        this.buildCharts(data);
        this.cdr.markForCheck();
      },
      error: () => {
        this.error = true;
        this.cdr.markForCheck();
      },
    });
  }

  private buildCharts(s: DashboardStats): void {
    this.severitySegments = [
      { label: 'Critical', value: s.critical_vulns, color: '#C43030' },
      { label: 'High', value: s.high_vulns, color: '#E8871E' },
      { label: 'Medium', value: s.medium_vulns, color: '#C07012' },
      { label: 'Low', value: s.low_vulns, color: '#4b5563' },
    ];
    this.severityBars = [...this.severitySegments];

    const lb = s.license_breakdown || {};
    this.licenseSegments = [
      { label: 'Permissive', value: lb['permissive'] || 0, color: '#0D6B5E' },
      { label: 'Copyleft', value: lb['copyleft'] || 0, color: '#C43030' },
      { label: 'Exempted', value: s.exempted_packages || 0, color: '#E8871E' },
      { label: 'Unknown', value: lb['unknown'] || 0, color: '#9ca3af' },
    ];
    this.licenseBars = [...this.licenseSegments];

    this.vexSegments = s.total_vex_statements > 0
      ? [
          { label: 'Effective', value: s.effective_vulnerabilities, color: '#E8871E' },
          { label: 'Suppressed', value: s.suppressed_by_vex, color: '#0D6B5E' },
        ]
      : [];
  }
}

