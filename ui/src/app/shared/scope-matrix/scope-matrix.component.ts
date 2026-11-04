import { ChangeDetectionStrategy, Component, Input, OnChanges } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import type { DependencyScope, ScopeBreakdown, SeverityCounts } from '../../core/api.models';
import { DonutChartComponent, DonutSegment } from '../charts/donut-chart.component';
import { scopeLabel, scopeTitle } from '../dependency-scope';

interface ScopeRow {
  scope: DependencyScope;
  label: string;
  title: string;
  counts: SeverityCounts;
  segments: DonutSegment[];
}

const SCOPES: DependencyScope[] = ['direct', 'transitive', 'unknown', 'root'];

/**
 * Severity × dependency-scope matrix: the same findings as the severity
 * donut, split into the CVEs in packages the product declares itself
 * (direct), the ones inherited through the tree (transitive) and the ones
 * whose position is not known. Transitive findings are most of the noise on
 * a large instance; this is where a reader sees how much of a number is
 * actually theirs to act on. `vulnLink` (optional) makes each row open the
 * vulnerability list filtered to that scope.
 */
@Component({
  selector: 'app-scope-matrix',
  standalone: true,
  imports: [CommonModule, RouterModule, DonutChartComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="scope-matrix" *ngIf="rows.length; else empty">
      <div class="scope-card" *ngFor="let r of rows" [title]="r.title">
        <app-donut-chart [segments]="r.segments" [centerLabel]="r.label" [size]="120" [strokeWidth]="18" />
        <table class="scope-table">
          <tbody>
            <tr><th>Total</th><td>{{ r.counts.total | number }}</td></tr>
            <tr class="sev-critical"><th>Critical</th><td>{{ r.counts.critical | number }}</td></tr>
            <tr class="sev-high"><th>High</th><td>{{ r.counts.high | number }}</td></tr>
            <tr class="sev-medium"><th>Medium</th><td>{{ r.counts.medium | number }}</td></tr>
            <tr class="sev-low"><th>Low</th><td>{{ r.counts.low | number }}</td></tr>
          </tbody>
        </table>
        <a *ngIf="vulnLink" class="scope-link" [routerLink]="vulnLink" [queryParams]="{ ...linkParams, scope: r.scope }">List →</a>
      </div>
    </div>
    <ng-template #empty><p class="scope-empty">No vulnerabilities.</p></ng-template>
  `,
  styles: [`
    .scope-matrix { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; }
    .scope-card { display: grid; grid-template-columns: auto 1fr; gap: 8px 16px; align-items: center; padding: 8px; }
    .scope-table { font-size: 0.8rem; border-collapse: collapse; }
    .scope-table th { text-align: left; font-weight: 500; color: var(--text-muted); padding: 2px 10px 2px 0; }
    .scope-table td { text-align: right; font-variant-numeric: tabular-nums; font-weight: 600; }
    .sev-critical td { color: var(--severity-critical); }
    .sev-high td { color: var(--severity-high); }
    .sev-medium td { color: var(--status-warning); }
    .sev-low td { color: var(--text-secondary); }
    .scope-link { grid-column: 1 / -1; font-size: 0.75rem; color: var(--accent); text-decoration: none; }
    .scope-empty { color: var(--text-muted); font-size: 0.85rem; margin: 0; }
  `],
})
export class ScopeMatrixComponent implements OnChanges {
  @Input() breakdown: ScopeBreakdown | undefined;
  @Input() vulnLink: string | unknown[] | undefined;
  /** Extra query params for the row links, e.g. the dashboard's cluster. */
  @Input() linkParams: Record<string, string> = {};

  rows: ScopeRow[] = [];

  ngOnChanges(): void {
    this.rows = SCOPES.flatMap((scope) => {
      const counts = this.breakdown?.[scope];
      if (!counts?.total) return [];
      return [{
        scope,
        label: scopeLabel(scope),
        title: scopeTitle(scope),
        counts,
        segments: [
          { label: 'Critical', value: counts.critical, color: '#C43030' },
          { label: 'High', value: counts.high, color: '#E8871E' },
          { label: 'Medium', value: counts.medium, color: '#C07012' },
          { label: 'Low', value: counts.low, color: '#4b5563' },
        ],
      }];
    });
  }
}
