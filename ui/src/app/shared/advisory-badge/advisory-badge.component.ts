import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import type { VulnerabilityListItem } from '../../core/api.models';

/** Reader-facing labels of the advisory feed status vocabulary. */
export const ADVISORY_STATUS_LABELS: Record<string, string> = {
  affected: 'Affected',
  under_investigation: 'Under investigation',
  pending_upstream_fix: 'Pending upstream fix',
  fix_not_planned: 'Fix not planned',
  not_affected: 'Not affected',
};

/** Label of an advisory status; unknown values are shown as sent. */
export function advisoryStatusLabel(status: string | undefined): string {
  if (!status) return '';
  return ADVISORY_STATUS_LABELS[status] ?? status.replace(/_/g, ' ');
}

/**
 * Names the advisory feed that decided a finding and the status it reports
 * ("wolfi · Pending upstream fix"), with the component locations as a
 * tooltip. Renders nothing for osv.dev findings, which are the default.
 */
@Component({
  selector: 'app-advisory-badge',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (source) {
      <span class="advisory-badge" [class]="'advisory-badge advisory-' + (vuln?.advisory_status || 'affected')"
            [title]="title">{{ label }}</span>
    }
  `,
  styles: [`
    .advisory-badge {
      display: inline-block; padding: 1px 6px; border-radius: 2px;
      font-size: 0.6rem; font-weight: 600; white-space: nowrap;
      vertical-align: middle; margin-left: 4px;
      background: var(--status-info-bg); color: var(--status-info);
    }
    .advisory-pending_upstream_fix, .advisory-under_investigation {
      background: var(--severity-high-bg); color: var(--status-warning);
    }
    .advisory-fix_not_planned { background: var(--severity-critical-bg); color: var(--status-error); }
    .advisory-not_affected { background: var(--status-success-bg); color: var(--status-success); }
  `],
})
export class AdvisoryBadgeComponent {
  @Input() vuln: Pick<VulnerabilityListItem, 'advisory_source' | 'advisory_status' | 'advisory_components'> | undefined;

  /** The feed name, or '' for osv.dev (and for servers without feeds). */
  get source(): string {
    const s = this.vuln?.advisory_source ?? '';
    return s === 'osv' ? '' : s;
  }

  get label(): string {
    const status = advisoryStatusLabel(this.vuln?.advisory_status);
    return status ? `${this.source} · ${status}` : this.source;
  }

  get title(): string {
    const lines = [`Decided by advisory feed "${this.source}"`];
    for (const c of this.vuln?.advisory_components ?? []) {
      const where = [c.location, c.architecture && `(${c.architecture})`].filter(Boolean).join(' ');
      if (where) lines.push(where);
    }
    return lines.join('\n');
  }
}
