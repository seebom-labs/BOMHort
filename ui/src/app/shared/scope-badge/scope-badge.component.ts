import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import type { DependencyScope } from '../../core/api.models';
import { scopeClass, scopeLabel, scopeTitle } from '../dependency-scope';

/**
 * DIRECT / TRANSITIVE / UNKNOWN badge for a package, so a reader can tell at
 * a glance whether a finding sits in code the project chose or in something
 * it inherited. Compact by default; `size="md"` for table rows.
 */
@Component({
  selector: 'app-scope-badge',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<span class="scope-badge" [class]="'scope-badge ' + cls + ' size-' + size" [title]="title">{{ label }}</span>`,
  styles: [`
    .scope-badge {
      display: inline-block; padding: 1px 5px; border-radius: 2px;
      font-size: 0.6rem; font-weight: 600; text-transform: uppercase;
      letter-spacing: 0.03em; min-width: 72px; text-align: center;
      white-space: nowrap; vertical-align: middle;
    }
    .scope-badge.size-md { font-size: 0.65rem; padding: 2px 7px; }
    .scope-direct { background: var(--status-info-bg); color: var(--status-info); }
    .scope-transitive { background: var(--severity-high-bg); color: var(--status-warning); }
    .scope-root { background: var(--status-success-bg); color: var(--status-success); }
    .scope-unknown { background: var(--severity-low-bg); color: var(--text-secondary); border: 1px dashed var(--border); }
  `],
})
export class ScopeBadgeComponent {
  @Input() scope: DependencyScope | undefined;
  @Input() depth: number | undefined;
  @Input() reason: string | undefined;
  @Input() size: 'sm' | 'md' = 'sm';

  get label(): string { return scopeLabel(this.scope); }
  get title(): string { return scopeTitle(this.scope, this.depth, this.reason); }
  get cls(): string { return scopeClass(this.scope); }
}
