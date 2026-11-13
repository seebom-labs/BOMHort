import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';

export interface ExtraFieldEntry {
  name: string;
  values: string[];
}

/**
 * Extra fields as a name-sorted list for the template; fields without a
 * value are dropped. The object key order of the API response is not
 * meaningful, so sorting keeps the rendering stable across reloads.
 */
export function extraFieldList(fields: Record<string, string[]> | undefined | null): ExtraFieldEntry[] {
  if (!fields) return [];
  return Object.keys(fields)
    .sort()
    .map((name) => ({ name, values: Array.isArray(fields[name]) ? fields[name] : [] }))
    .filter((f) => f.values.length > 0);
}

/**
 * Operator-declared extra fields read from an SBOM document. Values are
 * untrusted producer input: only ever interpolated as text, and linked out
 * only when they are http(s) URLs. Clicking a value lists every SBOM
 * carrying the same one.
 */
@Component({
  selector: 'app-extra-fields',
  standalone: true,
  imports: [CommonModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <dl class="extra-fields" *ngIf="fields.length">
      <div class="extra-field" *ngFor="let f of fields; trackBy: trackByName">
        <dt class="extra-name">{{ f.name }}</dt>
        <dd class="extra-values">
          <span class="extra-value" *ngFor="let v of f.values">
            <a [routerLink]="['/sboms']" [queryParams]="{ extra_field: f.name, extra_value: v }"
               class="extra-filter" [title]="'All SBOMs with ' + f.name + ' = ' + v">{{ v }}</a>
            <a *ngIf="isUrl(v)" [href]="v" target="_blank" rel="noopener noreferrer"
               class="extra-out" title="Open link">↗</a>
          </span>
        </dd>
      </div>
    </dl>
  `,
  styles: [`
    .extra-fields { margin: -4px 0 12px; font-size: 0.75rem; }
    .extra-field { display: flex; align-items: baseline; gap: 8px; }
    .extra-field dt { color: var(--text-secondary); font-weight: 500; }
    .extra-field dd { display: flex; flex-wrap: wrap; gap: 6px; margin: 0; min-width: 0; }
    .extra-value { border: 1px solid var(--border); padding: 0 6px; overflow-wrap: anywhere; }
    .extra-filter { color: var(--text); font-family: monospace; text-decoration: none; }
    .extra-filter:hover { color: var(--accent); }
    .extra-out { color: var(--accent); margin-left: 4px; text-decoration: none; }
  `],
})
export class ExtraFieldsComponent {
  /** Output of extraFieldList; an empty list renders nothing. */
  @Input() fields: ExtraFieldEntry[] = [];

  trackByName(_index: number, f: ExtraFieldEntry): string {
    return f.name;
  }

  isUrl(value: string): boolean {
    return !!value && (value.startsWith('http://') || value.startsWith('https://'));
  }
}
