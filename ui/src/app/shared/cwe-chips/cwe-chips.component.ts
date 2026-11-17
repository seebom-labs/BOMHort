import { ChangeDetectionStrategy, Component, Input } from '@angular/core';
import { CommonModule } from '@angular/common';
import { cweUrl } from '../cwe-ids';

/**
 * The weakness classes of a vulnerability (#409) as small chips next to its
 * aliases, each linking to its MITRE definition. At most `max` are shown;
 * the rest are summarised as "+N" with the full list in the tooltip — the
 * same convention the alias chips use. Findings without CWEs render nothing.
 */
@Component({
  selector: 'app-cwe-chips',
  standalone: true,
  imports: [CommonModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <span class="cwes" *ngIf="ids.length" [title]="'Weakness classes: ' + ids.join(', ')">
      <a *ngFor="let id of shown" class="cwe" [href]="cweUrl(id)" target="_blank" rel="noopener noreferrer">{{ id }}</a>
      <span class="cwe more" *ngIf="ids.length > shown.length" [title]="'Weakness classes: ' + ids.join(', ')">+{{ ids.length - shown.length }}</span>
    </span>
  `,
  styles: [`
    .cwes { display: inline-flex; flex-wrap: wrap; gap: 4px; vertical-align: middle; }
    .cwe {
      font-family: var(--font-mono, monospace); font-size: 0.65rem; line-height: 1.4;
      padding: 0 5px; border-radius: 2px; white-space: nowrap;
      background: var(--bg); color: var(--accent); border: 1px solid var(--border);
      text-decoration: none;
    }
    a.cwe:hover { border-color: var(--accent); }
    .cwe.more { font-family: inherit; color: var(--text-secondary); }
  `],
})
export class CweChipsComponent {
  // undefined: findings without CWEs (e.g. NVD-sourced OSV entries) render nothing.
  @Input() cwes?: string[] = [];
  @Input() max = 2;

  readonly cweUrl = cweUrl;

  get ids(): string[] { return this.cwes ?? []; }
  get shown(): string[] { return this.ids.slice(0, this.max); }
}
