import { ChangeDetectionStrategy, ChangeDetectorRef, Component, ElementRef, Input, OnChanges, SimpleChanges, ViewChild, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { CdkVirtualScrollViewport, ScrollingModule } from '@angular/cdk/scrolling';
import type { DependencyNode, VulnerabilityListItem } from '../../core/api.models';
import { ScopeBadgeComponent } from '../../shared/scope-badge/scope-badge.component';
import { DependencyTree, FlatDep, TreeRow, buildTree, defaultExpanded, visibleRows } from './dependency-tree';

/** How a dependency's license is shown: copyleft, copyleft under an exception, or neither. */
export type LicenseFlag = '' | 'copyleft' | 'exempted';

/** Severity order for the worst open finding of a package. */
const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

/**
 * The Dependencies tab of the SBOM detail page (#56): the dependency graph as
 * an expandable tree, or every package once as a list. SBOMs without
 * relationships only have the list. License and archived-repository flags
 * come from the page, which owns that data.
 */
@Component({
  selector: 'app-dependency-tree',
  standalone: true,
  imports: [CommonModule, ScrollingModule, ScopeBadgeComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="dep-toolbar">
      <div class="view-toggle" role="group" aria-label="Dependency view">
        <button type="button" class="toggle-btn"
                [class.active]="view === 'tree'" [attr.aria-pressed]="view === 'tree'"
                [disabled]="!tree?.hasEdges"
                [title]="tree?.hasEdges ? 'Dependencies as a tree' : 'This SBOM has no dependency relationships'"
                (click)="setView('tree')">Tree</button>
        <button type="button" class="toggle-btn"
                [class.active]="view === 'list'" [attr.aria-pressed]="view === 'list'"
                (click)="setView('list')">List</button>
      </div>
      <input type="search" class="dep-search" placeholder="Search name, version or purl"
             aria-label="Search dependencies" [value]="query"
             (input)="onSearch($any($event.target).value)">
      <button *ngIf="view === 'tree' && !searching" type="button" class="dep-collapse" (click)="collapseAll()">Collapse all</button>
    </div>
    <p class="dep-hint" *ngIf="view === 'tree' && truncated">
      Showing the first {{ treeRows.length | number }} rows: the matching packages are reachable through many paths. Refine the search to see the rest.
    </p>
    <p class="dep-hint" *ngIf="searching && !(view === 'tree' ? treeRows.length : listDeps.length)">
      No dependencies match "{{ query }}".
    </p>
    <div class="dep-table-header">
      <span class="dep-col-name">Package</span>
      <span class="dep-col-scope">Scope</span>
      <span class="dep-col-version">Version</span>
      <span class="dep-col-license">License</span>
    </div>
    <cdk-virtual-scroll-viewport *ngIf="view === 'tree'" itemSize="44" class="viewport" role="tree" aria-label="Dependency tree">
      <!-- WAI-ARIA tree pattern: one row is in the tab order (roving
           tabindex) and the arrow keys move between rows; see onTreeKeydown. -->
      <div *cdkVirtualFor="let row of treeRows; let i = index; trackBy: trackByRow" class="dep-row" role="treeitem"
           [attr.data-key]="row.key"
           [attr.tabindex]="row.key === activeKey ? 0 : -1"
           [attr.aria-level]="row.level + 1"
           [attr.aria-posinset]="row.posInSet"
           [attr.aria-setsize]="row.setSize"
           [attr.aria-expanded]="row.hasChildren && !row.cycle ? row.expanded : null"
           [class.match]="row.match"
           [style.padding-left.px]="12 + row.level * 20"
           (focus)="activeKey = row.key"
           (keydown)="onTreeKeydown($event, i)">
        <!-- Mouse affordance only: the row itself takes the keyboard. A search
             shows the paths to its matches and ignores manual expansion, so
             there is nothing to toggle while it is active. -->
        <button *ngIf="canToggle(row); else spacer" type="button" class="tree-toggle" tabindex="-1" aria-hidden="true"
                (click)="toggleRow(row); activeKey = row.key">{{ row.expanded ? '▾' : '▸' }}</button>
        <ng-template #spacer><span class="tree-spacer"></span></ng-template>
        <ng-container *ngTemplateOutlet="cells; context: { $implicit: depAt(row.index), row: row }"></ng-container>
      </div>
    </cdk-virtual-scroll-viewport>
    <cdk-virtual-scroll-viewport *ngIf="view === 'list'" itemSize="44" class="viewport">
      <div *cdkVirtualFor="let node of listDeps; trackBy: trackByDep" class="dep-row"
           [style.padding-left.px]="12 + node.level * 24">
        <ng-container *ngTemplateOutlet="cells; context: { $implicit: node, row: null }"></ng-container>
      </div>
    </cdk-virtual-scroll-viewport>
    <ng-template #cells let-node let-row="row">
      <span class="dep-name" [title]="node.purl || node.name">
        {{ node.name }}
        <span class="dep-tag" *ngIf="row?.cycle" title="Already listed above on this path: the dependency graph has a cycle here">CYCLE</span>
        <span class="dep-tag" *ngIf="row?.detached && row.level === 0" title="Not reachable from the product in the dependency graph">NOT CONNECTED</span>
        <span class="dep-vulns" *ngIf="vulnSummary(node.purl) as v" [ngClass]="'sev-' + v.worst.toLowerCase()"
              [title]="v.count + (v.count === 1 ? ' open vulnerability' : ' open vulnerabilities') + ', worst ' + v.worst">{{ v.count }}</span>
        <span class="archived-tag" *ngIf="isArchived(node.purl)" title="This package uses an archived GitHub repository"> ARCHIVED</span>
      </span>
      <span class="dep-scope"><app-scope-badge [scope]="node.scope" [depth]="node.depth"></app-scope-badge></span>
      <span class="dep-version">{{ node.version }}</span>
      <span class="dep-license" *ngIf="licenseFlag(node.license) as flag; else plainLicense"
            [title]="node.licenseTitle" [class.copyleft]="flag === 'copyleft'" [class.exempted]="flag === 'exempted'">
        {{ node.license || '—' }}
        <span class="dep-exempted-tag" *ngIf="flag === 'exempted'">✓</span>
      </span>
      <ng-template #plainLicense>
        <span class="dep-license" [title]="node.licenseTitle">{{ node.license || '—' }}</span>
      </ng-template>
    </ng-template>
  `,
  styles: [`
    :host { display: flex; flex-direction: column; height: 100%; min-height: 0; }
    .viewport { height: 100%; min-height: 400px; }
    .dep-toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
    .view-toggle { display: flex; border: 1px solid var(--border); border-radius: 4px; overflow: hidden; }
    .toggle-btn {
      background: var(--surface); border: none; cursor: pointer; font-family: inherit;
      padding: 5px 12px; font-size: 0.74rem; color: var(--text-secondary); transition: all 0.12s;
    }
    .toggle-btn + .toggle-btn { border-left: 1px solid var(--border); }
    .toggle-btn:hover:not(:disabled) { color: var(--text); }
    .toggle-btn.active { background: var(--accent); color: var(--surface); font-weight: 600; }
    .toggle-btn:disabled { cursor: not-allowed; opacity: 0.5; }
    .dep-search {
      flex: 1; min-width: 180px; max-width: 360px; padding: 6px 10px; font-size: 0.8rem;
      border: 1px solid var(--border); border-radius: 4px; background: var(--surface); color: var(--text);
    }
    .dep-collapse {
      background: none; border: none; cursor: pointer; font-family: inherit;
      font-size: 0.76rem; color: var(--accent); padding: 4px 0;
    }
    .dep-hint { font-size: 0.78rem; color: var(--text-secondary); margin: 0 0 8px; }
    .dep-table-header {
      display: flex; align-items: center; gap: 16px; padding: 8px 12px;
      background: var(--bg); border-radius: 2px; font-weight: 600; font-size: 0.7rem;
      color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.04em;
      margin-bottom: 2px; border-bottom: 1px solid var(--border);
    }
    .dep-col-name { flex: 1; min-width: 0; }
    .dep-col-scope, .dep-scope { width: 90px; flex-shrink: 0; }
    .dep-col-version { width: 140px; flex-shrink: 0; }
    .dep-col-license { width: 180px; flex-shrink: 0; }
    .dep-row {
      height: 42px; display: flex; align-items: center; gap: 16px;
      padding: 0 12px; border-bottom: 1px solid var(--border); font-size: 0.82rem;
      transition: background 0.1s;
    }
    .dep-row:hover { background: var(--surface-alt); }
    .dep-row.match .dep-name { color: var(--accent); }
    .dep-row:focus { outline: none; }
    .dep-row:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
    .tree-toggle {
      width: 18px; flex-shrink: 0; margin-right: -10px; background: none; border: none; cursor: pointer;
      color: var(--text-secondary); font-size: 0.8rem; padding: 0; line-height: 1;
    }
    .tree-toggle:hover { color: var(--text); }
    .tree-spacer { width: 18px; flex-shrink: 0; margin-right: -10px; }
    .dep-name {
      font-weight: 500; flex: 1; min-width: 0;
      overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
      display: flex; align-items: center; gap: 8px;
    }
    .dep-tag {
      padding: 1px 6px; border-radius: 2px; font-size: 0.6rem; font-weight: 600; flex-shrink: 0;
      border: 1px solid var(--border); color: var(--text-secondary);
    }
    .dep-vulns {
      min-width: 18px; text-align: center; padding: 1px 5px; border-radius: 9px;
      font-size: 0.66rem; font-weight: 700; flex-shrink: 0;
    }
    .sev-critical { background: var(--severity-critical-bg); color: var(--severity-critical); }
    .sev-high { background: var(--severity-high-bg); color: var(--severity-high); }
    .sev-medium { background: var(--severity-high-bg); color: var(--status-warning); }
    .sev-low { background: var(--bg); color: var(--text-secondary); }
    .archived-tag {
      background: var(--severity-high); color: #fff;
      padding: 1px 6px; border-radius: 2px; font-size: 0.6rem; font-weight: 600;
      flex-shrink: 0;
    }
    .dep-version {
      color: var(--text-secondary); width: 140px; flex-shrink: 0;
      font-family: monospace; font-size: 0.78rem;
    }
    .dep-license {
      color: var(--status-success); font-size: 0.75rem;
      width: 180px; flex-shrink: 0; display: flex; align-items: center; gap: 4px;
    }
    .copyleft { color: var(--severity-critical); }
    .exempted { color: var(--status-warning); }
    .dep-exempted-tag {
      font-size: 0.6rem; font-weight: 700; color: var(--status-success);
      background: var(--status-success-bg); padding: 0 3px; border-radius: 2px;
    }
  `],
})
export class DependencyTreeComponent implements OnChanges {
  /** The dependency graph as the API returns it. */
  @Input() nodes: DependencyNode[] = [];
  /** One display row per node, by `index`. */
  @Input() deps: FlatDep[] = [];
  /** The SBOM's findings; VEX-resolved ones are not counted. */
  @Input() vulns: VulnerabilityListItem[] = [];
  @Input() licenseFlag: (license: string) => LicenseFlag = () => '';
  @Input() isArchived: (purl: string) => boolean = () => false;

  tree: DependencyTree | null = null;
  view: 'tree' | 'list' = 'list';
  query = '';
  treeRows: TreeRow[] = [];
  truncated = false;
  /** deps narrowed by the search, for the list view. */
  listDeps: FlatDep[] = [];
  /** The row in the tab order (roving tabindex); the first row by default. */
  activeKey: string | null = null;
  private byIndex = new Map<number, FlatDep>();
  private expanded = new Set<string>();
  private vulnByPurl = new Map<string, { count: number; worst: string }>();

  @ViewChild(CdkVirtualScrollViewport) private viewport?: CdkVirtualScrollViewport;
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly cdr = inject(ChangeDetectorRef);

  /** A search is active; whitespace alone is no search, as in visibleRows. */
  get searching(): boolean {
    return this.query.trim() !== '';
  }

  ngOnChanges(changes: SimpleChanges): void {
    if (changes['nodes']) {
      this.tree = buildTree(this.nodes);
      this.view = this.tree.hasEdges ? 'tree' : 'list';
      this.expanded = defaultExpanded(this.tree);
    }
    if (changes['deps']) this.byIndex = new Map(this.deps.map((d) => [d.index, d]));
    if (changes['vulns']) this.indexOpenFindings();
    this.refresh();
  }

  trackByRow(_i: number, r: TreeRow): string { return r.key; }
  trackByDep(_i: number, d: FlatDep): number { return d.index; }

  setView(view: 'tree' | 'list'): void {
    if (view === 'tree' && !this.tree?.hasEdges) return;
    this.view = view;
  }

  onSearch(query: string): void {
    this.query = query;
    this.refresh();
  }

  /** Whether the row can be expanded or collapsed by the user right now. */
  canToggle(row: TreeRow): boolean {
    return row.hasChildren && !row.cycle && !this.searching;
  }

  /**
   * Keyboard interaction of the WAI-ARIA tree pattern: Up/Down move between
   * visible rows, Right expands a row or moves to its first child, Left
   * collapses it or moves to its parent, Home/End jump to the first/last row,
   * Enter/Space toggle.
   */
  onTreeKeydown(event: KeyboardEvent, index: number): void {
    const rows = this.treeRows;
    const row = rows[index];
    if (!row) return;
    let target = index;
    switch (event.key) {
      case 'ArrowDown': target = Math.min(index + 1, rows.length - 1); break;
      case 'ArrowUp': target = Math.max(index - 1, 0); break;
      case 'Home': target = 0; break;
      case 'End': target = rows.length - 1; break;
      case 'ArrowRight':
        if (this.canToggle(row) && !row.expanded) this.toggleRow(row);
        else if (row.expanded && rows[index + 1]?.level === row.level + 1) target = index + 1;
        break;
      case 'ArrowLeft':
        if (this.canToggle(row) && row.expanded) {
          this.toggleRow(row);
        } else {
          for (let j = index - 1; j >= 0; j--) {
            if (rows[j].level === row.level - 1) { target = j; break; }
          }
        }
        break;
      case 'Enter':
      case ' ':
        if (this.canToggle(row)) this.toggleRow(row);
        break;
      default:
        return;
    }
    event.preventDefault();
    // Expanding or collapsing only changes rows below this one, so the
    // index of the row itself and of everything above it stays valid.
    this.focusRow(target);
  }

  /**
   * Makes the row the tab stop and focuses it. Virtual scrolling renders only
   * the rows near the viewport, so a row outside the rendered range is
   * scrolled to first and focused once it is rendered.
   */
  private focusRow(index: number): void {
    const row = this.treeRows[index];
    if (!row) return;
    this.activeKey = row.key;
    this.cdr.detectChanges();
    const range = this.viewport?.getRenderedRange();
    if (this.viewport && range && (index < range.start || index >= range.end)) {
      this.viewport.scrollToIndex(index);
    }
    this.focusWhenRendered(row.key, 20);
  }

  private focusWhenRendered(key: string, attempts: number): void {
    // Keys hold only digits, '/', 'd' and ':', so they are safe in a quoted
    // attribute selector.
    const el = this.host.nativeElement.querySelector<HTMLElement>(`[data-key="${key}"]`);
    if (el) {
      el.focus();
    } else if (attempts > 0) {
      setTimeout(() => this.focusWhenRendered(key, attempts - 1), 16);
    }
  }

  toggleRow(row: TreeRow): void {
    if (this.expanded.has(row.key)) this.expanded.delete(row.key);
    else this.expanded.add(row.key);
    this.refresh();
  }

  collapseAll(): void {
    if (!this.tree) return;
    this.expanded = defaultExpanded(this.tree);
    this.refresh();
  }

  depAt(index: number): FlatDep {
    return this.byIndex.get(index)!;
  }

  vulnSummary(purl: string): { count: number; worst: string } | null {
    return (purl && this.vulnByPurl.get(purl)) || null;
  }

  private refresh(): void {
    const q = this.query.trim().toLowerCase();
    this.listDeps = q
      ? this.deps.filter((d) =>
          d.name.toLowerCase().includes(q) || (d.version ?? '').toLowerCase().includes(q) || (d.purl ?? '').toLowerCase().includes(q))
      : this.deps;
    if (this.tree) {
      const { rows, truncated } = visibleRows(this.tree, this.expanded, this.query);
      this.treeRows = rows;
      this.truncated = truncated;
      // Keep exactly one row in the tab order.
      if (!rows.some((r) => r.key === this.activeKey)) this.activeKey = rows[0]?.key ?? null;
    }
  }

  /** Findings a VEX statement resolved (not_affected, fixed) do not count. */
  private indexOpenFindings(): void {
    this.vulnByPurl = new Map();
    for (const v of this.vulns) {
      if (!v.purl || v.vex_status === 'not_affected' || v.vex_status === 'fixed') continue;
      const sev = (v.severity || 'UNKNOWN').toUpperCase();
      const cur = this.vulnByPurl.get(v.purl);
      if (!cur) {
        this.vulnByPurl.set(v.purl, { count: 1, worst: sev });
        continue;
      }
      cur.count++;
      if ((SEVERITY_RANK[sev] ?? 0) > (SEVERITY_RANK[cur.worst] ?? 0)) cur.worst = sev;
    }
  }
}
