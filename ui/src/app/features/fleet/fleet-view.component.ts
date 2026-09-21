import { Component, OnInit, ChangeDetectionStrategy, ChangeDetectorRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterModule } from '@angular/router';
import { ApiService } from '../../core/api.service';
import { FleetCluster, FleetNamespace, NamespaceStats, ClusterStats } from '../../core/api.models';

/**
 * Fleet view (#131 cluster, #138 namespace, #57 project).
 *
 * This is the visual counterpart to the three ownership columns: the tree on
 * the left answers "what exists where", the panel on the right answers "how
 * bad is it there". Everything is driven by a single `GET /api/v1/fleet` call —
 * one request for the whole hierarchy, because a per-cluster fan-out would
 * turn a fleet of 50 clusters into 50 round trips on page load.
 *
 * Unassigned dimensions arrive as an empty string (the column DEFAULT). They
 * are rendered as "(unassigned)" rather than hidden: a large unassigned bucket
 * is the single most useful signal that INGEST_PATH_LAYOUT is misconfigured.
 */
@Component({
  selector: 'app-fleet-view',
  standalone: true,
  imports: [CommonModule, RouterModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="fleet">
      <div class="list-header">
        <h1>Fleet</h1>
        <span class="result-count" *ngIf="clusters.length">
          {{ clusters.length }} {{ clusters.length === 1 ? 'cluster' : 'clusters' }} ·
          {{ namespaceCount }} {{ namespaceCount === 1 ? 'namespace' : 'namespaces' }}
        </span>
      </div>

      <div class="hint" *ngIf="!loading && onlyUnassigned">
        All SBOMs are unassigned. Set <code>CLUSTER_NAME</code> / <code>NAMESPACE</code> /
        <code>PROJECT</code>, per-bucket values in <code>S3_BUCKETS</code>, or
        <code>INGEST_PATH_LAYOUT</code> (e.g. <code>cluster/namespace/project</code>) and re-ingest.
      </div>

      <div class="columns">
        <div class="tree" *ngIf="!loading">
          <div class="cluster" *ngFor="let c of clusters; trackBy: trackByName">
            <button
              class="node cluster-node"
              [class.selected]="selected?.kind === 'cluster' && selected?.cluster === c.name"
              (click)="selectCluster(c)"
            >
              <span class="caret">{{ isExpanded(c) ? '▾' : '▸' }}</span>
              <span class="label">{{ c.name || '(unassigned)' }}</span>
              <span class="counts">
                {{ c.sbom_count | number }} SBOMs
                <span class="vulns" [class.has-vulns]="c.vuln_count > 0">{{ c.vuln_count | number }} vulns</span>
              </span>
            </button>

            <div class="namespaces" *ngIf="isExpanded(c)">
              <div class="namespace" *ngFor="let ns of c.namespaces; trackBy: trackByName">
                <button
                  class="node namespace-node"
                  [class.selected]="selected?.kind === 'namespace' && selected?.cluster === c.name && selected?.namespace === ns.name"
                  (click)="selectNamespace(c, ns)"
                >
                  <span class="label">{{ ns.name || '(unassigned)' }}</span>
                  <span class="counts">
                    {{ ns.sbom_count | number }} SBOMs
                    <span class="vulns" [class.has-vulns]="ns.vuln_count > 0">{{ ns.vuln_count | number }} vulns</span>
                  </span>
                </button>

                <div class="projects">
                  <a
                    class="node project-node"
                    *ngFor="let p of ns.projects; trackBy: trackByName"
                    [routerLink]="['/sboms']"
                    [queryParams]="{ search: p.name }"
                  >
                    <span class="label">{{ p.name || '(unassigned)' }}</span>
                    <span class="counts">
                      {{ p.sbom_count | number }} SBOMs
                      <span class="vulns" [class.has-vulns]="p.vuln_count > 0">{{ p.vuln_count | number }} vulns</span>
                    </span>
                  </a>
                </div>
              </div>
            </div>
          </div>

          <div class="empty-state" *ngIf="!clusters.length">
            No SBOMs ingested yet.
          </div>
        </div>

        <aside class="detail" *ngIf="stats">
          <h2>
            {{ selected?.kind === 'cluster' ? 'Cluster' : 'Namespace' }}:
            {{ selectedLabel }}
          </h2>
          <p class="scope" *ngIf="selected?.kind === 'namespace'">
            in cluster {{ selected?.cluster || '(unassigned)' }}
          </p>

          <dl class="stats">
            <div><dt>SBOMs</dt><dd>{{ stats.total_sboms | number }}</dd></div>
            <div><dt>Packages</dt><dd>{{ stats.total_packages | number }}</dd></div>
            <div><dt>Vulnerabilities</dt><dd>{{ stats.total_vulnerabilities | number }}</dd></div>
            <div><dt class="sev critical">Critical</dt><dd>{{ stats.critical_vulns | number }}</dd></div>
            <div><dt class="sev high">High</dt><dd>{{ stats.high_vulns | number }}</dd></div>
            <div><dt class="sev medium">Medium</dt><dd>{{ stats.medium_vulns | number }}</dd></div>
            <div><dt class="sev low">Low</dt><dd>{{ stats.low_vulns | number }}</dd></div>
          </dl>

          <h3>Licenses</h3>
          <dl class="stats">
            <div *ngFor="let entry of licenseEntries">
              <dt>{{ entry.key }}</dt><dd>{{ entry.value | number }}</dd>
            </div>
            <div *ngIf="!licenseEntries.length"><dt>—</dt><dd>no data</dd></div>
          </dl>

          <p class="ingested" *ngIf="stats.last_ingested">
            Last ingested {{ stats.last_ingested | date:'short' }}
          </p>
        </aside>
      </div>

      <div class="loading" *ngIf="loading">Loading fleet…</div>
    </div>
  `,
  styles: [`
    .fleet { padding: 24px; height: 100%; display: flex; flex-direction: column; }
    .list-header { display: flex; align-items: baseline; gap: 12px; margin-bottom: 12px; }
    h1 { margin: 0; font-size: 1.1rem; font-weight: 700; letter-spacing: -0.02em; }
    .result-count { font-size: 0.75rem; color: var(--text-muted); }

    .hint {
      font-size: 0.78rem; color: var(--text-secondary); background: var(--surface-alt);
      border: 1px solid var(--border); border-radius: 4px; padding: 10px 12px; margin-bottom: 12px;
    }
    .hint code { font-size: 0.74rem; }

    .columns { display: flex; gap: 20px; align-items: flex-start; flex: 1; min-height: 0; }
    .tree { flex: 1; min-width: 0; overflow: auto; }
    .detail {
      width: 280px; flex-shrink: 0; border: 1px solid var(--border);
      border-radius: 4px; padding: 14px; background: var(--surface);
    }
    .detail h2 { margin: 0; font-size: 0.9rem; }
    .detail h3 { margin: 16px 0 6px; font-size: 0.78rem; color: var(--text-muted); text-transform: uppercase; }
    .scope { margin: 2px 0 10px; font-size: 0.74rem; color: var(--text-muted); }

    .node {
      display: flex; align-items: center; gap: 8px; width: 100%;
      padding: 7px 10px; font-family: inherit; font-size: 0.82rem;
      background: none; border: none; border-bottom: 1px solid var(--border);
      color: inherit; cursor: pointer; text-align: left; text-decoration: none;
    }
    .node:hover { background: var(--surface-alt); }
    .node.selected { background: var(--surface-alt); box-shadow: inset 2px 0 0 var(--accent); }
    .cluster-node { font-weight: 700; }
    .namespace-node { padding-left: 28px; font-weight: 600; }
    .project-node { padding-left: 48px; color: var(--text-secondary); }
    .caret { width: 10px; color: var(--text-muted); }
    .label { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .counts { font-size: 0.74rem; color: var(--text-muted); display: flex; gap: 12px; }
    .vulns { width: 78px; text-align: right; }
    .has-vulns { color: var(--severity-critical); font-weight: 600; }

    .stats { margin: 0; font-size: 0.8rem; }
    .stats > div { display: flex; justify-content: space-between; padding: 3px 0; }
    .stats dt { color: var(--text-muted); margin: 0; }
    .stats dd { margin: 0; font-variant-numeric: tabular-nums; }
    .sev.critical { color: var(--severity-critical); }
    .sev.high { color: var(--severity-high); }
    .sev.medium { color: var(--severity-medium); }
    .sev.low { color: var(--severity-low); }
    .ingested { margin-top: 14px; font-size: 0.72rem; color: var(--text-muted); }

    .loading, .empty-state { padding: 32px; text-align: center; color: var(--text-muted); font-size: 0.85rem; }
  `],
})
export class FleetViewComponent implements OnInit {
  clusters: FleetCluster[] = [];
  loading = true;

  selected: { kind: 'cluster' | 'namespace'; cluster: string; namespace?: string } | null = null;
  stats: ClusterStats | NamespaceStats | null = null;

  private readonly expanded = new Set<string>();

  constructor(
    private readonly api: ApiService,
    private readonly cdr: ChangeDetectorRef,
  ) {}

  ngOnInit(): void {
    this.api.getFleet().subscribe((clusters) => {
      this.clusters = clusters;
      this.loading = false;
      // Open the first cluster so the page is never an empty shell.
      if (clusters.length) {
        this.selectCluster(clusters[0]);
      }
      this.cdr.markForCheck();
    });
  }

  get namespaceCount(): number {
    return this.clusters.reduce((sum, c) => sum + c.namespaces.length, 0);
  }

  /** True when nothing carries an ownership label — i.e. it is unconfigured. */
  get onlyUnassigned(): boolean {
    return this.clusters.length > 0 && this.clusters.every((c) => c.name === '');
  }

  get selectedLabel(): string {
    if (!this.selected) return '';
    const name = this.selected.kind === 'cluster' ? this.selected.cluster : this.selected.namespace ?? '';
    return name || '(unassigned)';
  }

  get licenseEntries(): { key: string; value: number }[] {
    const breakdown = this.stats?.license_breakdown ?? {};
    return Object.keys(breakdown).map((key) => ({ key, value: breakdown[key] }));
  }

  isExpanded(cluster: FleetCluster): boolean {
    return this.expanded.has(cluster.name);
  }

  selectCluster(cluster: FleetCluster): void {
    // Clicking the already-selected cluster collapses it; otherwise select+expand.
    if (this.selected?.kind === 'cluster' && this.selected.cluster === cluster.name) {
      this.toggle(cluster.name);
    } else {
      this.expanded.add(cluster.name);
    }
    this.selected = { kind: 'cluster', cluster: cluster.name };
    this.stats = null;
    this.api.getClusterStats(cluster.name).subscribe({
      next: (s) => { this.stats = s; this.cdr.markForCheck(); },
      // 404 just means the cluster has no SBOMs — not an error worth surfacing.
      error: () => { this.stats = null; this.cdr.markForCheck(); },
    });
  }

  selectNamespace(cluster: FleetCluster, ns: FleetNamespace): void {
    this.selected = { kind: 'namespace', cluster: cluster.name, namespace: ns.name };
    this.stats = null;
    // Scoped to the cluster: `payments` in prod-eu is a different team's
    // namespace than `payments` in staging, so the stats must not be merged.
    this.api.getNamespaceStats(ns.name, cluster.name).subscribe({
      next: (s) => { this.stats = s; this.cdr.markForCheck(); },
      error: () => { this.stats = null; this.cdr.markForCheck(); },
    });
  }

  trackByName(_index: number, item: { name: string }): string {
    return item.name;
  }

  private toggle(name: string): void {
    if (this.expanded.has(name)) {
      this.expanded.delete(name);
    } else {
      this.expanded.add(name);
    }
  }
}

