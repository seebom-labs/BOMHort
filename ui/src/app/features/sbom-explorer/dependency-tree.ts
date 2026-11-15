import type { DependencyNode, DependencyScope } from '../../core/api.models';

/**
 * Dependency tree view (#56).
 *
 * The API returns the dependency graph as nodes with parent→child index
 * references (`children`). A package can have several parents and the graph
 * can contain cycles, so the tree is drawn per *path*: a shared package shows
 * up under every parent, and its children are only produced when that
 * occurrence is expanded. A node that is already on its own path is a cycle
 * and is not expandable.
 *
 * The tree starts at the product the SBOM describes (`dependency_scope` =
 * root). CycloneDX keeps the product outside the component list, so there the
 * product's direct dependencies are the top level. Without either, the
 * packages nothing depends on are used. Packages the tree does not reach are
 * listed after it rather than dropped.
 */

export interface DependencyTree {
  /** Nodes by their `index`. */
  readonly byIndex: ReadonlyMap<number, DependencyNode>;
  readonly roots: readonly number[];
  /** Packages not reachable from the roots, in index order. */
  readonly detached: readonly number[];
  /** False when the SBOM carries no dependency relationships at all. */
  readonly hasEdges: boolean;
}

export interface TreeRow {
  index: number;
  /** 0 for a top-level package. */
  level: number;
  /** Identifies this occurrence: the index path from the top, e.g. "0/3/7". */
  key: string;
  hasChildren: boolean;
  expanded: boolean;
  /** The package is already on the path above it. */
  cycle: boolean;
  /** Not reachable from the top level of the tree. */
  detached: boolean;
  /** Matches the search term. */
  match: boolean;
}

export interface TreeRows {
  rows: TreeRow[];
  /** The search produced more rows than `limit`; the rest were left out. */
  truncated: boolean;
}

/** Rows a search may produce before the rest is cut off. */
export const SEARCH_ROW_LIMIT = 2000;

export function buildTree(nodes: readonly DependencyNode[]): DependencyTree {
  const byIndex = new Map<number, DependencyNode>();
  for (const n of nodes) byIndex.set(n.index, n);

  const hasParent = new Set<number>();
  let hasEdges = false;
  for (const n of nodes) {
    for (const c of n.children ?? []) {
      if (byIndex.has(c) && c !== n.index) {
        hasParent.add(c);
        hasEdges = true;
      }
    }
  }

  let roots = nodes.filter((n) => n.dependency_scope === 'root').map((n) => n.index);
  if (!roots.length) roots = nodes.filter((n) => n.dependency_scope === 'direct').map((n) => n.index);
  if (!roots.length) {
    roots = nodes.filter((n) => !hasParent.has(n.index) && (n.children ?? []).length > 0).map((n) => n.index);
  }

  const reached = new Set<number>();
  const stack = [...roots];
  while (stack.length) {
    const i = stack.pop()!;
    if (reached.has(i)) continue;
    reached.add(i);
    for (const c of childrenOf(byIndex, i)) stack.push(c);
  }
  const detached = nodes.map((n) => n.index).filter((i) => !reached.has(i)).sort((a, b) => a - b);

  return { byIndex, roots, detached, hasEdges };
}

/** The keys expanded when the tree is first shown: the product, if there is one. */
export function defaultExpanded(tree: DependencyTree): Set<string> {
  return new Set(
    tree.roots
      .filter((i) => tree.byIndex.get(i)?.dependency_scope === 'root')
      .map((i) => String(i)),
  );
}

/**
 * The rows to render: every top-level package, and below each expanded
 * occurrence its children. With a search term, only the paths that lead to a
 * matching package are shown, expanded down to the match; `expanded` is
 * ignored then.
 */
export function visibleRows(tree: DependencyTree, expanded: ReadonlySet<string>, query = ''): TreeRows {
  const q = query.trim().toLowerCase();
  const leadsToMatch = q ? matchingAncestors(tree, q) : null;
  const rows: TreeRow[] = [];
  let truncated = false;

  // Iterative depth-first walk; `path` holds the indices above the current
  // occurrence so a cycle is recognised on the spot.
  type Frame = { index: number; level: number; key: string; path: ReadonlySet<number>; detached: boolean };
  const walk = (top: readonly number[], detached: boolean, prefix: string) => {
    const stack: Frame[] = [...top]
      .reverse()
      .map((i) => ({ index: i, level: 0, key: prefix + i, path: new Set<number>(), detached }));
    while (stack.length) {
      const f = stack.pop()!;
      if (leadsToMatch && !leadsToMatch.has(f.index)) continue;
      if (leadsToMatch && rows.length >= SEARCH_ROW_LIMIT) {
        truncated = true;
        return;
      }
      const node = tree.byIndex.get(f.index);
      if (!node) continue;
      const cycle = f.path.has(f.index);
      const children = cycle ? [] : childrenOf(tree.byIndex, f.index);
      const path = new Set(f.path).add(f.index);
      // A search opens a node only towards children that lead to a match and
      // are not already on the path: a cycle adds no new way to a match.
      const shown = leadsToMatch ? children.filter((c) => leadsToMatch.has(c) && !path.has(c)) : children;
      const open = !cycle && shown.length > 0 && (leadsToMatch ? true : expanded.has(f.key));
      rows.push({
        index: f.index,
        level: f.level,
        key: f.key,
        hasChildren: children.length > 0,
        expanded: open,
        cycle,
        detached: f.detached,
        match: !!q && matches(node, q),
      });
      if (!open) continue;
      for (let k = shown.length - 1; k >= 0; k--) {
        stack.push({ index: shown[k], level: f.level + 1, key: `${f.key}/${shown[k]}`, path, detached: f.detached });
      }
    }
  };

  walk(tree.roots, false, '');
  if (!truncated) walk(tree.detached, true, 'd:');
  return { rows, truncated };
}

/** Case-insensitive match on name, version or purl; `q` is lower-case. */
export function matches(node: DependencyNode, q: string): boolean {
  return (
    node.name.toLowerCase().includes(q) ||
    (node.version ?? '').toLowerCase().includes(q) ||
    (node.purl ?? '').toLowerCase().includes(q)
  );
}

/**
 * Every package from which a matching package can be reached, the matches
 * included: one walk over the reversed edges, so shared packages and cycles
 * cost nothing extra.
 */
function matchingAncestors(tree: DependencyTree, q: string): Set<number> {
  const parents = new Map<number, number[]>();
  const found: number[] = [];
  for (const node of tree.byIndex.values()) {
    if (matches(node, q)) found.push(node.index);
    for (const c of childrenOf(tree.byIndex, node.index)) {
      const list = parents.get(c);
      if (list) list.push(node.index);
      else parents.set(c, [node.index]);
    }
  }
  const out = new Set<number>();
  const stack = found;
  while (stack.length) {
    const i = stack.pop()!;
    if (out.has(i)) continue;
    out.add(i);
    for (const p of parents.get(i) ?? []) stack.push(p);
  }
  return out;
}

function childrenOf(byIndex: ReadonlyMap<number, DependencyNode>, index: number): number[] {
  return (byIndex.get(index)?.children ?? []).filter((c) => c !== index && byIndex.has(c));
}

/** A package as the Dependencies tab shows it; built by the SBOM detail page. */
export interface FlatDep {
  name: string;
  version: string;
  license: string;
  licenseTitle: string;
  purl: string;
  level: number;
  index: number;
  scope: DependencyScope;
  depth?: number;
}
