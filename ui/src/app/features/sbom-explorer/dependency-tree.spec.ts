import { describe, it, expect } from 'vitest';
import type { DependencyNode, DependencyScope } from '../../core/api.models';
import { buildTree, defaultExpanded, visibleRows, SEARCH_ROW_LIMIT } from './dependency-tree';

function node(index: number, name: string, children: number[], scope: DependencyScope = 'transitive'): DependencyNode {
  return {
    index, spdx_id: `SPDXRef-${name}`, name, version: '1.0.0',
    purl: `pkg:npm/${name}@1.0.0`, license: 'MIT', children, dependency_scope: scope,
  };
}

/** app → (express, lodash); express → (lodash, debug); debug → ms; ms → debug (cycle); orphan unconnected. */
function sample(): DependencyNode[] {
  return [
    node(0, 'app', [1, 2], 'root'),
    node(1, 'express', [2, 3], 'direct'),
    node(2, 'lodash', [], 'direct'),
    node(3, 'debug', [4]),
    node(4, 'ms', [3]),
    node(5, 'orphan', [], 'unknown'),
  ];
}

const names = (rows: { index: number }[], nodes = sample()) => rows.map((r) => nodes[r.index].name);
const nodeName = (index: number) => sample()[index].name;

describe('buildTree', () => {
  it('starts at the product and lists unreachable packages separately', () => {
    const tree = buildTree(sample());
    expect(tree.roots).toEqual([0]);
    expect(tree.detached).toEqual([5]);
    expect(tree.hasEdges).toBe(true);
  });

  it('uses the direct dependencies when the product is not a package (CycloneDX)', () => {
    const nodes = sample().slice(1).map((n) => ({ ...n }));
    const tree = buildTree(nodes);
    expect(tree.roots).toEqual([1, 2]);
    expect(tree.detached).toEqual([5]);
    expect(defaultExpanded(tree).size).toBe(0);
  });

  it('falls back to the packages nothing depends on', () => {
    const nodes = [node(0, 'a', [1], 'unknown'), node(1, 'b', [], 'unknown'), node(2, 'c', [], 'unknown')];
    const tree = buildTree(nodes);
    expect(tree.roots).toEqual([0]);
    expect(tree.detached).toEqual([2]);
  });

  it('reports an SBOM without relationships', () => {
    const tree = buildTree([node(0, 'a', [], 'unknown'), node(1, 'b', [], 'unknown')]);
    expect(tree.hasEdges).toBe(false);
    expect(tree.detached).toEqual([0, 1]);
  });
});

describe('visibleRows', () => {
  it('shows the product expanded and everything below it collapsed', () => {
    const tree = buildTree(sample());
    const { rows } = visibleRows(tree, defaultExpanded(tree));
    expect(names(rows)).toEqual(['app', 'express', 'lodash', 'orphan']);
    expect(rows.map((r) => r.level)).toEqual([0, 1, 1, 0]);
    expect(rows[0].expanded).toBe(true);
    expect(rows[1]).toMatchObject({ hasChildren: true, expanded: false, key: '0/1' });
    expect(rows[2].hasChildren).toBe(false);
    expect(rows[3]).toMatchObject({ detached: true, level: 0 });
  });

  it('numbers every row among its siblings (aria-posinset / aria-setsize)', () => {
    const tree = buildTree(sample());
    const { rows } = visibleRows(tree, new Set(['0', '0/1']));
    // app and the unconnected orphan form the top level; express has two
    // children, app has two.
    expect(rows.map((r) => [nodeName(r.index), r.posInSet, r.setSize])).toEqual([
      ['app', 1, 2], ['express', 1, 2], ['lodash', 1, 2], ['debug', 2, 2], ['lodash', 2, 2], ['orphan', 2, 2],
    ]);
    // In a search only the siblings that are shown count.
    const searched = visibleRows(tree, new Set(), 'ms').rows;
    expect(searched.map((r) => [r.posInSet, r.setSize])).toEqual([[1, 1], [1, 1], [1, 1], [1, 1]]);
  });

  it('shows a shared package under every parent and marks a cycle instead of looping', () => {
    const tree = buildTree(sample());
    const expanded = new Set(['0', '0/1', '0/1/3', '0/1/3/4']);
    const { rows } = visibleRows(tree, expanded);
    expect(names(rows)).toEqual(['app', 'express', 'lodash', 'debug', 'ms', 'debug', 'lodash', 'orphan']);
    const cycle = rows[5];
    expect(cycle).toMatchObject({ cycle: true, hasChildren: false, expanded: false, level: 4 });
  });

  it('expands the path to every match when searching', () => {
    const tree = buildTree(sample());
    const { rows, truncated } = visibleRows(tree, new Set(), 'MS');
    expect(names(rows)).toEqual(['app', 'express', 'debug', 'ms']);
    expect(rows.filter((r) => r.match).map((r) => r.index)).toEqual([4]);
    expect(rows.slice(0, 3).every((r) => r.expanded)).toBe(true);
    expect(truncated).toBe(false);
  });

  it('finds matches among the unreachable packages and by purl', () => {
    const tree = buildTree(sample());
    expect(names(visibleRows(tree, new Set(), 'orph').rows)).toEqual(['orphan']);
    expect(names(visibleRows(tree, new Set(), 'pkg:npm/lodash').rows)).toEqual(['app', 'express', 'lodash', 'lodash']);
    expect(visibleRows(tree, new Set(), 'nothing-like-this').rows).toEqual([]);
  });

  it('cuts a search off when shared packages multiply the paths', () => {
    // A ladder of diamonds: every level doubles the number of paths to the
    // bottom package, 2^14 in total.
    const nodes: DependencyNode[] = [node(0, 'root', [1, 2], 'root')];
    for (let level = 0; level < 14; level++) {
      const a = 1 + level * 2;
      const next = level === 13 ? [29] : [a + 2, a + 3];
      nodes.push(node(a, `a${level}`, next), node(a + 1, `b${level}`, next));
    }
    nodes.push(node(29, 'needle', []));
    const { rows, truncated } = visibleRows(buildTree(nodes), new Set(), 'needle');
    expect(truncated).toBe(true);
    expect(rows.length).toBe(SEARCH_ROW_LIMIT);
  });
});
