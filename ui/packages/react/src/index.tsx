import {
  createElement,
  useLayoutEffect,
  useRef,
  type HTMLAttributes,
  type ReactElement,
} from 'react';
import type { ScopeBreakdown, Vulnerability } from '@bomhort/api-client';

/**
 * Binds every non-string prop as a DOM property each render, so objects and arrays
 * (chart segments, breakdowns) reach the Angular element without JSON attributes.
 */
function wrap<P extends object>(tag: string) {
  return function Wrapped(props: P & HTMLAttributes<HTMLElement>): ReactElement {
    const ref = useRef<HTMLElement>(null);
    const attrs: Record<string, unknown> = { ref };
    const objectProps: [string, unknown][] = [];
    for (const [key, value] of Object.entries(props)) {
      if (typeof value === 'string' || typeof value === 'number' || key === 'children') {
        attrs[key === 'className' ? 'class' : key] = value;
      } else if (!key.startsWith('on')) {
        objectProps.push([key, value]);
      }
    }
    useLayoutEffect(() => {
      const el = ref.current as unknown as (HTMLElement & Record<string, unknown>) | null;
      if (!el) return;
      for (const [key, value] of objectProps) el[key] = value;
    });
    // React does not bind `onX` to custom events. One stable listener per event name,
    // reading the latest handler from a ref, so re-renders never detach and miss an event.
    const handlers = useRef<Record<string, unknown>>({});
    handlers.current = props;
    const eventNames = Object.keys(props)
      .filter((k) => k.startsWith('on'))
      .join(',');
    useLayoutEffect(() => {
      const el = ref.current;
      if (!el || !eventNames) return;
      const pairs = eventNames
        .split(',')
        .map((k): [string, EventListener] => [
          k.slice(2).toLowerCase(),
          (e) => (handlers.current[k] as EventListener | undefined)?.(e),
        ]);
      for (const [name, fn] of pairs) el.addEventListener(name, fn);
      return () => {
        for (const [name, fn] of pairs) el.removeEventListener(name, fn);
      };
    }, [eventNames]);
    return createElement(tag, attrs);
  };
}

export interface ChartSegment {
  label: string;
  value: number;
  color: string;
}
export interface BarItem {
  label: string;
  value: number;
  color?: string;
}

export const DonutChart = wrap<{
  segments: ChartSegment[];
  centerLabel?: string;
  size?: number;
  strokeWidth?: number;
}>('bomhort-donut-chart');
export const BarChart = wrap<{ bars: BarItem[] }>('bomhort-bar-chart');
export const ScopeBadge = wrap<{ scope: string; depth?: number; size?: 'sm' | 'md' }>(
  'bomhort-scope-badge',
);
export const ScopeMatrix = wrap<{ breakdown?: ScopeBreakdown }>('bomhort-scope-matrix');
export const VulnAliases = wrap<{ vuln: Vulnerability; max?: number }>('bomhort-vuln-aliases');
/** Any BOMHort route (`/`, `/projects/:name`, `/sboms/:id`, `/vulnerabilities`, …). Give it a height. */
export const BomhortPage = wrap<{ route: string; onNavigate?: (e: CustomEvent<string>) => void }>(
  'bomhort-page',
);
