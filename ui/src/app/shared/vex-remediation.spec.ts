import { describe, expect, it } from 'vitest';
import { decidedAgo, firstActionStatementLine, vexDecidedAt, vexDecidedBy } from './vex-remediation';

describe('vex-remediation', () => {
  it('shows the first line of the action statement, trimmed', () => {
    expect(firstActionStatementLine('Upgrade to v2.0.1\nthen re-scan')).toBe('Upgrade to v2.0.1');
    expect(firstActionStatementLine('  padded  ')).toBe('padded');
    expect(firstActionStatementLine('')).toBe('');
  });

  it('truncates a long first line with an ellipsis', () => {
    const long = 'x'.repeat(150);
    const got = firstActionStatementLine(long);
    expect(got.length).toBe(118);
    expect(got.endsWith('…')).toBe(true);
  });

  it('prefers the author over the tooling for the decided-by', () => {
    expect(vexDecidedBy('Security Team', 'vexctl')).toBe('by Security Team');
    expect(vexDecidedBy('', 'vexctl')).toBe('by vexctl');
    expect(vexDecidedBy('', '')).toBe('');
    expect(vexDecidedBy(undefined, undefined)).toBe('');
  });

  it('derives the decided time: action statement timestamp, else statement timestamp', () => {
    expect(vexDecidedAt({ vex_action_statement_timestamp: '2026-05-15T02:00:00Z', vex_timestamp: '2026-05-10T00:00:00Z' })).toBe('2026-05-15T02:00:00Z');
    expect(vexDecidedAt({ vex_timestamp: '2026-05-10T00:00:00Z' })).toBe('2026-05-10T00:00:00Z');
    expect(vexDecidedAt({})).toBeUndefined();
  });

  it('formats relative ages from an RFC 3339 timestamp', () => {
    const now = Date.parse('2026-05-20T00:00:00Z');
    expect(decidedAgo('2026-05-15T00:00:00Z', now)).toBe('5 days ago');
    expect(decidedAgo('2026-05-19T00:00:00Z', now)).toBe('yesterday');
    expect(decidedAgo('2026-05-19T19:30:00Z', now)).toBe('4 hours ago');
    expect(decidedAgo('2026-05-19T22:30:00Z', now)).toBe('an hour ago'); // 90 minutes
    expect(decidedAgo('2026-05-19T23:59:00Z', now)).toBe('just now'); // 60 seconds
    expect(decidedAgo('2026-05-20T01:00:00Z', now)).toBe('just now');
  });

  it('returns an empty age for absent or malformed timestamps', () => {
    expect(decidedAgo(undefined)).toBe('');
    expect(decidedAgo('')).toBe('');
    expect(decidedAgo('not-a-timestamp')).toBe('');
  });
});
