// Remediation record formatting for the vulnerability register (#413).
//
// A register row must show "what is being done, decided when, by whom"
// inline: the first line of the winning VEX statement's action statement,
// the time that statement was issued (action_statement_timestamp, falling
// back to the statement's own timestamp for legacy rows) and the author or
// tooling that issued it. The full text stays in the row tooltip and the
// SBOM's VEX tab.

/** First line of the action statement, trimmed; long lines get an ellipsis. */
export function firstActionStatementLine(statement: string): string {
  const line = statement.split('\n', 1)[0].trim();
  return line.length > 120 ? line.slice(0, 117) + '…' : line;
}

/** "by <author|tooling>" for the statement's provenance; '' when neither is set. */
export function vexDecidedBy(author?: string, tooling?: string): string {
  const who = author || tooling || '';
  return who ? `by ${who}` : '';
}

/** The time the action statement was decided: the OpenVEX
 *  action_statement_timestamp when the statement carries one, else the
 *  statement's own timestamp (legacy rows have no action timestamp). */
export function vexDecidedAt(item: { vex_action_statement_timestamp?: string; vex_timestamp?: string }): string | undefined {
  return item.vex_action_statement_timestamp || item.vex_timestamp || undefined;
}

/** Relative age of an RFC 3339 timestamp ("5 days ago"); '' when absent or
 *  unparseable. A timestamp in the future reads as "just now". */
export function decidedAgo(timestamp?: string, now: number = Date.now()): string {
  if (!timestamp) return '';
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) return '';
  const diff = now - t;
  if (diff <= 0) return 'just now';
  const days = Math.floor(diff / 86_400_000);
  if (days >= 1) return days === 1 ? 'yesterday' : `${days} days ago`;
  const hours = Math.floor(diff / 3_600_000);
  if (hours >= 1) return hours === 1 ? 'an hour ago' : `${hours} hours ago`;
  return 'just now';
}
