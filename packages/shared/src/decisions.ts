/** `DECISIONS.md` — append-only `### D<n> · YYYY-MM-DD · <title>` blocks (SPEC §4.6). */

import { escapeStructuralLines } from './md.ts';
import type { Decision } from './types.ts';

const HEAD = /^###\s+D(\d+)\s*·\s*(\d{4}-\d{2}-\d{2})\s*·\s*(.*)$/;

export function parseDecisions(text: string, repo: string): Decision[] {
  const out: Decision[] = [];
  let current: Decision | null = null;
  const push = (): void => {
    if (current) {
      current.body = current.body.trim();
      out.push(current);
    }
  };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '');
    const m = HEAD.exec(line);
    if (m) {
      push();
      current = { n: Number(m[1]), date: m[2] ?? '', title: (m[3] ?? '').trim(), body: '', repo };
      continue;
    }
    if (current) current.body += `${line}\n`;
  }
  push();
  return out;
}

export function serializeDecision(d: Decision): string {
  return `### D${d.n} · ${d.date} · ${d.title}\n${escapeStructuralLines(d.body.trim())}\n`;
}

export function nextDecisionNumber(existing: Decision[]): number {
  return existing.reduce((max, d) => Math.max(max, d.n), 0) + 1;
}

export function decisionLine(d: Decision): string {
  return `D${d.n} ${d.date} ${d.repo} · ${d.title}`;
}
