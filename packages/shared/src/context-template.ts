/** `CONTEXT.md` skeleton for a freshly registered repo (SPEC §4.6, ≤ 80 lines). */

export function contextTemplate(slug: string): string {
  return `# ${slug} — repo map

Max 80 lines. Updated by the orchestrator when the structure or commands change.

## Stack

- (language, framework, DB, runtime)

## Structure

- (where things are — folder → what it is responsible for)

## Commands

- dev:
- test:
- release:

## Contracts

- (key APIs/DTOs/events that other layers depend on)

## Pitfalls

- (what surprises people here — migration order, cache, env, index.lock…)

## Links

- (handoff notes, graph, docs)
`;
}

export function decisionsTemplate(slug: string): string {
  return `# ${slug} — decisions

Appended by \`ledger decide\`. Never rewrite old blocks.
`;
}
