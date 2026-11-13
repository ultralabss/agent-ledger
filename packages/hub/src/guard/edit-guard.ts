/**
 * PreToolUse guard for Edit|Write|MultiEdit|NotebookEdit — SPEC §10.3.
 *
 * The rule order in `evaluate()` is the spec's order and nothing else: the first
 * rule that matches wins, and each rule is a separate `if` on purpose so the
 * order is readable in one screen. Rules 3–5 all *deny*, and they deny for
 * different reasons — collapsing them into one condition would produce a reason
 * text that tells the agent the wrong next command, which is the only thing
 * that makes a guard worse than no guard.
 *
 * Every deny reason carries: the held path, the owning session's
 * 4-char handle, its item id, how long ago it was active, and the exact command
 * to run next. That is the whole interface an agent has to this guard.
 */

import { shortSession } from '@agent-ledger/shared';
import type { GuardRule, SessionView, TouchedView } from '@agent-ledger/shared';
import { STALE_OWNER_MS, type LeaseRow, type RuntimeStore, type TouchedRow } from '../db/store.ts';
import type { Ledger } from '../ledger/ledger.ts';
import { realpathOrParent, sessionLabel, type ResolvedPath, type Sessions } from '../sessions.ts';
import { isExcludedPath, isLedgerContextFile, matchAny, toPosix } from './globs.ts';
import type { GuardSwitch } from './switch.ts';

export interface EditGuardDeps {
  ledger: Ledger;
  store: RuntimeStore;
  sessions: Sessions;
  guard: GuardSwitch;
  /** False in tests whose repos live under `tmpdir()`. */
  excludeTemp?: boolean;
  /**
   * `LEDGER_INTRUDE` (config). When false the cross-repo lease protocol does
   * not exist: no lease can be taken (no auto-lease either) and deny hints say
   * the protocol is disabled. Default false, like the config flag.
   */
  intrude?: boolean;
  now?: () => number;
}

export interface EditGuardResult {
  decision: 'allow' | 'deny';
  rule: GuardRule;
  reason: string | null;
  /** Rule 6: allowed, but the agent is told about the future merge conflict. */
  warning: string | null;
  /** Rule 5b: the lease the hub took on the session's behalf. */
  autoLease: { id: string; repo: string; checkout: string; rel_path: string } | null;
}

const ALLOW: EditGuardResult = {
  decision: 'allow',
  rule: 'allow',
  reason: null,
  warning: null,
  autoLease: null,
};

function allow(rule: GuardRule, warning: string | null = null): EditGuardResult {
  return { ...ALLOW, rule, warning };
}

/** A lock only denies while an editor write of a session that is still
 *  working stands behind it. Everything weaker informs and lets the edit through. */
type Holder = { session: SessionView; row: TouchedRow; stale: boolean };

function deny(rule: GuardRule, reason: string): EditGuardResult {
  return { decision: 'deny', rule, reason, warning: null, autoLease: null };
}

export class EditGuard {
  private readonly deps: EditGuardDeps;
  /**
   * A non-blocking note is said once per (session, path, kind) —
   * repeated on every edit it becomes noise the agent learns to skip. Bounded;
   * the oldest half is dropped when it grows, so a long session cannot leak.
   */
  private notes = new Set<string>();

  constructor(deps: EditGuardDeps) {
    this.deps = deps;
  }

  private once(key: string): boolean {
    if (this.notes.has(key)) return false;
    if (this.notes.size > 2_000) this.notes = new Set([...this.notes].slice(1_000));
    this.notes.add(key);
    return true;
  }

  private now(): number {
    return (this.deps.now ?? Date.now)();
  }

  /**
   * One path, one decision. `session` is the agent session id; a subagent
   * shares it with its parent, which is correct here — a subagent's edit belongs
   * to the session that spawned it.
   */
  async evaluate(input: { session: string; absPath: string }): Promise<EditGuardResult> {
    if (!this.deps.guard.enabled) return allow('guard-off');

    const raw = input.absPath;
    if (typeof raw !== 'string' || raw.trim() === '') return ALLOW;

    /* ---- 1. the ledger is changed through `ledger`, never by an editor ---- */
    const ledgerRoot = this.deps.ledger.paths.root;
    // S1: raw AND realpath. A symlink inside a registered repo pointed at the
    // ledger (`ln -s <ledger> repo/l`) has a raw path outside the ledger but a
    // realpath inside it; checking raw alone let rule 2 fail to resolve it (the
    // ledger is not a registered repo) and fall through to `allow('no-repo')`,
    // writing straight into the ledger.
    // `ledgerRoot` itself is not realpathed (it is config, not attacker input),
    // so it needs its own realpath to compare against `real` — `mkdtemp()` on
    // macOS returns `/var/folders/…`, whose realpath is `/private/var/folders/…`;
    // comparing raw `ledgerRoot` against a realpathed `real` would always miss.
    const ledgerRootReal = (await realpathOrParent(ledgerRoot)) ?? ledgerRoot;
    const real = await realpathOrParent(raw);
    const rawUnderLedger = isUnder(raw, ledgerRoot);
    const realUnderLedger = real !== null && isUnder(real, ledgerRootReal);
    const rawIsContext = rawUnderLedger && isLedgerContextFile(raw, ledgerRoot);
    const realIsContext = realUnderLedger && isLedgerContextFile(real as string, ledgerRootReal);
    if ((rawUnderLedger || realUnderLedger) && !rawIsContext && !realIsContext) {
      return deny(
        'ledger',
        `The ledger is changed through \`ledger\`, not by an editor (${relTo(ledgerRoot, raw)}). ` +
          'Item: `ledger add` / `ledger note <ID>` · decision: `ledger decide` · ' +
          'summary: `ledger log`. You may edit only `<repo>/CONTEXT.md`.',
      );
    }

    /* ---- 2. outside every registered git repo → not ours to police ---- */
    const resolved = await this.deps.sessions.resolvePath(raw);
    if (resolved === null || resolved.rel_path === '') return allow('no-repo');
    if (
      isExcludedPath(resolved.abs, {
        ledgerRoot,
        excludeTemp: this.deps.excludeTemp ?? true,
      })
    ) {
      return allow('no-repo');
    }

    const now = this.now();
    const intrude = this.deps.intrude ?? false;
    const checkout = resolved.layout.checkout;
    const rel = toPosix(resolved.rel_path);
    const self = this.deps.store.getSession(input.session);
    // An override the user authorised in chat lifts rules 3 and 4 for this path
    // (SPEC §15: the guard stops accidents, not deliberate action).
    const overridden = this.hasLease(input.session, checkout, rel, 'override');

    // Non-blocking notes collected on the way down; emitted with the final
    // allow so a warning never short-circuits a later deny (rules 4, 5).
    const notes: string[] = [];
    let rule: GuardRule = 'allow';

    /* ---- 3. held by another live session in this same checkout ---- */
    if (!overridden) {
      const holder = this.holderOf(checkout, rel, input.session, now);
      if (holder !== null && !holder.stale) {
        return deny('held-by-session', this.heldReason(holder, resolved, rel));
      }
      if (holder !== null) {
        /* Owner idle > 2 h — a stale lock, not live work. */
        rule = 'stale-owner';
        notes.push(
          `\`${rel}\` is held by ${sessionLabel(holder.session)} (${liveness(holder.session)}) — ` +
            'the lock is stale, letting you through. If you are taking it over, transfer ownership: ' +
            `\`ledger adopt ${resolved.abs}\`.`,
        );
      }
      const weak = this.weakOwnerOf(checkout, rel, input.session, now);
      if (weak !== null && rule === 'allow') {
        rule = 'weak-owner';
        if (this.once(`weak|${input.session}|${checkout}|${rel}`)) {
          notes.push(
            `\`${rel}\` is recorded as ${weak.row.via === 'ambiguous' ? 'ambiguous' : 'a change from Bash'} ` +
              `(${shortSession(weak.row.session_id)}) — not a certain owner, not blocking. ` +
              `If you overlap: \`ledger who ${resolved.repo}\`.`,
          );
        }
      }
      /* A claim glob is intent, not a lock — warn once, never deny. */
      const claim = this.claimOf(checkout, rel, input.session, now);
      if (claim !== null && this.once(`claim|${input.session}|${checkout}|${rel}`)) {
        if (rule === 'allow') rule = 'claim-note';
        notes.push(
          `\`${rel}\` is in the claim of ${shortSession(claim.lease.session_id)} on \`${claim.pattern}\`` +
            `${claim.lease.item_id ? ` (${claim.lease.item_id})` : ''} — coordinate: ` +
            `\`ledger who ${resolved.repo}\`.`,
        );
      }
    }

    /* ---- 4. orphan: uncommitted work of a session that ended ---- */
    if (!overridden) {
      const orphan = this.orphanOf(checkout, rel, now);
      if (orphan !== null && orphan.via === 'edit') {
        const item = this.itemsOfSession(orphan.session);
        return deny(
          'orphan',
          `Uncommitted change from the ended session ${shortSession(orphan.session)}` +
            `${item.length > 0 ? ` (${item.join(', ')})` : ''} in \`${rel}\`. ` +
            `Take over: \`ledger adopt ${resolved.abs}\`. ` +
            'If it was a manual change by the user, ask once (§11).',
        );
      }
      if (orphan !== null && this.once(`orphan|${input.session}|${checkout}|${rel}`)) {
        if (rule === 'allow') rule = 'weak-owner';
        notes.push(
          `\`${rel}\` was in progress in the ended session ${shortSession(orphan.session)}, ` +
            `but only by ${orphan.via === 'ambiguous' ? 'an ambiguous' : 'a Bash'} guess — not blocking.`,
        );
      }
    }

    /* ---- 5. a repo that is not this session's home repo ---- */
    const home = self?.home_repo ?? null;
    if (home !== null && resolved.repo !== home) {
      const hasIntrude = intrude && this.hasLease(input.session, checkout, rel, 'intrude');
      if (!hasIntrude) {
        const others = this.liveOthers(resolved.repo, input.session, now);
        if (others.length > 0) {
          /* 5a */
          return deny(
            'foreign-repo',
            intrude
              ? this.foreignReason(resolved, rel, others)
              : this.foreignDisabledReason(resolved, rel, others),
          );
        }
        if (!intrude) {
          /* Protocol disabled: no lease can exist, so a foreign repo stays denied. */
          return deny('foreign-repo', this.foreignDisabledReason(resolved, rel, []));
        }
        /* 5b — nobody home in `r`: take the lease ourselves and let it through */
        const lease = this.autoLease(input.session, resolved, rel, now);
        return {
          decision: 'allow',
          rule: 'auto-lease',
          reason: null,
          warning:
            `Auto-lease in another repo ${resolved.repo} (nobody is active there): ${rel}. ` +
            `Commit right away: \`git -C ${resolved.layout.checkout} commit --only -- ${rel}\` ` +
            'with a `Refs: <ID>` trailer, then `ledger intrude end`.',
          autoLease: lease,
        };
      }
    }

    /* ---- 6. same relative path live in another worktree of this repo ---- */
    const twin = this.otherWorktree(resolved.repo, checkout, rel, input.session, now);
    if (twin !== null) {
      notes.push(
        `The same file ${rel} is in progress by ${shortSession(twin.session)} in another worktree ` +
          `(${twin.checkout}) — this will conflict on merge. Coordinate: \`ledger who ${resolved.repo}\`.`,
      );
      if (rule === 'allow') rule = 'other-worktree';
    }

    /* ---- 7 ---- */
    if (notes.length > 0) return allow(rule, notes.join(' · '));
    return ALLOW;
  }

  /* ---------------- rule helpers ---------------- */

  /**
   * Rule 3: the only thing that denies is an **editor write** (`via:
   * edit`) of another session that is still live. `bash`/`ambiguous` rows and
   * claim globs are handled separately and never deny.
   */
  private holderOf(checkout: string, rel: string, self: string, now: number): Holder | null {
    for (const row of this.deps.store.ownersOfPath(checkout, rel)) {
      if (row.session_id === self) continue;
      if (row.via !== 'edit') continue;
      const view = this.liveView(row.session_id, now);
      if (view !== null) return { session: view, row, stale: view.idle_ms > STALE_OWNER_MS };
    }
    return null;
  }

  /** An inferred owner — informative only. */
  private weakOwnerOf(
    checkout: string,
    rel: string,
    self: string,
    now: number,
  ): { session: SessionView; row: TouchedRow } | null {
    for (const row of this.deps.store.ownersOfPath(checkout, rel)) {
      if (row.session_id === self) continue;
      if (row.via === 'edit') continue;
      const view = this.liveView(row.session_id, now);
      if (view !== null) return { session: view, row };
    }
    return null;
  }

  /** A live claim glob covering the path, for the coordination note. */
  private claimOf(
    checkout: string,
    rel: string,
    self: string,
    now: number,
  ): { lease: LeaseRow; pattern: string } | null {
    for (const lease of this.deps.store.listLeases({ active: true })) {
      if (lease.session_id === self) continue;
      if (lease.kind !== 'claim') continue;
      if (lease.checkout !== null && lease.checkout !== checkout) continue;
      const pattern = matchAny(leasePaths(lease), rel);
      if (pattern === null) continue;
      if (this.liveView(lease.session_id, now) === null) continue;
      return { lease, pattern };
    }
    return null;
  }

  /** Rule 4: the path is uncommitted work of a session that is no longer live. */
  private orphanOf(checkout: string, rel: string, now: number): TouchedView | null {
    for (const row of this.deps.store.ownersOfPath(checkout, rel)) {
      const view = this.liveView(row.session_id, now);
      if (view === null) return this.deps.sessions.touchedView(row, now);
    }
    return null;
  }

  /** Rule 6: a live session holds the same rel path in a different checkout. */
  private otherWorktree(
    repo: string,
    checkout: string,
    rel: string,
    self: string,
    now: number,
  ): { session: string; checkout: string } | null {
    for (const row of this.deps.store.listTouched({ repo })) {
      if (row.checkout === checkout) continue;
      if (row.rel_path !== rel) continue;
      if (row.session_id === self) continue;
      if (this.liveView(row.session_id, now) === null) continue;
      return { session: row.session_id, checkout: row.checkout };
    }
    return null;
  }

  /** Live sessions in `repo` other than `self`, freshest first, capped for the
   *  reason text (a 30-session repo would produce an unreadable deny). */
  private liveOthers(repo: string, self: string, now: number): SessionView[] {
    void now; // `list()` computes liveness against its own clock
    return this.deps.sessions
      .list({ repo, liveOnly: true })
      .filter((s) => s.id !== self)
      .sort((a, b) => a.idle_ms - b.idle_ms)
      .slice(0, 4);
  }

  private liveView(id: string, now: number): SessionView | null {
    const row = this.deps.store.getSession(id);
    if (row === null) return null;
    const view = this.deps.sessions.view(row, now);
    return view.liveness === 'ended' ? null : view;
  }

  private hasLease(session: string, checkout: string, rel: string, kind: LeaseRow['kind']): boolean {
    for (const lease of this.deps.store.listLeases({ session, active: true })) {
      if (lease.kind !== kind) continue;
      if (lease.checkout !== null && lease.checkout !== checkout) continue;
      if (matchAny(leasePaths(lease), rel) !== null) return true;
    }
    return false;
  }

  /** Rule 5b. Extends an existing auto-lease instead of piling up rows. */
  private autoLease(
    session: string,
    resolved: ResolvedPath,
    rel: string,
    now: number,
  ): { id: string; repo: string; checkout: string; rel_path: string } {
    const checkout = resolved.layout.checkout;
    const existing = this.deps.store
      .listLeases({ session, repo: resolved.repo, active: true })
      .find((l) => l.kind === 'intrude' && (l.checkout === null || l.checkout === checkout));
    if (existing) {
      const paths = leasePaths(existing);
      if (!paths.includes(rel)) this.deps.store.setLeasePaths(existing.id, [...paths, rel]);
      return { id: existing.id, repo: resolved.repo, checkout, rel_path: rel };
    }
    const id = this.deps.store.addLease({
      session_id: session,
      repo: resolved.repo,
      checkout,
      kind: 'intrude',
      item_id: null,
      paths: [rel],
      intent: 'auto-lease: no live session in the repo',
      now,
    });
    return { id, repo: resolved.repo, checkout, rel_path: rel };
  }

  /* ---------------- reason texts ---------------- */

  private heldReason(holder: Holder, resolved: ResolvedPath, rel: string): string {
    const s = holder.session;
    const items = s.items.length > 0 ? s.items : this.itemsOfSession(s.id);
    const title = items.length > 0 ? this.titleOf(items[0] as string) : null;
    const label = items.length > 0 ? `${items.join(',')}${title ? ` "${title}"` : ''}` : 'no item';
    const how = 'uncommitted change from Edit/Write';
    return (
      `File \`${rel}\` is held by ${sessionLabel(s)} (${label}, ${liveness(s)}) — ${how}. ` +
      `Coordinate: \`ledger who ${resolved.repo}\`. ` +
      `Override only on the user's explicit instruction: \`ledger override ${resolved.abs} --reason "<why>"\`.`
    );
  }

  private foreignReason(resolved: ResolvedPath, rel: string, others: SessionView[]): string {
    const who = others
      .map((s) => {
        const items = s.items.length > 0 ? s.items.join(',') : 'no item';
        return `${s.short} (${items}, ${liveness(s)})`;
      })
      .join(' · ');
    return (
      `\`${rel}\` is in another repo ${resolved.repo}, where ${who} is active. ` +
      `Protocol §11: 1) \`ledger who ${resolved.repo}\` 2) if you overlap, change nothing — ` +
      `\`ledger add --repo ${resolved.repo} --requested-by <your ID> --owner agent "…"\` and \`ledger block <your ID> --by <new>\` ` +
      `3) if clear: \`ledger intrude begin --repo ${resolved.repo} --item <your ID> --paths "${rel}"\`, ` +
      `then Edit/Write, \`git -C ${resolved.layout.checkout} commit --only -- ${rel}\`, \`ledger intrude commit <sha>\`, \`ledger intrude end\`.`
    );
  }

  /** Same deny when the intrude protocol is switched off (`LEDGER_INTRUDE` unset). */
  private foreignDisabledReason(resolved: ResolvedPath, rel: string, others: SessionView[]): string {
    const who =
      others.length > 0
        ? `, where ${others
            .map((s) => `${s.short} (${s.items.length > 0 ? s.items.join(',') : 'no item'}, ${liveness(s)})`)
            .join(' · ')} is active`
        : '';
    return (
      `\`${rel}\` is in another repo ${resolved.repo}${who}, which is not this session's repo. ` +
      'The cross-repo `intrude` protocol is disabled (set LEDGER_INTRUDE=1 to enable it). ' +
      `Coordinate instead: \`ledger add --repo ${resolved.repo} --requested-by <your ID> --owner agent "…"\` ` +
      'and \`ledger block <your ID> --by <new>\`.'
    );
  }

  private itemsOfSession(session: string): string[] {
    const out = new Set<string>();
    for (const lease of this.deps.store.listLeases({ session, active: true })) {
      if (lease.kind === 'claim' && lease.item_id) out.add(lease.item_id);
    }
    for (const item of this.deps.ledger.listItems()) {
      if (item.fm.status === 'doing' && item.fm.claimed_by?.session === session) out.add(item.fm.id);
    }
    return [...out].sort();
  }

  private titleOf(id: string): string | null {
    for (const item of this.deps.ledger.listItems()) {
      if (item.fm.id === id) {
        const t = item.fm.title.trim();
        return t.length > 44 ? `${t.slice(0, 43)}…` : t;
      }
    }
    return null;
  }
}

/* ---------------- small helpers ---------------- */

export function leasePaths(lease: { paths: string }): string[] {
  try {
    const parsed: unknown = JSON.parse(lease.paths);
    return Array.isArray(parsed) ? parsed.filter((p): p is string => typeof p === 'string') : [];
  } catch {
    return [];
  }
}

function liveness(s: SessionView): string {
  const mins = Math.round(s.idle_ms / 60_000);
  const state = s.liveness === 'active' ? 'active' : 'idle';
  if (mins <= 0) return `${state} just now`;
  if (mins < 60) return `${state} ${mins} min ago`;
  return `${state} ${Math.round(mins / 60)} h ago`;
}

function isUnder(abs: string, root: string): boolean {
  const a = toPosix(abs);
  const r = toPosix(root);
  return a === r || a.startsWith(r.endsWith('/') ? r : `${r}/`);
}

function relTo(root: string, abs: string): string {
  const a = toPosix(abs);
  const r = toPosix(root).replace(/\/$/, '');
  return a.startsWith(`${r}/`) ? a.slice(r.length + 1) : a;
}
