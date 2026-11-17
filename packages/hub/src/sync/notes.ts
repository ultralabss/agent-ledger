/** SyncNote / ingress rejections -> journal lines + inbox messages (F3b B2, note
 *  mapping paragraph of docs/f3b-plan.md §2.3). Pure: no clock, no fs, no db.
 *
 *  Every text that reaches a journal line or an inbox body is attacker-influenced
 *  (paths, session names, free `detail` built from peer data). `cleanText` removes
 *  C0/C1/ESC, ANSI sequences, bidi + zero-width + tag characters, lone surrogates and
 *  newlines, then caps the length; inbox bodies are additionally narrowed to
 *  `untrustedSnippet`'s charset and framed. No content excerpts leave this module
 *  except `SyncNote.detail` (itself capped); `sync.secret` never carries `detail`
 *  (rule + path only, F3A-6).
 *
 *  Mapping:
 *   sync.conflict | sync.decision-conflict | sync.context-conflict -> journal `sync.conflict`
 *   sync.claim-lost -> journal `sync.conflict` (field claim-lost, the "Log line"); if the
 *                      note's `device` is the local device and the session id is sane ->
 *                      inbox message (origin hub) + lease release request
 *   sync.reject, ingress rejection (any rule but secret) -> journal `sync.reject`
 *   sync.secret, ingress rule `secret` -> journal `sync.secret`
 *   sync.unverified / sync.warning -> journal of the same name
 */

import {
  frameUntrusted,
  isItemId,
  journalLine,
  safeOutput,
  untrustedSnippet,
} from '@agent-ledger/shared';
import { cmpStr, stampOf } from './merge/common.ts';
import type { SyncNote } from './merge/types.ts';

export const NOTE_CAPS = { detail: 200, path: 120, field: 40, journalLines: 100, inbox: 20 } as const;

const NO_TAGS = /[\u{E0000}-\u{E007F}]/gu;
const NO_FORMAT = /[︀-️\u{E0100}-\u{E01EF}͏ᅟᅠ឴឵ㅤﾠ]/gu;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g;
const TOKEN_RE = /^[a-z0-9][a-z0-9:_.-]{0,39}$/;
const SLUG_RE = /^[a-z0-9-]{1,100}$/;
const SESSION_RE = /^[A-Za-z0-9._:-]{1,64}$/;
const DEVICE_RE = /^d_[a-z2-7]{10}$/;

/** One line, no control / bidi / invisible characters, at most `max` characters. */
export function cleanText(value: unknown, max: number = NOTE_CAPS.detail): string {
  const raw = typeof value === 'string' ? value : '';
  const stripped = raw.replace(LONE_SURROGATE, '').replace(NO_TAGS, '').replace(NO_FORMAT, '');
  return safeOutput(stripped, max);
}

const token = (v: unknown): string => (typeof v === 'string' && TOKEN_RE.test(v) ? v : 'unknown');

export interface IngressRejectionLike {
  path: string;
  rule: string;
}

export interface JournalOut {
  /** Repo slug whose journal gets the line; `null` = not about one repo (caller picks / skips). */
  repo: string | null;
  line: string;
}

export interface InboxOut {
  to_session: string;
  repo: string | null;
  item_id: string | null;
  body: string;
  origin: 'hub';
}

export interface NotePlan {
  journal: JournalOut[];
  inbox: InboxOut[];
  /** Local sessions whose claim was lost: the caller releases the local lease. */
  releaseLeases: { item: string; session: string }[];
}

export interface MapNotesInput {
  notes: readonly SyncNote[];
  rejections?: readonly IngressRejectionLike[];
  /** ISO time for the journal stamp (caller's deterministic choice, e.g. the merged `updated`). */
  at: string;
  /** This device's id, to recognise our own lost claims. */
  localDevice: string;
}

type Ev = 'sync.conflict' | 'sync.reject' | 'sync.secret' | 'sync.unverified' | 'sync.warning';

function eventOf(n: SyncNote): Ev {
  switch (n.type) {
    case 'sync.reject':
    case 'sync.secret':
    case 'sync.unverified':
    case 'sync.warning':
      return n.type;
    case 'sync.conflict':
    case 'sync.decision-conflict':
    case 'sync.context-conflict':
    case 'sync.claim-lost':
      return 'sync.conflict';
    default:
      return 'sync.warning'; // unknown future type: visible, harmless
  }
}

export function mapNotes(input: MapNotesInput): NotePlan {
  const stampAt = stampOf(typeof input.at === 'string' ? input.at : '');
  const journal: JournalOut[] = [];
  const inbox: InboxOut[] = [];
  const releases: { item: string; session: string }[] = [];
  const seenLines = new Set<string>();
  let suppressed = 0;

  const push = (repo: string | null, type: Ev, fields: string[]): void => {
    const line = journalLine({ at: stampAt, session: 'sync', type, fields });
    const key = `${repo ?? ''}\u0000${line}`;
    if (seenLines.has(key)) return;
    seenLines.add(key);
    if (journal.length >= NOTE_CAPS.journalLines) {
      suppressed += 1;
      return;
    }
    journal.push({ repo, line });
  };

  const repoOf = (n: SyncNote): string | null => (typeof n.repo === 'string' && SLUG_RE.test(n.repo) ? n.repo : null);
  const itemOf = (n: SyncNote): string | null => (isItemId(n.item) ? n.item : null);

  // Hostile shapes: keep only plain objects and only string-typed members (no getters run twice, no toString).
  const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
  const safeNote = (n: unknown): SyncNote | null => {
    if (n === null || typeof n !== 'object') return null;
    try {
      const o = n as Record<string, unknown>;
      const out: Record<string, unknown> = { type: str(o.type) ?? 'unknown', detail: str(o.detail) ?? '' };
      for (const k of ['item', 'field', 'device', 'session', 'repo', 'path', 'rule'] as const) {
        const v = str(o[k]);
        if (v !== undefined) out[k] = v;
      }
      return out as unknown as SyncNote;
    } catch {
      return null;
    }
  };
  const safeNotes = (Array.isArray(input.notes) ? input.notes : []).map(safeNote).filter((n): n is SyncNote => n !== null);

  const sorted = safeNotes.sort(
    (a, b) =>
      cmpStr(a.type, b.type) || cmpStr(a.repo ?? '', b.repo ?? '') || cmpStr(a.item ?? '', b.item ?? '') ||
      cmpStr(a.path ?? '', b.path ?? '') || cmpStr(a.rule ?? '', b.rule ?? '') || cmpStr(a.detail ?? '', b.detail ?? ''),
  );

  for (const n of sorted) {
    const ev = eventOf(n);
    const item = itemOf(n);
    const fields: string[] = [];
    if (item !== null) fields.push(item);
    // F3A-6: a secret note carries rule + path only (no field, no free text).
    if (n.type === 'sync.claim-lost') fields.push('claim-lost');
    else if (ev !== 'sync.secret' && typeof n.field === 'string') fields.push(`field=${cleanText(n.field, NOTE_CAPS.field)}`);
    if (typeof n.rule === 'string') fields.push(`rule=${token(n.rule)}`);
    if (typeof n.path === 'string') fields.push(`path=${cleanText(n.path, NOTE_CAPS.path)}`);
    if (typeof n.device === 'string' && DEVICE_RE.test(n.device)) fields.push(`device=${n.device}`);
    // F3A-6: a secret note never carries free text.
    fields.push(ev === 'sync.secret' ? 'secret scanner hit' : cleanText(n.detail));
    push(repoOf(n), ev, fields);

    if (
      n.type === 'sync.claim-lost' &&
      n.device === input.localDevice &&
      item !== null &&
      typeof n.session === 'string' &&
      SESSION_RE.test(n.session) &&
      inbox.length < NOTE_CAPS.inbox
    ) {
      const detail = untrustedSnippet(cleanText(n.detail, NOTE_CAPS.detail), 120);
      inbox.push({
        to_session: n.session,
        repo: repoOf(n),
        item_id: item,
        body: `Your claim on ${item} was not kept by a sync merge. ${frameUntrusted(detail)}`,
        origin: 'hub',
      });
      releases.push({ item, session: n.session });
    }
  }

  const rej = (Array.isArray(input.rejections) ? input.rejections : [])
    .filter((r) => r !== null && typeof r === 'object')
    .map((r) => ({ rule: str((r as Record<string, unknown>).rule) ?? '', path: str((r as Record<string, unknown>).path) ?? '' }))
    .sort((a, b) => cmpStr(a.rule, b.rule) || cmpStr(a.path, b.path));
  for (const r of rej) {
    const rule = token(r.rule);
    const path = cleanText(r.path, NOTE_CAPS.path);
    if (rule === 'secret') push(null, 'sync.secret', [`rule=secret`, `path=${path}`]);
    else push(null, 'sync.reject', [`rule=${rule}`, `path=${path}`]);
  }

  if (suppressed > 0) {
    journal.push({
      repo: null,
      line: journalLine({ at: stampAt, session: 'sync', type: 'sync.warning', fields: [`${suppressed} more sync notes suppressed`] }),
    });
  }
  return { journal, inbox, releaseLeases: releases };
}
