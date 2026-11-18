/** `ledger sync init|join` (F3b B4b, docs/f3b-b4-plan.md §1.1-1.2, §2.2, §5, §6 T-B4-12/13). OFFLINE like `device`: no hub
 *  client, no spool drain; the hub must be stopped (the flows themselves refuse with `HUB_RUNNING`).
 *
 *  Threat model:
 *   - Actor: an agent or script with a shell that tries to enrol / join a ledger unattended (it cannot answer a prompt
 *     that reads the TTY), a hostile first-contact remote or `ssh-keyscan` answer whose text ends up on the terminal,
 *     a typo'd or hostile argv (`-oProxyCommand…`, `user:pw@host`, control characters).
 *   - Protected: the two trust anchors (host key fp, root key fp) are accepted only from a person who RETYPES the
 *     fingerprint on a terminal (or from the same fp given on the command line: `--host-fp` / `--root-fp`, mandatory
 *     without a terminal). One answer = one boolean; nothing is held (no device lock, no marker lock) while the
 *     prompt waits: the flows take their locks only inside short operations. No URL, git stderr or key material is
 *     ever printed: only fixed texts per `EnrolError.code`, sanitised host tokens and `SHA256:` fingerprints.
 *   - Failure modes: prompt injection (the fp shown is re-validated against `^SHA256:[A-Za-z0-9+/]{43}$` before it is
 *     printed; the answer is capped and compared exactly), a swallowed switch (`--normalize x` eats `x`: refused, not
 *     guessed), an unknown / repeated option (refused: a security flag silently ignored is worse than an error).
 *   - Stance: fail closed. Never reads `.git/config`, never reads the URL back out of anything. Test seams (`io.seams`)
 *     are an in-process parameter only, never filled from argv, env or a file.
 *   Exit: 0 ok · 2 conflict / precondition (hub running, not empty, remote state, waiting for the trusted device) ·
 *   4 invalid input or no terminal · 6 trust refusal (host / root fp, public remote, genesis / range / egress rule,
 *   revoked) · 7 remote or tool failure (unreachable, auth, fetch, push, ssh-keygen, git) · 1 internal. */

import { timingSafeEqual } from 'node:crypto';
import { safeOutput, labelSchema } from '@agent-ledger/shared';
import { EnrolError, enrolAbort, syncInit, syncJoin, syncJoinContinue, type EnrolIo, type EnrolSeams } from '@agent-ledger/hub/sync-enrol';
import type { Args } from './args.ts';
import { CliError, readEnvConfig } from './client.ts';

export interface EnrolCliIo {
  out: (line: string) => void;
  err: (line: string) => void;
  env: NodeJS.ProcessEnv;
  /** Whether stdin / stdout are terminals. Absent = not a TTY (tests, pipes). */
  tty?: { stdin: boolean; stdout: boolean };
  /** Interactive prompt (tests inject one; a real TTY gets readline). */
  ask?: (prompt: string) => Promise<string | null>;
  /** TEST seam only (in-process): hub probe, `ssh-keyscan`, local remotes. Never from argv / env. */
  seams?: EnrolSeams;
}

export const ENROL_USAGE = `  ledger sync init --remote <url> [--label <x>] [--normalize] [--host-fp <SHA256:…>] [--abort]
                                            first device: put this ledger on an EMPTY, private remote (hub stopped)
  ledger sync join <url> [--label <x>] [--host-fp <SHA256:…>] [--root-fp <SHA256:…>]
                                            another device: fetch + verify the ledger, print what to run on a trusted device
  ledger sync join --continue --add-commit <sha>     (required) finish after \`ledger device add\` ran on a trusted device
  ledger sync join --abort                  drop an interrupted enrolment (marker + sync.yml only)
  Without a terminal --host-fp (and --root-fp for join) are mandatory; with one you retype the fingerprint.`;

const FP_RE = /^SHA256:[A-Za-z0-9+/]{43}$/;
const SHA_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const MAX_URL_CHARS = 2048;
const MAX_ANSWER_CHARS = 80;

export const EXIT_OK = 0;
export const EXIT_INTERNAL = 1;
export const EXIT_CONFLICT = 2;
export const EXIT_INPUT = 4;
export const EXIT_TRUST = 6;
export const EXIT_REMOTE = 7;

const CONFLICT = new Set([
  'HUB_RUNNING', 'NOT_EMPTY', 'NOT_REPO', 'FORMAT', 'LOCAL_YML', 'DIRTY', 'INFLIGHT', 'ALREADY_ENROLLED', 'GIT_CONFIG',
  'REGISTRY_TRACKED', 'PINNED', 'REMOTE_SAME_AS_CODE', 'REMOTE_NOT_EMPTY', 'REMOTE_EMPTY', 'PUSH_REJECTED', 'MARKER_BUSY',
  'MARKER_MISSING', 'MARKER_STAGE', 'STATE_MISMATCH', 'STATE',
]);
const INPUT = new Set(['BAD_INPUT', 'URL']);
const TRUST = new Set(['REMOTE_PUBLIC', 'REMOTE_INCONCLUSIVE', 'HOSTKEY_REFUSED', 'ROOT_FP_REFUSED', 'ROOT_REVOKED', 'REVOKED', 'ADD_COMMIT', 'REMOTE_REWOUND', 'UNSAFE']);
const REMOTE = new Set(['REMOTE_UNREACHABLE', 'REMOTE_AUTH', 'HOSTKEY_FAILED', 'FETCH_FAILED', 'PUSH_FAILED', 'SSH_KEYGEN']);
const PREFIXED_RE = /^(GENESIS|RANGE|EGRESS|DEVICE|GIT):[A-Za-z0-9:_.-]{1,64}$/;

/** `EnrolError.code` -> (exit code, fixed one-line text). Never echoes anything but the code token. */
export function classify(err: EnrolError): { exit: number; text: string } {
  const code: string = err.code;
  const m = PREFIXED_RE.exec(code);
  if (m !== null) {
    const kind = m[1] as string;
    const exit = kind === 'GENESIS' || kind === 'RANGE' || kind === 'EGRESS' ? EXIT_TRUST : EXIT_REMOTE;
    return { exit, text: `refused (${code})` };
  }
  const exit = CONFLICT.has(code) ? EXIT_CONFLICT : INPUT.has(code) ? EXIT_INPUT : TRUST.has(code) ? EXIT_TRUST : REMOTE.has(code) ? EXIT_REMOTE : EXIT_INTERNAL;
  // `EnrolError.message` is a fixed text per code (never a URL, stderr or key); the code itself is re-checked.
  return { exit, text: /^[A-Z_]{3,24}$/.test(code) ? safeOutput(err.message, 200) : 'internal error' };
}

function fail(io: EnrolCliIo, message: string, code = EXIT_INPUT): number {
  io.err(`ledger: ${message}`);
  return code;
}

const usageFail = (io: EnrolCliIo, why: string): number => fail(io, `${why}\n${ENROL_USAGE}`);

/* ---------------- argv (docs §5) ---------------- */

interface Spec {
  valued: readonly string[];
  switches: readonly string[];
}

type Flags = Map<string, string>;

/** Strict flag reader: unknown / repeated / valueless-valued / valued-switch options are refused (never guessed).
 *  Returns the one-line reason on error: it never contains argv text. */
function readFlags(args: Args, spec: Spec): Flags | string {
  const out: Flags = new Map();
  const known = new Set<string>([...spec.valued, ...spec.switches, 'help']);
  for (const name of [...args.flags.keys(), ...args.bools]) if (!known.has(name)) return 'unknown option for this command';
  for (const name of spec.valued) {
    if (args.bools.has(name)) return 'an option is missing its value';
    const values = args.flags.get(name);
    if (values === undefined) continue;
    if (values.length !== 1 || values[0] === '' || values[0] === undefined) return 'an option was given twice or empty';
    out.set(name, values[0]);
  }
  for (const name of spec.switches) {
    const values = args.flags.get(name);
    if (values !== undefined) {
      // `--normalize x` is parsed as a value `x` (the parser only knows some switches): refuse, do not guess
      if (values.length !== 1 || (values[0] !== 'true' && values[0] !== '1')) return 'put switches (--normalize, --continue, --abort) after the arguments';
      out.set(name, 'true');
    } else if (args.bools.has(name)) {
      out.set(name, 'true');
    }
  }
  return out;
}

/** Everything a remote URL must satisfy BEFORE it touches the flows; the real grammar is `validateRemoteUrl` (ssh / scp
 *  only, no credentials), reached through the flow and mapped to the fixed `URL` refusal. */
function urlShapeOk(s: string): boolean {
  return s.length >= 1 && s.length <= MAX_URL_CHARS && /^[\x21-\x7e]+$/.test(s) && !s.startsWith('-');
}

function validFp(s: string | undefined): boolean {
  return s === undefined || FP_RE.test(s);
}

/* ---------------- the human channel ---------------- */

function sameText(a: string, b: string): boolean {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
}

const hasTty = (io: EnrolCliIo): boolean => io.tty?.stdin === true && io.tty.stdout === true;

const PROMPTS = {
  host: 'host key fingerprint offered by the remote server',
  root: 'root key fingerprint of the ledger you are joining',
} as const;

/** The ONLY human channel of the flows: needs a terminal on both ends, shows the fingerprint (re-validated, so a hostile
 *  `ssh-keyscan` answer cannot inject text) and makes the human RETYPE it. One answer = one boolean. Holds no lock: it
 *  only awaits the prompt. Any failure of the prompt = not confirmed. */
export function makeEnrolIo(io: EnrolCliIo, ask: () => Promise<(prompt: string) => Promise<string | null>>): EnrolIo {
  return {
    out: (line) => io.out(safeOutput(line, 1000)),
    async confirm(kind, fp) {
      if (kind !== 'host' && kind !== 'root') return false;
      if (!hasTty(io)) return false;
      if (typeof fp !== 'string' || !FP_RE.test(fp)) return false;
      try {
        const answer = await (await ask())(
          `${PROMPTS[kind]}:\n  ${fp}\ncompare it out of band, then retype it to trust it (anything else refuses): `,
        );
        return answer !== null && answer.length <= MAX_ANSWER_CHARS && sameText(answer.trim(), fp);
      } catch {
        return false;
      }
    },
  };
}

/* ---------------- command ---------------- */

export async function cmdSyncEnrol(args: Args, io: EnrolCliIo): Promise<number> {
  const sub = args.positional[1];
  if (sub !== 'init' && sub !== 'join') return usageFail(io, 'usage');
  // the flows pin a host key once and have no re-pin input: refuse loudly instead of ignoring the switch
  if (args.bools.has('repin') || args.flags.has('repin')) return fail(io, '--repin is not supported by this build: a different pinned host key is refused (HOSTKEY_REFUSED)');
  let ledgerDir: string;
  let hubPort: number;
  try {
    const cfg = readEnvConfig(io.env);
    ledgerDir = cfg.ledgerDir;
    hubPort = Number(new URL(cfg.baseUrl).port || '80');
  } catch (err) {
    if (err instanceof CliError) return fail(io, safeOutput(err.message, 200), err.exitCode);
    throw err;
  }

  let close: (() => void) | undefined;
  let cachedAsk: ((prompt: string) => Promise<string | null>) | undefined;
  const askOnce = async (): Promise<(prompt: string) => Promise<string | null>> => {
    if (cachedAsk !== undefined) return cachedAsk;
    if (io.ask !== undefined) {
      cachedAsk = io.ask;
    } else {
      const rl = await (await import('./tidy.ts')).makeReadlineAsk();
      close = rl.close;
      cachedAsk = rl.ask;
    }
    return cachedAsk;
  };

  try {
    return sub === 'init' ? await init(args, io, ledgerDir, hubPort, askOnce) : await join(args, io, ledgerDir, hubPort, askOnce);
  } catch (err) {
    if (err instanceof EnrolError) {
      const c = classify(err);
      return fail(io, c.text, c.exit);
    }
    // never the raw error: it could carry a path, a URL or git output
    return fail(io, 'internal error', EXIT_INTERNAL);
  } finally {
    close?.();
  }
}

type AskFactory = () => Promise<(prompt: string) => Promise<string | null>>;

async function abort(io: EnrolCliIo, ledgerDir: string): Promise<number> {
  const r = await enrolAbort(ledgerDir);
  io.out(r.aborted ? 'enrolment aborted: marker and sync.yml removed (keys, refs and commits are untouched)' : 'nothing to abort');
  return EXIT_OK;
}

async function init(args: Args, io: EnrolCliIo, ledgerDir: string, hubPort: number, ask: AskFactory): Promise<number> {
  const f = readFlags(args, { valued: ['remote', 'label', 'host-fp'], switches: ['normalize', 'abort'] });
  if (typeof f === 'string') return usageFail(io, f);
  if (args.positional.length > 2) return usageFail(io, 'unexpected argument');
  if (f.has('abort')) {
    if (f.size > 1) return usageFail(io, '--abort takes no other option');
    return abort(io, ledgerDir);
  }
  const remote = f.get('remote');
  const label = f.get('label');
  const hostFp = f.get('host-fp');
  if (remote === undefined || !urlShapeOk(remote)) return usageFail(io, 'usage: --remote <ssh url> is required (ssh / scp form, no credentials)');
  if (label !== undefined && !labelSchema.safeParse(label).success) return usageFail(io, 'label: lowercase letters, digits, - (max 32)');
  if (!validFp(hostFp)) return usageFail(io, '--host-fp must look like SHA256:<43 base64 characters>');
  if (hostFp === undefined && !hasTty(io)) return fail(io, 'without a terminal --host-fp <SHA256:…> is mandatory: a human must confirm the host key');
  await syncInit(
    {
      ledgerDir,
      hubPort,
      remote,
      ...(label !== undefined ? { label } : {}),
      ...(hostFp !== undefined ? { hostFp } : {}),
      ...(f.has('normalize') ? { normalize: true } : {}),
      ...(io.seams !== undefined ? { seams: io.seams } : {}),
    },
    makeEnrolIo(io, ask),
  );
  // the flow already printed id, root fingerprint and the next step through `EnrolIo.out`
  return EXIT_OK;
}

async function join(args: Args, io: EnrolCliIo, ledgerDir: string, hubPort: number, ask: AskFactory): Promise<number> {
  const f = readFlags(args, { valued: ['label', 'host-fp', 'root-fp', 'add-commit'], switches: ['continue', 'abort'] });
  if (typeof f === 'string') return usageFail(io, f);
  if (f.has('abort')) {
    if (f.size > 1 || args.positional.length > 2) return usageFail(io, '--abort takes no other option');
    return abort(io, ledgerDir);
  }
  if (f.has('continue')) {
    if (f.size > 1 + (f.has('add-commit') ? 1 : 0) || args.positional.length > 2) return usageFail(io, '--continue takes only --add-commit <sha> (required)');
    const addCommit = f.get('add-commit');
    if (addCommit === undefined) return usageFail(io, '--continue requires --add-commit <sha>: the commit printed by `ledger device add` on the trusted device');
    if (!SHA_RE.test(addCommit)) return usageFail(io, '--add-commit must be a full commit id');
    const r = await syncJoinContinue(
      { ledgerDir, hubPort, addCommit, ...(io.seams !== undefined ? { seams: io.seams } : {}) },
      makeEnrolIo(io, ask),
    );
    if (r.status === 'waiting') return fail(io, 'waiting for `ledger device add` on a trusted device (the enrolment is kept; re-run `ledger sync join --continue --add-commit <sha>`)', EXIT_CONFLICT);
    return EXIT_OK;
  }
  if (f.has('add-commit')) return usageFail(io, '--add-commit only goes with --continue');
  const remote = args.positional[2];
  if (args.positional.length !== 3 || remote === undefined || !urlShapeOk(remote)) return usageFail(io, 'usage: ledger sync join <ssh url> (scp / ssh form, no credentials)');
  const label = f.get('label');
  const hostFp = f.get('host-fp');
  const rootFp = f.get('root-fp');
  if (label !== undefined && !labelSchema.safeParse(label).success) return usageFail(io, 'label: lowercase letters, digits, - (max 32)');
  if (!validFp(hostFp) || !validFp(rootFp)) return usageFail(io, '--host-fp / --root-fp must look like SHA256:<43 base64 characters>');
  if ((hostFp === undefined || rootFp === undefined) && !hasTty(io)) {
    return fail(io, 'without a terminal --host-fp and --root-fp (<SHA256:…>) are mandatory: a human must confirm the host key and the root key');
  }
  await syncJoin(
    {
      ledgerDir,
      hubPort,
      remote,
      ...(label !== undefined ? { label } : {}),
      ...(hostFp !== undefined ? { hostFp } : {}),
      ...(rootFp !== undefined ? { rootFp } : {}),
      ...(io.seams !== undefined ? { seams: io.seams } : {}),
    },
    makeEnrolIo(io, ask),
  );
  return EXIT_OK;
}
