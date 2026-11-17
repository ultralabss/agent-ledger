/**
 * Secret scanner for the hub's md writer (§6.2 → 422, the text is not stored).
 *
 * Threat model:
 *  - Actor: an agent or human who pastes text from a terminal, `.env`, a CI log
 *    or chat into an item/journal.
 *  - Protected: the md ledger, a git repo with a remote backup — whatever lands
 *    there stays in history forever.
 *  - Failure modes: (a) a secret passes as "plain text"; (b) a false positive
 *    blocks an ordinary record (git SHA, path, UUID) and people switch the scanner off.
 *  - Hence: concrete shapes aggressively, the entropy heuristic conservatively.
 *  - Functions never return or log the value itself, only the range and the rule.
 */

export type SecretFinding = { rule: string; start: number; end: number };

/** `group`: the finding is capture group N (needs the `d` flag), not the whole match. */
type Rule = { name: string; re: RegExp; group?: number; check?: (value: string) => boolean };

const KEY = '(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key)';
// Bounded whitespace, no lookbehind: `\s*` inside a lookbehind was quadratic on whitespace runs (F3A-1).
const SEP = '["\']?\\s{0,8}(?:=|:)\\s{0,8}';

/** Placeholders, not secrets. */
const PLACEHOLDER_RE =
  /^(?:<.*>|\{\{?.*\}?\}|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?|x{3,}|\*{3,}|\.{3,}|-{3,}|_{3,})$/i;
const PLACEHOLDER_WORD_RE =
  /^(?:redacted|redacted-value|changeme|change[_-]?me|your[_-].*|my[_-].*|example.*|sample.*|dummy.*|placeholder|todo|tbd|null|none|undefined|true|false|process\.env\..*|env\..*|os\.environ.*|some[_-]?secret|value|fill.*)$/i;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const HEX_RE = /^[0-9a-f]+$/i;
const DIGITS_RE = /^[0-9]+$/;

function isPlaceholder(v: string): boolean {
  return PLACEHOLDER_RE.test(v) || PLACEHOLDER_WORD_RE.test(v);
}

function classes(v: string): number {
  let n = 0;
  if (/[a-z]/.test(v)) n += 1;
  if (/[A-Z]/.test(v)) n += 1;
  if (/[0-9]/.test(v)) n += 1;
  if (/[^A-Za-z0-9]/.test(v)) n += 1;
  return n;
}

/** Shannon entropia v bitoch na znak. */
export function shannon(v: string): number {
  if (v.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of v) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / v.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Value after `key =` without quotes. It must look like a secret, not a word:
 * ≥ 3 character classes, or ≥ 2 classes at length ≥ 16. That lets `Passw0rd123`
 * through but not "token will be set later" or "password is in 1Password".
 */
function looksSecretish(v: string): boolean {
  if (isPlaceholder(v)) return false;
  if (DIGITS_RE.test(v)) return false; // Snowflake id, item numbers
  if (UUID_RE.test(v)) return false;
  if (/^https?:\/\//i.test(v)) return false;
  if (v.startsWith('/') || v.startsWith('./') || v.startsWith('~/')) return false; // path
  if (/^v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.]+)?$/.test(v)) return false; // semver
  if (/^\d{4}-\d{2}-\d{2}/.test(v)) return false; // ISO date
  const c = classes(v);
  if (c >= 3) return true;
  return c >= 2 && v.length >= 16;
}

/**
 * Entropy heuristic — deliberately narrow:
 *  - a candidate is a contiguous run of `[A-Za-z0-9+=_-]` of length ≥ 28 (no `/`
 *    or `.`, so paths, URLs, domains, versions and ISO dates never enter),
 *  - it must have lowercase + uppercase + a digit (kills hex SHAs, numeric ids,
 *    SCREAMING_CASE constants, plain words),
 *  - Shannon ≥ 4.1 bits/char (random base64url 32 B is ~4.4–4.7; long
 *    camelCase identifiers and natural-language words sit below 4.0).
 * The threshold is deliberately high: a false positive destroys trust in the
 * scanner more than one missed secret of an unusual shape.
 */
const GENERIC_RULE = 'high-entropy';
const ENTROPY_MIN_LEN = 28;
const ENTROPY_MIN_BITS = 4.1;

function looksHighEntropy(v: string): boolean {
  if (v.length < ENTROPY_MIN_LEN) return false;
  if (HEX_RE.test(v)) return false;
  if (DIGITS_RE.test(v)) return false;
  if (isPlaceholder(v)) return false;
  if (!(/[a-z]/.test(v) && /[A-Z]/.test(v) && /[0-9]/.test(v))) return false;
  return shannon(v) >= ENTROPY_MIN_BITS;
}

const RULES: Rule[] = [
  // — PEM first, so it covers the whole header block —
  { name: 'pem-private-key', re: /-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----/g },
  { name: 'stripe-key', re: /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b/g },
  { name: 'stripe-webhook-secret', re: /\bwhsec_[A-Za-z0-9]{16,}\b/g },
  { name: 'github-token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
  { name: 'github-pat', re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
  { name: 'slack-token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'aws-access-key-id', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { name: 'google-api-key', re: /\bAIza[0-9A-Za-z_-]{35,}/g },
  { name: 'anthropic-key', re: /\bsk-ant-[A-Za-z0-9_-]{16,}/g },
  { name: 'openai-key', re: /\bsk-proj-[A-Za-z0-9_-]{16,}/g },
  { name: 'openai-key', re: /\bsk-[A-Za-z0-9]{20,}\b/g },
  {
    name: 'jwt',
    re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g,
  },
  // scheme://user:pass@host — covers only the userinfo, not the whole URL
  {
    name: 'url-password',
    re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/?#@]+:[^\s:/?#@]{1,}@/gi,
    check: (v) => {
      const m = /:\/\/[^\s:/?#@]+:([^\s:/?#@]+)@$/.exec(v);
      return m !== null && !isPlaceholder(m[1]);
    },
  },
  {
    name: 'secret-assignment',
    re: new RegExp(`${KEY}${SEP}"([^"\\n]{8,})(?=")`, 'gid'),
    group: 1,
    check: (v) => !isPlaceholder(v.trim()),
  },
  {
    name: 'secret-assignment',
    re: new RegExp(`${KEY}${SEP}([^\\s"'\`;,)\\]}]{8,})`, 'gid'),
    group: 1,
    check: looksSecretish,
  },
  { name: GENERIC_RULE, re: /[A-Za-z0-9+=_-]{28,}/g, check: looksHighEntropy },
];

/**
 * Name of a merged finding. `high-entropy` is only a fallback — if the range is
 * also covered by a concrete rule, the concrete one stays in the name (stable `[REDACTED:...]`).
 */
function mergeRuleNames(a: string, b: string): string {
  const parts = [...a.split('+'), ...b.split('+')];
  const specific = [...new Set(parts.filter((p) => p !== GENERIC_RULE))];
  if (specific.length === 0) return GENERIC_RULE;
  return specific.join('+');
}

function merge(findings: SecretFinding[]): SecretFinding[] {
  const sorted = [...findings].sort((a, b) => a.start - b.start || b.end - a.end);
  const out: SecretFinding[] = [];
  for (const f of sorted) {
    const last = out[out.length - 1];
    if (last && f.start <= last.end) {
      last.end = Math.max(last.end, f.end);
      last.rule = mergeRuleNames(last.rule, f.rule);
      continue;
    }
    out.push({ ...f });
  }
  return out;
}

/**
 * Finds secrets in text. Overlapping findings are merged into one range; the
 * result is sorted and disjoint. Returns metadata only, never the value.
 */
export function scanSecrets(text: string): SecretFinding[] {
  if (typeof text !== 'string' || text.length === 0) return [];
  const raw: SecretFinding[] = [];
  for (const rule of RULES) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      let value = m[0];
      let start = m.index;
      if (rule.group !== undefined) {
        const idx = m.indices?.[rule.group];
        if (!idx) continue;
        start = idx[0];
        value = m[rule.group] ?? '';
      }
      if (value.length === 0) {
        re.lastIndex += 1;
        continue;
      }
      if (rule.check && !rule.check(value)) continue;
      raw.push({ rule: rule.name, start, end: start + value.length });
    }
  }
  return merge(raw);
}

/** Replaces findings with `[REDACTED:<rule>]`. */
export function redactSecrets(text: string): { text: string; findings: SecretFinding[] } {
  const findings = scanSecrets(text);
  if (findings.length === 0) return { text, findings };
  let out = '';
  let cursor = 0;
  for (const f of findings) {
    out += text.slice(cursor, f.start);
    out += `[REDACTED:${f.rule}]`;
    cursor = f.end;
  }
  out += text.slice(cursor);
  return { text: out, findings };
}
