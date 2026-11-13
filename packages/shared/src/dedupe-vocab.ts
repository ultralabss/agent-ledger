/**
 * Synonym vocabulary + light English stemming for near-duplicate detection.
 *
 * Agents and humans phrase the same work differently. Token-set similarity
 * therefore scored low on pairs that are obviously the same work: "Add Google
 * login" / "Implement Google sign-in" share a single token.
 *
 * Two cheap, synchronous layers fix that, both applied *before* the token sets
 * meet each other in {@link ../dedupe.ts}:
 *
 *  1. a hand-written **vocabulary** that maps the synonyms and inflections of
 *     a developer term onto one canonical token
 *     (`implement`/`create`/`adding` → `add`), and
 *  2. a conservative **English stemmer** for everything the vocabulary does
 *     not know, so `indexes`/`indexed`/`index` collapse without 300 more rows.
 *
 * No embeddings, no language detection, no async. The vocabulary is biased
 * towards the words that actually occur in a ledger (auth, deploy, DB,
 * billing, infra), not towards general English.
 *
 * The third export here is the part that keeps the layers honest:
 * {@link ANTONYM_GROUPS}. Canonicalisation makes titles *more* similar, which
 * is exactly how "DB backup" and "Restore DB from backup" become a false
 * positive — they differ only in the one word that carries the whole meaning.
 * Mutually exclusive canonical tokens are grouped, and a pair that disagrees
 * inside a group can never reach the duplicate threshold.
 */

/**
 * `[canonical, ...surface forms]`. Surface forms are written the way
 * `normalizeTitle` leaves them: lowercase ASCII, no diacritics. The canonical
 * token does not have to appear among the surfaces — it is added automatically.
 *
 * Rows are single words only; multi-word idioms live in {@link PHRASES}.
 */
const VOCAB_ROWS: readonly (readonly string[])[] = [
  // ---- actions ----
  ['add', 'adds', 'added', 'adding', 'append', 'implement', 'implements',
    'implemented', 'implementing', 'implementation', 'introduce', 'create',
    'creates', 'created', 'creating', 'creation'],
  ['fix', 'fixes', 'fixed', 'fixing', 'repair', 'repairs', 'repaired',
    'bugfix', 'hotfix', 'resolve', 'resolves', 'resolved'],
  ['bug', 'bugs', 'defect', 'defects', 'error', 'errors', 'failure',
    'failures', 'fail', 'fails', 'failed', 'failing', 'glitch'],
  ['crash', 'crashes', 'crashed', 'crashing', 'panic', 'segfault'],
  ['deploy', 'deploys', 'deployed', 'deploying', 'deployment', 'deployments',
    'rollout', 'release', 'releases', 'released', 'releasing', 'ship',
    'ships', 'shipped', 'shipping'],
  ['verify', 'verifies', 'verified', 'verifying', 'verification', 'check',
    'checks', 'checked', 'checking', 'validate', 'validates', 'validated',
    'validation', 'confirm', 'confirmed', 'confirmation'],
  ['remove', 'removes', 'removed', 'removing', 'removal', 'delete', 'deletes',
    'deleted', 'deleting', 'deletion', 'erase', 'purge', 'cancel', 'cancels',
    'cancelled', 'canceled', 'cancellation', 'drop', 'discard'],
  ['new', 'newer', 'newly', 'fresh'],
  ['old', 'older', 'legacy', 'stale', 'outdated', 'deprecated', 'obsolete'],
  ['change', 'changes', 'changed', 'changing', 'modify', 'modifies',
    'modified', 'edit', 'edits', 'edited', 'editing', 'alter', 'adjust',
    'tweak'],
  ['update', 'updates', 'updated', 'updating', 'upgrade', 'upgrades',
    'upgraded', 'bump'],
  ['move', 'moves', 'moved', 'moving', 'relocate', 'relocation', 'transfer'],
  ['rename', 'renames', 'renamed', 'renaming'],
  ['refactor', 'refactors', 'refactored', 'refactoring', 'rewrite',
    'rewriting', 'restructure'],
  ['start', 'starts', 'started', 'starting', 'startup', 'launch', 'launches',
    'boot', 'begin'],
  ['stop', 'stops', 'stopped', 'stopping', 'halt', 'shutdown', 'terminate'],
  ['enable', 'enables', 'enabled', 'enabling', 'activate'],
  ['disable', 'disables', 'disabled', 'disabling', 'deactivate'],
  ['open', 'opens', 'opened', 'opening'],
  ['close', 'closes', 'closed', 'closing', 'shut'],
  ['show', 'shows', 'shown', 'showing', 'display', 'displays', 'displayed'],
  ['hide', 'hides', 'hidden', 'hiding', 'conceal'],
  ['import', 'imports', 'imported', 'importing', 'ingest'],
  ['export', 'exports', 'exported', 'exporting'],
  ['upload', 'uploads', 'uploaded', 'uploading'],
  ['download', 'downloads', 'downloaded', 'downloading'],
  ['lock', 'locks', 'locked', 'locking', 'lockout'],
  ['unlock', 'unlocks', 'unlocked', 'unlocking'],
  ['grant', 'grants', 'granted', 'granting'],
  ['revoke', 'revokes', 'revoked', 'revoking', 'revocation', 'withdraw'],
  ['increase', 'increases', 'increased', 'increasing', 'raise', 'raises',
    'raised', 'boost', 'expand'],
  ['decrease', 'decreases', 'decreased', 'decreasing', 'reduce', 'reduces',
    'reduced', 'lower', 'shrink'],
  ['measure', 'measures', 'measured', 'measuring', 'measurement', 'benchmark',
    'benchmarks'],
  ['decide', 'decides', 'decided', 'decision', 'decisions'],
  ['support', 'supports', 'supported', 'supporting'],
  ['cleanup', 'clean', 'cleans', 'cleaned', 'cleaning', 'tidy', 'prune'],
  ['sync', 'syncs', 'synced', 'syncing', 'synchronize', 'synchronise',
    'synchronized', 'synchronization', 'synchronisation'],
  ['retry', 'retries', 'retried', 'retrying', 'replay', 'replays', 'reattempt'],
  ['search', 'searches', 'searched', 'searching', 'find', 'lookup'],
  ['filter', 'filters', 'filtered', 'filtering'],
  ['sort', 'sorts', 'sorted', 'sorting'],

  // ---- auth / security ----
  // Multi-word spellings ("sign in", "log out") are rewritten by PHRASES.
  ['login', 'logins', 'signin', 'logon'],
  ['logout', 'logouts', 'signout', 'logoff'],
  ['signup', 'signups', 'register', 'registers', 'registered', 'registering',
    'registration', 'enroll', 'enrollment'],
  ['password', 'passwords', 'passwd', 'passphrase', 'pwd'],
  ['user', 'users', 'account', 'accounts'],
  ['token', 'tokens'],
  ['rotation', 'rotations', 'rotate', 'rotates', 'rotated', 'rotating'],
  ['session', 'sessions'],
  ['permission', 'permissions', 'privilege', 'privileges', 'authorization',
    'authorisation', 'authz', 'scope', 'scopes', 'rbac', 'acl'],
  ['auth', 'authentication', 'authenticate', 'authenticated', 'authn'],
  ['secret', 'secrets', 'credential', 'credentials', 'creds'],
  ['key', 'keys', 'keypair'],
  ['encrypt', 'encrypts', 'encrypted', 'encrypting', 'encryption', 'cipher'],
  ['decrypt', 'decrypts', 'decrypted', 'decrypting', 'decryption'],
  ['hash', 'hashes', 'hashed', 'hashing'],
  ['mfa', '2fa', 'multifactor'],
  ['otp', 'totp', 'hotp'],
  ['passkey', 'passkeys', 'webauthn', 'fido'],
  ['oauth', 'oidc', 'sso'],
  ['security', 'secure', 'secured', 'securing', 'harden', 'hardening'],
  ['audit', 'audits', 'audited', 'auditing'],
  ['allowlist', 'whitelist'],
  ['denylist', 'blocklist', 'blacklist'],
  ['csrf'],
  ['cors'],
  ['csp'],

  // ---- data / DB ----
  ['migration', 'migrations', 'migrate', 'migrates', 'migrated', 'migrating'],
  ['backup', 'backups', 'dump', 'dumps'],
  ['restore', 'restores', 'restored', 'restoring', 'recover', 'recovery',
    'revert', 'reverts', 'reverted', 'rollback', 'rollbacks'],
  ['database', 'databases', 'db', 'dbs', 'postgres', 'postgresql',
    'datastore'],
  ['index', 'indexes', 'indices', 'indexing', 'indexed'],
  ['query', 'queries', 'queried', 'querying'],
  ['transaction', 'transactions', 'txn'],
  ['column', 'columns'],
  ['field', 'fields'],
  ['schema', 'schemas'],
  ['pagination', 'paginate', 'paginated', 'paging', 'cursor', 'cursors'],
  ['cache', 'caches', 'cached', 'caching'],
  ['queue', 'queues', 'queued', 'queuing', 'queueing'],

  // ---- platform / infra ----
  ['production', 'prod', 'live'],
  ['dev', 'development'],
  ['staging', 'stage', 'preprod'],
  ['env', 'environment', 'environments', 'envs'],
  ['version', 'versions', 'versioning', 'versioned', 'semver'],
  ['server', 'servers', 'backend', 'backends'],
  ['web', 'website', 'frontend'],
  ['mobile', 'phone', 'phones', 'smartphone'],
  ['build', 'builds', 'built', 'building', 'compile', 'compiles', 'compiled',
    'compiling', 'compilation'],
  ['test', 'tests', 'tested', 'testing'],
  ['lint', 'lints', 'linter', 'linting', 'eslint'],
  ['docs', 'doc', 'documentation', 'documented', 'readme'],
  ['log', 'logs', 'logged', 'logging'],
  ['config', 'configs', 'configuration', 'configurations', 'configure',
    'configured', 'configuring', 'setting', 'settings'],
  ['domain', 'domains', 'host', 'hosts', 'hostname', 'hostnames'],
  ['certificate', 'certificates', 'cert', 'certs', 'tls', 'ssl'],
  ['dns', 'zone', 'zones', 'nameserver'],
  ['docker', 'container', 'containers', 'dockerfile'],
  ['performance', 'perf', 'speed', 'latency', 'slow', 'slowness',
    'optimize', 'optimise', 'optimized', 'optimization', 'optimisation'],
  ['memory', 'ram', 'heap'],
  ['disk', 'disks', 'storage', 'filesystem'],
  ['network', 'networks', 'networking'],
  ['timeout', 'timeouts'],
  ['throttle', 'throttles', 'throttled', 'throttling', 'ratelimit'],
  ['limit', 'limits', 'limited', 'cap', 'ceiling', 'quota', 'quotas'],
  ['worker', 'workers', 'daemon'],
  ['cron', 'crons', 'cronjob', 'scheduler', 'schedulers', 'scheduled',
    'schedule', 'schedules', 'scheduling'],
  ['webhook', 'webhooks', 'callback', 'callbacks'],
  ['endpoint', 'endpoints', 'route', 'routes'],
  ['api'],
  ['sdk'],
  ['cli'],

  // ---- product / billing / UI ----
  ['payment', 'payments', 'billing', 'pay', 'paying', 'paid'],
  ['invoice', 'invoices', 'invoicing'],
  ['subscription', 'subscriptions', 'subscribe', 'subscribed', 'subscriber',
    'subscribers'],
  ['credit', 'credits'],
  ['notification', 'notifications', 'notify', 'notifies', 'notified', 'alert',
    'alerts', 'alerting'],
  ['email', 'emails', 'mail', 'mails'],
  ['header', 'headers'],
  ['cookie', 'cookies'],
  ['page', 'pages'],
  ['screen', 'screens'],
  ['button', 'buttons', 'btn'],
  ['form', 'forms'],
  ['style', 'styles', 'styling', 'styled', 'css', 'stylesheet'],
  ['translation', 'translations', 'translate', 'translated', 'i18n', 'l10n',
    'localization', 'localisation'],
  ['state', 'states', 'status', 'statuses'],
  ['duplicate', 'duplicates', 'duplicated', 'dupe', 'dupes', 'dup', 'dups',
    'dedupe', 'dedup', 'deduplicate', 'deduplication'],
  ['threshold', 'thresholds', 'cutoff'],
  ['score', 'scores', 'scoring', 'scored'],
  ['offline'],
  ['online'],
];

/**
 * Multi-word idioms, rewritten on the normalised string before tokenising.
 * Only pairs whose parts mean something different on their own belong here —
 * "sign in" must not leave a bare `in`/`sign` behind.
 */
const PHRASES: readonly (readonly [string, string])[] = [
  ['sign in', 'login'],
  ['signing in', 'login'],
  ['log in', 'login'],
  ['logging in', 'login'],
  ['logged in', 'login'],
  ['sign on', 'login'],
  ['sign out', 'logout'],
  ['signing out', 'logout'],
  ['log out', 'logout'],
  ['logs out', 'logout'],
  ['logging out', 'logout'],
  ['logged out', 'logout'],
  ['log off', 'logout'],
  ['sign up', 'signup'],
  ['back up', 'backup'],
  ['backed up', 'backup'],
  ['roll back', 'rollback'],
  ['clean up', 'cleanup'],
  ['time out', 'timeout'],
  ['timed out', 'timeout'],
  ['turn on', 'enable'],
  ['switch on', 'enable'],
  ['turn off', 'disable'],
  ['switch off', 'disable'],
  ['two factor', 'mfa'],
  ['multi factor', 'mfa'],
  ['rate limit', 'throttle'],
  ['rate limits', 'throttle'],
  ['rate limited', 'throttle'],
  ['rate limiting', 'throttle'],
  ['pull request', 'pr'],
  ['merge request', 'pr'],
  ['feature flag', 'flag'],
  ['query plan', 'queryplan'],
];

/**
 * Canonical tokens that are mutually exclusive. A title on each side of the
 * same group describes the *opposite* or a *different* piece of work, however
 * much text they share, so such a pair is capped below the duplicate
 * threshold — see `POLARITY_CONFLICT_CAP` in `dedupe.ts`.
 *
 * This is the guard that makes aggressive canonicalisation safe: without it
 * "DB backup" ⊂ "Restore DB from backup" is a containment match at 0.85.
 */
export const ANTONYM_GROUPS: readonly ReadonlySet<string>[] = [
  new Set(['add', 'remove']),
  new Set(['backup', 'restore']),
  new Set(['login', 'logout', 'signup']),
  new Set(['enable', 'disable']),
  new Set(['start', 'stop']),
  new Set(['open', 'close']),
  new Set(['show', 'hide']),
  new Set(['import', 'export']),
  new Set(['upload', 'download']),
  new Set(['encrypt', 'decrypt']),
  new Set(['lock', 'unlock']),
  new Set(['grant', 'revoke']),
  new Set(['increase', 'decrease']),
  new Set(['allowlist', 'denylist']),
  // Not antonyms, but mutually exclusive targets: the same change on web and
  // on mobile, or on prod and on dev, is two items.
  new Set(['production', 'dev', 'staging']),
  new Set(['web', 'mobile']),
];

/** `surface form → canonical token`, built once at module load. */
const VOCAB: Map<string, string> = (() => {
  const map = new Map<string, string>();
  for (const row of VOCAB_ROWS) {
    const canonical = row[0];
    if (canonical === undefined) continue;
    map.set(canonical, canonical);
    for (const surface of row.slice(1)) {
      // A surface form may only ever point at one canonical token; a clash
      // means the dictionary contradicts itself and would make similarity
      // depend on row order.
      const existing = map.get(surface);
      if (existing !== undefined && existing !== canonical) {
        throw new Error(
          `dedupe-vocab: "${surface}" mapped to both "${existing}" and "${canonical}"`,
        );
      }
      map.set(surface, canonical);
    }
  }
  return map;
})();

/** Number of canonical concepts in the dictionary. */
export const VOCAB_CONCEPT_COUNT = VOCAB_ROWS.length;

/** Number of recognised surface forms (canonical tokens included). */
export const VOCAB_FORM_COUNT = VOCAB.size;

/**
 * English inflection endings, longest first. Only suffixes whose removal
 * leaves a stem that is still a recognisable word root are listed.
 */
const SUFFIXES: readonly string[] = [
  'ations', 'ation', 'ings', 'ing', 'ers', 'ed', 'er', 'es', 's', 'e',
];

/** A stem shorter than this is noise, so the suffix is left alone. */
const MIN_STEM = 4;

/** Words at or below this length are never stemmed — too little signal. */
const MIN_STEMMABLE = 5;

/**
 * Conservative stemmer for words the vocabulary does not know.
 *
 * Correctness as linguistics is not the goal — *convergence* is. Two
 * inflected forms of one word must land on the same string, which a single
 * pass does not give you: `rotating` → `rotat` and `rotates` → `rotat`, but
 * `rotate` only reaches `rotat` by also dropping the final `e`. So endings are
 * stripped to a fixpoint, and the guards ({@link MIN_STEMMABLE} to enter,
 * {@link MIN_STEM} to keep) are what stops it from eating the root. `cadd`
 * for "Caddy" is harmless because both titles get the same `cadd`.
 *
 * `-ies` → `-y` is special-cased (`queries` → `query`), and a plural `-s` is
 * never stripped after `s`/`u`/`i` (`access`, `status`, `analysis`).
 */
export function stemWord(word: string): string {
  let w = word;
  for (;;) {
    if (w.length <= MIN_STEMMABLE) return w;
    let next = w;
    if (w.endsWith('ies')) {
      next = `${w.slice(0, -3)}y`;
    } else {
      for (const suffix of SUFFIXES) {
        if (!w.endsWith(suffix)) continue;
        if (suffix === 's' && /[sui]s$/.test(w)) continue;
        let stem = w.slice(0, -suffix.length);
        // `stopped` → `stopp` → `stop`: collapse a doubled final consonant.
        if (
          (suffix === 'ing' || suffix === 'ed' || suffix === 'er') &&
          /([b-df-hj-np-tv-z])\1$/.test(stem) &&
          !/(ss|ll)$/.test(stem) &&
          stem.length - 1 >= MIN_STEM
        ) {
          stem = stem.slice(0, -1);
        }
        if (stem.length >= MIN_STEM) next = stem;
        break;
      }
    }
    if (next === w) return w;
    w = next;
  }
}

/**
 * `stem → canonical token`, so the dictionary covers case forms it does not
 * list. Collisions are expected (stemming is lossy) and resolved by row order:
 * the first row to claim a stem keeps it, which keeps the map deterministic
 * without pretending the ambiguity is a bug.
 */
const STEM_VOCAB: Map<string, string> = (() => {
  const map = new Map<string, string>();
  for (const [surface, canonical] of VOCAB) {
    const stem = stemWord(surface);
    if (stem === surface || VOCAB.has(stem) || map.has(stem)) continue;
    map.set(stem, canonical);
  }
  return map;
})();

/**
 * Canonical token for one normalised word: exact dictionary form, then the
 * dictionary keyed by stem, then the bare stem.
 */
export function canonicalWord(word: string): string {
  const direct = VOCAB.get(word);
  if (direct !== undefined) return direct;
  const stem = stemWord(word);
  return VOCAB.get(stem) ?? STEM_VOCAB.get(stem) ?? stem;
}

/** Rewrites {@link PHRASES} inside an already-normalised title. */
export function applyPhrases(normalized: string): string {
  if (normalized === '') return normalized;
  let out = ` ${normalized} `;
  for (const [phrase, replacement] of PHRASES) {
    out = out.split(` ${phrase} `).join(` ${replacement} `);
  }
  return out.trim();
}

/**
 * Do two canonical token sets disagree inside an {@link ANTONYM_GROUPS} group?
 * A group where only one side has a member is not a disagreement: "Deploy" and
 * "Deploy to prod" are still the same item.
 */
export function hasPolarityConflict(
  a: ReadonlySet<string>,
  b: ReadonlySet<string>,
): boolean {
  for (const group of ANTONYM_GROUPS) {
    let aHit = false;
    let bHit = false;
    let differs = false;
    for (const member of group) {
      const inA = a.has(member);
      const inB = b.has(member);
      if (inA) aHit = true;
      if (inB) bHit = true;
      if (inA !== inB) differs = true;
    }
    if (aHit && bHit && differs) return true;
  }
  return false;
}
