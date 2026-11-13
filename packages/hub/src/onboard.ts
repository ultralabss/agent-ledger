/**
 * `ledger onboard` / `GET /v1/onboard?path=` — facts about a repo, no LLM.
 *
 * The point is to give the first session in a new repo everything it can learn
 * cheaply, so the expensive part (reading code, writing `CONTEXT.md`) starts
 * from facts instead of from `ls`. Everything here is:
 *  - filesystem-only inside `realpath(toplevel)` — no git process in a repo we
 *    may not own, config is read from `.git/config` as text,
 *  - read-only, size-capped, and never fatal: an unreadable file is skipped.
 */

import { lstat, readFile, readdir, stat } from 'node:fs/promises';
import { join, relative, sep } from 'node:path';
import { resolveCheckout, type CheckoutLayout } from './git.ts';

const MAX_FILE = 256 * 1024;
const IGNORE_DIRS = new Set([
  'node_modules',
  '.git',
  '.wt',
  'dist',
  'build',
  '.next',
  '.turbo',
  'vendor',
  'target',
  '.venv',
  '__pycache__',
  '.pnpm-store',
  'coverage',
  'Pods',
]);

export interface OnboardFacts {
  toplevel: string;
  worktree: boolean;
  slug_suggestion: string;
  remote: string | null;
  default_branch: string | null;
  head_branch: string | null;
  stack: string[];
  docs: string[];
  todo_files: string[];
  graphify: string | null;
  claude_md: string[];
  registered_as: string | null;
  onboarded: boolean;
}

async function readCapped(file: string): Promise<string | null> {
  try {
    const st = await stat(file);
    if (!st.isFile() || st.size > MAX_FILE) return null;
    return await readFile(file, 'utf8');
  } catch {
    return null;
  }
}

async function exists(p: string): Promise<boolean> {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

/** `url = https://user:pw@host/x.git` → `https://host/x.git`. Credentials in a
 *  remote URL are a secret; they never leave this function. */
export function stripCredentials(url: string): string {
  return url.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^@/]*@/i, '$1');
}

/** First `[remote "origin"] url = …` in a git config file, as text. */
export function parseRemoteUrl(config: string): string | null {
  const lines = config.split('\n');
  let inOrigin = false;
  let fallback: string | null = null;
  for (const raw of lines) {
    const line = raw.trim();
    const section = /^\[remote\s+"([^"]+)"\]$/.exec(line);
    if (section) {
      inOrigin = section[1] === 'origin';
      continue;
    }
    if (line.startsWith('[')) {
      inOrigin = false;
      continue;
    }
    const m = /^url\s*=\s*(.+)$/.exec(line);
    if (!m?.[1]) continue;
    const url = stripCredentials(m[1].trim());
    if (inOrigin) return url;
    fallback ??= url;
  }
  return fallback;
}

/** `ref: refs/heads/main` in a HEAD file. */
function parseHeadRef(head: string): string | null {
  const m = /^ref:\s*refs\/heads\/(.+?)\s*$/m.exec(head);
  return m?.[1] ?? null;
}

async function detectStack(top: string): Promise<string[]> {
  const out: string[] = [];
  const pkgText = await readCapped(join(top, 'package.json'));
  if (pkgText !== null) {
    let pkg: Record<string, unknown> = {};
    try {
      pkg = JSON.parse(pkgText) as Record<string, unknown>;
    } catch {
      pkg = {};
    }
    const deps = {
      ...((pkg.dependencies as Record<string, string>) ?? {}),
      ...((pkg.devDependencies as Record<string, string>) ?? {}),
    };
    const has = (name: string): boolean => Object.hasOwn(deps, name);
    const parts: string[] = ['node'];
    if (has('typescript')) parts.push('typescript');
    if (has('@nestjs/core')) parts.push('nestjs');
    if (has('next')) parts.push('next');
    if (has('expo')) parts.push('expo');
    if (has('react-native')) parts.push('react-native');
    else if (has('react')) parts.push('react');
    if (has('vite')) parts.push('vite');
    if (has('prisma') || has('@prisma/client')) parts.push('prisma');
    if (has('typeorm')) parts.push('typeorm');
    if (has('hono')) parts.push('hono');
    if (has('express')) parts.push('express');
    if (Array.isArray(pkg.workspaces)) parts.push('npm-workspaces');
    out.push(`package.json: ${parts.join(' + ')}`);
    const scripts = pkg.scripts as Record<string, string> | undefined;
    if (scripts) {
      const known = ['dev', 'build', 'test', 'typecheck', 'lint', 'start'].filter((k) =>
        Object.hasOwn(scripts, k),
      );
      if (known.length > 0) out.push(`scripts: ${known.join(', ')}`);
    }
  }
  const markers: [string, string][] = [
    ['pnpm-workspace.yaml', 'pnpm workspace'],
    ['turbo.json', 'turborepo'],
    ['go.mod', 'go'],
    ['Cargo.toml', 'rust'],
    ['pyproject.toml', 'python (pyproject)'],
    ['requirements.txt', 'python (requirements)'],
    ['Gemfile', 'ruby'],
    ['composer.json', 'php'],
    ['Package.swift', 'swift package'],
    ['app.json', 'expo/react-native app.json'],
    ['Dockerfile', 'docker'],
    ['docker-compose.yml', 'docker compose'],
    ['compose.yaml', 'docker compose'],
    ['Makefile', 'make'],
    ['tsconfig.json', 'tsconfig'],
  ];
  for (const [file, label] of markers) {
    if (await exists(join(top, file))) out.push(`${file}: ${label}`);
  }
  return out;
}

const DOC_CANDIDATES = [
  'README.md',
  'README',
  'CLAUDE.md',
  'HANDOFF.md',
  'ARCHITECTURE.md',
  'CONTRIBUTING.md',
  'CHANGELOG.md',
];
const LEDGER_CANDIDATES = ['BACKLOG.md', 'TODO.md', 'TASKS.md', 'ROADMAP.md', 'NOTES.md'];

async function listDir(dir: string): Promise<string[]> {
  try {
    return (await readdir(dir)).sort();
  } catch {
    return [];
  }
}

/** Recursive, bounded, skips build/vendor dirs. Returns paths relative to `top`. */
async function findFiles(
  top: string,
  match: (name: string, relDir: string) => boolean,
  maxDepth: number,
  limit: number,
): Promise<string[]> {
  const out: string[] = [];
  const walk = async (dir: string, depth: number): Promise<void> => {
    if (out.length >= limit || depth > maxDepth) return;
    for (const name of await listDir(dir)) {
      if (out.length >= limit) return;
      const abs = join(dir, name);
      let st;
      try {
        st = await lstat(abs);
      } catch {
        continue;
      }
      // A symlink (file or dir) can point outside the checkout — never
      // follow it, and never descend into a symlinked directory.
      if (st.isSymbolicLink()) continue;
      const rel = relative(top, abs).split(sep).join('/');
      if (st.isDirectory()) {
        if (IGNORE_DIRS.has(name) || name.startsWith('.')) continue;
        await walk(abs, depth + 1);
        continue;
      }
      if (st.isFile() && match(name, rel)) out.push(rel);
    }
  };
  await walk(top, 0);
  return out;
}

export interface OnboardDeps {
  /** slug for a registered checkout, or null. */
  lookup: (layout: CheckoutLayout) => Promise<{ slug: string; onboarded: boolean } | null>;
  suggestSlug: (name: string) => string | null;
}

export async function collectOnboardFacts(
  dir: string,
  deps: OnboardDeps,
): Promise<OnboardFacts | null> {
  const layout = await resolveCheckout(dir);
  if (!layout) return null;
  const top = layout.checkout;

  const config = await readCapped(join(layout.commonDir, 'config'));
  const head = await readCapped(join(layout.gitDir, 'HEAD'));
  // `origin/HEAD` records the remote's default branch without asking the remote.
  const originHead = await readCapped(join(layout.commonDir, 'refs', 'remotes', 'origin', 'HEAD'));
  const packed = await readCapped(join(layout.commonDir, 'packed-refs'));

  const headBranch = head === null ? null : parseHeadRef(head);
  const defaultBranch =
    // 1. What the remote says, without asking the remote.
    (originHead === null ? null : /refs\/remotes\/origin\/(.+)$/m.exec(originHead)?.[1]?.trim() ?? null) ??
    // 2. A local `main`/`master` that actually exists.
    (packed !== null && /refs\/heads\/main$/m.test(packed)
      ? 'main'
      : (await exists(join(layout.commonDir, 'refs', 'heads', 'main')))
        ? 'main'
        : (await exists(join(layout.commonDir, 'refs', 'heads', 'master')))
          ? 'master'
          : // 3. A repo with no commits yet has no refs at all — the symref in
            // HEAD is its default branch (`git init -b main`).
            headBranch);

  const docsRoot = await findFiles(top, (name, rel) => {
    if (DOC_CANDIDATES.includes(name) && !rel.includes('/')) return true;
    return rel.startsWith('docs/') && name.endsWith('.md');
  }, 2, 12);

  const todoFiles = await findFiles(
    top,
    (name, rel) =>
      LEDGER_CANDIDATES.includes(name) ||
      (/^(todo|backlog|tasks)[-.]/i.test(name) && name.endsWith('.md')) ||
      (rel.startsWith('docs/') && /^(todo|backlog)/i.test(name)),
    2,
    12,
  );

  const claudeMd = await findFiles(top, (name) => name === 'CLAUDE.md', 2, 6);

  const registered = await deps.lookup(layout);
  const graphifyDir = (await exists(join(top, 'graphify-out')))
    ? join(top, 'graphify-out')
    : (await exists(join(top, '..', 'graphify-out')))
      ? join(top, '..', 'graphify-out')
      : null;

  return {
    toplevel: top,
    worktree: layout.worktree,
    slug_suggestion: deps.suggestSlug(top.split(sep).pop() ?? '') ?? '',
    remote: config === null ? null : parseRemoteUrl(config),
    default_branch: defaultBranch,
    head_branch: headBranch,
    stack: await detectStack(top),
    docs: docsRoot,
    todo_files: todoFiles,
    graphify: graphifyDir,
    claude_md: claudeMd,
    registered_as: registered?.slug ?? null,
    onboarded: registered?.onboarded ?? false,
  };
}

/** ≤ 30 lines, one fact per line — pasteable straight into a recap. */
export function formatOnboardFacts(f: OnboardFacts): string {
  const lines: string[] = [];
  lines.push(`repo ${f.toplevel}${f.worktree ? ' (worktree)' : ''}`);
  lines.push(
    `ledger: ${f.registered_as ? `${f.registered_as}${f.onboarded ? '' : ' · onboarded=false'}` : `unregistered · suggested slug ${f.slug_suggestion || '?'}`}`,
  );
  lines.push(`remote: ${f.remote ?? '—'}`);
  lines.push(`branch: ${f.head_branch ?? '—'} · default ${f.default_branch ?? '—'}`);
  if (f.stack.length > 0) {
    lines.push('stack:');
    for (const s of f.stack.slice(0, 8)) lines.push(`  ${s}`);
  } else {
    lines.push('stack: not recognized');
  }
  lines.push(`docs: ${f.docs.length > 0 ? f.docs.slice(0, 8).join(', ') : '—'}`);
  lines.push(`TODO files: ${f.todo_files.length > 0 ? f.todo_files.join(', ') : '—'}`);
  lines.push(`graphify: ${f.graphify ?? 'no'} · CLAUDE.md: ${f.claude_md.join(', ') || 'no'}`);
  return `${lines.slice(0, 30).join('\n')}\n`;
}

export interface DiscoveredRepo {
  path: string;
  /** Registered slug, or null when the hub does not know it yet. */
  slug: string | null;
}

/**
 * Git repos at or under `dir`, depth ≤ 3 — the list the briefing shows when the
 * session started outside any repo. Cheap: it only looks for a `.git` entry and
 * never descends into one.
 */
export async function discoverRepos(
  dir: string,
  lookup: (layout: CheckoutLayout) => Promise<string | null>,
  maxDepth = 3,
  limit = 20,
): Promise<{ repos: DiscoveredRepo[]; truncated: boolean }> {
  const out: DiscoveredRepo[] = [];
  let seen = 0;
  const walk = async (current: string, depth: number): Promise<void> => {
    if (depth > maxDepth) return;
    const layout = await resolveCheckout(current);
    if (layout && layout.checkout === current) {
      seen += 1;
      if (out.length < limit) out.push({ path: current, slug: await lookup(layout) });
      return; // never descend into a repo
    }
    for (const name of await listDir(current)) {
      if (IGNORE_DIRS.has(name) || name.startsWith('.')) continue;
      const abs = join(current, name);
      let st;
      try {
        st = await stat(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) await walk(abs, depth + 1);
    }
  };
  await walk(dir, 0);
  out.sort((a, b) => (a.path < b.path ? -1 : 1));
  return { repos: out, truncated: seen > out.length };
}
