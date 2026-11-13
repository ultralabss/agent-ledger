import { useState } from 'react';
import { useParams } from 'react-router';
import {
  useReleaseLock,
  useItems,
  useRepoTidy,
  useLeasesForSessions,
  useOverride,
  useRepo,
  useRepoContext,
  useRepoDecisions,
  useReleaseNotes,
  useTimeline,
} from '../api/queries.tsx';
import { Loading, RequestError } from '../components/RequestState.tsx';
import { itemAge } from '../lib/age.ts';
import { ItemRow } from '../components/ItemRow.tsx';
import { RelativeTime } from '../components/RelativeTime.tsx';
import { Markdown } from '../components/Markdown.tsx';
import type { ItemStatus, TouchedView } from '@agent-ledger/shared';
import type { ItemView } from '@agent-ledger/shared/api';
import { Link } from 'react-router';

const COLUMNS: { key: ItemStatus[]; label: string }[] = [
  { key: ['proposed', 'open'], label: 'open' },
  { key: ['doing'], label: 'doing' },
  { key: ['blocked'], label: 'blocked' },
  { key: ['done'], label: 'done' },
];

/**
 * Orphaned files (locks whose session ended mid-edit).
 *
 * The web UI is a cookie caller — already owner-authorized by the
 * browser session, so it neither asks for nor sends a session id; that is only
 * meaningful for a token caller (CLI).
 *
 * The first button used to say "Take over", but a person in a
 * browser is not a session that will keep editing the file — the hub had to
 * invent the owner `manual`, which no heartbeat matched, so the file reappeared
 * as an orphan and the click looked like a no-op. The hub now releases the lock
 * for a cookie caller, and the button says so. "Release (override)" is the
 * different, louder action: breaking a LIVE session's lock, which needs a
 * reason and notifies that session.
 */
function OrphanRow({ file, repoPath }: { file: TouchedView; repoPath: string | null }) {
  const [reason, setReason] = useState('');
  const release = useReleaseLock();
  const override = useOverride();
  const absPath = repoPath ? `${repoPath}/${file.rel_path}` : null;

  function doRelease() {
    if (!absPath) return;
    if (!confirm(`Release the lock on "${file.rel_path}"? Nobody will own it afterwards.`)) return;
    release.mutate({ path: absPath });
  }

  function doOverride() {
    if (!reason.trim() || !absPath) return;
    if (
      !confirm(`Release "${file.rel_path}"? This intrudes on someone else's work — reason: "${reason}".`)
    )
      return;
    override.mutate({ path: absPath, reason: reason.trim() });
  }

  return (
    <li className="item-row" style={{ flexDirection: 'column', alignItems: 'stretch', borderColor: 'var(--k-blocking)' }}>
      <div className="row">
        <span className="title">{file.rel_path}</span>
        <span className="muted">orphan · naposledy {file.last_at}</span>
      </div>
      {!absPath && (
        <div className="muted">repo has no known path — release/override is unavailable here.</div>
      )}
      {absPath && (
        <div className="row" style={{ flexWrap: 'wrap', gap: '0.4rem' }}>
          <button onClick={doRelease} disabled={release.isPending}>
            Release lock
          </button>
          <input
            type="text"
            placeholder="reason (required)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            style={{ width: '12rem' }}
          />
          <button onClick={doOverride} disabled={override.isPending || !reason.trim()}>
            Release (override)
          </button>
        </div>
      )}
      {release.isError && <RequestError error={release.error} />}
      {override.isError && <RequestError error={override.error} />}
    </li>
  );
}

/** Release notes: one row per `release` timeline event, items
 *  closed in that release fetched on demand via the release-notes endpoint. */
function ReleaseRow({ slug, tag, at }: { slug: string; tag: string; at: string }) {
  const [open, setOpen] = useState(false);
  const notes = useReleaseNotes(slug, tag, open);
  return (
    <li className="item-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
      <div className="row">
        <button onClick={() => setOpen((v) => !v)}>{open ? '▾' : '▸'} {tag}</button>
        <span className="muted">{at}</span>
      </div>
      {open && notes.isLoading && <Loading />}
      {open && notes.isError && <RequestError error={notes.error} />}
      {open && notes.data && (
        <ul className="item-list" style={{ marginTop: '0.4rem' }}>
          {notes.data.items.length === 0 && <li className="muted">no closed items.</li>}
          {notes.data.items.map((it) => (
            <li key={it.id} className="item-row">
              <Link className="id" to={`/i/${encodeURIComponent(it.id)}`}>
                {it.id}
              </Link>
              <span className="title">{it.title}</span>
              <span className="muted">{it.commit ?? '—'}</span>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export function RepoPage() {
  const { slug = '' } = useParams();
  const repo = useRepo(slug);
  const items = useItems({ repo: slug });
  const tidy = useRepoTidy(slug);
  const [staleOnly, setStaleOnly] = useState(false);
  const decisions = useRepoDecisions(slug);
  const timeline = useTimeline({ repo: slug });
  const context = useRepoContext(slug);
  const releases = useTimeline({ repo: slug, type: 'release' });
  // Hooks must run unconditionally, before the loading/error early returns.
  const leases = useLeasesForSessions((repo.data?.repo.sessions ?? []).map((s) => s.id));

  if (repo.isLoading) return <Loading />;
  if (repo.isError) return <RequestError error={repo.error} />;
  if (!repo.data) return null;
  const r = repo.data.repo;
  const claimPaths = (sessionId: string) =>
    leases.leases.filter((l) => l.session === sessionId && l.kind === 'claim').flatMap((l) => l.paths);

  return (
    <div>
      <section className="card">
        <h2>
          {r.slug}
          {r.kind !== 'repo' && (
            <span className="badge" style={{ marginLeft: '0.5rem', background: 'var(--muted-foreground)' }}>
              {r.kind === 'vps' ? `vps${r.host ? ` ${r.host}` : ''}` : 'system'}
            </span>
          )}
        </h2>
        <div className="row">
          <span className="muted">branch:</span> {r.git?.branch ?? '—'}
          <span className="muted">ahead/behind:</span> {r.git?.ahead ?? '—'}/{r.git?.behind ?? '—'}
          <span className="muted">last release:</span>{' '}
          {r.last_release ? `${r.last_release.tag} (${r.last_release.at ?? '—'})` : '—'}
        </div>
      </section>

      <div className="grid-2">
        <section className="card">
          <h2>Live</h2>
          <ul className="item-list">
            {r.sessions.length === 0 && <li className="muted">nobody working here right now.</li>}
            {r.sessions.map((s) => {
              const paths = claimPaths(s.id);
              return (
                <li key={s.id} className="item-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
                  <div className="row">
                    <Link className="id" to={`/s/${encodeURIComponent(s.id)}`}>
                      {s.short}
                    </Link>
                    <span className="muted">{s.items.join(', ') || '—'}</span>
                    <RelativeTime at={s.last_seen} />
                  </div>
                  {paths.length > 0 && <div className="muted">claim: {paths.join(', ')}</div>}
                </li>
              );
            })}
          </ul>
        </section>

        <section className="card">
          <h2>Working tree</h2>
          <ul className="item-list">
            {r.dirty.length === 0 && <li className="muted">clean.</li>}
            {r.dirty.map((f) => (
              <li key={f.rel_path} className="item-row" style={f.orphan ? { borderColor: 'var(--k-blocking)' } : undefined}>
                <span className="id">{f.code}</span>
                <span className="title">{f.rel_path}</span>
                <span className="muted">{f.owner_short ?? (f.orphan ? 'orphan' : '—')}</span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section className="card">
        <h2>Claims and intrude leases</h2>
        <ul className="item-list">
          {leases.leases.length === 0 && <li className="muted">none active.</li>}
          {leases.leases.map((l) => (
            <li key={l.id} className="item-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <div className="row">
                <span className="badge" style={{ background: l.kind === 'intrude' ? 'var(--k-deploy)' : 'var(--muted-foreground)' }}>
                  {l.kind}
                </span>
                <Link className="id" to={`/s/${encodeURIComponent(l.session)}`}>
                  {l.session.slice(0, 4)}
                </Link>
                {l.item_id && (
                  <Link className="id" to={`/i/${encodeURIComponent(l.item_id)}`}>
                    {l.item_id}
                  </Link>
                )}
                {l.intent && <span className="muted">{l.intent}</span>}
                <span className="muted">
                  od <RelativeTime at={l.created_at} />
                </span>
              </div>
              {l.paths.length > 0 && <div className="muted">{l.paths.join(', ')}</div>}
            </li>
          ))}
        </ul>
      </section>

      {r.orphans.length > 0 && (
        <section className="card">
          <h2>Orphan files</h2>
          <ul className="item-list">
            {r.orphans.map((f) => (
              <OrphanRow key={f.id} file={f} repoPath={r.path} />
            ))}
          </ul>
        </section>
      )}

      <section className="card">
        <h2>Branches and worktrees</h2>
        <ul className="item-list">
          {r.branches.map((b) => (
            <li key={b.name} className="item-row" style={b.stale ? { borderColor: 'var(--k-deploy)' } : undefined}>
              <span className="title">{b.name}</span>
              <span className="muted">
                +{b.ahead}/-{b.behind} {b.base ? `(${b.base})` : ''}
              </span>
              {b.stale && <span className="badge" style={{ background: 'var(--k-deploy)' }}>visiaca task/*</span>}
            </li>
          ))}
        </ul>
        <ul className="item-list" style={{ marginTop: '0.5rem' }}>
          {r.worktrees.map((w) => (
            <li key={w.path} className="item-row">
              <span className="title">{w.path}</span>
              <span className="muted">{w.branch ?? (w.detached ? 'detached' : '—')}</span>
              {w.live && <span className="badge" style={{ background: 'var(--ok)' }}>live</span>}
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2>Board</h2>
        <div className="row" style={{ marginBottom: '0.5rem' }}>
          <button
            type="button"
            className="badge"
            aria-pressed={staleOnly}
            onClick={() => setStaleOnly((v) => !v)}
            style={{
              cursor: 'pointer',
              border: '1px solid var(--k-blocking)',
              background: staleOnly ? 'var(--k-blocking)' : 'transparent',
              color: staleOnly ? '#fff' : 'var(--k-blocking)',
            }}
          >
            Stale{tidy.data ? ` · ${tidy.data.stale}` : ''}
          </button>
        </div>
        {items.isLoading && <Loading />}
        {items.isError && <RequestError error={items.error} />}
        {items.data && (
          <div className="board">
            {COLUMNS.map((col) => {
              const list: ItemView[] = items.data.items.filter(
                (i) => col.key.includes(i.status) && (!staleOnly || itemAge(i)?.stale),
              );
              return (
                <div key={col.label} className="board-col">
                  <h3>
                    {col.label} ({list.length})
                  </h3>
                  <ul className="item-list">
                    {list.map((i) => (
                      <ItemRow key={i.id} item={i} />
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        )}
      </section>

      <section className="card">
        <h2>Timeline</h2>
        <ul className="item-list">
          {(timeline.data?.events ?? []).slice(0, 30).map((e, idx) => (
            <li key={idx} className="log-line">
              {e.at} · {e.session} · {e.type} · {e.fields.join(' · ')}
            </li>
          ))}
          {timeline.data?.events.length === 0 && <li className="muted">no events.</li>}
        </ul>
      </section>

      <section className="card">
        <h2>Decisions</h2>
        <ul className="item-list">
          {decisions.data?.decisions.length === 0 && <li className="muted">none.</li>}
          {decisions.data?.decisions.map((d) => (
            <li key={d.n} className="item-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <div className="row">
                <span className="id">D{d.n}</span>
                <span className="title">{d.title}</span>
                <span className="muted">{d.date}</span>
              </div>
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2>Context</h2>
        {context.isLoading && <Loading />}
        {context.isError && <RequestError error={context.error} />}
        {context.data && (
          context.data.context === null ? (
            <p className="muted">CONTEXT.md neexistuje.</p>
          ) : (
            <>
              {context.data.truncated && <p className="muted">truncated to {context.data.bytes} B.</p>}
              <Markdown text={context.data.context} />
            </>
          )
        )}
      </section>

      <section className="card">
        <h2>Release notes</h2>
        <ul className="item-list">
          {(releases.data?.events ?? []).length === 0 && <li className="muted">no releases.</li>}
          {(releases.data?.events ?? []).map((e, idx) => (
            <ReleaseRow key={idx} slug={r.slug} tag={e.fields[0] ?? '—'} at={e.at} />
          ))}
        </ul>
      </section>
    </div>
  );
}
