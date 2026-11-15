import { useState } from 'react';
import { Link, useSearchParams } from 'react-router';
import { FeatureDisabledError } from '../api/client.tsx';
import { useGroom, useHealthz, useRepos, useSessions } from '../api/queries.tsx';
import { useRepoSelection } from '../hooks/useRepoSelection.tsx';
import { Loading, RequestError } from '../components/RequestState.tsx';
import { RelativeTime } from '../components/RelativeTime.tsx';
import { SessionTag } from '../components/SessionTag.tsx';
import { repoColorVar } from '../lib/repoColor.ts';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs.tsx';
import { Badge } from '../components/ui/badge.tsx';
import { Button } from '../components/ui/button.tsx';

function SessionsTab() {
  const repos = useRepoSelection();
  const [liveOnly, setLiveOnly] = useState(false);
  const sessions = useSessions(repos.csv, liveOnly);
  return (
    <div className="flex flex-col gap-3">
      <label className="flex items-center gap-2 text-[12.5px]" style={{ color: 'var(--muted-foreground)' }}>
        <input type="checkbox" checked={liveOnly} onChange={(e) => setLiveOnly(e.target.checked)} />
        live only
      </label>
      {sessions.isLoading && <Loading />}
      {sessions.isError && <RequestError error={sessions.error} />}
      {sessions.data && (
        <ul className="item-list">
          {sessions.data.sessions.length === 0 && <li className="muted">no sessions.</li>}
          {sessions.data.sessions.map((s) => (
            <li key={s.id} className="item-row">
              <span
                className={s.liveness === 'active' ? 'pulse-dot' : 'repo-dot'}
                style={{ background: s.home_repo ? repoColorVar(s.home_repo) : 'var(--muted-foreground)' }}
              />
              <SessionTag session={s} />
              <span className="muted">{s.home_repo ?? '—'}</span>
              <span className="muted">{s.items.join(', ') || '—'}</span>
              <RelativeTime at={s.last_seen} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function RepoHealthTab() {
  const repoList = useRepos();
  const healthz = useHealthz();
  return (
    <div className="flex flex-col gap-3">
      {repoList.isLoading && <Loading />}
      {repoList.isError && <RequestError error={repoList.error} />}
      {repoList.data && (
        <ul className="item-list">
          {Object.entries(repoList.data.repos).map(([slug, cfg]) => (
            <li key={slug} className="item-row">
              <span className="repo-dot" style={{ background: repoColorVar(slug) }} />
              <Link className="title" to={`/r/${encodeURIComponent(slug)}`}>
                {slug}
              </Link>
              <span className="muted id">{cfg.prefix}</span>
              {cfg.kind === 'system' || cfg.kind === 'vps' ? (
                <span className="badge" style={{ background: 'var(--muted-foreground)' }}>
                  {cfg.kind === 'vps' ? `vps${cfg.host ? ` ${cfg.host}` : ''}` : 'system'}
                </span>
              ) : (
                <span className="muted">{cfg.path ?? '—'}</span>
              )}
            </li>
          ))}
        </ul>
      )}
      {healthz.data?.git && (
        <div className="muted text-[12px]">
          git sync: {healthz.data.git.enabled ? 'on' : 'off'} · pending summaries {healthz.data.git.pendingSummaries} ·
          last push {healthz.data.git.lastPushAt ?? '—'}
          {healthz.data.git.lastPushError && <span> · push error: {healthz.data.git.lastPushError}</span>}
        </div>
      )}
      <p className="muted text-[12px]">Open a repo above for branch/ahead-behind, dirty files, orphans, worktrees, CONTEXT.md and decisions.</p>
    </div>
  );
}

function SystemTab() {
  const healthz = useHealthz();
  const groom = useGroom();
  const [groomError, setGroomError] = useState<string | null>(null);

  function runGroom() {
    if (!confirm('Run ledger grooming now?')) return;
    setGroomError(null);
    groom.mutate(
      {},
      {
        onError: (err) => {
          console.error(err);
          setGroomError(
            err instanceof FeatureDisabledError ? err.message : 'something went wrong, see console for detail',
          );
        },
      },
    );
  }

  const guard = healthz.data?.guard;
  const spool = healthz.data?.spool;
  const headless = healthz.data?.headless;
  const fsWeak = healthz.data?.fs_weak ?? [];

  return (
    <div className="flex flex-col gap-4">
      {fsWeak.length > 0 && (
        <div role="alert" className="rounded px-3 py-2 text-[13px]" style={{ background: 'var(--k-blocking)', color: '#fff' }}>
          <strong>Weak filesystem: private-permission checks are relaxed</strong> (LEDGER_ALLOW_WEAK_FS=1). Other local
          accounts may be able to read the ledger, token or spool on: {fsWeak.join(', ')}. Move them to a local NTFS/ext4/APFS
          volume and unset the variable.
        </div>
      )}
      <div className="flex flex-wrap items-center gap-2">
        {guard && (
          <Badge
            style={{ background: guard.state === 'on' ? 'var(--ok)' : 'var(--k-blocking)', color: '#fff' }}
            title={`guard ${guard.state}${guard.pinned ? ' (pinned via env)' : ''} · source: ${guard.source}`}
          >
            guard {guard.state}
          </Badge>
        )}
        {spool && spool.queued > 0 && (
          <Badge style={{ background: 'var(--k-deploy)', color: '#fff' }} title={`${spool.queued} queued, ${spool.failed} failed`}>
            spool queue {spool.queued}
          </Badge>
        )}
        {spool && spool.failed > 0 && (
          <Badge style={{ background: 'var(--k-blocking)', color: '#fff' }}>spool failed {spool.failed}</Badge>
        )}
      </div>

      <div className="flex items-center gap-2">
        <Button size="sm" onClick={runGroom} disabled={groom.isPending}>
          {groom.isPending ? 'grooming…' : 'Groom now'}
        </Button>
        <span className="muted text-[12px]">
          last run:{' '}
          {healthz.data?.headless?.last_groom ? (
            <>
              <RelativeTime at={healthz.data.headless.last_groom.at} /> · {healthz.data.headless.last_groom.ok ? 'ok' : 'failed'}
            </>
          ) : (
            '—'
          )}
        </span>
      </div>
      {groomError && <div className="error-box">{groomError}</div>}

      {headless && (
        <div className="text-[12px] flex flex-col gap-1" style={{ color: 'var(--muted-foreground)' }}>
          <div>headless runner: {headless.configured ? 'configured' : 'not configured (LEDGER_HEADLESS / LEDGER_CLAUDE_BIN unset)'} · {headless.busy ? 'busy' : 'idle'} · queued {headless.queued}</div>
          {headless.last && (
            <div>
              last run ({headless.last.kind}): {headless.last.ok ? 'ok' : 'failed'}, {headless.last.ms} ms —{' '}
              <RelativeTime at={headless.last.at} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

const TABS = [
  { value: 'sessions', label: 'Sessions' },
  { value: 'repos', label: 'Repo health' },
  { value: 'system', label: 'System' },
] as const;

/** System (`/system`) — everything about the hub itself, not about items:
 *  live sessions, per-repo health, and the guard/spool/headless/grooming
 *  status the sidebar's SYSTEM section links to. */
export function SystemPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get('tab') ?? 'sessions';
  return (
    <div className="p-4">
      <Tabs value={tab} onValueChange={(v) => setParams({ tab: v }, { replace: true })}>
        <TabsList>
          {TABS.map((t) => (
            <TabsTrigger key={t.value} value={t.value}>
              {t.label}
            </TabsTrigger>
          ))}
        </TabsList>
        <TabsContent value="sessions">
          <SessionsTab />
        </TabsContent>
        <TabsContent value="repos">
          <RepoHealthTab />
        </TabsContent>
        <TabsContent value="system">
          <SystemTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
