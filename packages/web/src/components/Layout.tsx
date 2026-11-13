import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useNavigate } from 'react-router';
import { useLiveEvents } from '../hooks/useSSE.tsx';
import { useHealthz, useItems, useRepos, useSessions } from '../api/queries.tsx';
import { useRepoSelection } from '../hooks/useRepoSelection.tsx';
import { SearchBox } from './SearchBox.tsx';
import { repoColorVar } from '../lib/repoColor.ts';

const LINKS = [
  { to: '/', label: 'Board', end: true, key: 'B' },
  { to: '/needs-you', label: 'Needs you', key: 'N' },
  { to: '/intake', label: 'Intake', key: 'I' },
  { to: '/timeline', label: 'Activity', key: 'A' },
];

const SYSTEM_LINKS = [
  { to: '/system?tab=sessions', label: 'Sessions', key: 'S' },
  { to: '/system?tab=repos', label: 'Repo health', key: 'H' },
  { to: '/system?tab=system', label: 'System', key: 'Y' },
];

/** Guard kill switch, read-only here: turning it off only ever happens via
 *  `ledger guard off` in the CLI, the web UI never offers a toggle. */
function GuardIndicator() {
  const healthz = useHealthz();
  const guard = healthz.data?.guard;
  if (!guard) return null;
  const on = guard.state === 'on';
  return (
    <span
      className="badge"
      style={{ background: on ? 'var(--ok)' : 'var(--k-blocking)' }}
      title={`guard ${guard.state}${guard.pinned ? ' (pinned via env)' : ''} · source: ${guard.source}`}
    >
      guard {on ? 'on' : 'off'}
    </span>
  );
}

function SpoolWarning() {
  const healthz = useHealthz();
  const spool = healthz.data?.spool;
  if (!spool || spool.queued <= 0) return null;
  return (
    <span className="badge" style={{ background: 'var(--k-deploy)' }} title={`${spool.queued} queued, ${spool.failed} failed`}>
      hub queue {spool.queued}
    </span>
  );
}

function ConnPill({ conn }: { conn: string }) {
  const healthz = useHealthz();
  const live = healthz.data?.sessions?.live ?? healthz.data?.sessions?.active ?? 0;
  const port = healthz.data?.port ?? 4747;
  return (
    <span
      className="hidden sm:flex items-center gap-2 h-[30px] px-2.5 border font-mono text-[11px]"
      style={{ borderColor: 'var(--border)', color: 'var(--muted-foreground)' }}
    >
      <span className={`conn-dot ${conn === 'open' ? '' : 'down'}`} />
      <span style={{ color: 'var(--foreground)' }}>live</span>
      <span>· {live} sessions · :{port}</span>
    </span>
  );
}

function NeedsYouButton() {
  const navigate = useNavigate();
  const items = useItems({ owner: 'human', open: true });
  const n = items.data?.items.length ?? 0;
  return (
    <button
      onClick={() => navigate('/needs-you')}
      className="flex items-center gap-2 h-[30px] pl-2.5 pr-1 border rounded-[2px] text-[12.5px] font-medium"
      style={{ borderColor: 'var(--input)', background: 'var(--background)', color: 'var(--foreground)' }}
    >
      Needs you
      <span
        className="min-w-[22px] h-[22px] grid place-items-center px-1 font-mono text-[11px] font-semibold text-white"
        style={{ background: 'var(--k-blocking)' }}
      >
        {n}
      </span>
    </button>
  );
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(() => readStoredTheme());
  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem('agent-ledger.theme', theme);
    } catch {
      /* storage unavailable — the choice just isn't remembered */
    }
    if (theme !== 'system') return;
    // Tokens only exist under [data-theme], so "system" must resolve to a
    // concrete value and follow OS changes while it is selected.
    const mq = window.matchMedia('(prefers-color-scheme: light)');
    const onChange = () => applyTheme('system');
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [theme]);
  return [theme, () => setTheme((t) => (t === 'dark' ? 'light' : t === 'light' ? 'system' : 'dark'))];
}

export function readStoredTheme(): string {
  try {
    return localStorage.getItem('agent-ledger.theme') ?? 'system';
  } catch {
    return 'system';
  }
}

/** Sets a concrete `data-theme` — the design tokens are scoped to it. */
export function applyTheme(theme: string): void {
  const resolved =
    theme === 'light' || theme === 'dark'
      ? theme
      : window.matchMedia('(prefers-color-scheme: light)').matches
        ? 'light'
        : 'dark';
  document.documentElement.setAttribute('data-theme', resolved);
}

function Sidebar({ collapsed, onCollapse }: { collapsed: boolean; onCollapse: () => void }) {
  const repos = useRepos();
  const sel = useRepoSelection();
  const live = useSessions(undefined, true);
  const [theme, cycleTheme] = useTheme();
  const liveByRepo = new Map<string, number>();
  for (const s of live.data?.sessions ?? []) {
    if (!s.home_repo) continue;
    liveByRepo.set(s.home_repo, (liveByRepo.get(s.home_repo) ?? 0) + 1);
  }

  return (
    <aside className={`sidebar${collapsed ? ' collapsed' : ''}`}>
      <div className="sidebar-brand">
        <span className="brand-logo"><span /></span>
        <Link to="/" className="brand-mark">agent-ledger</Link>
        {!collapsed && <span className="brand-scope">local</span>}
      </div>

      <nav className="sidebar-nav">
        {LINKS.map((l) => (
          <NavLink key={l.to} to={l.to} end={l.end} className={({ isActive }) => (isActive ? 'active' : '')} title={l.label}>
            <span className="kbd">{l.key}</span>
            <span>{l.label}</span>
          </NavLink>
        ))}
      </nav>

      {!collapsed && <div className="sidebar-section-head" style={{ padding: '14px 8px 6px' }}><span>System</span></div>}
      <nav className="sidebar-nav">
        {SYSTEM_LINKS.map((l) => (
          <NavLink key={l.to} to={l.to} className={({ isActive }) => (isActive ? 'active' : '')} title={l.label}>
            <span className="kbd">{l.key}</span>
            <span>{l.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-section">
        <div className="sidebar-section-head">
          <span>Repos</span>
          <button className="link-btn" onClick={sel.selectAll} disabled={sel.isAll}>
            All repos
          </button>
        </div>
        <ul className="repo-list">
          {repos.data &&
            Object.entries(repos.data.repos).map(([slug, cfg]) => {
              const checked = sel.isAll || sel.selected.includes(slug);
              const liveCount = liveByRepo.get(slug) ?? 0;
              return (
                <li key={slug} className="repo-list-item">
                  {/* The checkbox used to live inside a <label> wrapping the
                   *  <Link> too. Clicking the repo name bubbled the click to the
                   *  label, and browsers disagree on whether a label forwards a
                   *  click to its control when the click originated on a nested
                   *  <a> — Chrome mostly suppresses it, Firefox/Safari sometimes
                   *  forward it, so the checkbox toggled *or* navigated
                   *  inconsistently depending on browser and exact click target.
                   *  Fix: no <label>, checkbox is a plain standalone control
                   *  (onChange, no preventDefault hack) and the repo name is a
                   *  separate sibling — filter toggle and navigation never
                   *  share one event anymore. */}
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) => sel.toggle(slug, (e.nativeEvent as MouseEvent).altKey)}
                    title="Alt-click to select only this repo"
                  />
                  <span className="repo-dot" style={{ background: repoColorVar(slug) }} />
                  <Link to={`/r/${encodeURIComponent(slug)}`} className="repo-name">
                    {slug}
                  </Link>
                  <span className="repo-meta">
                    {liveCount > 0 && <span className="pulse-dot" title={`${liveCount} live session(s)`} />}
                    <span className="muted id">{cfg.prefix}</span>
                  </span>
                </li>
              );
            })}
        </ul>
      </div>

      <div className="sidebar-foot">
        <button className="sidebar-collapse" onClick={cycleTheme} title="Cycle theme" style={{ width: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11.5, padding: '0 9px' }}>
          {theme}
        </button>
        <button
          className="sidebar-collapse"
          onClick={onCollapse}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          style={{ marginLeft: collapsed ? 0 : 'auto' }}
        >
          {collapsed ? '»' : '«'}
        </button>
      </div>
    </aside>
  );
}

export function Layout() {
  const conn = useLiveEvents();
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem('agent-ledger.sidebar') === '1');
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    localStorage.setItem('agent-ledger.sidebar', collapsed ? '1' : '0');
  }, [collapsed]);

  return (
    <div className={`app-shell${collapsed ? ' sidebar-collapsed' : ''}`}>
      {drawerOpen && <div className="drawer-scrim" onClick={() => setDrawerOpen(false)} />}
      <div className={`sidebar-slot${drawerOpen ? ' open' : ''}`}>
        <Sidebar collapsed={collapsed} onCollapse={() => setCollapsed((c) => !c)} />
      </div>
      <div className="app-main grid-bg">
        <header className="topbar">
          <button
            className="sidebar-collapse"
            onClick={() => (window.innerWidth <= 900 ? setDrawerOpen((o) => !o) : setCollapsed((c) => !c))}
            aria-label="Toggle sidebar"
            title="Toggle sidebar"
          >
            ☰
          </button>
          <SearchBox />
          <div className="row" style={{ marginLeft: 'auto' }}>
            <SpoolWarning />
            <GuardIndicator />
            <ConnPill conn={conn} />
            <NeedsYouButton />
          </div>
        </header>
        <main>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
