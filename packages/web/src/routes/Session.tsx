import { Link, useParams } from 'react-router';
import { useInbox, useSession } from '../api/queries.tsx';
import { Loading, RequestError } from '../components/RequestState.tsx';
import { RelativeTime } from '../components/RelativeTime.tsx';
import { SessionTag } from '../components/SessionTag.tsx';

export function SessionPage() {
  const { session: id = '' } = useParams();
  const q = useSession(id);
  const inbox = useInbox(id, true);

  if (q.isLoading) return <Loading />;
  if (q.isError) return <RequestError error={q.error} />;
  if (!q.data) return null;
  const { session, touched, leases, events } = q.data;
  const activeLeases = leases.filter((l) => l.released_at === null);

  return (
    <div>
      <section className="card">
        <h1 style={{ fontSize: '1.1rem', margin: 0 }}>
          <SessionTag session={session} linked={false} />
        </h1>
        <div className="row muted" style={{ marginTop: '0.5rem' }}>
          <span>repo: {session.home_repo ?? '—'}</span>
          <span>branch: {session.branch ?? '—'}</span>
          <span>source: {session.source}</span>
          <span>state: {session.liveness}</span>
          <span>
            last seen <RelativeTime at={session.last_seen} />
          </span>
        </div>
        {session.items.length > 0 && (
          <div className="row">
            <span className="muted">items:</span>
            {session.items.map((id2) => (
              <Link key={id2} to={`/i/${encodeURIComponent(id2)}`} className="id">
                {id2}
              </Link>
            ))}
          </div>
        )}
      </section>

      <section className="card">
        <h2>Touched files</h2>
        <ul className="item-list">
          {touched.length === 0 && <li className="muted">none.</li>}
          {touched.map((t) => (
            <li key={t.id} className="item-row" style={t.orphan ? { borderColor: 'var(--k-blocking)' } : undefined}>
              <span className="title">{t.rel_path}</span>
              <span className="muted">{t.via}</span>
              <RelativeTime at={t.last_at} />
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2>Claims and intrude leases</h2>
        <ul className="item-list">
          {activeLeases.length === 0 && <li className="muted">none active.</li>}
          {activeLeases.map((l) => (
            <li key={l.id} className="item-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
              <div className="row">
                <span className="badge" style={{ background: l.kind === 'intrude' ? 'var(--k-deploy)' : 'var(--muted-foreground)' }}>
                  {l.kind}
                </span>
                {l.item_id && (
                  <Link className="id" to={`/i/${encodeURIComponent(l.item_id)}`}>
                    {l.item_id}
                  </Link>
                )}
                {l.intent && <span className="muted">{l.intent}</span>}
                <RelativeTime at={l.created_at} />
              </div>
              {l.paths.length > 0 && <div className="muted">{l.paths.join(', ')}</div>}
            </li>
          ))}
        </ul>
      </section>

      <section className="card">
        <h2>Inbox</h2>
        {inbox.isLoading && <Loading />}
        {inbox.isError && <RequestError error={inbox.error} />}
        {inbox.data && (
          <ul className="item-list">
            {inbox.data.messages.length === 0 && <li className="muted">no messages.</li>}
            {inbox.data.messages.map((m) => (
              <li key={m.id} className="item-row" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
                <div className="row">
                  <span
                    className="badge"
                    style={{ background: m.delivered_at ? 'var(--ok)' : 'var(--k-deploy)' }}
                  >
                    {m.delivered_at ? 'delivered' : 'undelivered'}
                  </span>
                  <span className="muted">from: {m.from_session ? m.from_session.slice(0, 4) : '—'}</span>
                  <RelativeTime at={m.created_at} />
                </div>
                <p style={{ margin: '0.3rem 0' }}>{m.body}</p>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="card">
        <h2>Events</h2>
        {events.map((e, idx) => (
          <div key={idx} className="log-line">
            {e.at} · {e.type} · {e.fields.join(' · ')}
          </div>
        ))}
        {events.length === 0 && <p className="muted">none.</p>}
      </section>
    </div>
  );
}
