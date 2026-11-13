import { Link } from 'react-router';
import type { SessionView } from '@agent-ledger/shared/api';

/** Session identity everywhere it appears: title on top, short monospace id
 *  underneath/alongside. Falls back to the short id alone when untitled. */
export function SessionTag({
  session,
  linked = true,
}: {
  session: Pick<SessionView, 'id' | 'short' | 'title' | 'title_source'>;
  linked?: boolean;
}) {
  const short = session.short ?? session.id.slice(0, 8);
  const body = (
    <span className="session-tag">
      {session.title && <span className="session-tag-title">{session.title}</span>}
      <span className="id session-tag-id">{short}</span>
    </span>
  );
  if (!linked) return body;
  return (
    <Link to={`/s/${encodeURIComponent(session.id)}`} className="session-tag-link" title={session.title_source ? `title source: ${session.title_source}` : undefined}>
      {body}
    </Link>
  );
}
