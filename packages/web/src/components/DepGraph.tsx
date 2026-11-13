import { Link } from 'react-router';
import { useItem } from '../api/queries.tsx';
import { StatusBadge } from './Badges.tsx';

/** One node fetched by id — used for both level-1 and level-2 neighbours.
 *  `depth` controls whether we also draw its own neighbours (max depth 2,
 *  dependency graph). */
function DepNode({ id, depth }: { id: string; depth: number }) {
  const q = useItem(id);
  if (!q.data) {
    return (
      <div className="dep-node muted" style={{ padding: '0.4rem 0.6rem' }}>
        {id}…
      </div>
    );
  }
  const { item } = q.data;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
      <Link
        to={`/i/${encodeURIComponent(item.id)}`}
        className="dep-node"
        style={{
          display: 'block',
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          padding: '0.4rem 0.6rem',
          maxWidth: '11rem',
        }}
      >
        <div className="row" style={{ gap: '0.3rem' }}>
          <span className="id">{item.id}</span>
          <StatusBadge status={item.status} />
        </div>
        <div style={{ fontSize: '0.85em' }}>{item.title}</div>
      </Link>
      {depth > 1 && item.blocked_by.length > 0 && (
        <div className="muted" style={{ fontSize: '0.8em' }}>
          blocked by: {item.blocked_by.join(', ')}
        </div>
      )}
      {depth > 1 && item.blocks.length > 0 && (
        <div className="muted" style={{ fontSize: '0.8em' }}>
          blocks: {item.blocks.join(', ')}
        </div>
      )}
    </div>
  );
}

/** Two-level `blocks`/`blocked_by` visualization — plain CSS flex, no chart
 *  dependency. Level 2 is shown as a text summary inside the level-1 node
 *  instead of a third column, to stay readable at 375px. */
export function DepGraph({
  id,
  blocks,
  blockedBy,
}: {
  id: string;
  blocks: string[];
  blockedBy: string[];
}) {
  if (blocks.length === 0 && blockedBy.length === 0) return null;
  return (
    <div className="row" style={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {blockedBy.length > 0 && <span className="muted">blocked by (→ {id}):</span>}
        {blockedBy.map((b) => (
          <DepNode key={b} id={b} depth={2} />
        ))}
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        {blocks.length > 0 && <span className="muted">{id} blocks:</span>}
        {blocks.map((b) => (
          <DepNode key={b} id={b} depth={2} />
        ))}
      </div>
    </div>
  );
}
