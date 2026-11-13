import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '../components/ui/sheet.tsx';
import {
  useAddComment,
  useBlockItem,
  useDoneItem,
  useDropItem,
  useItem,
  usePatchItem,
  useReleaseItem,
  useReopenItem,
  useToggleStep,
} from '../api/queries.tsx';
import { Loading, RequestError } from '../components/RequestState.tsx';
import { KindBadge, PriorityBadge, StatusBadge } from '../components/Badges.tsx';
import { RelativeTime } from '../components/RelativeTime.tsx';
import { Markdown } from '../components/Markdown.tsx';
import { DepGraph } from '../components/DepGraph.tsx';
import { findAuthorizedLine } from '../lib/format.tsx';
import { ReplyStatusChip } from '../components/ReplyStatusChip.tsx';
import { ReplyPopover } from '../components/ReplyPopover.tsx';

export function ItemPage() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const close = () => navigate(-1);
  const q = useItem(id);
  const addComment = useAddComment(id);
  const patch = usePatchItem(id);
  const done = useDoneItem(id);
  const drop = useDropItem(id);
  const reopen = useReopenItem(id);
  const block = useBlockItem(id);
  const release = useReleaseItem(id);
  const toggleStep = useToggleStep(id);

  const [comment, setComment] = useState('');
  const [reason, setReason] = useState('');
  const [ref, setRef] = useState('');
  const [copied, setCopied] = useState(false);

  const authLine = q.data ? findAuthorizedLine(q.data.detail.rec) : null;

  async function copyAuth() {
    if (!authLine) return;
    await navigator.clipboard.writeText(authLine);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <Sheet open onOpenChange={(open) => { if (!open) close(); }}>
      <SheetContent side="right" className="w-full sm:max-w-xl overflow-y-auto gap-0 px-4">
        {q.isLoading && <Loading />}
        {q.isError && <RequestError error={q.error} />}
        {q.data && (() => {
          const { item, detail } = q.data;
          return (
    <div>
      <SheetHeader className="px-0">
        <SheetTitle className="font-mono text-sm">{item.id}</SheetTitle>
      </SheetHeader>
      <section className="card">
        <div className="row">
          <span className="id">{item.id}</span>
          <KindBadge kind={item.kind} />
          <StatusBadge status={item.status} />
          <PriorityBadge priority={item.priority} />
          {item.last_reply && <ReplyStatusChip reply={item.last_reply} />}
          <div style={{ marginLeft: 'auto' }}>
            <ReplyPopover item={item} recommended={detail.rec} />
          </div>
        </div>
        <h1 style={{ fontSize: '1.2rem' }}>{item.title}</h1>
        {item.last_reply?.status === 'needs_chat_auth' && (
          <div className="error-box" style={{ background: 'color-mix(in oklch, var(--k-blocking) 15%, var(--card))' }}>
            This needs your confirmation in your agent chat (deploy/prod/auth) — the worker won't act without it.
          </div>
        )}
        {item.last_reply?.result && (
          <div className="card" style={{ margin: '0.5rem 0 0' }}>
            <h2 style={{ margin: '0 0 0.3rem' }}>Worker result</h2>
            <pre style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{item.last_reply.result}</pre>
          </div>
        )}
        <div className="row muted">
          <span>repo: {item.repo}</span>
          <span>owner: {item.owner}</span>
          <span>
            created <RelativeTime at={item.created} />
          </span>
          <span>
            updated <RelativeTime at={item.updated} />
          </span>
        </div>
        {item.blocks.length > 0 && (
          <div className="row">
            <span className="muted">blocks:</span>
            {item.blocks.map((b) => (
              <Link key={b} to={`/i/${encodeURIComponent(b)}`} className="id">
                {b}
              </Link>
            ))}
          </div>
        )}
        {item.blocked_by.length > 0 && (
          <div className="row">
            <span className="muted">blocked by:</span>
            {item.blocked_by.map((b) => (
              <Link key={b} to={`/i/${encodeURIComponent(b)}`} className="id">
                {b}
              </Link>
            ))}
          </div>
        )}
        {item.intake && <div className="muted">intake origin: {item.intake}</div>}
        {item.done?.commit && <div className="muted">commit: <code title={item.done.commit}>{item.done.commit.slice(0, 7)}</code></div>}
      </section>

      {(item.blocks.length > 0 || item.blocked_by.length > 0) && (
        <section className="card">
          <h2>Dependency graph</h2>
          <DepGraph id={item.id} blocks={item.blocks} blockedBy={item.blocked_by} />
        </section>
      )}

      <section className="card">
        <h2>Why</h2>
        <Markdown text={detail.why || '—'} />
      </section>

      <section className="card">
        <h2>Plan</h2>
        <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {detail.steps.map((s) => (
            <li key={s.n} className="plan-step">
              <input
                type="checkbox"
                checked={s.done}
                disabled={toggleStep.isPending}
                onChange={(e) => toggleStep.mutate({ n: s.n, done: e.target.checked })}
              />
              <span>{s.text}</span>
            </li>
          ))}
          {detail.steps.length === 0 && <li className="muted">no steps.</li>}
        </ul>
      </section>

      <section className="card">
        <div className="row">
          <h2 style={{ margin: 0 }}>Recommendation</h2>
          {authLine && (
            <button onClick={copyAuth}>{copied ? 'copied' : 'Copy'}</button>
          )}
        </div>
        <Markdown text={detail.rec || '—'} />
      </section>

      <section className="card">
        <h2>Actions</h2>
        <div className="row" style={{ flexWrap: 'wrap', gap: '0.5rem' }}>
          <button onClick={() => patch.mutate({ owner: 'human' })} disabled={patch.isPending}>
            owner → human
          </button>
          <input
            type="text"
            placeholder="commit/ref"
            value={ref}
            onChange={(e) => setRef(e.target.value)}
            style={{ width: '10rem' }}
          />
          <button className="primary" onClick={() => done.mutate({ ref: ref || undefined })} disabled={done.isPending}>
            done
          </button>
          <input
            type="text"
            placeholder="reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            style={{ width: '12rem' }}
          />
          <button onClick={() => reason && drop.mutate({ why: reason })} disabled={drop.isPending || !reason}>
            drop
          </button>
          <button onClick={() => reason && reopen.mutate({ why: reason })} disabled={reopen.isPending || !reason}>
            needs rework
          </button>
          <button onClick={() => block.mutate({ on: 'human' })} disabled={block.isPending}>
            block on human
          </button>
          <button onClick={() => release.mutate({})} disabled={release.isPending}>
            release
          </button>
        </div>
        {(patch.isError || done.isError || drop.isError || reopen.isError || block.isError || release.isError) && (
          <RequestError error={patch.error ?? done.error ?? drop.error ?? reopen.error ?? block.error ?? release.error} />
        )}
      </section>

      <section className="card">
        <h2>Comments</h2>
        <div className="row">
          <input
            type="text"
            placeholder="new comment"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
          />
          <button
            onClick={() => {
              if (comment.trim()) addComment.mutate({ text: comment }, { onSuccess: () => setComment('') });
            }}
            disabled={addComment.isPending || comment.trim().length === 0}
          >
            add
          </button>
        </div>
        {addComment.isError && <RequestError error={addComment.error} />}
        {detail.comments.map((c) => (
          <div key={c.id} className="comment">
            <div className="meta">
              {c.author} · <RelativeTime at={c.at} />
            </div>
            <Markdown text={c.text} />
          </div>
        ))}
        {detail.comments.length === 0 && <p className="muted">no comments.</p>}
      </section>

      <section className="card">
        <h2>Log</h2>
        {detail.log.map((l, idx) => (
          <div key={idx} className="log-line">
            {l.at} · {l.session} · {l.text}
          </div>
        ))}
        {detail.log.length === 0 && <p className="muted">empty.</p>}
      </section>
    </div>
          );
        })()}
      </SheetContent>
    </Sheet>
  );
}
