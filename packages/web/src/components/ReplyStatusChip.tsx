import type { ReplyStatus, ReplyView } from '@agent-ledger/shared/api';
import { RelativeTime } from './RelativeTime.tsx';

const STATUS_LABEL: Record<ReplyStatus, string> = {
  queued: 'Queued',
  delivered: 'Delivered',
  working: 'Working',
  done: 'Resolved',
  failed: 'Failed',
  needs_chat_auth: 'Needs chat authorization',
};

const STATUS_COLOR: Record<ReplyStatus, string> = {
  queued: 'var(--muted-foreground)',
  delivered: 'var(--ring)',
  working: 'var(--k-deploy)',
  done: 'var(--ok)',
  failed: 'var(--k-blocking)',
  needs_chat_auth: 'var(--k-risk)',
};

/** Shows where the last reply on an item stands. `needs_chat_auth`
 *  never gets a button that could bypass the authorization it is asking for —
 *  it only ever tells the human to go confirm in the agent chat. */
export function ReplyStatusChip({ reply }: { reply: ReplyView }) {
  const at = reply.finished_at ?? reply.delivered_at ?? reply.created_at;
  return (
    <span className="row" style={{ gap: '0.3rem' }}>
      <span className="badge" style={{ background: STATUS_COLOR[reply.status] }}>
        {STATUS_LABEL[reply.status]}
      </span>
      <RelativeTime at={at} />
    </span>
  );
}
