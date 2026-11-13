import { useState } from 'react';
import { Link } from 'react-router';
import {
  useCreateIntake,
  useIntakeList,
  useProcessIntake,
  useProcessPending,
  useRepos,
  useSessions,
  type IntakeAction,
} from '../api/queries.tsx';
import { ApiError, FeatureDisabledError } from '../api/client.tsx';
import { Loading, RequestError } from '../components/RequestState.tsx';
import { RelativeTime } from '../components/RelativeTime.tsx';
import type { IntakeRecord } from '@agent-ledger/shared';
import { Card, CardContent, CardHeader, CardTitle } from '../components/ui/card.tsx';
import { Textarea } from '../components/ui/textarea.tsx';
import { Button } from '../components/ui/button.tsx';
import { Badge } from '../components/ui/badge.tsx';
import { ToggleGroup, ToggleGroupItem } from '../components/ui/toggle-group.tsx';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../components/ui/select.tsx';

const STATUS_LABEL: Record<string, string> = { new: 'new', triaged: 'triaged', partial: 'partial' };

/** A disabled headless feature (403) or a missing agent binary (503) gets its own message, not a generic one. */
function headlessErrorMessage(err: unknown): string {
  if (err instanceof FeatureDisabledError) return err.message;
  if (err instanceof ApiError && err.status === 503) {
    return 'triage run is unavailable — LEDGER_CLAUDE_BIN is not configured on the hub.';
  }
  console.error(err);
  return 'something went wrong, see console for detail';
}

function IntakeRow({ rec }: { rec: IntakeRecord }) {
  const process = useProcessIntake(rec.id);
  return (
    <div className="border rounded-[2px] p-3 flex flex-col gap-2" style={{ borderColor: 'var(--border)' }}>
      <div className="flex items-center gap-2 flex-wrap">
        <Badge variant="secondary">{STATUS_LABEL[rec.status] ?? rec.status}</Badge>
        <span className="muted">{rec.channel}</span>
        <span className="muted">{rec.repo_hint ?? '—'}</span>
        <RelativeTime at={rec.at} />
        {rec.status === 'new' && (
          <Button size="sm" variant="outline" className="ml-auto" onClick={() => process.mutate({})} disabled={process.isPending}>
            {process.isPending ? 'processing…' : 'Process now'}
          </Button>
        )}
      </div>
      <p className="text-[13px] m-0">{rec.text}</p>
      {rec.items.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <span className="muted">created:</span>
          {rec.items.map((id) => (
            <Link key={id} to={`/i/${encodeURIComponent(id)}`} className="id">
              {id}
            </Link>
          ))}
        </div>
      )}
      {rec.dropped.length > 0 && <div className="muted">dropped: {rec.dropped.map((d) => d.reason).join(', ')}</div>}
      {process.isSuccess && (
        <div className="muted">
          run {process.data.run.ok ? 'ok' : 'failed'} ({process.data.run.ms} ms): {process.data.run.text}
        </div>
      )}
      {process.isError && <div className="error-box">{headlessErrorMessage(process.error)}</div>}
    </div>
  );
}

const ACTIONS: { value: IntakeAction; label: string }[] = [
  { value: 'triage', label: 'Triage only' },
  { value: 'send_to_session', label: 'Send to session' },
  { value: 'triage_and_run', label: 'Triage + run worker' },
];

/** Intake (`/intake`) — free-text goes to `/v1/intake`, target picks whether it
 *  is just triaged, forwarded into a live session's inbox, or triaged and
 *  handed to a headless worker. */
export function Intake() {
  const [text, setText] = useState('');
  const [repoHint, setRepoHint] = useState('');
  const [action, setAction] = useState<IntakeAction>('triage');
  const [session, setSession] = useState('');
  const create = useCreateIntake();
  const list = useIntakeList();
  const processPending = useProcessPending();
  const repos = useRepos();
  const liveSessions = useSessions(repoHint || undefined, true);

  function submit() {
    if (text.trim().length === 0) return;
    if (action === 'send_to_session' && !session) return;
    create.mutate(
      { text, repo_hint: repoHint || undefined, action, session: action === 'send_to_session' ? session : undefined },
      { onSuccess: () => setText('') },
    );
  }

  function runAll() {
    if (!confirm('Process all untriaged entries now?')) return;
    processPending.mutate({});
  }

  return (
    <div className="p-4 flex flex-col gap-4 max-w-3xl">
      <Card>
        <CardHeader>
          <CardTitle>New entry</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <Textarea
            rows={5}
            placeholder="Paste the text verbatim — it gets split into items during triage."
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          <div className="flex items-center gap-2 flex-wrap">
            <Select value={repoHint || 'any'} onValueChange={(v) => setRepoHint(v === 'any' ? '' : v)}>
              <SelectTrigger size="sm" className="h-[30px] text-[12.5px]">
                <SelectValue placeholder="repo: any" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="any">repo: any</SelectItem>
                {repos.data &&
                  Object.keys(repos.data.repos).map((slug) => (
                    <SelectItem key={slug} value={slug}>
                      {slug}
                    </SelectItem>
                  ))}
              </SelectContent>
            </Select>
            <ToggleGroup type="single" value={action} onValueChange={(v) => v && setAction(v as IntakeAction)}>
              {ACTIONS.map((a) => (
                <ToggleGroupItem key={a.value} value={a.value} size="sm" className="text-[11.5px] h-7 px-2.5">
                  {a.label}
                </ToggleGroupItem>
              ))}
            </ToggleGroup>
            {action === 'send_to_session' && (
              <Select value={session || undefined} onValueChange={setSession}>
                <SelectTrigger size="sm" className="h-[30px] text-[12.5px]">
                  <SelectValue placeholder="session…" />
                </SelectTrigger>
                <SelectContent>
                  {(liveSessions.data?.sessions ?? []).map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.title ?? s.id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>
          <div className="flex items-center gap-2">
            <Button onClick={submit} disabled={create.isPending || text.trim().length === 0 || (action === 'send_to_session' && !session)}>
              {create.isPending ? 'sending…' : 'Add to intake'}
            </Button>
            {create.isError && <RequestError error={create.error} />}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>Entries</CardTitle>
          <Button size="sm" variant="outline" onClick={runAll} disabled={processPending.isPending}>
            {processPending.isPending ? 'processing…' : 'Process all'}
          </Button>
        </CardHeader>
        <CardContent className="flex flex-col gap-2">
          {processPending.isSuccess && (
            <p className="muted">
              run {processPending.data.run.ok ? 'ok' : 'failed'} ({processPending.data.run.ms} ms): {processPending.data.run.text}
            </p>
          )}
          {processPending.isError && <div className="error-box">{headlessErrorMessage(processPending.error)}</div>}
          {list.isLoading && <Loading />}
          {list.isError && <RequestError error={list.error} />}
          {list.data?.intake.length === 0 && <p className="muted">intake is empty.</p>}
          {list.data?.intake.map((rec) => <IntakeRow key={rec.id} rec={rec} />)}
        </CardContent>
      </Card>
    </div>
  );
}
