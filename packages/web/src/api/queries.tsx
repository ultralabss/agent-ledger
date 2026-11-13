/** react-query hooks — one per `/v1/*` read, plus the write mutations the UI
 *  offers. Types come only from `@agent-ledger/shared/api`. */

import { useMutation, useQueries, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query';
import type {
  AdoptResponse,
  ContextResponse,
  DecisionsResponse,
  GroomResponse,
  HealthzResponse,
  IntakeListResponse,
  IntakeProcessResponse,
  IntakeResponse,
  InboxResponse,
  ItemDetailResponse,
  ItemResponse,
  ItemsResponse,
  LeaseView,
  OverrideResponse,
  ReleaseNotesResponse,
  RepliesResponse,
  RepoDecisionsResponse,
  RepoStatusResponse,
  ReposResponse,
  ReplyResponse,
  SearchResponse,
  SessionDetailResponse,
  SessionsResponse,
  TimelineResponse,
} from '@agent-ledger/shared/api';
import { apiGet, apiPatch, apiPost, qs } from './client.tsx';

export const qk = {
  repos: ['repos'] as const,
  repo: (slug: string) => ['repo', slug] as const,
  items: (params: Record<string, string | undefined>) => ['items', params] as const,
  item: (id: string) => ['item', id] as const,
  intake: (status?: string) => ['intake', status] as const,
  intakeOne: (id: string) => ['intake-one', id] as const,
  decisions: (repo?: string) => ['decisions', repo] as const,
  sessions: (repo?: string) => ['sessions', repo] as const,
  session: (id: string) => ['session', id] as const,
  timeline: (params: Record<string, string | undefined>) => ['timeline', params] as const,
  search: (q: string, repo?: string) => ['search', q, repo] as const,
  context: (slug: string) => ['context', slug] as const,
  repoDecisions: (slug: string) => ['repo-decisions', slug] as const,
  inbox: (session: string, all: boolean) => ['inbox', session, all] as const,
  healthz: ['healthz'] as const,
  releaseNotes: (slug: string, from: string | undefined, to: string) =>
    ['release-notes', slug, from, to] as const,
};

export function useRepos(): UseQueryResult<ReposResponse> {
  return useQuery({ queryKey: qk.repos, queryFn: () => apiGet<ReposResponse>('/v1/repos') });
}

export function useRepo(slug: string | undefined): UseQueryResult<RepoStatusResponse> {
  return useQuery({
    queryKey: qk.repo(slug ?? ''),
    queryFn: () => apiGet<RepoStatusResponse>(`/v1/repos/${encodeURIComponent(slug ?? '')}`),
    enabled: Boolean(slug),
  });
}

export interface ItemsFilter {
  /** comma-joined repo slugs (multi-repo filter) */
  repo?: string;
  status?: string;
  owner?: string;
  kind?: string;
  priority?: string;
  open?: boolean;
  session?: string;
  q?: string;
}

export function useItems(filter: ItemsFilter): UseQueryResult<ItemsResponse> {
  const params = {
    repo: filter.repo,
    status: filter.status,
    owner: filter.owner,
    kind: filter.kind,
    priority: filter.priority,
    open: filter.open ? '1' : undefined,
    session: filter.session,
    q: filter.q,
  };
  return useQuery({
    queryKey: qk.items(params),
    queryFn: () => apiGet<ItemsResponse>(`/v1/items${qs(params)}`),
  });
}

export function useItem(id: string | undefined): UseQueryResult<ItemDetailResponse> {
  return useQuery({
    queryKey: qk.item(id ?? ''),
    queryFn: () => apiGet<ItemDetailResponse>(`/v1/items/${encodeURIComponent(id ?? '')}`),
    enabled: Boolean(id),
  });
}

export function useIntakeList(status?: string): UseQueryResult<IntakeListResponse> {
  return useQuery({
    queryKey: qk.intake(status),
    queryFn: () => apiGet<IntakeListResponse>(`/v1/intake${qs({ status })}`),
  });
}

export function useIntakeOne(id: string | undefined): UseQueryResult<IntakeResponse> {
  return useQuery({
    queryKey: qk.intakeOne(id ?? ''),
    queryFn: () => apiGet<IntakeResponse>(`/v1/intake/${encodeURIComponent(id ?? '')}`),
    enabled: Boolean(id),
  });
}

export function useDecisions(repo?: string): UseQueryResult<DecisionsResponse> {
  return useQuery({
    queryKey: qk.decisions(repo),
    queryFn: () => apiGet<DecisionsResponse>(`/v1/decisions${qs({ repo })}`),
  });
}

export function useSessions(repo?: string, live?: boolean): UseQueryResult<SessionsResponse> {
  return useQuery({
    queryKey: qk.sessions(repo),
    queryFn: () => apiGet<SessionsResponse>(`/v1/sessions${qs({ repo, live: live ? '1' : undefined })}`),
  });
}

export function useSession(id: string | undefined): UseQueryResult<SessionDetailResponse> {
  return useQuery({
    queryKey: qk.session(id ?? ''),
    queryFn: () => apiGet<SessionDetailResponse>(`/v1/sessions/${encodeURIComponent(id ?? '')}`),
    enabled: Boolean(id),
  });
}

export interface TimelineFilter {
  repo?: string;
  type?: string;
  since?: string;
}

export function useTimeline(filter: TimelineFilter): UseQueryResult<TimelineResponse> {
  const params = { repo: filter.repo, type: filter.type, since: filter.since, limit: '200' };
  return useQuery({
    queryKey: qk.timeline(params),
    queryFn: () => apiGet<TimelineResponse>(`/v1/timeline${qs(params)}`),
  });
}

export function useSearch(q: string, repo?: string): UseQueryResult<SearchResponse> {
  return useQuery({
    queryKey: qk.search(q, repo),
    queryFn: () => apiGet<SearchResponse>(`/v1/search${qs({ q, repo, limit: '20' })}`),
    enabled: q.trim().length >= 2,
  });
}

/** Repo context (CONTEXT.md), rendered as markdown only. */
export function useRepoContext(slug: string | undefined): UseQueryResult<ContextResponse> {
  return useQuery({
    queryKey: qk.context(slug ?? ''),
    queryFn: () => apiGet<ContextResponse>(`/v1/repos/${encodeURIComponent(slug ?? '')}/context`),
    enabled: Boolean(slug),
  });
}

export function useRepoDecisions(slug: string | undefined): UseQueryResult<RepoDecisionsResponse> {
  return useQuery({
    queryKey: qk.repoDecisions(slug ?? ''),
    queryFn: () => apiGet<RepoDecisionsResponse>(`/v1/repos/${encodeURIComponent(slug ?? '')}/decisions`),
    enabled: Boolean(slug),
  });
}

/** Inbox for one session; `all=true` includes already-delivered messages so
 *  the UI can show a delivered/undelivered split . */
export function useInbox(session: string | undefined, all = true): UseQueryResult<InboxResponse> {
  return useQuery({
    queryKey: qk.inbox(session ?? '', all),
    queryFn: () =>
      apiGet<InboxResponse>(`/v1/inbox${qs({ session: session ?? '', all: all ? '1' : undefined })}`),
    enabled: Boolean(session),
  });
}

/** No dedicated "unread across sessions" endpoint — sum undelivered messages
 *  over the given session ids (F1's `/v1/inbox`, one call per session). */
export function useUnreadTotal(sessionIds: string[]): { total: number; loading: boolean } {
  const results = useQueries({
    queries: sessionIds.map((id) => ({
      queryKey: qk.inbox(id, true),
      queryFn: () => apiGet<InboxResponse>(`/v1/inbox${qs({ session: id, all: '1' })}`),
    })),
  });
  const loading = results.some((r) => r.isLoading);
  const total = results.reduce(
    (sum, r) => sum + (r.data?.messages.filter((m) => m.delivered_at === null).length ?? 0),
    0,
  );
  return { total, loading };
}

/** Active claim/intrude leases across the given sessions — reuses
 *  `/v1/sessions/:id`, there is no repo-wide leases endpoint. */
export function useLeasesForSessions(sessionIds: string[]): { leases: LeaseView[]; loading: boolean } {
  const results = useQueries({
    queries: sessionIds.map((id) => ({
      queryKey: qk.session(id),
      queryFn: () => apiGet<SessionDetailResponse>(`/v1/sessions/${encodeURIComponent(id)}`),
    })),
  });
  const loading = results.some((r) => r.isLoading);
  const leases = results.flatMap((r) => (r.data?.leases ?? []).filter((l) => l.released_at === null));
  return { leases, loading };
}

export function useHealthz(): UseQueryResult<HealthzResponse> {
  return useQuery({
    queryKey: qk.healthz,
    queryFn: () => apiGet<HealthzResponse>('/v1/healthz'),
    refetchInterval: 30_000,
  });
}

export function useReleaseNotes(
  slug: string | undefined,
  to: string | undefined,
  enabled: boolean,
): UseQueryResult<ReleaseNotesResponse> {
  return useQuery({
    queryKey: qk.releaseNotes(slug ?? '', undefined, to ?? ''),
    queryFn: () =>
      apiGet<ReleaseNotesResponse>(
        `/v1/repos/${encodeURIComponent(slug ?? '')}/release-notes${qs({ to: to ?? '', format: 'json' })}`,
      ),
    enabled: enabled && Boolean(slug) && Boolean(to),
  });
}

/* ---------------- mutations ---------------- */

function useInvalidateItem(id: string) {
  const qc = useQueryClient();
  return () => {
    void qc.invalidateQueries({ queryKey: qk.item(id) });
    void qc.invalidateQueries({ queryKey: ['items'] });
    void qc.invalidateQueries({ queryKey: ['timeline'] });
  };
}

export function useAddComment(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: { text: string; author?: string }) =>
      apiPost<ItemResponse>(`/v1/items/${encodeURIComponent(id)}/comments`, vars),
    onSuccess: invalidate,
  });
}

export function usePatchItem(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: {
      title?: string;
      owner?: string;
      kind?: string;
      priority?: string;
      status?: string;
    }) => apiPatch<ItemResponse>(`/v1/items/${encodeURIComponent(id)}`, vars),
    onSuccess: invalidate,
  });
}

export function useDoneItem(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: { ref?: string }) =>
      apiPost<ItemResponse>(`/v1/items/${encodeURIComponent(id)}/done`, vars),
    onSuccess: invalidate,
  });
}

export function useDropItem(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: { why: string }) =>
      apiPost<ItemResponse>(`/v1/items/${encodeURIComponent(id)}/drop`, vars),
    onSuccess: invalidate,
  });
}

export function useReopenItem(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: { why: string }) =>
      apiPost<ItemResponse>(`/v1/items/${encodeURIComponent(id)}/reopen`, vars),
    onSuccess: invalidate,
  });
}

export function useBlockItem(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: { by?: string; on?: 'human' }) =>
      apiPost<ItemResponse>(`/v1/items/${encodeURIComponent(id)}/block`, vars),
    onSuccess: invalidate,
  });
}

export function useToggleStep(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: { n: number; done: boolean }) =>
      apiPost<ItemResponse>(`/v1/items/${encodeURIComponent(id)}/steps`, vars),
    onSuccess: invalidate,
  });
}

/** Send a reply to whoever/whatever should act on an item next. */
export function useReplyToItem(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: { text?: string; mode?: 'auto' | 'session' | 'worker' }) =>
      apiPost<ReplyResponse>(`/v1/items/${encodeURIComponent(id)}/reply`, vars),
    onSuccess: invalidate,
  });
}

export function useReplies(id: string | undefined): UseQueryResult<RepliesResponse> {
  return useQuery({
    queryKey: ['replies', id ?? ''],
    queryFn: () => apiGet<RepliesResponse>(`/v1/items/${encodeURIComponent(id ?? '')}/replies`),
    enabled: Boolean(id),
  });
}

export function useReleaseItem(id: string) {
  const invalidate = useInvalidateItem(id);
  return useMutation({
    mutationFn: (vars: { why?: string }) =>
      apiPost<ItemResponse>(`/v1/items/${encodeURIComponent(id)}/release`, vars),
    onSuccess: invalidate,
  });
}

import type { IntakeAction } from '@agent-ledger/shared/api';
export type { IntakeAction };

export interface CreateIntakeVars {
  text: string;
  repo_hint?: string;
  action?: IntakeAction;
  session?: string;
}

export function useCreateIntake() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: CreateIntakeVars) =>
      apiPost<IntakeResponse & { redacted: number }>('/v1/intake', { ...vars, channel: 'web' }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['intake'] }),
  });
}

/** Headless triage ("Process now") of one intake record. Needs `LEDGER_HEADLESS=1` on the hub. */
export function useProcessIntake(id: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { session?: string }) =>
      apiPost<IntakeProcessResponse>(`/v1/intake/${encodeURIComponent(id)}/process`, vars),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['intake'] }),
  });
}

/** "Process all" — triages up to `limit` pending records in one run. */
export function useProcessPending() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { session?: string; limit?: number }) =>
      apiPost<IntakeProcessResponse>('/v1/intake/process-pending', vars),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['intake'] }),
  });
}

/** Headless grooming ("Groom now"). Needs `LEDGER_HEADLESS=1` on the hub. */
export function useGroom() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { repo?: string; session?: string }) => apiPost<GroomResponse>('/v1/groom', vars),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.healthz }),
  });
}

/**
 * Orphaned files — `POST /v1/adopt`.
 *
 * The web UI is always a cookie caller, which is owner-authorized
 * without naming a session — `session` is only for a token caller (CLI).
 *
 * For a cookie caller the hub RELEASES the lock instead of
 * handing the file to a session (the browser is a person, not a session that
 * will keep editing). The response then carries `released`. The old UI called
 * this "Take over", which is why the file kept reappearing as an orphan — see
 * `OrphanRow` for the label that matches what actually happens.
 */
export function useReleaseLock() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { path: string }) => apiPost<AdoptResponse>('/v1/adopt', vars),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['repo'] });
      void qc.invalidateQueries({ queryKey: ['session'] });
    },
  });
}

/** Break another session's lock. `reason` is mandatory — this is a
 *  deliberate intrusion into someone else's work, not a routine action.
 *  `session` optional, same reasoning as `useReleaseLock` above. */
export function useOverride() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { session?: string; path: string; reason: string }) =>
      apiPost<OverrideResponse>('/v1/override', vars),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['repo'] });
      void qc.invalidateQueries({ queryKey: ['session'] });
    },
  });
}
