import { FeatureDisabledError, SecretRejectedError, UnauthorizedError } from '../api/client.tsx';

/** API error detail goes to the console only, the user sees a generic
 *  message (except for secret rejections and disabled features). 401 gets its
 *  own screen — "not logged in", not a red box. */
export function RequestError({ error }: { error: unknown }) {
  if (error instanceof UnauthorizedError) return <LoginRequired />;
  console.error(error);
  const message =
    error instanceof SecretRejectedError || error instanceof FeatureDisabledError
      ? error.message
      : 'Something went wrong — see the console for detail.';
  return <div className="error-box">{message}</div>;
}

export function LoginRequired() {
  return (
    <div className="error-box">
      <p>Not signed in — run <code>ledger open</code> in a terminal.</p>
    </div>
  );
}

export function Loading() {
  return <p className="muted">Loading…</p>;
}
