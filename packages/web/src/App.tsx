import { lazy, Suspense } from 'react';
import { BrowserRouter, Route, Routes } from 'react-router';
import { Layout } from './components/Layout.tsx';
import { Skeleton } from './components/ui/skeleton.tsx';

// Board (`/`) is the landing route — kept eager so first paint has no extra
// network round trip. Every other route is code-split so its JS only loads
// on navigation.
import { Overview } from './routes/Overview.tsx';
const Intake = lazy(() => import('./routes/Intake.tsx').then((m) => ({ default: m.Intake })));
const RepoPage = lazy(() => import('./routes/Repo.tsx').then((m) => ({ default: m.RepoPage })));
const ItemPage = lazy(() => import('./routes/Item.tsx').then((m) => ({ default: m.ItemPage })));
const SessionPage = lazy(() => import('./routes/Session.tsx').then((m) => ({ default: m.SessionPage })));
const TimelinePage = lazy(() => import('./routes/Timeline.tsx').then((m) => ({ default: m.TimelinePage })));
const NeedsYou = lazy(() => import('./routes/NeedsYou.tsx').then((m) => ({ default: m.NeedsYou })));
const SystemPage = lazy(() => import('./routes/System.tsx').then((m) => ({ default: m.SystemPage })));

function RouteFallback() {
  return (
    <div className="p-4 space-y-2">
      <Skeleton className="h-8 w-1/3" />
      <Skeleton className="h-32 w-full" />
      <Skeleton className="h-32 w-full" />
    </div>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<RouteFallback />}>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<Overview />} />
            <Route path="/needs-you" element={<NeedsYou />} />
            <Route path="/intake" element={<Intake />} />
            <Route path="/r/:slug" element={<RepoPage />} />
            <Route path="/i/:id" element={<ItemPage />} />
            <Route path="/s/:session" element={<SessionPage />} />
            <Route path="/timeline" element={<TimelinePage />} />
            <Route path="/system" element={<SystemPage />} />
            <Route path="*" element={<p>Page not found.</p>} />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
