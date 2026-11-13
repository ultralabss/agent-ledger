import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { UnauthorizedError } from './api/client.tsx';
import { App } from './App.tsx';
import { applyTheme, readStoredTheme } from './components/Layout.tsx';
import '@fontsource-variable/space-grotesk';
import '@fontsource-variable/jetbrains-mono';
import './styles/tokens.css';
import './styles/global.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: (count, err) => !(err instanceof UnauthorizedError) && count < 2,
      staleTime: 10_000,
    },
    mutations: {
      retry: false,
    },
  },
});

// Before the first render: the design tokens live under [data-theme], so the
// login screen and first paint must already have a concrete theme.
applyTheme(readStoredTheme());

const el = document.getElementById('root');
if (!el) throw new Error('#root is missing');

createRoot(el).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
