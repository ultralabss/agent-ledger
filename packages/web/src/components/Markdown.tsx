import { lazy, Suspense } from 'react';

// react-markdown pulls in a sizeable parser tree — split it into its own
// chunk so pages that never render markdown don't pay for it on first paint.
const ReactMarkdown = lazy(() => import('react-markdown'));

/** Agent- and user-supplied text can contain arbitrary markup. We render it as
 *  markdown only — no `rehype-raw`, no `dangerouslySetInnerHTML` — so any raw
 *  HTML in the source is shown as literal text, never executed. */
export function Markdown({ text }: { text: string }) {
  return (
    <div className="markdown">
      <Suspense fallback={<span className="whitespace-pre-wrap">{text}</span>}>
        <ReactMarkdown>{text}</ReactMarkdown>
      </Suspense>
    </div>
  );
}
