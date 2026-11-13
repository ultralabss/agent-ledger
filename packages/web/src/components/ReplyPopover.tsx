import { useState } from 'react';
import { useReplyToItem } from '../api/queries.tsx';
import { FeatureDisabledError } from '../api/client.tsx';
import { useIsMobile } from '../hooks/use-mobile.ts';
import type { ItemFrontmatter } from '@agent-ledger/shared';
import { Button } from './ui/button.tsx';
import { Textarea } from './ui/textarea.tsx';
import { ToggleGroup, ToggleGroupItem } from './ui/toggle-group.tsx';
import { Popover, PopoverContent, PopoverTrigger } from './ui/popover.tsx';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from './ui/sheet.tsx';

type Mode = 'auto' | 'session' | 'worker';

const MODE_LABEL: Record<Mode, string> = {
  auto: 'Auto',
  session: 'This session',
  worker: 'Background worker',
};

/** Reply — Popover on desktop, bottom Sheet on mobile (same body).
 *  Ctrl/Cmd+Enter sends. Empty text = "do as recommended" — the button
 *  label makes that explicit so nothing is sent silently. */
function ReplyBody({ item, recommended, onSent }: { item: ItemFrontmatter; recommended?: string; onSent: () => void }) {
  const [mode, setMode] = useState<Mode>('auto');
  const [text, setText] = useState('');
  const reply = useReplyToItem(item.id);

  function send() {
    reply.mutate({ text: text.trim() || undefined, mode }, { onSuccess: onSent, onError: (err) => console.error(err) });
  }

  return (
    <div
      className="flex flex-col gap-2"
      onKeyDown={(e) => {
        if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') {
          e.preventDefault();
          send();
        }
      }}
    >
      <ToggleGroup type="single" value={mode} onValueChange={(v) => v && setMode(v as Mode)} className="justify-start">
        {(['auto', 'session', 'worker'] as Mode[]).map((m) => (
          <ToggleGroupItem key={m} value={m} size="sm" className="text-[11.5px] h-7 px-2.5">
            {MODE_LABEL[m]}
          </ToggleGroupItem>
        ))}
      </ToggleGroup>
      <p className="text-[12px]" style={{ color: 'var(--muted-foreground)' }}>
        {mode === 'auto' && '→ hub picks the live session if one is open, otherwise a background worker'}
        {mode === 'session' && '→ delivered into the inbox of the session holding this item'}
        {mode === 'worker' && `→ background worker in ${item.repo}`}
      </p>
      <Textarea
        autoFocus
        rows={4}
        placeholder="What should happen next…"
        value={text}
        onChange={(e) => setText(e.target.value)}
      />
      {text.trim().length === 0 && recommended && (
        <p className="text-[11.5px]" style={{ color: 'var(--muted-foreground)' }}>
          Empty = do as recommended: <em>{recommended.slice(0, 200)}</em>
        </p>
      )}
      {reply.isError && (
        <div className="error-box">
          {reply.error instanceof FeatureDisabledError
            ? reply.error.message
            : 'something went wrong, see console for detail'}
        </div>
      )}
      <div className="flex justify-end">
        <Button size="sm" onClick={send} disabled={reply.isPending}>
          {reply.isPending ? 'sending…' : text.trim().length === 0 ? 'Do as recommended' : 'Send'}
        </Button>
      </div>
    </div>
  );
}

export function ReplyPopover({ item, recommended }: { item: ItemFrontmatter; recommended?: string }) {
  const isMobile = useIsMobile();
  const [open, setOpen] = useState(false);

  if (isMobile) {
    return (
      <Sheet open={open} onOpenChange={setOpen}>
        <Button size="sm" variant="outline" onClick={() => setOpen(true)}>
          Reply
        </Button>
        <SheetContent side="bottom" className="max-h-[85vh]">
          <SheetHeader>
            <SheetTitle>Reply — {item.id}</SheetTitle>
          </SheetHeader>
          <div className="px-4 pb-4">
            <ReplyBody item={item} recommended={recommended} onSent={() => setOpen(false)} />
          </div>
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button size="sm" variant="outline">
          Reply
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[400px]">
        <div className="font-medium text-[12.5px] mb-2">Reply — {item.id}</div>
        <ReplyBody item={item} recommended={recommended} onSent={() => setOpen(false)} />
      </PopoverContent>
    </Popover>
  );
}
