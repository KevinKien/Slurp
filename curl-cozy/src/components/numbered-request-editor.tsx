import { useEffect, useRef, useState } from 'react';

export function NumberedRequestEditor({ value, onChange, invalid }: { value: string; onChange: (value: string) => void; invalid: boolean }) {
  const input = useRef<HTMLTextAreaElement>(null);
  const [viewport, setViewport] = useState({ top: 0, height: 400 });
  useEffect(() => {
    const node = input.current;
    if (!node) return;
    const measure = () => setViewport({ top: node.scrollTop, height: node.clientHeight || 400 });
    measure();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(measure); observer.observe(node);
    return () => observer.disconnect();
  }, []);
  const count = value.split('\n').length;
  const start = Math.min(count, Math.max(0, Math.floor(viewport.top / 24) - 4));
  const end = Math.min(count, Math.ceil((viewport.top + viewport.height) / 24) + 4);
  return <div className="relative flex min-h-0 flex-1 overflow-hidden bg-background font-mono text-xs leading-6">
    <div aria-hidden="true" data-testid="raw-request-line-numbers" className="relative shrink-0 select-none overflow-hidden border-r border-border text-right text-muted-foreground" style={{ width: `${Math.max(3, String(count).length) + 2}ch` }}>
      {Array.from({ length: end - start }, (_, offset) => { const index = start + offset; return <span key={index} className="absolute inset-x-0 pr-2" style={{ top: 12 + index * 24 - viewport.top, height: 24 }}>{index + 1}</span>; })}
    </div>
    <textarea ref={input} aria-label="Raw request" aria-invalid={invalid} className="min-h-0 min-w-0 flex-1 resize-none overflow-auto bg-transparent px-3 py-3 font-mono text-xs leading-6 outline-none" value={value}
      onChange={event => onChange(event.target.value)} onScroll={event => setViewport({ top: event.currentTarget.scrollTop, height: event.currentTarget.clientHeight || 400 })}
      spellCheck={false} autoCapitalize="off" autoCorrect="off" wrap="off"/>
  </div>;
}
