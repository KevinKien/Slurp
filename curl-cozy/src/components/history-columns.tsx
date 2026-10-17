import { useEffect, useRef, useState, type ReactNode, type RefObject } from 'react';

const KEY = 'slurp.history.column-widths.v1';
export const historyColumns = [
  { name: 'ID', width: 96, min: 72 },
  { name: 'Method', width: 80, min: 64 },
  { name: 'Host', width: 144, min: 80 },
  { name: 'Path', width: 240, min: 80 },
  { name: 'Status', width: 80, min: 64 },
  { name: 'Size', width: 80, min: 56 },
  { name: 'Time', width: 96, min: 64 },
  { name: 'Timestamp', width: 112, min: 80 },
];
const clamp = (index: number, width: number) => Math.round(Math.max(historyColumns[index]!.min, Math.min(2000, width)));
export function useHistoryColumns(viewport: RefObject<HTMLDivElement | null>) {
  const [overrides, setOverrides] = useState<Record<string, number>>(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(KEY) ?? '{}');
      return Object.fromEntries(historyColumns.flatMap((c, i) => typeof saved?.[c.name] === 'number' && Number.isFinite(saved[c.name]) ? [[c.name, clamp(i, saved[c.name])]] : []));
    } catch { return {}; }
  });
  const [available, setAvailable] = useState(0);
  useEffect(() => {
    const node = viewport.current;
    if (!node) return;
    const measure = () => setAvailable(node.clientWidth);
    measure();
    if (typeof ResizeObserver === 'undefined') return;
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, [viewport]);
  useEffect(() => { try { localStorage.setItem(KEY, JSON.stringify(overrides)); } catch { /* Storage is optional. */ } }, [overrides]);
  const fixed = historyColumns.reduce((sum, c) => sum + (c.name === 'Path' ? 0 : overrides[c.name] ?? c.width), 40);
  const widths = historyColumns.map(c => overrides[c.name] ?? (c.name === 'Path' ? Math.max(c.width, available - fixed) : c.width));
  return { widths, setWidth: (index: number, value: number | null) => setOverrides(previous => {
    const next = { ...previous }, name = historyColumns[index]!.name;
    if (value === null) delete next[name]; else next[name] = clamp(index, value);
    return next;
  }) };
}

export function HistoryColumnHeader({ index, width, onWidth, children }: { index: number; width: number; onWidth: (width: number | null) => void; children?: ReactNode }) {
  const drag = useRef<{ x: number; width: number; pointer: number } | null>(null);
  const column = historyColumns[index]!;
  return <th scope="col" className={`relative overflow-hidden whitespace-nowrap pr-3 ${index === 0 ? 'pl-5' : ''}`}>
    {children ?? column.name}
    <span role="separator" aria-label={`Resize ${column.name} column`} aria-orientation="vertical" aria-valuenow={width} aria-valuemin={column.min} aria-valuemax={2000} tabIndex={0}
      title="Drag to resize; double-click to reset" className="absolute inset-y-0 right-0 z-20 w-2 cursor-col-resize touch-none select-none border-r border-border/60 hover:bg-primary/30 focus-visible:bg-primary/30 focus-visible:outline-none"
      onPointerDown={event => { if (event.button !== 0) return; event.preventDefault(); event.stopPropagation(); drag.current = { x: event.clientX, width, pointer: event.pointerId }; event.currentTarget.setPointerCapture(event.pointerId); }}
      onPointerMove={event => { const current = drag.current; if (current && current.pointer === event.pointerId) onWidth(current.width + event.clientX - current.x); }}
      onPointerUp={event => { drag.current = null; if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId); }}
      onPointerCancel={() => { drag.current = null; }} onLostPointerCapture={() => { drag.current = null; }}
      onClick={event => event.stopPropagation()} onDoubleClick={event => { event.stopPropagation(); onWidth(null); }}
      onKeyDown={event => { if (['ArrowLeft', 'ArrowRight', 'Home'].includes(event.key)) { event.preventDefault(); event.stopPropagation(); onWidth(event.key === 'Home' ? null : width + (event.key === 'ArrowRight' ? 10 : -10)); } }}/>
  </th>;
}
