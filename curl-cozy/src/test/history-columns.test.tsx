import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useRef } from 'react';
import { HistoryColumnHeader, useHistoryColumns } from '@/components/history-columns';

function Table() {
  const viewport = useRef<HTMLDivElement>(null);
  const { widths, setWidth } = useHistoryColumns(viewport);
  return <div ref={viewport}><table><thead><tr><HistoryColumnHeader index={2} width={widths[2]!} onWidth={width => setWidth(2, width)}/></tr></thead></table></div>;
}
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });
it('resizes the Host column by dragging, persists its width and supports keyboard/reset', () => {
  const stored = new Map<string, string>();
  vi.stubGlobal('localStorage', { getItem: (key: string) => stored.get(key) ?? null, setItem: (key: string, value: string) => stored.set(key, value) });
  vi.stubGlobal('PointerEvent', class extends MouseEvent { pointerId: number; constructor(type: string, init: PointerEventInit = {}) { super(type, init); this.pointerId = init.pointerId ?? 0; } });
  const ui = render(<Table/>);
  const handle = screen.getByRole('separator', { name: 'Resize Host column' });
  handle.setPointerCapture = vi.fn(); handle.hasPointerCapture = () => true; handle.releasePointerCapture = vi.fn();
  fireEvent.pointerDown(handle, { button: 0, clientX: 100, pointerId: 1 });
  fireEvent.pointerMove(handle, { clientX: 200, pointerId: 1 });
  fireEvent.pointerUp(handle, { pointerId: 1 });
  expect(handle).toHaveAttribute('aria-valuenow', '244');
  ui.unmount(); render(<Table/>);
  const restored = screen.getByRole('separator', { name: 'Resize Host column' });
  expect(restored).toHaveAttribute('aria-valuenow', '244');
  fireEvent.keyDown(restored, { key: 'ArrowLeft' });
  expect(restored).toHaveAttribute('aria-valuenow', '234');
  fireEvent.doubleClick(restored);
  expect(restored).toHaveAttribute('aria-valuenow', '144');
});
