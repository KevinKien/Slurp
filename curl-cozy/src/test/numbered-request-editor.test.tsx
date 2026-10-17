import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { NumberedRequestEditor } from '@/components/numbered-request-editor';

afterEach(cleanup);
it('updates line numbers without changing editable text and keeps long content bounded on scroll', () => {
  const change = vi.fn();
  const ui = render(<NumberedRequestEditor value={'GET / HTTP/1.1\nHost: localhost\n\nhello'} onChange={change} invalid={false}/>);
  const gutter = screen.getByTestId('raw-request-line-numbers');
  expect(gutter.children).toHaveLength(4);
  fireEvent.change(screen.getByLabelText('Raw request'), { target: { value: 'edited\nrequest' } });
  expect(change).toHaveBeenCalledWith('edited\nrequest');
  ui.rerender(<NumberedRequestEditor value={Array(1000).fill('line').join('\n')} onChange={change} invalid={false}/>);
  const editor = screen.getByLabelText('Raw request');
  fireEvent.scroll(editor, { target: { scrollTop: 2400 } });
  expect(gutter.children.length).toBeLessThan(30);
  expect(gutter).toHaveTextContent('101');
  expect(editor).toHaveValue(Array(1000).fill('line').join('\n'));
});
