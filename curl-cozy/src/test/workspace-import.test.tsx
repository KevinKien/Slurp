import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { ImportWorkspaceButton } from '@/components/workspace-archive';
import { importWorkspace } from '@/lib/api';

const retryHistory = vi.fn();
vi.mock('@/components/inspector', () => ({
  useInspector: () => ({
    retryHistory,
    workspaces: [
      { id: 'default', name: 'Default', request_count: 3, created_at: '', active: true },
      { id: 'w2', name: 'Client work', request_count: 10, created_at: '', active: false },
    ],
  }),
}));
vi.mock('@/lib/api', () => ({ importWorkspace: vi.fn(), exportWorkspace: vi.fn() }));

const result = (over = {}) => ({ workspace: { id: 'w2', name: 'Client work', request_count: 12, created_at: '', active: false }, rows: 5, merged: false, skipped: 0, kept_documents: [], ...over });
const file = () => new File(['x'], 'export.slurp');
async function choose() {
  render(<ImportWorkspaceButton />);
  fireEvent.change(screen.getByLabelText('Choose .slurp file'), { target: { files: [file()] } });
  await screen.findByText('Import export.slurp');
}

beforeEach(() => {
  retryHistory.mockReset();
  vi.mocked(importWorkspace).mockReset().mockResolvedValue(result());
});

it('creates a new workspace by default', async () => {
  await choose();
  fireEvent.click(screen.getByRole('button', { name: 'Import' }));
  await waitFor(() => expect(importWorkspace).toHaveBeenCalledWith(expect.any(File), undefined));
  expect(retryHistory).not.toHaveBeenCalled();
});

it('merges into the chosen workspace and refreshes history', async () => {
  vi.mocked(importWorkspace).mockResolvedValue(result({ merged: true, skipped: 2, kept_documents: ['replay_tabs'] }));
  await choose();
  fireEvent.click(screen.getByLabelText(/Merge into an existing workspace/));
  fireEvent.change(screen.getByLabelText('Workspace to merge into'), { target: { value: 'w2' } });
  fireEvent.click(screen.getByRole('button', { name: 'Merge' }));
  await waitFor(() => expect(importWorkspace).toHaveBeenCalledWith(expect.any(File), 'w2'));
  await waitFor(() => expect(retryHistory).toHaveBeenCalledWith(true));
});

it('merges into the first workspace when none was picked, and keeps the dialog open on failure', async () => {
  vi.mocked(importWorkspace).mockRejectedValue(new Error('the file is corrupted'));
  await choose();
  fireEvent.click(screen.getByLabelText(/Merge into an existing workspace/));
  fireEvent.click(screen.getByRole('button', { name: 'Merge' }));
  await waitFor(() => expect(importWorkspace).toHaveBeenCalledWith(expect.any(File), 'default'));
  expect(screen.getByText('Import export.slurp')).toBeTruthy();
  expect(retryHistory).not.toHaveBeenCalled();
});
