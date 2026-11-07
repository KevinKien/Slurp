import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { ReverseProxySettings } from '@/components/reverse-proxies';
import { createReverseProxy, deleteReverseProxy, fetchReverseProxies, setReverseProxyEnabled } from '@/lib/api';

vi.mock('@/lib/api', () => ({ fetchReverseProxies: vi.fn(), createReverseProxy: vi.fn(), setReverseProxyEnabled: vi.fn(), deleteReverseProxy: vi.fn() }));

const rule = { id: 'r1', name: 'Payments', listen: '127.0.0.1:9000', upstream: 'https://api.example.com', tls: false, rewrite_host: true, enabled: true, running: true, error: null };

beforeEach(() => {
  vi.mocked(fetchReverseProxies).mockReset().mockResolvedValue({ available: true, rules: [] });
  vi.mocked(createReverseProxy).mockReset().mockResolvedValue(rule);
  vi.mocked(setReverseProxyEnabled).mockReset().mockResolvedValue({ ...rule, running: false });
  vi.mocked(deleteReverseProxy).mockReset().mockResolvedValue();
});

it('renders nothing when this instance runs no proxy', async () => {
  vi.mocked(fetchReverseProxies).mockResolvedValue({ available: false, rules: [] });
  const { container } = render(<ReverseProxySettings />);
  await waitFor(() => expect(fetchReverseProxies).toHaveBeenCalled());
  expect(container.textContent).toBe('');
});

it('creates a reverse proxy that rewrites Host by default', async () => {
  render(<ReverseProxySettings />);
  fireEvent.change(await screen.findByLabelText('Reverse proxy upstream'), { target: { value: 'https://api.example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Add' }));
  await waitFor(() => expect(createReverseProxy).toHaveBeenCalledWith({ name: 'https://api.example.com', listen: '127.0.0.1:9000', upstream: 'https://api.example.com', tls: false, rewrite_host: true }));
});

it('stops and deletes a rule, and shows a bind error and network exposure', async () => {
  vi.mocked(fetchReverseProxies).mockResolvedValue({ available: true, rules: [rule, { ...rule, id: 'r2', name: 'Open', listen: '0.0.0.0:9100', running: false, error: 'cannot listen on 0.0.0.0:9100: address in use' }] });
  render(<ReverseProxySettings />);
  fireEvent.click(await screen.findByRole('switch', { name: 'Stop Payments' }));
  await waitFor(() => expect(setReverseProxyEnabled).toHaveBeenCalledWith('r1', false));
  expect(screen.getByText('Reachable from the network, no authentication')).toBeTruthy();
  expect(screen.getByRole('alert').textContent).toContain('address in use');
  fireEvent.click(screen.getByRole('button', { name: 'Delete Payments' }));
  await waitFor(() => expect(deleteReverseProxy).toHaveBeenCalledWith('r1'));
});
