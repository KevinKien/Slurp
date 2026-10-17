import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { ProxyListenerSettingsPanel } from '@/components/proxy-listener-settings';
import { fetchProxyInterfaces, proxyListenerSettings } from '@/lib/api';
vi.mock('@/lib/api', () => ({ proxyListenerSettings: vi.fn(), fetchProxyInterfaces: vi.fn() }));
const request = vi.mocked(proxyListenerSettings);
beforeEach(() => {
  request.mockReset();
  vi.mocked(fetchProxyInterfaces).mockReset().mockResolvedValue([{ name: 'en0', address: '192.168.1.10' }]);
});
it('loads the active port and confirms successful updates', async () => {
  request.mockResolvedValueOnce({ host: '127.0.0.1', port: 8888 }).mockResolvedValueOnce({ host: '127.0.0.1', port: 9999 });
  render(<ProxyListenerSettingsPanel/>);
  await screen.findByText('Listening on 127.0.0.1:8888');
  fireEvent.change(screen.getByLabelText('Proxy port'), { target: { value: '9999' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
  await screen.findByText('Proxy listener updated and saved.');
  expect(request).toHaveBeenLastCalledWith({ host: '127.0.0.1', port: 9999 });
  expect(screen.getByText('Listening on 127.0.0.1:9999')).toBeTruthy();
});
it('keeps the active address on a failed update and rejects invalid ports', async () => {
  request.mockResolvedValueOnce({ host: '127.0.0.1', port: 8888 }).mockRejectedValueOnce(new Error('Port is occupied'));
  render(<ProxyListenerSettingsPanel/>);
  await screen.findByText('Listening on 127.0.0.1:8888');
  fireEvent.change(screen.getByLabelText('Proxy port'), { target: { value: '0' } });
  expect((screen.getByRole('button', { name: 'Apply' }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(screen.getByLabelText('Proxy port'), { target: { value: '9999' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Port is occupied'));
  expect(screen.getByText('Listening on 127.0.0.1:8888')).toBeTruthy();
  expect(screen.queryByText('Proxy listener updated and saved.')).toBeNull();
});

it('applies all IPv4 interfaces at the same port', async () => {
  request.mockResolvedValueOnce({ host: '127.0.0.1', port: 8888 }).mockResolvedValueOnce({ host: '0.0.0.0', port: 8888 });
  render(<ProxyListenerSettingsPanel/>);
  await screen.findByText('Listening on 127.0.0.1:8888');
  fireEvent.change(screen.getByLabelText('Proxy IP address'), { target: { value: '0.0.0.0' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
  await screen.findByText('Listening on 0.0.0.0:8888');
  expect(request).toHaveBeenLastCalledWith({ host: '0.0.0.0', port: 8888 });
});

it('detects and selects a LAN interface without changing the port', async () => {
  request.mockResolvedValueOnce({ host: '127.0.0.1', port: 8888 }).mockResolvedValueOnce({ host: '192.168.1.10', port: 8888 });
  render(<ProxyListenerSettingsPanel/>);
  await screen.findByRole('option', { name: '192.168.1.10 (en0)' });
  await screen.findByText('Listening on 127.0.0.1:8888');
  fireEvent.change(screen.getByLabelText('Proxy IP address'), { target: { value: '192.168.1.10' } });
  fireEvent.click(screen.getByRole('button', { name: 'Apply' }));
  await screen.findByText('Listening on 192.168.1.10:8888');
  expect(request).toHaveBeenLastCalledWith({ host: '192.168.1.10', port: 8888 });
});
it('refreshes detected IPs after a network change', async () => {
  request.mockResolvedValue({ host: '127.0.0.1', port: 8888 });
  render(<ProxyListenerSettingsPanel/>);
  await screen.findByRole('option', { name: '192.168.1.10 (en0)' });
  vi.mocked(fetchProxyInterfaces).mockResolvedValueOnce([{ name: 'en1', address: '192.168.2.20' }]);
  fireEvent.click(screen.getByRole('button', { name: 'Refresh IPs' }));
  await screen.findByRole('option', { name: '192.168.2.20 (en1)' });
  expect(screen.queryByRole('option', { name: '192.168.1.10 (en0)' })).toBeNull();
});
