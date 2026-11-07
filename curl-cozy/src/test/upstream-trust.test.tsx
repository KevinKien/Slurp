import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { UpstreamTrustSettings } from '@/components/upstream-trust';
import { addTrustedCa, fetchUpstreamTrust, removeTrustedCa, setTrustSystemStore } from '@/lib/api';

vi.mock('@/lib/api', () => ({ fetchUpstreamTrust: vi.fn(), addTrustedCa: vi.fn(), removeTrustedCa: vi.fn(), setTrustSystemStore: vi.fn() }));

const ca = { name: 'staging-ca', source: 'file' as const, subject: 'CN=Staging Root', issuer: 'CN=Staging Root', fingerprint_sha256: 'AA:BB', not_before: 0, not_after: 4_000_000_000, is_ca: true, expired: false };
const empty = { system: false, system_locked: false, system_certificates: 0, cas: [] };

beforeEach(() => {
  vi.mocked(fetchUpstreamTrust).mockReset().mockResolvedValue(empty);
  vi.mocked(addTrustedCa).mockReset().mockResolvedValue([ca]);
  vi.mocked(removeTrustedCa).mockReset().mockResolvedValue();
  vi.mocked(setTrustSystemStore).mockReset().mockResolvedValue({ ...empty, system: true, system_certificates: 120 });
});

it('uploads a CA file under a sanitized name and lists what is trusted', async () => {
  vi.mocked(fetchUpstreamTrust).mockResolvedValueOnce(empty).mockResolvedValue({ ...empty, cas: [ca] });
  render(<UpstreamTrustSettings />);
  const file = new File(['-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n'], 'Staging CA.crt');
  fireEvent.change(await screen.findByLabelText('Choose CA certificate file'), { target: { files: [file] } });
  await waitFor(() => expect(addTrustedCa).toHaveBeenCalledWith('Staging-CA', expect.stringContaining('BEGIN CERTIFICATE')));
  expect(await screen.findByText('CN=Staging Root')).toBeTruthy();
});

it('removes a trusted CA and keeps environment-provided CAs read-only', async () => {
  vi.mocked(fetchUpstreamTrust).mockResolvedValue({ ...empty, cas: [ca, { ...ca, name: 'corp.pem', source: 'env' }] });
  render(<UpstreamTrustSettings />);
  fireEvent.click(await screen.findByRole('button', { name: 'Remove staging-ca' }));
  await waitFor(() => expect(removeTrustedCa).toHaveBeenCalledWith('staging-ca'));
  expect(screen.queryByRole('button', { name: 'Remove corp.pem' })).toBeNull();
});

it('toggles the system store and respects the environment lock', async () => {
  render(<UpstreamTrustSettings />);
  fireEvent.click(await screen.findByRole('switch', { name: 'Trust the system certificate store' }));
  await waitFor(() => expect(setTrustSystemStore).toHaveBeenCalledWith(true));
});

it('disables the switch when the environment forces the system store on', async () => {
  vi.mocked(fetchUpstreamTrust).mockResolvedValue({ ...empty, system: true, system_locked: true, system_certificates: 5 });
  render(<UpstreamTrustSettings />);
  const toggle = (await screen.findByRole('switch', { name: 'Trust the system certificate store' })) as HTMLButtonElement;
  expect(toggle.disabled).toBe(true);
});
