import { beforeEach, expect, it, vi } from 'vitest';

beforeEach(() => {
  vi.resetModules();
  sessionStorage.clear();
  window.history.replaceState(null, '', '/dashboard');
});

it('offers a public WebSocket protocol alongside the private credential', async () => {
  const { setApiToken, websocketProtocols } = await import('@/lib/api-auth');
  const token = 'a'.repeat(64);
  setApiToken(token);
  expect(websocketProtocols()).toEqual(['slurp.v1', `slurp-auth.${token}`]);
});

it('consumes the startup token before opening a WebSocket and removes it from the URL', async () => {
  const token = 'b'.repeat(64);
  window.history.replaceState(null, '', `/dashboard#slurp-token=${token}`);
  const { websocketProtocols } = await import('@/lib/api-auth');
  expect(websocketProtocols()).toEqual(['slurp.v1', `slurp-auth.${token}`]);
  expect(window.location.hash).toBe('');
  expect(sessionStorage.getItem('slurp.management-token')).toBe(token);
});

it('does not invent credentials for a disconnected browser', async () => {
  const { websocketProtocols } = await import('@/lib/api-auth');
  expect(websocketProtocols()).toEqual([]);
});
