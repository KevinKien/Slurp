// Credentials stay in this browser tab and are never sent to replay destinations.
const key = 'slurp.management-token';
let memoryToken = '';
export function getApiToken(): string {
  if (typeof window === 'undefined') return '';
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const supplied = fragment.get('slurp-token');
  if (supplied && /^[a-f0-9]{64}$/i.test(supplied)) {
    memoryToken = supplied;
    try { sessionStorage.setItem(key, supplied); } catch {}
    fragment.delete('slurp-token');
    window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search + (fragment.size ? `#${fragment}` : ''));
  }
  if (!memoryToken) { try { memoryToken = sessionStorage.getItem(key) ?? ''; } catch {} }
  return memoryToken;
}
export function setApiToken(value: string) {
  const token = value.includes('#') ? new URLSearchParams(value.slice(value.indexOf('#') + 1)).get('slurp-token') ?? '' : value.trim();
  if (!/^[a-f0-9]{64}$/i.test(token)) throw Error('Paste the Slurp startup URL or its connection token.');
  memoryToken = token;
  try { sessionStorage.setItem(key, token); } catch {}
}
export async function authorizedFetch(input: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  const token = getApiToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(input, { ...init, headers });
  if (response.status === 401 && typeof window !== 'undefined') window.dispatchEvent(new Event('slurp:authorization-required'));
  return response;
}
export function websocketProtocols(): string[] {
  const token = getApiToken();
  // The server selects the public protocol; the credential is never echoed.
  return token ? ['slurp.v1', `slurp-auth.${token}`] : [];
}
