import { authorizedFetch } from '@/lib/api-auth';
import { API_BASE } from './api';

export interface SendRequest {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
  url: string;
  headers: Record<string, string>;
  body: string;
  timeout: number;
}
export type SendResult = {
  ok: true; status: number; statusText: string; duration: number; size: number;
  responseHeaders: Record<string, string>; setCookies: string[]; responseBody: string;
} | { ok: false; error: string };

// Keep the call shape shared by Replay, Flows, Intruder, Matrix and Scan.
export async function sendHttpRequest({ data }: { data: SendRequest }): Promise<SendResult> {
  try {
    const response = await authorizedFetch(`${API_BASE}/api/replay/send`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data), signal: AbortSignal.timeout(data.timeout + 5000),
    });
    if (!response.ok) {
      const detail = await response.json().catch(() => null);
      throw new Error(detail?.error ?? `Request failed (${response.status})`);
    }
    return await response.json() as SendResult;
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : 'Request failed' };
  }
}
