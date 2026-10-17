import type { ReplayVariables } from './replay-features';
import { methods } from './traffic';

/** What is persisted for one Replay tab. Responses and in-flight state are not stored. */
export interface StoredTab {
  id: number;
  name: string;
  customName?: boolean;
  afterResponse?: string;
  wsKind?: "text" | "binary";
  request: { method: string; url: string; headers: Record<string, string>; body: string };
}

/** The saved Replay document of a workspace. */
export interface StoredReplay {
  tabs: StoredTab[];
  active: number | null;
  variables?: ReplayVariables;
}

const MAX_TABS = 100;
const MAX_NAME = 200;
const MAX_URL = 4096;
const MAX_HEADERS = 200;
const MAX_BODY = 1_000_000; // same limit the replay endpoint enforces

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/**
 * Turn whatever was stored into valid tabs. The document comes from disk and may be from an older
 * version or damaged, so every field is checked rather than trusted; unusable tabs are skipped.
 */
export function normalizeStoredTabs(doc: unknown): StoredTab[] {
  const raw = isRecord(doc) && Array.isArray(doc['tabs']) ? (doc['tabs'] as unknown[]) : [];
  const seen = new Set<number>();
  const tabs: StoredTab[] = [];
  for (const item of raw) {
    if (tabs.length >= MAX_TABS) break;
    if (!isRecord(item) || !isRecord(item['request'])) continue;
    const id = item['id'];
    if (typeof id !== 'number' || !Number.isInteger(id) || id < 1 || seen.has(id)) continue;
    seen.add(id);

    const req = item['request'];
    const rawMethod = req['method'];
    const method = typeof rawMethod === 'string' ? rawMethod.toUpperCase() : 'GET';
    const headers: Record<string, string> = {};
    const rawHeaders = req['headers'];
    if (isRecord(rawHeaders)) {
      for (const [k, v] of Object.entries(rawHeaders).slice(0, MAX_HEADERS)) {
        if (typeof v === 'string') headers[k] = v;
      }
    }
    const rawName = item['name'];
    const name = typeof rawName === 'string' && rawName.trim() ? rawName.trim().slice(0, MAX_NAME) : 'Untitled request';
    const url = req['url'];
    const body = req['body'];
    tabs.push({
      id,
      name,
      ...(item["wsKind"] === "binary" && {wsKind:"binary" as const}),
      ...(typeof item['afterResponse']==='string' && {afterResponse:item['afterResponse'].slice(0,32000)}),
      ...(item['customName'] === true && { customName: true }),
      request: {
        method: methods.includes(method) ? method : 'GET',
        url: typeof url === 'string' ? url.slice(0, MAX_URL) : '',
        headers,
        body: typeof body === 'string' ? body.slice(0, MAX_BODY) : '',
      },
    });
  }
  return tabs;
}

/** The stored active tab if it still exists, otherwise the first one. */
export function pickActive(tabs: StoredTab[], active: unknown): number {
  return tabs.find((t) => t.id === active)?.id ?? tabs[0]?.id ?? 1;
}

interface TabLike {
  id: number;
  name: string;
  customName?: boolean | undefined;
  afterResponse?: string;
  wsKind?: "text" | "binary";
  request: StoredTab['request'];
}

/** The document to save for the current tabs: persisted fields only. */
export function serializeTabs(tabs: TabLike[], active: number, variables: ReplayVariables = {}): StoredReplay {
  return {
    tabs: tabs.map((t) => ({
      id: t.id,
      name: t.name,
      ...(t.wsKind && {wsKind:t.wsKind}),
      ...(t.afterResponse && {afterResponse:t.afterResponse.slice(0,32000)}),
      ...(t.customName && { customName: true }),
      request: { method: t.request.method, url: t.request.url, headers: t.request.headers, body: t.request.body },
    })),
    active,
    ...(Object.keys(variables).length && { variables }),
  };
}

let lastTabId=0;
export function nextReplayTabId(tabs:{id:number}[]):number {
  lastTabId=Math.max(lastTabId+1,Date.now(),...tabs.map(tab=>tab.id+1));return lastTabId;
}
