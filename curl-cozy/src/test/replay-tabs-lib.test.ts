import { describe, expect, it } from 'vitest';
import { normalizeStoredTabs, pickActive, serializeTabs } from '@/lib/replay-tabs';

const tab = (over: Record<string, unknown> = {}) => ({
  id: 1,
  name: 'Login',
  request: { method: 'POST', url: 'https://api.acme.io/login', headers: { Accept: 'application/json' }, body: '{"u":1}' },
  ...over,
});

describe('normalizeStoredTabs', () => {
  it('round-trips what serializeTabs writes, dropping responses and in-flight state', () => {
    const live = [
      { ...tab(), customName: true, response: { status: 200 }, loading: true, error: 'x' },
      tab({ id: 2, name: 'Other' }),
    ];
    const doc = serializeTabs(live as never, 2);
    expect(doc).toEqual({
      tabs: [
        { id: 1, name: 'Login', customName: true, request: tab().request },
        { id: 2, name: 'Other', request: tab().request },
      ],
      active: 2,
    });
    expect(normalizeStoredTabs(JSON.parse(JSON.stringify(doc)))).toEqual(doc.tabs);
  });

  it('returns nothing for missing or malformed documents', () => {
    for (const bad of [null, undefined, 42, 'x', [], {}, { tabs: 'nope' }, { tabs: {} }]) {
      expect(normalizeStoredTabs(bad)).toEqual([]);
    }
  });

  it('skips unusable tabs and duplicate ids but keeps the good ones', () => {
    const tabs = normalizeStoredTabs({
      tabs: [tab({ id: 0 }), tab({ id: 1.5 }), tab({ id: '3' }), null, 'x', tab({ id: 4, request: null }), tab({ id: 5 }), tab({ id: 5, name: 'dup' })],
    });
    expect(tabs.map((t) => [t.id, t.name])).toEqual([[5, 'Login']]);
  });

  it('repairs individual fields', () => {
    const [t] = normalizeStoredTabs({
      tabs: [
        {
          id: 9,
          name: '   ',
          customName: 'yes',
          request: { method: 'fetch', url: 42, headers: { ok: 'v', bad: 1, worse: null }, body: { not: 'a string' } },
        },
      ],
    });
    expect(t).toEqual({ id: 9, name: 'Untitled request', request: { method: 'GET', url: '', headers: { ok: 'v' }, body: '' } });
  });

  it('upper-cases methods, and bounds sizes and counts', () => {
    const [t] = normalizeStoredTabs({ tabs: [tab({ name: 'x'.repeat(500), request: { method: 'post', url: 'u'.repeat(9000), headers: {}, body: '' } })] });
    expect(t?.request.method).toBe('POST');
    expect(t?.name).toHaveLength(200);
    expect(t?.request.url).toHaveLength(4096);
    const many = { tabs: Array.from({ length: 150 }, (_, i) => tab({ id: i + 1 })) };
    expect(normalizeStoredTabs(many)).toHaveLength(100);
  });
});

describe('pickActive', () => {
  const tabs = normalizeStoredTabs({ tabs: [tab({ id: 3 }), tab({ id: 8 })] });
  it('keeps a valid active tab, otherwise falls back to the first', () => {
    expect(pickActive(tabs, 8)).toBe(8);
    expect(pickActive(tabs, 99)).toBe(3);
    expect(pickActive(tabs, null)).toBe(3);
    expect(pickActive([], 5)).toBe(1);
  });
});

it('persists WebSocket message type and request draft without a live transcript',()=>{
 const live={id:99,name:'Socket',wsKind:'binary' as const,request:{method:'GET',url:'wss://example.com/socket',headers:{},body:'00ff'},wsMessages:[{body:'private response'}]};
 const document=serializeTabs([live],99);
 expect(normalizeStoredTabs(document)[0]).toMatchObject({wsKind:'binary',request:live.request});
 expect(JSON.stringify(document)).not.toContain('private response');
});
