export type UuidVersion = 'v4' | 'v7';

export interface UuidOptions {
  version: UuidVersion;
  uppercase?: boolean;
  /** Keep the hyphens (default true). */
  hyphens?: boolean;
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

function format(bytes: Uint8Array): string {
  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Random UUID (version 4) from the browser's cryptographic random source. */
function uuidV4(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  return format(bytes);
}

// State for v7: UUIDs made in the same millisecond must still sort in creation order (RFC 9562, 6.2 method 1).
let lastMs = 0;
let counter = 0;

/** Time-ordered UUID (version 7): 48-bit millisecond timestamp, then a counter and random bits. */
function uuidV7(now: number = Date.now()): string {
  let ms = now;
  if (ms <= lastMs) {
    ms = lastMs;
    counter += 1;
    if (counter > 0xfff) {
      // Counter exhausted within one millisecond: borrow the next one.
      ms += 1;
      counter = 0;
    }
  } else {
    counter = crypto.getRandomValues(new Uint16Array(1))[0]! & 0x7ff; // leave headroom so it can count up
  }
  lastMs = ms;

  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[0] = Math.floor(ms / 2 ** 40) & 0xff;
  bytes[1] = Math.floor(ms / 2 ** 32) & 0xff;
  bytes[2] = Math.floor(ms / 2 ** 24) & 0xff;
  bytes[3] = Math.floor(ms / 2 ** 16) & 0xff;
  bytes[4] = Math.floor(ms / 2 ** 8) & 0xff;
  bytes[5] = ms & 0xff;
  bytes[6] = 0x70 | ((counter >> 8) & 0x0f);
  bytes[7] = counter & 0xff;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  return format(bytes);
}

/** Generate `count` UUIDs (1 to 1000). */
export function generateUuids(count: number, options: UuidOptions): string[] {
  const n = Math.min(1000, Math.max(1, Math.floor(count) || 1));
  return Array.from({ length: n }, () => {
    let id = options.version === 'v7' ? uuidV7() : uuidV4();
    if (options.hyphens === false) id = id.replace(/-/g, '');
    return options.uppercase ? id.toUpperCase() : id;
  });
}
