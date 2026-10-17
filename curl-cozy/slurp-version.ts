import { readFileSync } from 'node:fs';
export const slurpVersion = readFileSync(new URL('../Cargo.toml', import.meta.url), 'utf8').match(/^version = "([^\"]+)"/m)![1];
