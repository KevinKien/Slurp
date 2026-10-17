#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: node scripts/package.mjs [--input standalone-directory]\nPackages a native standalone build: macOS DMG, Linux binary, Windows EXE.');
  process.exit(0);
}
if (args.length && (args.length !== 2 || args[0] !== '--input')) throw new Error('Use --help.');
const platform = { darwin: 'macos', linux: 'linux', win32: 'windows' }[process.platform];
if (!platform) throw new Error('Unsupported platform');
const version = readFileSync(join(root, 'crates/cli/Cargo.toml'), 'utf8').match(/^version = "([^"]+)"/m)[1];
const name = `slurp-${version}-${platform}-${process.arch}`;
const input = args.length ? resolve(args[1]) : join(root, 'dist', `${name}-standalone`);
const executable = process.platform === 'win32' ? 'slurp.exe' : 'slurp';
if (!existsSync(join(input, executable))) throw new Error(`Missing ${join(input, executable)}. Run node scripts/build.mjs first.`);
const output = join(root, 'dist', 'artifacts');
mkdirSync(output, { recursive: true });
const artifact = join(output, name + (process.platform === 'darwin' ? '.dmg' : process.platform === 'win32' ? '.exe' : ''));
if (existsSync(artifact)) throw new Error(`Output already exists: ${artifact}. Move it aside before packaging.`);
if (process.platform === 'darwin') {
  const staging = mkdtempSync(join(tmpdir(), 'slurp-dmg-'));
  const folder = join(staging, 'Slurp');
  mkdirSync(folder);
  copyFileSync(join(input, executable), join(folder, executable));
  chmodSync(join(folder, executable), 0o755);
  if (existsSync(join(input, 'README.txt'))) copyFileSync(join(input, 'README.txt'), join(folder, 'README.txt'));
  writeFileSync(join(folder, 'Start Slurp.command'), '#!/bin/sh\ncd -- "$(dirname -- "$0")" || exit 1\nexec ./slurp\n', { mode: 0o755 });
  writeFileSync(join(staging, 'INSTALL.txt'), 'Slurp — Sip traffic\n\nCopy the Slurp folder to your Mac, then eject this disk.\nDouble-click Start Slurp.command, or run ./slurp in Terminal.\nThe browser opens automatically. Press Ctrl+C in Terminal to stop.\nThis build is unsigned and not notarized.\n');
  const result = spawnSync('hdiutil', ['create', '-volname', 'Slurp', '-srcfolder', staging, '-format', 'UDZO', artifact], { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`hdiutil exited with ${result.status}`);
} else {
  copyFileSync(join(input, executable), artifact);
  if (process.platform === 'linux') chmodSync(artifact, 0o755);
}
const checksum = createHash('sha256').update(readFileSync(artifact)).digest('hex');
writeFileSync(`${artifact}.sha256`, `${checksum}  ${artifact.split(/[\\/]/).at(-1)}\n`);
console.log(`Package ready: ${artifact}`);
