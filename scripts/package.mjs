#!/usr/bin/env node
import { packageMacOS } from './package-macos.mjs';
import { createHash } from 'node:crypto';
import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const options = {};
for (let i = 0; i < args.length && args[i] !== '--help'; i += 2) {
  if (!['--input', '--arch'].includes(args[i]) || !args[i + 1] || options[args[i]]) throw new Error('Use --help.');
  options[args[i]] = args[i + 1];
}
const arch = options['--arch'] ?? process.arch;
if (!['x64', 'arm64'].includes(arch)) throw new Error('Supported architectures: x64, arm64');
if (arch !== process.arch && process.platform !== 'darwin') throw new Error('--arch is supported only for macOS cross-packaging.');
if (args.includes('--help')) {
  console.log('Usage: node scripts/package.mjs [--input standalone-directory] [--arch x64|arm64]\nPackages a native standalone build: macOS DMG, Linux binary, Windows EXE.');
  process.exit(0);
}
const platform = { darwin: 'macos', linux: 'linux', win32: 'windows' }[process.platform];
if (!platform) throw new Error('Unsupported platform');
const version = readFileSync(join(root, 'Cargo.toml'), 'utf8').match(/^version = "([^"]+)"/m)[1];
const name = `slurp-${version}-${platform}-${arch}`;
const input = options['--input'] ? resolve(options['--input']) : join(root, 'dist', `${name}-standalone`);
const executable = process.platform === 'win32' ? 'slurp.exe' : 'slurp';
if (!existsSync(join(input, executable))) throw new Error(`Missing ${join(input, executable)}. Run node scripts/build.mjs first.`);
const output = join(root, 'dist', 'artifacts');
mkdirSync(output, { recursive: true });
const artifact = join(output, name + (process.platform === 'darwin' ? '.dmg' : process.platform === 'win32' ? '.exe' : ''));
if (existsSync(artifact)) throw new Error(`Output already exists: ${artifact}. Move it aside before packaging.`);
if (process.platform === 'darwin') {
  packageMacOS({ root, input, output, name, arch, version, artifact });
} else {
  copyFileSync(join(input, executable), artifact);
  if (process.platform === 'linux') chmodSync(artifact, 0o755);
}
const checksum = createHash('sha256').update(readFileSync(artifact)).digest('hex');
writeFileSync(`${artifact}.sha256`, `${checksum}  ${artifact.split(/[\\/]/).at(-1)}\n`);
console.log(`Package ready: ${artifact}`);
