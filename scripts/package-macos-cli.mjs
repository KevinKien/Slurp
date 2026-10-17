#!/usr/bin/env node
// Combine the two native CLI archives into one universal macOS CLI package.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.includes('--help')) {
  console.log('Usage: node scripts/package-macos-cli.mjs --intel <x64-cli.tar.gz> --arm64 <arm64-cli.tar.gz>');
  process.exit(0);
}
const options = {};
for (let i = 0; i < args.length; i += 2) {
  if (!['--intel', '--arm64'].includes(args[i]) || !args[i + 1] || options[args[i]]) throw new Error('Use --help.');
  options[args[i]] = resolve(args[i + 1]);
}
if (process.platform !== 'darwin' || !options['--intel'] || !options['--arm64']) throw new Error('Run on macOS with both native CLI archives (see --help).');
function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed (${result.status})`);
}
const version = readFileSync(join(root, 'Cargo.toml'), 'utf8').match(/^version = "([^"]+)"/m)[1];
const staging = mkdtempSync(join(tmpdir(), 'slurp-universal-'));
for (const arch of ['x64', 'arm64']) {
  const archive = options[arch === 'x64' ? '--intel' : '--arm64'];
  run('tar', ['-xzf', archive, '-C', staging]);
}
const name = `slurp-${version}-macos-universal-cli`;
const folder = join(staging, name);
mkdirSync(folder);
const binary = join(folder, 'slurp');
run('lipo', ['-create', join(staging, `slurp-${version}-macos-x64-cli/slurp`), join(staging, `slurp-${version}-macos-arm64-cli/slurp`), '-output', binary]);
run('lipo', [binary, '-verify_arch', 'x86_64', 'arm64']);
chmodSync(binary, 0o755);
run('codesign', ['--force', '--sign', '-', binary]);
run('codesign', ['--verify', '--strict', binary]);
writeFileSync(join(folder, 'README.txt'), 'Slurp CLI — Intel and Apple Silicon\nRequires macOS 12 or newer.\n\nExtract this folder and run ./slurp from Terminal.\nUI/API are embedded; the browser opens automatically. Use ./slurp --no-open to disable opening it.\nUse ./slurp mcp for the MCP stdio server. Ctrl+C stops Slurp.\nData/CA: ~/.slurp\nAd-hoc signed, not notarized. No Node.js required.\nDo not run alongside Slurp.app on the same ports.\n');
const output = join(root, 'dist/artifacts');
mkdirSync(output, { recursive: true });
const archive = join(output, `${name}.tar.gz`);
if (existsSync(archive)) throw new Error(`Output already exists: ${archive}`);
run('tar', ['-czf', archive, '-C', staging, name]);
writeFileSync(`${archive}.sha256`, `${createHash('sha256').update(readFileSync(archive)).digest('hex')}  ${name}.tar.gz\n`);
console.log(`Universal CLI: ${archive}`);
