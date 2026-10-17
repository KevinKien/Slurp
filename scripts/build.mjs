#!/usr/bin/env node
// Native builds: run this script on the OS/architecture you want to distribute.
import { spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const backendOnly = process.argv.includes('--backend-only');
if (process.argv.includes('--help')) {
  console.log('Usage: node scripts/build.mjs [--backend-only]\nBuilds a native release for the current OS and architecture into dist/.');
  process.exit(0);
}
if (process.argv.slice(2).some(arg => arg !== '--backend-only')) {
  throw new Error('Unknown option. Use --help.');
}
if (!['darwin', 'linux', 'win32'].includes(process.platform)) throw new Error('Unsupported platform');
if (process.env.CARGO_BUILD_TARGET) throw new Error('Native builds only: unset CARGO_BUILD_TARGET.');
const label = { darwin: 'macos', linux: 'linux', win32: 'windows' }[process.platform];
const version = readFileSync(join(root, 'Cargo.toml'), 'utf8').match(/^version = "([^"]+)"/m)[1];
const output = join(root, 'dist', `slurp-${version}-${label}-${process.arch}${backendOnly ? '-backend' : '-standalone'}`);
if (existsSync(output)) throw new Error(`Output already exists: ${output}. Move it aside before rebuilding.`);
function run(command, args, cwd = root, extraEnv = {}) {
  console.log(`> ${command} ${args.join(' ')}`);
  // npm.cmd requires cmd.exe on Windows; every argument here is a fixed script literal.
  const result = spawnSync(command, args, {
    cwd, stdio: 'inherit', shell: process.platform === 'win32' && command === 'npm',
    env: { ...process.env, ...extraEnv },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited with code ${result.status}`);
}
if (!backendOnly) {
  const frontend = join(root, 'curl-cozy');
  if (!existsSync(join(frontend, 'node_modules'))) {
    run('bun', ['install', '--frozen-lockfile'], frontend);
  }
  run(process.execPath, [join(frontend, 'node_modules/typescript/bin/tsc'), '--noEmit'], frontend);
  run('npm', ['run', 'build:standalone'], frontend);
  if (!existsSync(join(frontend, 'dist-rust/index.html'))) {
    throw new Error('Missing standalone UI entry: dist-rust/index.html');
  }
}
run('cargo', ['build', '--release', '--locked', '-p', 'slurp', ...(backendOnly ? [] : ['--features', 'embedded-ui'])], root,
  backendOnly ? {} : { SLURP_UI_DIR: join(root, 'curl-cozy/dist-rust') });
mkdirSync(output, { recursive: true });
const executable = process.platform === 'win32' ? 'slurp.exe' : 'slurp';
const targetDir = process.env.CARGO_TARGET_DIR ? resolve(root, process.env.CARGO_TARGET_DIR) : join(root, 'target');
cpSync(join(targetDir, 'release', executable), join(output, executable));
writeFileSync(join(output, 'README.txt'), `Slurp — Sip traffic\nPlatform: ${label} ${process.arch}\n\nRun: ./${executable} (Windows: .\\${executable})\n${backendOnly
  ? 'Backend-only build. No embedded UI.\n'
  : 'UI and API: http://127.0.0.1:5174/dashboard\nThe browser opens automatically. Use --no-open to disable this.\nNo Node.js runtime is required.\n'}Proxy: http://127.0.0.1:8888 (unless saved settings override it)\nCtrl+C stops Slurp.\nData/CA: ~/.slurp on macOS/Linux; %USERPROFILE%\\.slurp on Windows.\nInstall ca.crt in your OS/browser to trust captured HTTPS traffic.\n`);
console.log(`\nRelease ready: ${output}`);
