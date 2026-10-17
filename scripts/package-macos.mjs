import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} failed (${result.status})`);
}
function checksum(file) {
  writeFileSync(`${file}.sha256`, `${createHash('sha256').update(readFileSync(file)).digest('hex')}  ${file.split('/').at(-1)}\n`);
}
export function packageMacOS({ root, input, output, name, arch, version, artifact }) {
  const cpu = { x64: 'x86_64', arm64: 'arm64' }[arch];
  if (!cpu) throw new Error('macOS supports x64 or arm64');
  run('lipo', [join(input, 'slurp'), '-verify_arch', cpu]);
  const staging = mkdtempSync(join(tmpdir(), 'slurp-app-'));
  const app = join(staging, 'Slurp.app');
  const contents = join(app, 'Contents');
  const resources = join(contents, 'Resources');
  const executables = join(contents, 'MacOS');
  mkdirSync(resources, { recursive: true });
  mkdirSync(executables);
  const cache = join(root, 'target', 'macos-packaging');
  mkdirSync(cache, { recursive: true });
  const sdk = spawnSync('xcrun', ['--sdk', 'macosx', '--show-sdk-path'], { encoding: 'utf8' });
  if (sdk.status !== 0) throw new Error('macOS SDK is required');
  const swift = ['-swift-version', '5', '-O', '-module-cache-path', join(cache, 'module-cache'), '-sdk', sdk.stdout.trim()];
  run('xcrun', ['swiftc', ...swift, '-target', `${cpu}-apple-macosx12.0`, join(root, 'scripts/macos/Launcher.swift'), '-o', join(executables, 'Slurp')]);
  const iconTool = join(cache, 'make-icon');
  run('xcrun', ['swiftc', ...swift, join(root, 'scripts/macos/Icon.swift'), '-o', iconTool]);
  const png = join(staging, 'slurp.png');
  run(iconTool, [png]);
  const icons = join(staging, 'Slurp.iconset');
  mkdirSync(icons);
  for (const size of [16, 32, 128, 256, 512]) {
    for (const scale of [1, 2]) {
      run('sips', ['-z', String(size * scale), String(size * scale), png, '--out', join(icons, `icon_${size}x${size}${scale === 2 ? '@2x' : ''}.png`)]);
    }
  }
  run('iconutil', ['-c', 'icns', icons, '-o', join(resources, 'Slurp.icns')]);
  copyFileSync(join(input, 'slurp'), join(resources, 'slurp'));
  chmodSync(join(resources, 'slurp'), 0o755);
  writeFileSync(join(contents, 'Info.plist'), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Slurp</string>
<key>CFBundleDisplayName</key><string>Slurp</string>
<key>CFBundleIdentifier</key><string>io.slurp.proxy</string>
<key>CFBundleExecutable</key><string>Slurp</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>${version}</string>
<key>CFBundleVersion</key><string>${version}</string>
<key>CFBundleIconFile</key><string>Slurp.icns</string>
<key>LSMinimumSystemVersion</key><string>12.0</string>
<key>NSHighResolutionCapable</key><true/>
</dict></plist>\n`);
  for (const path of [join(resources, 'slurp'), join(executables, 'Slurp'), app]) run('codesign', ['--force', '--sign', '-', '--options', 'runtime', path]);
  run('codesign', ['--verify', '--deep', '--strict', '--verbose=2', app]);
  // Keep a directly testable app bundle outside the disk image.
  const appOutput = join(root, 'dist', `${name}.app`);
  if (existsSync(appOutput)) throw new Error(`Output already exists: ${appOutput}`);
  run('ditto', [app, appOutput]);
  const disk = join(staging, 'disk');
  mkdirSync(disk);
  run('ditto', [app, join(disk, 'Slurp.app')]);
  symlinkSync('/Applications', join(disk, 'Applications'));
  writeFileSync(join(disk, 'INSTALL.txt'), `Slurp — Sip traffic (${arch})\nRequires macOS 12 or newer.\n\nDrag Slurp.app into Applications, then open it.\nIf macOS blocks the first launch, open System Settings > Privacy & Security > Open Anyway.\nThe app uses an ad-hoc signature; it is not Developer ID signed or notarized.\n\nThe UI opens in your browser. Open it again from the Slurp menu bar icon or Dock.\nUse Quit Slurp (or Cmd+Q with Slurp active) to stop the backend. Closing the browser does not stop it.\nDo not run the GUI and CLI simultaneously on the same ports.\nData/CA: ~/.slurp\nLogs: ~/Library/Logs/Slurp/slurp.log\n`);
  run('hdiutil', ['create', '-volname', 'Slurp', '-srcfolder', disk, '-format', 'UDZO', artifact]);
  run('codesign', ['--force', '--sign', '-', artifact]);
  checksum(artifact);
  const cli = join(staging, `${name}-cli`);
  mkdirSync(cli);
  copyFileSync(join(input, 'slurp'), join(cli, 'slurp'));
  chmodSync(join(cli, 'slurp'), 0o755);
  run('codesign', ['--force', '--sign', '-', join(cli, 'slurp')]);
  writeFileSync(join(cli, 'README.txt'), `Slurp CLI (${arch})\n\nRun ./slurp in Terminal. UI/API are embedded. Use ./slurp --no-open to skip opening the browser.\nCtrl+C stops the server. Data/CA: ~/.slurp\nNo Node.js required. Ad-hoc signed; not notarized.\n`);
  const archive = join(output, `${name}-cli.tar.gz`);
  if (existsSync(archive)) throw new Error(`Output already exists: ${archive}`);
  run('tar', ['-czf', archive, '-C', staging, `${name}-cli`]);
  checksum(archive);
  console.log(`App: ${appOutput}\nCLI: ${archive}`);
}
