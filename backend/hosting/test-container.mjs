// Exercise only the named local image; never deploy or pass owner credentials.
import { readFile, writeFile } from 'node:fs/promises';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import assert from 'node:assert/strict';
const exec = promisify(execFile), name = 'huma-publication-check-' + randomUUID();
const image = process.argv[2];
if (!image?.match(/^huma-publication-host:local-[a-z0-9-]+$/)) throw Error('Use a local Huma publication image tag.');
const fixtures = [];
for (const [label, file] of [['noir64', 'extra/experiments/noir-compact/browser/test/fixtures/Assurance64.json'],
  ['noir64-unicode', 'extra/experiments/noir-compact/browser/test/fixtures/Assurance64Unicode.json'],
  ['noir128-boundary', 'extra/experiments/noir-compact/browser/test/fixtures/Assurance128Boundary.json'],
  ['noir128-unicode', 'extra/experiments/noir-compact/browser/test/fixtures/Assurance128Unicode.json'],
  ['noir-cp32', 'extra/experiments/noir-compact/browser/test/fixtures/AssuranceCP32.json'],
]) {
  const proof = await readFile(file, 'utf8');
  const parsed=JSON.parse(proof);
  fixtures.push({ name: label, proof, master: Buffer.from(parsed.text + ' \t').toString('base64'), mediaType: 'text/plain;charset=utf-8',
    checkpointSignatures: parsed.signatures?.length });
}
for (const [kind, extension, mediaType] of [['image', 'png', 'image/png'], ['audio', 'flac', 'audio/flac'], ['video', 'mp4', 'video/mp4']]) {
  const prefix = 'extra/experiments/noir-media/reader/test/fixtures/' + kind;
  fixtures.push({ name: kind, proof: await readFile(prefix + '.json', 'utf8'), master: (await readFile(prefix + '.' + extension)).toString('base64'), mediaType });
}
const script = await readFile(new URL('./container-acceptance.mjs', import.meta.url), 'utf8');
const child = spawn('docker', ['run', '--name', name, '--network', 'none', '--read-only', '--cap-drop', 'ALL',
  '--security-opt', 'no-new-privileges=true', '--cpus', '2', '--memory', '768m',
  '--tmpfs', '/app/web/data:uid=1000,gid=1000,mode=0700', '--tmpfs', '/tmp:uid=1000,gid=1000,mode=0700',
  '-e', 'HUMA_STORAGE_BACKEND=local', '-i', image, 'node', '--input-type=module', '-e', script], { stdio: ['pipe', 'pipe', 'pipe'] });
let stdout = '', stderr = '', timer;
child.stdout.on('data', chunk => { if (stdout.length < 65536) stdout += chunk; });
child.stderr.on('data', chunk => { if (stderr.length < 4000) stderr += chunk; });
child.stdin.on('error', () => {}); child.stdin.end(JSON.stringify({ fixtures }));
try {
  const code = await Promise.race([new Promise((resolve, reject) => { child.once('error', reject); child.once('exit', resolve); }),
    new Promise((_, reject) => { timer = setTimeout(() => reject(Error('Container acceptance timed out.')), 120000); })]);
  if (code !== 0) throw Error('Container acceptance failed: ' + stderr.slice(-2000));
  const report = JSON.parse(stdout.trim());
  const details = JSON.parse((await exec('docker', ['inspect', name], { timeout: 10000 })).stdout)[0];
  assert.equal(details.HostConfig.NetworkMode, 'none'); assert.equal(details.HostConfig.ReadonlyRootfs, true);
  assert.equal(details.Config.User, 'node'); assert.equal(report.uid, 1000); assert.equal(report.platform, 'linux');
  assert.equal(report.cases.length, 8); assert.equal(report.passed, true);
  Object.assign(report, { image, networkMode: 'none', readOnlyRoot: true, nonRootUser: true });
  await writeFile('build/publication-host-container-results.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report));
} finally {
  clearTimeout(timer);
  await exec('docker', ['rm', '-f', name], { timeout: 10000 }).catch(() => {});
  if (child.exitCode === null) child.kill('SIGTERM');
}
