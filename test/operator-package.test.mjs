import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
const root = process.env.AC_OPERATOR_TEST_DIR || process.cwd();
if (!existsSync(join(root, 'SOURCE-MANIFEST.json'))) throw Error('Run inside an extracted operator package or set AC_OPERATOR_TEST_DIR');
const run = (args, cwd, env = {}) => new Promise((resolveRun, reject) => {
  const child = spawn(process.execPath, args, { cwd, env: { PATH: process.env.PATH, ...env } });
  let output = ''; child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { output += b; });
  child.on('error', reject); child.on('close', code => resolveRun({ code, output }));
});
const sha = data => createHash('sha256').update(data).digest('hex');

test('distributed source matches every recorded hash and includes no operator state', () => {
  const manifest = JSON.parse(readFileSync(join(root, 'SOURCE-MANIFEST.json')));
  for (const item of manifest.files) {
    assert.equal(sha(readFileSync(join(root, item.file))), item.sha256, item.file);
    assert.ok(!item.file.startsWith('.local/') && item.file !== '.env');
  }
  assert.equal(existsSync(join(root, '.env')), false);
  assert.equal(existsSync(join(root, '.local')), false);
});

test('setup preserves operator keys when rerun and prints no secret', async () => {
  // Use package entrypoint (so dependencies resolve there) with an isolated state directory.
  const cwd = mkdtempSync(join(tmpdir(), 'ac-setup-test-'));
  const first = await run([resolve(root, 'setup.mjs')], cwd);
  assert.equal(first.code, 0, first.output);
  const payer = readFileSync(join(cwd, '.local/payer.json')), seed = readFileSync(join(cwd, '.local/gateway-seed'));
  const second = await run([resolve(root, 'setup.mjs')], cwd);
  assert.equal(second.code, 0, second.output);
  assert.equal(sha(readFileSync(join(cwd, '.local/payer.json'))), sha(payer));
  assert.equal(sha(readFileSync(join(cwd, '.local/gateway-seed'))), sha(seed));
  assert.equal(first.output.includes(payer.toString()), false);
  assert.equal(first.output.includes(seed.toString()), false);
});

test('operator rejects a non-devnet RPC before sending any transaction', async () => {
  const methods = [];
  const server = createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    const body = JSON.parse(raw); methods.push(body.method);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp' }));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  try {
    const cwd = mkdtempSync(join(tmpdir(), 'ac-network-guard-'));
    await run([resolve(root, 'setup.mjs')], cwd);
    const result = await run([resolve(root, 'run.mjs'), 'relay'], cwd, {
      AC_RPC: `http://127.0.0.1:${server.address().port}`, AC_PUBLIC_URL: 'https://relay.operator.example',
      AC_PROGRAM: 'EWbCnf65YNqj2zvaZfnKDtkc8eR2PapKvksfzqRmfFav',
    });
    assert.equal(result.code, 1);
    assert.match(result.output, /only supports Solana devnet/);
    assert.deepEqual(methods, ['getGenesisHash']);
  } finally { await new Promise(r => server.close(r)); }
});
