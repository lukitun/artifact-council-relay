import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
const root = process.env.AC_OPERATOR_TEST_DIR || process.cwd();
// A neutral program id: these refusals happen before the program is read.
const PROGRAM = '11111111111111111111111111111112';
if (!existsSync(join(root, 'SOURCE-MANIFEST.json'))) throw Error('Run inside an extracted operator package or set AC_OPERATOR_TEST_DIR');
// This package's one network (sdk/index.mjs NETWORK: devnet, or mainnet-beta in the mainnet package), and
// another cluster's genesis for the wrong-cluster refusals.
const { NETWORK, DEVNET_GENESIS, DEVNET_PROGRAM, MAINNET_GENESIS, Keypair, PublicKey } = await import(resolve(root, 'sdk/index.mjs'));
const NET = NETWORK.name, [OTHER_GENESIS, OTHER] = NETWORK.genesis === MAINNET_GENESIS ? [DEVNET_GENESIS, 'devnet'] : [MAINNET_GENESIS, 'mainnet-beta'];
/** The live program this package names; null in a mainnet trial build (its placeholder), where the tests that read it skip. */
const LIVE_PROGRAM = NETWORK.program, needsProgram = LIVE_PROGRAM ? {} : { skip: `this ${NET} package names no program yet (a trial build)` };
const run = (args, cwd, env = {}) => new Promise((resolveRun, reject) => {
  const child = spawn(process.execPath, args, { cwd, env: { PATH: process.env.PATH, ...env } });
  let output = ''; child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { output += b; });
  child.on('error', reject); child.on('close', code => resolveRun({ code, output }));
});
const sha = data => createHash('sha256').update(data).digest('hex');

// The archive itself holding no .env or .local/ is checked in the repository (test/relay-package.test.mjs):
// here the operator may already have run init in this directory, and these tests still pass.
test('distributed source matches every recorded hash and includes no operator state', () => {
  const manifest = JSON.parse(readFileSync(join(root, 'SOURCE-MANIFEST.json')));
  for (const item of manifest.files) {
    assert.equal(sha(readFileSync(join(root, item.file))), item.sha256, item.file);
    assert.ok(!item.file.startsWith('.local/') && item.file !== '.env');
  }
});

test('init creates .env and the keys, preserves them when rerun, sets RPC and URL, and prints no secret', async () => {
  // Use package entrypoint (so dependencies resolve there) with an isolated state directory.
  const cwd = mkdtempSync(join(tmpdir(), 'ac-setup-test-'));
  const first = await run([resolve(root, 'ac-relay.mjs'), 'init'], cwd);
  assert.equal(first.code, 0, first.output);
  assert.match(first.output, /Created \.env\. Operator address: [1-9A-HJ-NP-Za-km-z]{32,44}/);
  if (NETWORK.faucet) assert.match(first.output, /faucet\.solana\.com/, 'says how to fund the key');
  else { assert.match(first.output, new RegExp(`send ${NET} SOL from a wallet you hold`), 'says how to fund the key'); assert.doesNotMatch(first.output, /faucet|airdrop/); }
  // The template, on the network's public RPC, with this copy's own docker compose project name.
  const address = /Operator address: (\S+)/.exec(first.output)[1], created = readFileSync(join(cwd, '.env'), 'utf8');
  assert.equal(created.replace(/\n# docker compose's project name[^\n]*\nCOMPOSE_PROJECT_NAME=[^\n]*\n$/, '\n'), readFileSync(join(root, '.env.example'), 'utf8').replace(/^AC_RPC=$/m, `AC_RPC=${NETWORK.publicRpc}`));
  assert.match(created, new RegExp(`^COMPOSE_PROJECT_NAME=ac-${address.slice(0, 8).toLowerCase()}$`, 'm'));
  const payer = readFileSync(join(cwd, '.local/payer.json')), seed = readFileSync(join(cwd, '.local/gateway-seed'));
  const second = await run([resolve(root, 'ac-relay.mjs'), 'init', '--rpc', 'https://rpc.operator.example/key123', '--url', 'https://relay.operator.example'], cwd);
  assert.equal(second.code, 0, second.output);
  assert.doesNotMatch(second.output, /Created \.env/);
  assert.equal(sha(readFileSync(join(cwd, '.local/payer.json'))), sha(payer));
  assert.equal(sha(readFileSync(join(cwd, '.local/gateway-seed'))), sha(seed));
  const env = readFileSync(join(cwd, '.env'), 'utf8');
  assert.match(env, /^AC_RPC=https:\/\/rpc\.operator\.example\/key123$/m); assert.match(env, /^AC_PUBLIC_URL=https:\/\/relay\.operator\.example$/m);
  for (const r of [first, second]) { assert.equal(r.output.includes(payer.toString()), false); assert.equal(r.output.includes(seed.toString()), false); }
  // An AC_KEY that points elsewhere gets its key there.
  const other = await run([resolve(root, 'ac-relay.mjs'), 'init'], cwd, { AC_KEY: 'keys/relay.json' });
  assert.equal(other.code, 0, other.output); assert.ok(existsSync(join(cwd, 'keys/relay.json')));
});

test(`operator rejects a non-${NET} RPC before sending any transaction`, async () => {
  const methods = [];
  const server = createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    const body = JSON.parse(raw); methods.push(body.method);
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result: OTHER_GENESIS }));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  try {
    const cwd = mkdtempSync(join(tmpdir(), 'ac-network-guard-'));
    await run([resolve(root, 'ac-relay.mjs'), 'init'], cwd);
    const result = await run([resolve(root, 'ac-relay.mjs'), 'start', 'relay'], cwd, {
      AC_RPC: `http://127.0.0.1:${server.address().port}`, AC_PUBLIC_URL: 'https://relay.operator.example',
      AC_PROGRAM: PROGRAM,
    });
    assert.equal(result.code, 1);
    assert.match(result.output, new RegExp(`serves ${OTHER}, not ${NET}`));
    assert.match(result.output, new RegExp(`only supports Solana ${NET}`));
    assert.match(result.output, /Nothing was sent and nothing was spent/);
    assert.doesNotMatch(result.output, /^\s+at /m, 'a refusal is a plain line, not a stack trace');
    assert.deepEqual(methods, ['getGenesisHash']);
  } finally { await new Promise(r => server.close(r)); }
});

test('operator refuses an unknown AC_CRANK before any RPC call', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ac-crank-setting-'));
  await run([resolve(root, 'ac-relay.mjs'), 'init'], cwd);
  const result = await run([resolve(root, 'ac-relay.mjs'), 'start', 'relay'], cwd, {
    AC_RPC: 'http://127.0.0.1:9', AC_PUBLIC_URL: 'https://relay.operator.example',
    AC_PROGRAM: PROGRAM, AC_CRANK: 'no',
  });
  assert.equal(result.code, 1);
  assert.match(result.output, /AC_CRANK must be 1/);
});

test('every relay cranks: AC_CRANK=0 is refused, and a second cranking process on one directory is refused before any RPC call', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ac-crank-lock-'));
  await run([resolve(root, 'ac-relay.mjs'), 'init'], cwd);
  const env = { AC_RPC: 'http://127.0.0.1:9', AC_PUBLIC_URL: 'https://relay.operator.example', AC_PROGRAM: PROGRAM, COLONY_USERNAME: 'op', COLONY_API_KEY: 'k' };
  const off = await run([resolve(root, 'ac-relay.mjs'), 'start', 'relay'], cwd, { ...env, AC_CRANK: '0' });
  assert.equal(off.code, 1); assert.match(off.output, /AC_CRANK must be 1 or unset/);
  // A live process holds the lock (this test runner stands in for an old standalone cranker).
  const lock = join(cwd, '.local/crank.pid');
  writeFileSync(lock, String(process.pid));
  for (const mode of ['relay', 'gateway', 'crank']) {
    const result = await run([resolve(root, 'ac-relay.mjs'), 'start', mode], cwd, env);
    assert.equal(result.code, 1, mode); assert.match(result.output, new RegExp(`Another relay or cranker \\(pid ${process.pid}\\)`), mode);
  }
  assert.equal(readFileSync(lock, 'utf8'), String(process.pid), 'the holder keeps its lock');
  // Another container: node is PID 1 in each, so a pid proves nothing there. A lock refreshed in the
  // last 90 s is held whatever its pid, even the starter's own; an old one from another host is taken.
  for (const pid of [1, 999999999]) {
    writeFileSync(lock, JSON.stringify({ host: 'another-container', pid, at: Date.now() - 10_000 }));
    const held = await run([resolve(root, 'ac-relay.mjs'), 'start', 'crank'], cwd, env);
    assert.equal(held.code, 1); assert.match(held.output, new RegExp(`Another relay or cranker \\(pid ${pid} on another-container\\)`));
  }
  writeFileSync(lock, JSON.stringify({ host: 'another-container', pid: 1, at: Date.now() - 600_000 }));
  const old = await run([resolve(root, 'ac-relay.mjs'), 'start', 'relay'], cwd, env);
  assert.equal(old.code, 1); assert.doesNotMatch(old.output, /Another relay or cranker/); assert.equal(existsSync(lock), false);
  // A lock left by a process that is gone is taken over, and released when this one exits.
  writeFileSync(lock, '999999999');
  const stale = await run([resolve(root, 'ac-relay.mjs'), 'start', 'relay'], cwd, env);
  assert.equal(stale.code, 1); assert.doesNotMatch(stale.output, /Another relay or cranker/);
  assert.equal(existsSync(lock), false);
});

// ---- The self-check (check.mjs): each problem is named with its fix, and nothing is sent. ----
const check = await import(resolve(root, 'check.mjs'));
/** A fake JSON-RPC provider: `accounts` by address ({ lamports, executable, data }), everything else absent. */
const fakeRpc = ({ genesis = NETWORK.genesis, accounts = {}, status = 200, calls = [] } = {}) => async (url, init) => {
  if (String(url).startsWith('https://thecolony.cc/')) throw Error('no Colony here');
  const { method, params } = JSON.parse(init.body); calls.push(method);
  if (status !== 200) return new Response('no', { status });
  const account = a => a ? { data: [Buffer.from(a.data ?? []).toString('base64'), 'base64'], owner: '11111111111111111111111111111111', lamports: a.lamports ?? 0, executable: !!a.executable, rentEpoch: 0, space: 0 } : null;
  const result = method === 'getGenesisHash' ? genesis : method === 'getAccountInfo' ? { context: { slot: 1 }, value: account(accounts[params[0]]) } : null;
  return Response.json({ jsonrpc: '2.0', id: 1, result });
};
const keyDir = () => { const cwd = mkdtempSync(join(tmpdir(), 'ac-check-')), k = Keypair.generate(); writeFileSync(join(cwd, 'key.json'), JSON.stringify([...k.secretKey])); return { path: join(cwd, 'key.json'), address: k.publicKey.toBase58() }; };
const resolveTo = address => async () => [{ address }];
const find = (r, level, pattern) => r.results.find(x => x.level === level && pattern.test(`${x.text} ${x.fix ?? ''}`));

test('self-check: a wrong cluster, an unreachable RPC and a refused API key are named, and the RPC key never printed', async () => {
  const key = keyDir(), env = { AC_RPC: 'https://rpc.example.net/v1/SECRETKEY?api-key=SECRET2', AC_KEY: key.path };
  const calls = [];
  const testnet = await check.selfCheck({ env, mode: 'crank', fetch: fakeRpc({ genesis: '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY', calls }) });
  assert.equal(testnet.ok, false); assert.ok(find(testnet, 'fail', new RegExp(`serves testnet, not ${NET}.*only supports Solana ${NET}`)), JSON.stringify(testnet.results));
  assert.deepEqual(calls, ['getGenesisHash'], 'nothing past the cluster check');
  const down = await check.selfCheck({ env, mode: 'crank', fetch: async () => { throw Object.assign(Error('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); } });
  assert.ok(find(down, 'fail', /does not answer: cannot connect \(ECONNREFUSED\)/), JSON.stringify(down.results));
  const refused = await check.selfCheck({ env, mode: 'crank', fetch: fakeRpc({ status: 401 }) });
  assert.ok(find(refused, 'fail', /HTTP 401.*API key in AC_RPC/));
  const limited = await check.selfCheck({ env, mode: 'crank', fetch: fakeRpc({ status: 429 }) });
  assert.ok(find(limited, 'fail', /rate-limiting/));
  for (const r of [testnet, down, refused, limited]) assert.doesNotMatch(JSON.stringify(r.results), /SECRET/, 'the provider key stays private');
  assert.equal(check.redact('https://devnet.helius-rpc.com/?api-key=abc'), 'https://devnet.helius-rpc.com/…');
});

test('self-check: a missing or foreign program says to use the live program; an unfunded key names its address and how to fund it', needsProgram, async () => {
  const key = keyDir(), env = { AC_RPC: 'https://rpc.example.net', AC_KEY: key.path };
  const missing = await check.selfCheck({ env: { ...env, AC_PROGRAM: '11111111111111111111111111111112' }, mode: 'crank', fetch: fakeRpc() });
  assert.ok(find(missing, 'fail', new RegExp(`no program at 11111111111111111111111111111112 on ${NET}.*${LIVE_PROGRAM}`)), JSON.stringify(missing.results));
  const notProgram = await check.selfCheck({ env: { ...env, AC_PROGRAM: '11111111111111111111111111111112' }, mode: 'crank', fetch: fakeRpc({ accounts: { '11111111111111111111111111111112': { lamports: 1 } } }) });
  assert.ok(find(notProgram, 'fail', /is an account, not a program/));
  // An executable program with no Artifact Council config: an old download's retired program.
  const foreign = await check.selfCheck({ env, mode: 'crank', fetch: fakeRpc({ accounts: { [LIVE_PROGRAM]: { lamports: 1, executable: true } } }) });
  assert.ok(find(foreign, 'fail', /is a program but not this release of Artifact Council.*get the current package/), JSON.stringify(foreign.results));
  assert.equal(check.settings({}).program, LIVE_PROGRAM, `AC_PROGRAM defaults to the live ${NET} program`);
  const unfunded = foreign;
  const how = NETWORK.faucet ? `faucet\\.solana\\.com.*solana airdrop 1 ${key.address} --url ${NET}` : `send ${NET} SOL from a wallet you hold`;
  assert.ok(find(unfunded, 'fail', new RegExp(`wallet ${key.address} holds 0 SOL; starting needs at least 0\\.02 SOL.*${how}`)), JSON.stringify(unfunded.results));
  // A preview needs no funds and no public URL.
  const preview = await check.selfCheck({ env, mode: 'preview', fetch: fakeRpc({ accounts: { [LIVE_PROGRAM]: { lamports: 1, executable: true } } }) });
  assert.ok(find(preview, 'info', /holds no SOL \(a preview needs none\)/)); assert.ok(!preview.results.some(r => /AC_PUBLIC_URL/.test(r.text)));
  const nokey = await check.selfCheck({ env: { AC_RPC: 'https://rpc.example.net', AC_KEY: '/nonexistent/key.json' }, mode: 'preview', fetch: fakeRpc() });
  assert.ok(find(nokey, 'fail', /no operator key at \/nonexistent\/key\.json/));
  // The default key path is relative: read it from an empty directory, not from wherever the tests run.
  const here = process.cwd(); process.chdir(mkdtempSync(join(tmpdir(), 'ac-unset-')));
  const unset = await check.selfCheck({ env: {}, mode: 'preview', fetch: fakeRpc() }).finally(() => process.chdir(here));
  assert.ok(find(unset, 'fail', /AC_RPC is not set/)); assert.ok(find(unset, 'fail', /no operator key at \.local\/payer\.json.*npm run init/));
});

test('self-check: a public URL the network could never route to is refused before anything is registered', async () => {
  for (const [url, why] of [['', /not set/], ['http://relay.operator.net', /must start with https/], ['https://relay.example.com', /example host/], ['https://relay.operator.net:8443', /port 443/],
    ['https://relay.operator.net/v2/x', /bare origin/], ['https://relay.operator.net/v2', /bare origin/], ['https://user:pw@relay.operator.net', /bare origin/], ['https://10.1.2.3', /private address/], ['https://relay.local', /private host/]])
    assert.match(check.publicUrlProblem(url) ?? 'accepted', why, url);
  assert.equal(check.publicUrlProblem('https://relay.operator.net'), null);
  const key = keyDir(), env = { AC_RPC: 'https://rpc.example.net', AC_KEY: key.path, AC_PUBLIC_URL: 'https://relay.operator.net' };
  const dns = await check.selfCheck({ env, mode: 'relay', fetch: fakeRpc(), resolve: async () => { throw Object.assign(Error('nx'), { code: 'ENOTFOUND' }); } });
  assert.ok(find(dns, 'fail', /relay\.operator\.net does not resolve \(ENOTFOUND\).*DNS A\/AAAA record/));
  const inside = await check.selfCheck({ env, mode: 'relay', fetch: fakeRpc(), resolve: resolveTo('192.168.1.5') });
  assert.ok(find(inside, 'fail', /resolves to a private address \(192\.168\.1\.5\)/));
  const good = await check.selfCheck({ env, mode: 'relay', fetch: fakeRpc(), resolve: resolveTo('93.184.216.34') });
  assert.ok(find(good, 'ok', /public URL https:\/\/relay\.operator\.net/));
});

test('self-check: a gateway\'s Colony key is checked against thecolony.cc and its account', async () => {
  const key = keyDir(), env = { AC_RPC: 'https://rpc.example.net', AC_KEY: key.path, AC_PUBLIC_URL: 'https://gw.operator.net', COLONY_USERNAME: 'my-gateway', COLONY_API_KEY: 'col_x' };
  const colony = ({ token = true, username = 'my-gateway' }) => async (url, init) => {
    if (String(url).endsWith('/auth/token')) return token ? Response.json({ access_token: 'jwt' }) : Response.json({ detail: 'Invalid API key' }, { status: 401 });
    if (String(url).endsWith('/users/me')) return Response.json({ id: 'u1', username });
    return fakeRpc()(url, init);
  };
  const missing = await check.selfCheck({ env: { ...env, COLONY_API_KEY: '' }, mode: 'gateway', fetch: colony({}), resolve: resolveTo('93.184.216.34') });
  assert.ok(find(missing, 'fail', /gateway mode needs COLONY_USERNAME and COLONY_API_KEY/));
  const bad = await check.selfCheck({ env, mode: 'gateway', fetch: colony({ token: false }), resolve: resolveTo('93.184.216.34') });
  assert.ok(find(bad, 'fail', /thecolony\.cc refuses COLONY_API_KEY \(HTTP 401\)/));
  const other = await check.selfCheck({ env, mode: 'gateway', fetch: colony({ username: 'someone-else' }), resolve: resolveTo('93.184.216.34') });
  assert.ok(find(other, 'fail', /COLONY_API_KEY belongs to @someone-else, not COLONY_USERNAME @my-gateway/));
  const good = await check.selfCheck({ env, mode: 'gateway', fetch: colony({}), resolve: resolveTo('93.184.216.34') });
  assert.ok(find(good, 'ok', /the key belongs to @my-gateway/));
});

test('the public-URL probe accepts only this relay\'s signed answer for this program, and says what it got instead', async () => {
  const me = 'Relay1111111111111111111111111111111111111', program = DEVNET_PROGRAM, answer = (status, body, signer = me) => async () => new Response(JSON.stringify(body), { status, headers: { 'x-ac-signer': signer } });
  const probe = fetch => check.probePublicUrl({ publicUrl: 'https://relay.operator.net', relay: me, program, seconds: 0, fetch });
  assert.equal(await probe(answer(200, { relay: me, program })), null);
  assert.match(await probe(answer(200, { relay: 'Other', program })), /answers as relay Other, not as this relay/);
  assert.match(await probe(answer(200, { relay: me, program }, 'Other')), /not signed by this relay's key/);
  assert.match(await probe(answer(200, { relay: me, program: 'Else' })), /for program Else/);
  assert.match(await probe(answer(502, {})), /HTTP 502 from the proxy/);
  assert.match(await probe(async () => { throw Object.assign(Error('fetch failed'), { cause: { code: 'CERT_HAS_EXPIRED' } }); }), /CERT_HAS_EXPIRED/);
  let tries = 0;
  assert.equal(await check.probePublicUrl({ publicUrl: 'https://relay.operator.net', relay: me, program, seconds: 60, every: 1, sleep: async () => {},
    fetch: async (...a) => ++tries < 3 ? answer(502, {})(...a) : answer(200, { relay: me, program })(...a) }), null, 'retries while the certificate is issued');
});

test('the check command prints plain FAIL lines with fixes and exits 1; help lists every step', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ac-check-cli-'));
  const r = await run([resolve(root, 'ac-relay.mjs'), 'check', 'crank'], cwd, { AC_RPC: 'http://127.0.0.1:9' });
  assert.equal(r.code, 1, r.output);
  assert.match(r.output, /FAIL  no operator key at \.local\/payer\.json\n\s+-> run `npm run init`/);
  assert.match(r.output, /FAIL  RPC http:\/\/127\.0\.0\.1:9 does not answer: cannot connect/);
  assert.doesNotMatch(r.output, /^\s+at /m);
  const help = await run([resolve(root, 'ac-relay.mjs'), 'help'], cwd);
  for (const step of ['init', 'check', 'preview', 'start', 'gateway', 'seat']) assert.match(help.output, new RegExp(`npm (run )?${step}`));
  assert.match(help.output, /With Docker: docker compose run --rm cli <command>/);
});

test('in the Docker image every hint names a docker compose command; init lists only the settings still to fill in', async () => {
  const docker = mkdtempSync(join(tmpdir(), 'ac-docker-init-'));
  const d = await run([resolve(root, 'ac-relay.mjs'), 'init', '--rpc', 'https://rpc.operator.net/key123'], docker, { AC_DOCKER: '1' });
  assert.equal(d.code, 0, d.output);
  assert.doesNotMatch(d.output, /npm /);
  assert.doesNotMatch(d.output, /Set AC_RPC/, 'the RPC came from --rpc');
  assert.match(d.output, /Set AC_PUBLIC_URL in \.env/);
  assert.match(d.output, /Start: docker compose up -d \(run it again after editing \.env/);
  assert.match(d.output, /docker compose run --rm --service-ports preview/);
  const c = await run([resolve(root, 'ac-relay.mjs'), 'check', 'crank'], mkdtempSync(join(tmpdir(), 'ac-docker-check-')), { AC_DOCKER: '1', AC_RPC: 'http://127.0.0.1:9' });
  assert.match(c.output, /-> run `docker compose run --rm cli init`/);
  // Behind the host's own proxy, or a cranker alone: the served command is relay-host, with no Caddy wording.
  for (const extra of [{ AC_PROXY: 'host' }, { AC_MODE: 'crank' }]) {
    const h = await run([resolve(root, 'ac-relay.mjs'), 'init'], mkdtempSync(join(tmpdir(), 'ac-docker-host-')), { AC_DOCKER: '1', ...extra });
    assert.match(h.output, /Start: docker compose up -d relay-host/, JSON.stringify(extra)); assert.doesNotMatch(h.output, /Caddy/);
  }
  assert.equal(check.command('start', '', { AC_MODE: 'gateway' }), 'npm run gateway');
  assert.equal(check.command('start', '', { AC_MODE: 'crank' }), 'npm run crank');
  // In the container AC_KEY is resolved inside it: a host path gets the .local/ fix.
  const key = await check.selfCheck({ env: { AC_DOCKER: '1', AC_RPC: 'https://rpc.example.net', AC_KEY: '/root/.config/solana/id.json' }, mode: 'preview', fetch: fakeRpc() });
  assert.ok(find(key, 'fail', /no operator key at \/root\/\.config\/solana\/id\.json inside the container.*under \.local\//), JSON.stringify(key.results));
  const plain = mkdtempSync(join(tmpdir(), 'ac-plain-init-'));
  const p = await run([resolve(root, 'ac-relay.mjs'), 'init', '--url', 'https://relay.operator.net'], plain);
  assert.match(p.output, new RegExp(`Set AC_RPC in \\.env to your own ${NET} RPC URL`), 'the template holds the public RPC');
  assert.doesNotMatch(p.output, /Set AC_PUBLIC_URL/);
  assert.match(p.output, /Start: npm start\n/);
  assert.match(p.output, /npm run preview/);
});

test('crank-only never registers a key with no URL unless the operator says so: the chain keeps it for good', () => {
  const [problem, fix] = check.crankRegistrationProblem({ mode: 'crank', publicUrl: '', noUrl: false });
  assert.match(problem, /no URL for good.*never serve as a relay/); assert.match(fix, /separate key.*--no-url.*AC_CRANK_NO_URL=1/);
  assert.equal(check.crankRegistrationProblem({ mode: 'crank', publicUrl: '', noUrl: true }), null);
  assert.equal(check.crankRegistrationProblem({ mode: 'crank', publicUrl: 'https://relay.operator.net', noUrl: false }), null);
  assert.equal(check.crankRegistrationProblem({ mode: 'relay', publicUrl: '', noUrl: false }), null);
  assert.match(readFileSync(join(root, 'check.mjs'), 'utf8'), /const noUrlProblem = crankRegistrationProblem\(\{ mode, publicUrl: s\.publicUrl, noUrl \}\);\n\s+if \(noUrlProblem\) fail/);
});

// ---- Docker: the files as shipped (a Docker run in the repository's review checks them live). ----
/** compose.yaml's services as { name: block text } (two-space service keys under `services:`). */
const services = () => {
  const text = readFileSync(join(root, 'compose.yaml'), 'utf8'), body = text.slice(text.indexOf('\nservices:\n') + 11, text.search(/\n(?:volumes|networks):\n/));
  const out = {}; let name = null;
  for (const line of body.split('\n')) { const m = /^  ([a-z][a-z0-9-]*):$/.exec(line); if (m) { name = m[1]; out[name] = ''; } else if (name) out[name] += line + '\n'; }
  return out;
};

test('compose: the shared network namespace is held by a container that never exits, never by the relay', () => {
  const s = services();
  assert.deepEqual(Object.keys(s).sort(), ['caddy', 'cli', 'net', 'preview', 'relay', 'relay-host']);
  for (const [name, block] of Object.entries(s)) {
    const target = /network_mode: service:([a-z0-9-]+)/.exec(block)?.[1];
    if (!target) continue;
    // A target that restarts takes a new namespace and strands whoever joined the old one.
    assert.equal(target, 'net', `${name} joins ${target}`);
    assert.doesNotMatch(s[target], /\bbuild:|\bcommand:/, 'the namespace holder runs no relay code');
    assert.match(s[target], /image: registry\.k8s\.io\/pause:/);
  }
  assert.match(s.relay, /network_mode: service:net/); assert.match(s.caddy, /network_mode: service:net/);
  assert.match(s.net, /ports: \["80:80", "443:443", "443:443\/udp"\]/);
  assert.doesNotMatch(s.relay, /ports:/, 'the relay owns no ports');
  // One-off commands start nothing else and bind nothing.
  assert.match(s.cli, /profiles: \[cli\]/); assert.doesNotMatch(s.cli, /ports:|depends_on|service:/);
  // Each copy is its own project (init writes COMPOSE_PROJECT_NAME).
  assert.match(readFileSync(join(root, 'compose.yaml'), 'utf8'), /^name: \$\{COMPOSE_PROJECT_NAME:-ac-relay\}$/m);
  for (const block of Object.values(s)) if (/\bbuild:/.test(block)) { assert.match(block, /cap_drop: \[ALL\]/); assert.doesNotMatch(block, /CHOWN/); }
});

test('Docker: the build context admits only code, never a key, .env backup or other JSON; nothing is chowned', () => {
  const lines = readFileSync(join(root, '.dockerignore'), 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  assert.equal(lines[0], '*', 'an allowlist');
  const allowed = lines.slice(1);
  for (const l of allowed) assert.ok(l.startsWith('!'), l);
  assert.deepEqual(allowed.filter(l => /json/.test(l)).sort(), ['!package-lock.json', '!package.json']);
  assert.ok(!allowed.some(l => /env$|\.local|\*\*|^!\*/.test(l) && l !== '!.env.example'), allowed.join());
  const dockerfile = readFileSync(join(root, 'Dockerfile'), 'utf8');
  assert.doesNotMatch(dockerfile, /^COPY \. /m); assert.doesNotMatch(dockerfile, /rm -rf/);
  const entry = readFileSync(join(root, 'docker-entrypoint.sh'), 'utf8').split('\n').filter(l => !l.trim().startsWith('#')).join('\n');
  assert.doesNotMatch(entry, /chown|id -u node/); assert.match(entry, /exec setpriv --reuid="\$uid"/);
});

// ---- Payouts (owner, 30 September): the relay key is the payout wallet; balance and withdraw. ----
/** A JSON-RPC provider over HTTP: `lamports` on the operator key, every other account absent. */
async function payoutRpc({ genesis = NETWORK.genesis, lamports = {} } = {}) {
  const calls = [];
  const server = createServer(async (req, res) => {
    let raw = ''; for await (const chunk of req) raw += chunk;
    const { id, method, params } = JSON.parse(raw); calls.push(method);
    const account = a => lamports[a] === undefined ? null : { data: ['', 'base64'], owner: '11111111111111111111111111111111', lamports: lamports[a], executable: false, rentEpoch: 0, space: 0 };
    const result = { getGenesisHash: genesis, getAccountInfo: () => ({ context: { slot: 1 }, value: account(params[0]) }), getMinimumBalanceForRentExemption: 890_880,
      getLatestBlockhash: { context: { slot: 1 }, value: { blockhash: Keypair.generate().publicKey.toBase58(), lastValidBlockHeight: 1000 } }, getBlockHeight: 10,
      sendTransaction: 'sent', getSignatureStatuses: { context: { slot: 1 }, value: [{ slot: 1, confirmations: 1, err: null, confirmationStatus: 'confirmed' }] }, getProgramAccounts: [] }[method];
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(result === undefined ? { jsonrpc: '2.0', id, error: { code: -32601, message: `no ${method} here` } } : { jsonrpc: '2.0', id, result: typeof result === 'function' ? result() : result }));
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, calls, close: () => new Promise(r => server.close(r)) };
}

test('withdraw: a dry run by default, the transfer with --yes, and every lost or wrong destination refused before sending', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ac-withdraw-'));
  const address = /Operator address: (\S+)/.exec((await run([resolve(root, 'ac-relay.mjs'), 'init'], cwd)).output)[1];
  const rpc = await payoutRpc({ lamports: { [address]: 1_500_000_000 } });
  const env = { AC_RPC: rpc.url }, to = Keypair.generate().publicKey.toBase58();
  try {
    const usage = await run([resolve(root, 'ac-relay.mjs'), 'withdraw'], cwd, env);
    assert.equal(usage.code, 1); assert.match(usage.output, /Use: npm run withdraw -- --to <your-wallet-address>/);
    const dry = await run([resolve(root, 'ac-relay.mjs'), 'withdraw', '--to', to], cwd, env);
    assert.equal(dry.code, 0, dry.output);
    assert.match(dry.output, new RegExp(`Relay key: ${address}\\nBalance: 1\\.5 SOL`));
    assert.match(dry.output, /Pending rewards: /);
    assert.match(dry.output, new RegExp(`Withdraw 1\\.299995 SOL to ${to} \\(fee 0\\.000005 SOL\\); 0\\.2 SOL stays on the relay key\\.`));
    assert.match(dry.output, /Dry run: nothing was sent\. .*--yes/);
    assert.ok(!rpc.calls.includes('sendTransaction'), 'a dry run sends nothing');
    for (const [args, why] of [[['--to', address], /this relay key itself/], [['--to', '11111111111111111111111111111111'], /reserved/],
      [['--to', PublicKey.findProgramAddressSync([Buffer.from('x')], new PublicKey(DEVNET_PROGRAM))[0].toBase58()], /off-curve/],
      [['--to', to, '--keep', '0'], /below what this key needs/], [['--to', to, '--keep', '2'], /nothing to withdraw/], [['--to', to, '--keep', 'lots'], /--keep must be an amount of SOL/]]) {
      const r = await run([resolve(root, 'ac-relay.mjs'), 'withdraw', ...args, '--yes'], cwd, env);
      assert.equal(r.code, 1, args.join(' ')); assert.match(r.output, why, args.join(' ')); assert.doesNotMatch(r.output, /^\s+at /m);
    }
    assert.ok(!rpc.calls.includes('sendTransaction'), 'no refusal sends');
    const sent = await run([resolve(root, 'ac-relay.mjs'), 'withdraw', '--to', to, '--keep', '0.5', '--yes'], cwd, env);
    assert.equal(sent.code, 0, sent.output);
    assert.match(sent.output, new RegExp(`Withdraw 0\\.999995 SOL to ${to}`)); assert.match(sent.output, /Sent: [1-9A-HJ-NP-Za-km-z]{64,88}\n/);
    assert.equal(rpc.calls.filter(m => m === 'sendTransaction').length, 1);
  } finally { await rpc.close(); }
});

test('balance and withdraw refuse the wrong cluster before reading anything else; balance names the key as the payout wallet', async () => {
  const cwd = mkdtempSync(join(tmpdir(), 'ac-balance-'));
  const address = /Operator address: (\S+)/.exec((await run([resolve(root, 'ac-relay.mjs'), 'init'], cwd)).output)[1];
  const wrong = await payoutRpc({ genesis: OTHER_GENESIS, lamports: { [address]: 1e9 } });
  try {
    for (const args of [['balance'], ['withdraw', '--to', Keypair.generate().publicKey.toBase58(), '--yes']]) {
      const r = await run([resolve(root, 'ac-relay.mjs'), ...args], cwd, { AC_RPC: wrong.url });
      assert.equal(r.code, 1, args[0]); assert.match(r.output, new RegExp(`serves ${OTHER}, not ${NET}: this package pays out only on ${NET}\\. Nothing was sent\\.`));
    }
    assert.deepEqual([...new Set(wrong.calls)], ['getGenesisHash']);
  } finally { await wrong.close(); }
  const rpc = await payoutRpc({ lamports: { [address]: 250_000_000 } });
  try {
    const r = await run([resolve(root, 'ac-relay.mjs'), 'balance'], cwd, { AC_RPC: rpc.url });
    assert.equal(r.code, 0, r.output);
    assert.match(r.output, new RegExp(`Relay key \\(the payout wallet\\): ${address}\\nBalance: 0\\.25 SOL`));
    assert.match(r.output, /npm run withdraw -- --to <your-wallet>/);
  } finally { await rpc.close(); }
  const help = await run([resolve(root, 'ac-relay.mjs'), 'help'], cwd);
  assert.match(help.output, /npm run balance/); assert.match(help.output, /npm run withdraw -- --to <wallet>/);
  assert.match(readFileSync(join(root, 'README.md'), 'utf8'), /\*\*The relay key file is the payout wallet\.\*\*/);
});
