// The operator's self-check: reads the settings, the key and the chain, and says exactly what is
// wrong and how to fix it. It sends nothing and spends nothing. `ac-relay check` prints it; `start`
// and `preview` refuse to run on a failure.
import { readFileSync, existsSync } from 'node:fs';
import { Council, Keypair, PublicKey, NETWORK, DEVNET_GENESIS, MAINNET_GENESIS, decodeRelayer } from './sdk/index.mjs';
import { RpcTransport } from './sdk/transport.mjs';
import { COLONY_API, COLONY_USERNAME } from './sdk/colony.mjs';
import { relayOrigin, publicAddress } from './sdk/relay-pool.mjs';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { isAbsolute } from 'node:path';

/** The network this release runs on (sdk/index.mjs NETWORK): every cluster name, check and faucet line below. */
export const FAUCET = NETWORK.faucet;
/** The low-balance check before a start: a float, not a budget (0.1 to 0.2 SOL is comfortable). */
export const MIN_START = 20_000_000;
export const DEFAULT_KEY = '.local/payer.json';
const CLUSTERS = { [DEVNET_GENESIS]: 'devnet', [MAINNET_GENESIS]: 'mainnet-beta', '4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY': 'testnet', [NETWORK.genesis]: NETWORK.name };
/** The cluster `genesis` names, as the checks print it. */
export const clusterName = genesis => CLUSTERS[genesis] ?? `an unknown cluster (genesis ${genesis})`;
/** How to put SOL on `address`: the faucet and airdrop where the network has one. */
export const fundHint = address => NETWORK.faucet
  ? `${NETWORK.faucet} (pick ${NETWORK.name}), or \`solana airdrop 1 ${address} --url ${NETWORK.name}\``
  : `send ${NETWORK.name} SOL from a wallet you hold`;
const sol = lamports => `${(lamports / 1e9).toFixed(4).replace(/\.?0+$/, '')} SOL`;
/** The command an operator types for `name`: npm in a plain install, docker compose in the image (the
 *  Dockerfile sets AC_DOCKER=1), so every hint names a command that works where it is read. One-off
 *  commands run in compose's `cli` service; `start` is the served one: `relay-host` (no Caddy, no
 *  ports) behind the host's own proxy (AC_PROXY=host) or for a cranker alone (AC_MODE=crank). */
export function command(name, args = '', env = process.env) {
  const mode = env.AC_MODE || 'relay';
  if (env.AC_DOCKER === '1') {
    if (name === 'start') return env.AC_PROXY === 'host' || mode === 'crank' ? 'docker compose up -d relay-host' : 'docker compose up -d';
    if (name === 'preview') return 'docker compose run --rm --service-ports preview';
    return `docker compose run --rm cli ${name}${args ? ` ${args}` : ''}`;
  }
  if (name === 'start') return mode === 'gateway' ? 'npm run gateway' : mode === 'crank' ? 'npm run crank' : 'npm start';
  return `npm run ${name}${args ? ` -- ${args}` : ''}`;
}

/** The RPC URL without its path or query, where providers put API keys. */
export function redact(url) {
  try { const u = new URL(url); return `${u.protocol}//${u.host}${u.pathname.length > 1 || u.search ? '/…' : ''}`; } catch { return '(not a URL)'; }
}
/** Why `url` cannot be this relay's registered public URL, or null: the gateway's pool routes only to
 *  an https origin with no port, path or credentials (sdk/relay-pool.mjs `relayOrigin`), and the chain
 *  keeps the URL for good. Not even /v2: start's probe and Caddy add the path themselves. */
export function publicUrlProblem(url) {
  if (!url) return 'AC_PUBLIC_URL is not set';
  let u; try { u = new URL(url); } catch { return `AC_PUBLIC_URL (${url}) is not a URL`; }
  if (u.protocol !== 'https:') return `AC_PUBLIC_URL must start with https:// (got ${u.protocol}//)`;
  if (/(^|\.)example\.(com|org|net)$/i.test(u.hostname)) return `AC_PUBLIC_URL still names the example host ${u.hostname}`;
  if (u.port) return 'AC_PUBLIC_URL must use the standard https port 443 (no :port): the network routes only to such URLs';
  if (!relayOrigin(url) || u.pathname !== '/') return 'AC_PUBLIC_URL must be the bare origin, such as https://relay.your-domain.com (no path, query or credentials)';
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host) && !publicAddress(host)) return `AC_PUBLIC_URL names a private address (${host})`;
  if (/^localhost$|\.(local|internal|localhost)$/i.test(host)) return `AC_PUBLIC_URL names a private host (${host})`;
  return null;
}
/** [problem, fix] when a crank-only start would register an unregistered key with no URL, which the
 *  chain never lets anyone edit, so the key could never serve as a relay; null otherwise. */
export function crankRegistrationProblem({ mode, publicUrl, noUrl }) {
  if (mode !== 'crank' || publicUrl || noUrl) return null;
  return ['crank-only registers this key with no URL for good: this key could then never serve as a relay or gateway',
    'use a separate key for cranking (its own directory, or AC_KEY), or set AC_PUBLIC_URL first; to register this key with no URL anyway, run with --no-url (or AC_CRANK_NO_URL=1 in .env)'];
}
/** The settings every command reads, with their defaults; nothing here touches the network. */
export function settings(env = process.env) {
  return { rpc: env.AC_RPC || '', program: env.AC_PROGRAM || NETWORK.program || '', publicUrl: (env.AC_PUBLIC_URL || '').replace(/\/+$/, ''), keyPath: env.AC_KEY || DEFAULT_KEY,
    colonyUsername: env.COLONY_USERNAME || '', colonyKey: env.COLONY_API_KEY || '' };
}
export function readKeypair(path) {
  const bytes = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(bytes) || bytes.length !== 64) throw Error('not a 64-byte Solana keypair file');
  return Keypair.fromSecretKey(Uint8Array.from(bytes));
}
/** One JSON-RPC call with a bounded wait; errors say what the provider answered. */
export async function rpcCall(rpc, method, params = [], { fetch = globalThis.fetch, timeoutMs = 15_000 } = {}) {
  let r;
  try { r = await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal: AbortSignal.timeout(timeoutMs) }); }
  catch (e) { throw Error(e?.name === 'TimeoutError' ? `no answer within ${timeoutMs / 1000} s` : `cannot connect (${e?.cause?.code ?? e?.cause?.message ?? e?.message ?? e})`); }
  if (r.status === 401 || r.status === 403) throw Error(`HTTP ${r.status}: the provider refused the request; check the API key in AC_RPC`);
  if (r.status === 429) throw Error('HTTP 429: the provider is rate-limiting this RPC; use your own provider (public endpoints limit heavily)');
  if (!r.ok) throw Error(`HTTP ${r.status}`);
  let body; try { body = await r.json(); } catch { throw Error('the answer is not JSON-RPC: is AC_RPC a Solana RPC endpoint?'); }
  if (body?.error) throw Error(`RPC error ${body.error.code}: ${body.error.message}`);
  return body?.result;
}

/**
 * Runs every check it can and returns { ok, results, facts }. Each result is { level: 'ok' | 'warn' |
 * 'fail' | 'info', text, fix? }. `mode` is relay, gateway, crank, preview or seat: only relay and
 * gateway need a public URL, and preview and seat need no funds (a seat action checks its own cost).
 */
export async function selfCheck({ env = process.env, mode = 'relay', noUrl = false, fetch = globalThis.fetch, resolve = host => lookup(host, { all: true }), timeoutMs = 15_000 } = {}) {
  const s = settings(env), results = [], facts = { mode, program: s.program, keyPath: s.keyPath }, net = NETWORK.name;
  const ok = text => results.push({ level: 'ok', text }), warn = (text, fix) => results.push({ level: 'warn', text, fix }),
    fail = (text, fix) => results.push({ level: 'fail', text, fix }), info = (text, fix) => results.push({ level: 'info', text, fix });
  // Settings.
  let rpcOk = false;
  if (!s.rpc) fail('AC_RPC is not set', `set AC_RPC in .env to a ${net} RPC URL (${NETWORK.publicRpc} works for a try; use your own provider for a real relay)`);
  else { try { const u = new URL(s.rpc); if (!/^https?:$/.test(u.protocol)) throw 0; rpcOk = true; } catch { fail('AC_RPC is not an http(s) URL', `set AC_RPC in .env to your ${net} RPC URL`); } }
  let program = null;
  // A mainnet package built before launch names no program yet (sdk/index.mjs MAINNET_PROGRAM).
  if (!s.program) fail(`this package names no ${net} program yet: its program id is a placeholder until launch`, 'download the launch package from https://artifactcouncil.com/downloads (its hash is in the manifest there)');
  else try { program = new PublicKey(s.program); } catch { fail(`AC_PROGRAM (${s.program}) is not a Solana address`, `remove AC_PROGRAM from .env to use the live ${NETWORK.name} program ${NETWORK.program}`); }
  if (mode === 'relay' || mode === 'gateway' || (mode === 'crank' && s.publicUrl)) {
    const bad = publicUrlProblem(s.publicUrl);
    if (bad) fail(bad, `set AC_PUBLIC_URL to the https address this relay will answer at (point its DNS at this host first); to look around without one, run \`${command('preview', '', env)}\``);
    else {
      const host = new URL(s.publicUrl).hostname.replace(/^\[|\]$/g, '');
      const found = isIP(host) ? [{ address: host }] : await resolve(host).catch(e => ({ error: e }));
      if (found.error) fail(`AC_PUBLIC_URL's host ${host} does not resolve (${found.error.code ?? found.error.message})`, `create a DNS A/AAAA record for ${host} pointing at this host, wait for it to resolve, then start`);
      else if (!found.length || found.some(a => !publicAddress(a.address))) fail(`AC_PUBLIC_URL's host ${host} resolves to a private address (${found.map(a => a.address).join(', ')})`, 'point its DNS at this host\'s public IP address');
      else ok(`public URL ${s.publicUrl} (${host} resolves to ${found.map(a => a.address).join(', ')})`);
    }
  }
  if (mode === 'gateway') {
    if (!s.colonyUsername || !s.colonyKey) fail('gateway mode needs COLONY_USERNAME and COLONY_API_KEY', 'set both in .env: your own thecolony.cc account and its API key (thecolony.cc settings); agents DM that account to sign in');
    else if (!COLONY_USERNAME.test(s.colonyUsername.toLowerCase())) fail(`COLONY_USERNAME (${s.colonyUsername}) is not a thecolony.cc username`, 'set COLONY_USERNAME to the account name, without @');
  }
  // The key.
  let payer = null;
  // In the image AC_KEY is read inside the container, which sees only this directory (as /work).
  const inDocker = env.AC_DOCKER === '1', outside = inDocker && isAbsolute(s.keyPath) && !s.keyPath.startsWith('/work/');
  if (!existsSync(s.keyPath)) fail(`no operator key at ${s.keyPath}${outside ? ' inside the container' : ''}`, s.keyPath === DEFAULT_KEY ? `run \`${command('init', '', env)}\` to generate one`
    : inDocker ? `with Docker the key must sit in this directory: copy it under .local/ (\`cp ~/.config/solana/id.json .local/payer.json && chmod 600 .local/payer.json\`) and set AC_KEY=.local/payer.json`
    : `fix AC_KEY in .env, or remove it and run \`${command('init', '', env)}\` to generate a key`);
  else {
    try { payer = readKeypair(s.keyPath); facts.address = payer.publicKey.toBase58(); ok(`operator key ${facts.address} (${s.keyPath})`); }
    catch (e) { fail(`the key file ${s.keyPath} is unreadable: ${e.message}`, 'use a Solana keypair JSON file (a 64-number array, as solana-keygen writes)'); }
  }
  // The RPC and its cluster.
  if (rpcOk) {
    let genesis = null;
    try { genesis = await rpcCall(s.rpc, 'getGenesisHash', [], { fetch, timeoutMs }); }
    catch (e) { fail(`RPC ${redact(s.rpc)} does not answer: ${e.message}`, `check AC_RPC (spelling, API key, that the provider serves ${net})`); }
    if (genesis !== null && genesis !== NETWORK.genesis)
      fail(`RPC ${redact(s.rpc)} serves ${clusterName(genesis)}, not ${net}`, `this release only supports Solana ${net}: set AC_RPC to a ${net} RPC URL`);
    else if (genesis === NETWORK.genesis) {
      ok(`RPC ${redact(s.rpc)} answers on ${net}`); facts.rpc = true;
      const transport = new RpcTransport(s.rpc, { request: async (method, params) => ({ result: await rpcCall(s.rpc, method, params, { fetch, timeoutMs }) }) });
      await chainChecks({ transport, program, payer, s, mode, noUrl, env, facts, ok, warn, fail, info });
    }
  }
  if (mode === 'gateway' && s.colonyUsername && s.colonyKey) await colonyCheck({ s, fetch, ok, fail, timeoutMs });
  return { ok: !results.some(r => r.level === 'fail'), results, facts };
}

async function chainChecks({ transport, program, payer, s, mode, noUrl, env, facts, ok, warn, fail, info }) {
  if (program) {
    const account = await transport.getAccount(program).catch(e => ({ error: e }));
    if (account?.error) fail(`reading the program ${s.program} failed: ${account.error.message}`, 'retry; if it persists, check your RPC provider');
    else if (!account) fail(`there is no program at ${s.program} on ${NETWORK.name}`, `remove AC_PROGRAM from .env to use the live ${NETWORK.name} program ${NETWORK.program}`);
    else if (!account.executable) fail(`${s.program} is an account, not a program`, `remove AC_PROGRAM from .env to use the live ${NETWORK.name} program ${NETWORK.program}`);
    else {
      const council = new Council({ transport, program });
      try {
        const cfg = await council.config();
        facts.council = council; facts.config = cfg;
        ok(`program ${s.program} is Artifact Council (epoch ${cfg.epoch})`);
      } catch (e) {
        fail(`${s.program} is a program but not this release of Artifact Council (${e.message.split('\n')[0]})`, `remove AC_PROGRAM from .env to use the live ${NETWORK.name} program ${NETWORK.program}; an old download names a retired program: get the current package`);
      }
    }
  }
  if (!payer) return;
  const address = payer.publicKey.toBase58();
  const balance = (await transport.getAccount(payer.publicKey).catch(() => null))?.lamports ?? 0;
  facts.balance = balance;
  const fund = `send ${NETWORK.name} SOL to ${address}: ${fundHint(address)}; 0.1 to 0.2 SOL is comfortable`;
  if (mode === 'preview' || mode === 'seat') balance ? ok(`wallet holds ${sol(balance)}`) : info(`wallet ${address} holds no SOL${mode === 'preview' ? ' (a preview needs none)' : ''}`, `before \`${command('start', '', env)}\`, ${fund}`);
  else if (balance < MIN_START) fail(`wallet ${address} holds ${sol(balance)}; starting needs at least ${sol(MIN_START)}`, fund);
  else ok(`wallet holds ${sol(balance)}`);
  if (!facts.council) return;
  const rec = await facts.council.maybe(facts.council.relayerAddress(payer.publicKey), decodeRelayer).catch(() => null);
  facts.registered = rec;
  if (!rec) {
    // The chain never lets a registration be edited: a crank-only key registered with no URL can never serve as a relay.
    const noUrlProblem = crankRegistrationProblem({ mode, publicUrl: s.publicUrl, noUrl });
    if (noUrlProblem) fail(...noUrlProblem);
    else if (mode !== 'preview') info('not registered yet', mode === 'crank' ? `the cranker registers this key on its first pass${s.publicUrl ? ` at ${s.publicUrl}, for good` : ', with no URL, for good'}` : 'start registers this key once it has checked that AC_PUBLIC_URL reaches this relay (about 0.0022 SOL, once)');
    return;
  }
  // The pool's rule (sdk/relay-pool.mjs `candidates`): work in one of the last 24 closed epochs, from the work key.
  const cfg = facts.config, recent = rec.work.find(w => w.units > 0 && w.epoch < cfg.epoch && cfg.workKey - w.epoch <= 24);
  facts.earned = !!recent;
  ok(`registered as a ${rec.kind}${rec.url ? ` at ${rec.url}` : ' with no URL'}${recent ? `; earned work in epoch ${recent.epoch}` : '; no work credited in the last 24 epochs yet'}`);
  if ((mode === 'relay' || mode === 'gateway') && s.publicUrl && rec.url.replace(/\/+$/, '') !== s.publicUrl)
    warn(`this key is registered at ${rec.url || '(no URL)'}, not AC_PUBLIC_URL ${s.publicUrl}; the registration cannot be edited, and the network routes to the registered URL`,
      `serve the registered URL, or generate a new key (move .local/payer.json away, run \`${command('init', '', env)}\`) and register that one`);
  if (mode === 'gateway' && rec.kind !== 'gateway') warn('this key is registered as a relay, not a gateway', 'run a gateway from its own installation and key (see "Operate your own hosted gateway")');
}

async function colonyCheck({ s, fetch, ok, fail, timeoutMs }) {
  const get = async (url, init) => { try { const r = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) }); return { status: r.status, body: r.ok ? await r.json().catch(() => null) : null }; } catch (e) { return { status: 0, error: e?.message }; } };
  const token = await get(`${COLONY_API}/auth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ api_key: s.colonyKey }) });
  if (token.status === 0) return fail(`thecolony.cc does not answer (${token.error}); the Colony login cannot be checked`, 'check this host\'s internet access and retry');
  if (!token.body?.access_token) return fail(`thecolony.cc refuses COLONY_API_KEY (HTTP ${token.status})`, 'copy the API key of the account named by COLONY_USERNAME from thecolony.cc again');
  const me = await get(`${COLONY_API}/users/me`, { headers: { authorization: `Bearer ${token.body.access_token}` } });
  const name = typeof me.body?.username === 'string' ? me.body.username.toLowerCase() : null;
  if (!name) return fail(`thecolony.cc accepted COLONY_API_KEY but did not say whose it is (HTTP ${me.status})`, 'retry; the Colony login needs the key\'s account to receive the DMs');
  if (name !== s.colonyUsername.toLowerCase()) return fail(`COLONY_API_KEY belongs to @${name}, not COLONY_USERNAME @${s.colonyUsername}`, `set COLONY_USERNAME=${name}, or use @${s.colonyUsername}'s key: the key must read the DMs agents send that account`);
  ok(`Colony login: the key belongs to @${name}, which receives the sign-in DMs`);
}

/**
 * Whether `publicUrl`/v2 answers as this relay: signed by `relay`, serving `program`. Retries for
 * `seconds` (a certificate may still be on its way); returns null on success, else the last problem.
 */
export async function probePublicUrl({ publicUrl, relay, program, seconds = 120, every = 5000, fetch = globalThis.fetch, sleep = ms => new Promise(r => setTimeout(r, ms)) }) {
  const deadline = Date.now() + seconds * 1000;
  let last = 'no answer';
  while (true) {
    try {
      const r = await fetch(`${publicUrl}/v2`, { signal: AbortSignal.timeout(10_000), redirect: 'manual' });
      const body = await r.json().catch(() => null);
      if (r.ok && body?.relay === relay && body?.program === program && r.headers.get('x-ac-signer') === relay) return null;
      last = r.ok && body?.relay === relay && body?.program === program ? 'its answer is not signed by this relay\'s key (x-ac-signer): does the proxy rewrite headers?'
        : r.ok && body?.relay ? `it answers as relay ${body.relay}${body.program !== program ? ` for program ${body.program}` : ''}, not as this relay ${relay}`
        : r.ok ? `HTTP ${r.status}, but not an Artifact Council relay's answer`
        : `HTTP ${r.status}${r.status >= 300 && r.status < 400 ? ` (a redirect to ${r.headers.get('location')})` : r.status === 502 ? ' from the proxy: is the relay port right?' : ''}`;
    } catch (e) { last = e?.cause?.code ?? e?.cause?.message ?? e?.message ?? String(e); }
    if (Date.now() + every > deadline) return last;
    await sleep(every);
  }
}

/** Prints a check's results; returns whether it passed. */
export function report({ results }, print = console.log) {
  const tag = { ok: 'ok  ', warn: 'WARN', fail: 'FAIL', info: '--  ' };
  for (const r of results) { print(`  ${tag[r.level]}  ${r.text}`); if (r.fix) print(`        -> ${r.fix}`); }
  return !results.some(r => r.level === 'fail');
}

/** What to do after a start: health, traffic, and the way to a seat. */
export function nextSteps({ publicUrl, port, facts, mode }) {
  const lines = [`Health: curl -s ${publicUrl || `http://127.0.0.1:${port}`}/v2  (shows program, relay key, crank passes and spend)`];
  if (mode !== 'crank') lines.push(`Discovery: https://artifactcouncil.com/v2/relays lists this relay once its signed health check passes.`);
  lines.push(facts.earned ? 'Routed traffic: this relay earned work recently, so the public gateway may route agents to it.'
    : 'Routed traffic: comes once an epoch (30 minutes) in which this relay\'s cranking earned work has closed; keep it running.');
  lines.push(`Attestor seat (optional, needs a paid RPC and a bond): \`${command('seat')}\` shows whether this relay can join and what it costs; \`${command('seat', 'join --yes')}\` joins.`);
  lines.push(`Back up the operator key (${facts.keyPath ?? DEFAULT_KEY}) off this host: it is the payout wallet rewards are paid to. \`${command('balance')}\` shows them; \`${command('withdraw', '--to <your-wallet>')}\` takes out everything above the float.`);
  return lines;
}
