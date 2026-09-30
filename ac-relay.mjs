// Artifact Council relay: one command for every step. Reads .env from the working directory (real
// environment variables win) and keeps its keys and state in .local/ there.
//
//   node ac-relay.mjs init [--rpc URL] [--url https://relay.your-domain.com]
//                                  create .env and the operator key (local only; sends nothing)
//   node ac-relay.mjs check [relay|gateway|crank|preview]
//                                  the self-check: settings, key, RPC, cluster, program, funds, registration
//   node ac-relay.mjs preview [--host 127.0.0.1]
//                                  a read-only relay on AC_PORT: no domain, funds or registration needed
//   node ac-relay.mjs start [relay|gateway|crank]
//                                  self-check, confirm AC_PUBLIC_URL reaches this relay, register, serve and crank
//   node ac-relay.mjs seat [status|join|activate|leave|withdraw] [--funder key.json] [--yes]
//                                  the optional attestor seat (--funder: another wallet pays the bond and gets it back)
//   node ac-relay.mjs balance      what the relay key (the payout wallet) holds and what it is still owed
//   node ac-relay.mjs withdraw --to <address> [--keep 0.2] [--yes]
//                                  send everything above the float to your own wallet (a dry run without --yes)
import { readFileSync, writeFileSync, rmSync, mkdirSync, existsSync, copyFileSync, chmodSync, statSync, renameSync } from 'node:fs';
import { hostname } from 'node:os';
import { resolve, dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Council, Keypair, PublicKey, NETWORK } from './sdk/index.mjs';
import { RpcTransport } from './sdk/transport.mjs';
import { runCranker } from './sdk/cranks.mjs';
import { colonyVerifier } from './sdk/colony.mjs';
import { snapshotFunds } from './sdk/funding.mjs';
import { joinSeat, activateSeat, leaveSeat, withdrawSeat } from './sdk/snapshots.mjs';
import { planWithdraw, sendWithdraw, pendingRewards, parseSol, DEFAULT_KEEP } from './sdk/payout.mjs';
import { startRelay, gatewaySettings } from './scripts/relay-server.mjs';
import { LOOPBACK } from './sdk/client-address.mjs';
import { selfCheck, report, nextSteps, settings, readKeypair, probePublicUrl, command, fundHint, rpcCall, redact, clusterName, MIN_START } from './check.mjs';

/** A refusal the operator fixes: printed as one plain line, never a stack trace. */
class Stop extends Error {}
const stop = message => { throw new Stop(message); };
const flag = name => process.argv.includes(`--${name}`);
const option = (name, fallback) => { const i = process.argv.indexOf(`--${name}`); return i > 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[i + 1] : fallback; };
const loadEnv = () => { try { process.loadEnvFile('.env'); } catch (e) { if (e.code !== 'ENOENT') stop(`.env could not be read: ${e.message}`); } };
const sol = lamports => `${(lamports / 1e9).toFixed(4).replace(/\.?0+$/, '')} SOL`;
/** To the lamport, for what a payout moves. */
const exact = lamports => `${(lamports / 1e9).toFixed(9).replace(/\.?0+$/, '')} SOL`;

/** Creates what is missing: .env from the template, the operator key, the gateway seed. Never overwrites. */
function init({ rpc, url, quiet = false } = {}) {
  mkdirSync('.local', { recursive: true, mode: 0o700 });
  let created = false;
  if (!existsSync('.env')) { copyFileSync(new URL('./.env.example', import.meta.url), '.env'); chmodSync('.env', 0o600); created = true; }
  // A new .env starts on the network's public RPC (sdk/index.mjs NETWORK): enough for a preview. Only
  // the file: a real AC_RPC in the environment still wins, as .env never overrides it.
  const template = created && !rpc ? NETWORK.publicRpc : null;
  if (rpc || url || template) {
    for (const [name, value] of [['AC_RPC', rpc || template], ['AC_PUBLIC_URL', url]]) if (value) {
      if (/[\s#"']/.test(value)) stop(`${name} must be a plain URL`);
      const text = readFileSync('.env', 'utf8'), line = new RegExp(`^${name}=.*$`, 'm');
      writeFileSync('.env', line.test(text) ? text.replace(line, `${name}=${value}`) : `${text.replace(/\n?$/, '\n')}${name}=${value}\n`);
      if (value !== template) process.env[name] = value;
    }
  }
  loadEnv();
  const keyPath = settings().keyPath;
  if (!existsSync(keyPath)) {
    mkdirSync(dirname(resolve(keyPath)), { recursive: true, mode: 0o700 });
    writeFileSync(keyPath, JSON.stringify([...Keypair.generate().secretKey]), { mode: 0o600, flag: 'wx' });
  }
  if (!existsSync('.local/gateway-seed')) writeFileSync('.local/gateway-seed', randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
  const address = readKeypair(keyPath).publicKey.toBase58(), s = settings();
  // docker compose names its project, containers and volumes after this: two copies on one host
  // (a relay and a gateway) never share or replace each other's (compose.yaml \`name\`).
  if (!/^COMPOSE_PROJECT_NAME=/m.test(readFileSync('.env', 'utf8'))) {
    const text = readFileSync('.env', 'utf8');
    writeFileSync('.env', `${text.replace(/\n?$/, '\n')}# docker compose's project name for this copy (init writes it once, from the operator address).\nCOMPOSE_PROJECT_NAME=ac-${address.slice(0, 8).toLowerCase()}\n`);
  }
  // Only the settings still to fill in; --rpc and --url fill them from the command line.
  const steps = [];
  if (!s.rpc || s.rpc.replace(/\/+$/, '') === NETWORK.publicRpc) steps.push(`Set AC_RPC in .env to your own ${NETWORK.name} RPC URL (Helius, Triton, QuickNode, ...): the public ${s.rpc ? 'one it holds now' : 'endpoint'} is enough for a preview but rate-limits a relay.`);
  if (!s.publicUrl) steps.push('Set AC_PUBLIC_URL in .env to the https address that will reach this host (its DNS record pointing here; no path, no port).');
  steps.push(`Fund ${address} with ${NETWORK.name} SOL: ${fundHint(address)} (0.1 to 0.2 SOL).`);
  const hostProxy = process.env.AC_PROXY === 'host' || process.env.AC_MODE === 'crank';
  steps.push(`Start: ${command('start')}${process.env.AC_DOCKER !== '1' ? '' : hostProxy ? ' (logs: docker compose logs -f relay-host)' : ' (run it again after editing .env: Caddy reads AC_PUBLIC_URL when it starts; logs: docker compose logs -f relay)'}`);
  if (!quiet) console.log([
    `${created ? 'Created .env. ' : ''}Operator address: ${address}`,
    `Key: ${keyPath} (existing keys are never overwritten). Back it up off this host: it is also the wallet your rewards are paid to.`,
    '',
    'Next:',
    ...steps.map((line, i) => `  ${i + 1}. ${line}`),
    `To look around first, with no domain or funds: ${command('preview')}`,
  ].join('\n'));
  return address;
}

const noUrl = () => flag('no-url') || process.env.AC_CRANK_NO_URL === '1';
async function check(mode) {
  console.log(`Self-check (${mode}):`);
  const result = await selfCheck({ mode, noUrl: noUrl() });
  report(result);
  return result;
}
const refuseOnFail = result => { if (!result.ok) stop('Fix the FAIL lines above and run this again. Nothing was sent and nothing was spent.'); };

const positive = (name, fallback) => {
  const value = Number(process.env[name] || fallback);
  if (!Number.isSafeInteger(value) || value <= 0) stop(`${name} must be a positive integer`);
  return value;
};

/** Who holds the cranking lock at `path`, or null when it is free to take: held while refreshed in the
 *  last LOCK_FRESH_MS (from any host or container), or by a live process on this host. */
export const LOCK_FRESH_MS = 90_000;
function lockHolder(path) {
  let text = '', h = null;
  try { text = readFileSync(path, 'utf8'); } catch { return null; }
  if (/^\d+$/.test(text.trim())) h = { pid: Number(text), host: hostname() }; // an older release's lock: a pid on this host
  else try { h = JSON.parse(text); } catch {}
  if (!h || typeof h !== 'object') { // unreadable: fresh by its file time
    try { return Date.now() - statSync(path).mtimeMs < LOCK_FRESH_MS ? 'an unreadable lock' : null; } catch { return null; }
  }
  const who = `pid ${h.pid ?? '?'}${h.host && h.host !== hostname() ? ` on ${h.host}` : ''}`;
  if (Number.isFinite(h.at) && Date.now() - h.at < LOCK_FRESH_MS) return who;
  if (h.host !== hostname() || !Number.isSafeInteger(h.pid) || h.pid <= 0 || h.pid === process.pid) return null;
  try { process.kill(h.pid, 0); return who; } catch (e) { return e.code === 'EPERM' ? who : null; }
}

/** Preview: a read-only relay that signs its answers with the operator key. */
async function preview() {
  init({ quiet: true });
  const result = await check('preview');
  refuseOnFail(result);
  const port = positive('AC_PORT', 8899), host = option('host', '127.0.0.1');
  const s = settings(), payer = readKeypair(s.keyPath);
  const { server } = await startRelay({ transport: new RpcTransport(s.rpc), program: new PublicKey(s.program), payer, host, port, readOnly: true, perMinute: positive('AC_PER_MINUTE', 60), trustedProxies: LOOPBACK });
  console.log([`\nPreview (read-only) at http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}/v2 (try /v2/artifacts). It sends nothing, registers nothing and spends nothing.`,
    `When you are ready: set AC_PUBLIC_URL, fund the key, then \`${command('start')}\`. Ctrl+C stops the preview.`].join('\n'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
}

/** Before the one registration the chain never lets us edit: does AC_PUBLIC_URL reach this relay? */
async function confirmPublicUrl({ transport, program, payer, port, publicUrl }) {
  const seconds = positive('AC_URL_CHECK_SECONDS', 120);
  console.log(`Checking that ${publicUrl}/v2 reaches this relay before registering it (up to ${seconds} s)...`);
  const { server } = await startRelay({ transport, program, payer, host: '127.0.0.1', port, readOnly: true, trustedProxies: LOOPBACK });
  let last;
  try { last = await probePublicUrl({ publicUrl, relay: payer.publicKey.toBase58(), program: program.toBase58(), seconds }); }
  finally { await new Promise(r => server.close(r)); }
  if (last === null) { console.log(`${publicUrl}/v2 reaches this relay.`); return; }
  stop([`${publicUrl}/v2 does not reach this relay (${last}). Nothing was registered.`,
    `  The chain keeps a relay's URL for good, so it must work before the first start. Check that:`,
    `  - DNS for ${new URL(publicUrl).hostname} points at this host, and ports 80 and 443 are open;`,
    `  - your HTTPS proxy (Caddy in docker compose, or your own nginx/Caddy) forwards to 127.0.0.1:${port} (operator guide, "HTTPS in front");`,
    '  then run start again. AC_URL_CHECK_SECONDS waits longer while a certificate is issued.'].join('\n'));
}

async function start(mode) {
  if (!['relay', 'gateway', 'crank'].includes(mode)) stop('Mode must be relay, gateway, or crank');
  init({ quiet: true });
  // Settings are refused before any RPC call.
  // Relay and gateway modes always crank in process every AC_CRANK_SECONDS (default 60, with jitter);
  // crank mode is the standalone cranker for operators who only crank (default every 30 s).
  const port = positive('AC_PORT', 8899), perMinute = positive('AC_PER_MINUTE', 60), every = positive('AC_CRANK_SECONDS', mode === 'crank' ? 30 : 60);
  if (port > 65535) stop('AC_PORT must be at most 65535');
  // AC_CRANK_SELF_PAY=0 (default 1): a step the vault cannot fund is left to others instead of run
  // self-paid with this wallet paying (owner, 30 September; README "If the treasury is empty").
  if (!['0', '1', undefined, ''].includes(process.env.AC_CRANK_SELF_PAY)) stop('AC_CRANK_SELF_PAY must be 0 or 1');
  const selfPay = process.env.AC_CRANK_SELF_PAY !== '0';
  if (!['1', undefined, ''].includes(process.env.AC_CRANK)) stop('AC_CRANK must be 1 or unset: every relay cranks in process (decision 8); run crank mode only on a host with no relay');
  if (!['0', '1', undefined, ''].includes(process.env.AC_ATTESTED_ONLY)) stop('AC_ATTESTED_ONLY must be 0 or 1');
  // The relay fronts only what the vault refunds; AC_ALLOW names agents this operator pays for anyway,
  // and AC_DAILY_CEILING (lamports) bounds what the relay process spends of its own in a UTC day.
  const dailyCeiling = positive('AC_DAILY_CEILING', 100_000_000);
  const allow = (process.env.AC_ALLOW || '').split(',').map(s => s.trim()).filter(Boolean);
  for (const key of allow) { try { new PublicKey(key); } catch { stop(`AC_ALLOW holds ${key}, which is not a Solana address`); } }
  const sendsPerHour = positive('AC_SENDS_PER_HOUR', 6), donationReadsPerMinute = positive('AC_DONATION_READS_PER_MINUTE', 60);
  const gateway = gatewaySettings(n => process.env[`AC_${n.toUpperCase().replaceAll('-', '_')}`] || undefined);
  // One cranking process per operator directory: a relay or gateway and a standalone cranker on the
  // same wallet would race each other's cranks, and the standalone one is outside the spend ceiling.
  // PIDs mean nothing across containers (node is PID 1 in each), so the lock names its host and is
  // refreshed while held: a fresh lock is held whatever its pid; an old one only by a live pid here.
  const lock = resolve('.local/crank.pid'), me = { host: hostname(), pid: process.pid };
  const mine = () => { try { const h = JSON.parse(readFileSync(lock, 'utf8')); return h.host === me.host && h.pid === me.pid; } catch { return false; } };
  for (let tries = 0; ; tries++) {
    try { writeFileSync(lock, JSON.stringify({ ...me, at: Date.now() }), { flag: 'wx' }); break; } catch (e) { if (e.code !== 'EEXIST' || tries) throw e; }
    const holder = lockHolder(lock);
    if (holder) stop(`Another relay or cranker (${holder}) already cranks from this directory; stop it first. A lock whose process is gone frees itself within ${LOCK_FRESH_MS / 1000} s (or remove .local/crank.pid). Every relay cranks, so a separate cranker is only for hosts without a relay.`);
    rmSync(lock, { force: true });
  }
  // Replaced whole (write, then rename), so a reader never sees half a lock.
  setInterval(() => { if (mine()) try { writeFileSync(`${lock}.new`, JSON.stringify({ ...me, at: Date.now() })); renameSync(`${lock}.new`, lock); } catch {} }, 30_000).unref();
  process.on('exit', () => { try { if (mine()) rmSync(lock); } catch {} });

  const result = await check(mode);
  refuseOnFail(result);
  const s = settings(), payer = readKeypair(s.keyPath), program = new PublicKey(s.program);
  const transport = new RpcTransport(s.rpc), council = new Council({ transport, program });
  console.log(`Mode: ${mode} | operator: ${payer.publicKey.toBase58()} | program: ${s.program}`);
  if (mode === 'crank') {
    let stopping = false, wake = () => {};
    for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { if (stopping) process.exit(130); stopping = true; wake(); });
    await runCranker(council, payer, { every: every * 1000, selfPay, stopped: () => stopping, register: { kind: 'relay', url: s.publicUrl || '' },
      sleep: ms => new Promise(r => { const t = setTimeout(r, ms); wake = () => { clearTimeout(t); r(); }; }),
      log: m => console.log(new Date().toISOString(), m), error: m => console.error(new Date().toISOString(), m) });
    process.exit(0);
  }
  if (!result.facts.registered && process.env.AC_SKIP_URL_CHECK !== '1') await confirmPublicUrl({ transport, program, payer, port, publicUrl: s.publicUrl });
  const colony = mode === 'gateway' ? {
    verifier: colonyVerifier({ apiKey: s.colonyKey, recipient: s.colonyUsername.toLowerCase(), colonyId: process.env.COLONY_ID || undefined }),
    seed: Buffer.from(readFileSync('.local/gateway-seed', 'utf8').trim(), 'hex'),
    // Independent gateways create their own hosted identities. No founder manifest or keys.
    siteAgentId: () => null,
  } : null;
  if (colony && colony.seed.length !== 32) stop('Invalid gateway seed in .local/gateway-seed');
  // The relay listens on loopback only, so its proxy is local: only its last X-Forwarded-For entry is read (README).
  const { server } = await startRelay({ transport, program, payer, host: '127.0.0.1', port,
    url: s.publicUrl, gatewayDir: mode === 'gateway' ? resolve('.local/hosted') : null,
    routePeers: mode === 'gateway' && process.env.AC_ROUTE_PEERS !== '0',
    // AC_ATTEST=1 works this wallet's attestor seat (join it first: npm run seat); its alerts go to the log.
    ...(process.env.AC_ATTEST === '1' ? { snapshotDir: resolve('.local/snapshots'), attest: { ours: (process.env.AC_OURS || '').split(',').map(s => s.trim()).filter(Boolean), notifier: null } } : {}),
    crank: { every: every * 1000, selfPay }, uploadDir: resolve('.local/uploads'), stateDir: resolve('.local/state'), dailyCeiling, allow, openRegister: false, perMinute,
    colony, trustedProxies: LOOPBACK, proxySecret: process.env.AC_PROXY_SECRET || null, attestedOnly: process.env.AC_ATTESTED_ONLY !== '0',
    sendsPerHour, donationReadsPerMinute, ...(process.env.AC_OPERATOR_NAME ? { operator: process.env.AC_OPERATOR_NAME } : {}), ...gateway });
  console.log(`Listening at http://127.0.0.1:${port}/v2 behind ${s.publicUrl}. Preserve .local/.`);
  console.log(['', 'Next steps:', ...nextSteps({ publicUrl: s.publicUrl, port, facts: result.facts, mode }).map(l => `  - ${l}`)].join('\n'));
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { server.close(() => process.exit(0)); });
}

/** The optional attestor seat: what it takes, then Join, Activate, Leave or Withdraw with --yes. */
async function seat(action) {
  const ops = { status: null, join: joinSeat, activate: activateSeat, leave: leaveSeat, withdraw: withdrawSeat };
  if (!(action in ops)) stop(`Use: ${command('seat', '[status|join|activate|leave|withdraw] [--yes]')}`);
  const result = await check('seat');
  refuseOnFail(result);
  const s = settings(), payer = readKeypair(s.keyPath), c = new Council({ transport: new RpcTransport(s.rpc), program: new PublicKey(s.program) });
  const [mine, balance] = [await c.attestor(payer.publicKey), result.facts.balance ?? 0];
  console.log(`\nSeat: ${mine ? `${mine.state}, bond ${sol(mine.bond)}` : 'none'}`);
  // The next step from each state: none joins, pending or pruned activates, active leaves, leaving withdraws.
  const op = action === 'status' ? ({ pending: 'activate', pruned: 'activate', active: 'leave', leaving: 'withdraw' }[mine?.state] ?? 'join') : action;
  // --funder: another wallet pays the bond and the seat's rent, and gets them back at Withdraw (it
  // co-signs Join only; it can go back offline after). Without it the relay key funds the seat.
  let funder = null;
  if (option('funder')) {
    if (op !== 'join') stop('--funder goes with join: Withdraw returns the bond to whoever funded the seat, with no signature of theirs');
    try { funder = readKeypair(option('funder')); } catch (e) { stop(`The funder key file ${option('funder')} is unreadable: ${e.message}${process.env.AC_DOCKER ? '. The container sees only this directory: copy the file to .local/funder.json (chmod 600), pass --funder .local/funder.json, and delete it after Join' : ''}`); }
  }
  const q = await snapshotFunds(c, op, { payer: payer.publicKey, ...(funder ? { funder: funder.publicKey } : {}) });
  if (action === 'status') {
    if (q.refused) console.log(`${op[0].toUpperCase() + op.slice(1)} is not possible yet: ${q.reason}.`);
    else console.log(`${op[0].toUpperCase() + op.slice(1)} would cost this wallet up to ${sol(q.worst)}${op === 'join' ? ` (bond and rent, returned after the seat leaves and unbonds, at least 14 days)` : ''}: ${command('seat', `${op} --yes`)}`);
    console.log('A seat needs relay work credited in the last 48 epochs, a paid RPC (AC_RPC) and AC_ATTEST=1 in .env once joined; see the operator guide, "Attestor seats".');
    return;
  }
  if (q.refused) stop(`${action} refused before sending: ${q.reason}`);
  if (balance < q.worst) stop(`${action} needs up to ${sol(q.worst)}; the wallet holds ${sol(balance)}. Fund ${payer.publicKey.toBase58()} first.`);
  const funded = funder ? q.deposits.filter(d => !d.own).reduce((n, d) => n + d.lamports, 0) : 0;
  if (funder) {
    const held = (await c.t.getAccount(funder.publicKey))?.lamports ?? 0;
    if (held < funded + 5000) stop(`The funder ${funder.publicKey.toBase58()} holds ${sol(held)}; the bond and rent need ${sol(funded)}. Fund it first.`);
  }
  const whose = funder ? `; the funder ${funder.publicKey.toBase58()} pays ${sol(funded)} (bond and rent, returned to it at Withdraw)` : '';
  if (!flag('yes')) { console.log(`${action} would cost this wallet up to ${sol(q.worst)}${whose}. Run again with --yes to send it.`); return; }
  const signature = await ops[action](c, payer, ...(funder ? [{ funder }] : []));
  console.log(`${action} sent: ${signature}`);
  if (action === 'join' || action === 'activate') console.log('Now set AC_ATTEST=1 in .env (and AC_OURS, your own seats\' relay keys, if you run several) and restart: the relay works the seat beside its crank and activates it once it matures (7 days after joining). It needs a paid RPC.');
}

/** The relay key and a transport on this network's RPC, or a Stop: no key, no RPC, another cluster.
 *  Payouts need no program, registration or public URL, so this is all they check. */
async function wallet() {
  const s = settings();
  if (!s.rpc) stop(`AC_RPC is not set: set it in .env to your ${NETWORK.name} RPC URL`);
  if (!existsSync(s.keyPath)) stop(`No operator key at ${s.keyPath}: nothing to pay out (${command('init')} creates one)`);
  let payer; try { payer = readKeypair(s.keyPath); } catch (e) { stop(`The key file ${s.keyPath} is unreadable: ${e.message}`); }
  let genesis; try { genesis = await rpcCall(s.rpc, 'getGenesisHash'); } catch (e) { stop(`RPC ${redact(s.rpc)} does not answer: ${e.message}. Nothing was sent.`); }
  if (genesis !== NETWORK.genesis) stop(`RPC ${redact(s.rpc)} serves ${clusterName(genesis)}, not ${NETWORK.name}: this package pays out only on ${NETWORK.name}. Nothing was sent.`);
  const transport = new RpcTransport(s.rpc);
  return { s, payer, transport, council: s.program ? new Council({ transport, program: new PublicKey(s.program) }) : null };
}
/** The pending-rewards lines, or why they could not be read (a public RPC may refuse the epoch scan). */
async function pendingLines(council, key) {
  if (!council) return ['Pending rewards: unknown (this package names no program yet).'];
  try {
    const p = await pendingRewards(council, key);
    if (!p.registered) return ['Pending rewards: none (this key is not registered as a relay yet).'];
    return [`Pending rewards: ${exact(p.accrued)} accrued on the relay record (paid to this key once it reaches ${exact(p.minPayout)})`,
      `  ${p.claimableUnits ? `about ${exact(p.claimable)} for ${p.claimableUnits} work unit(s) in closed epochs, claimed by the next crank pass` : 'no claimable work in closed epochs'}${p.tooSmallUnits ? `; ${p.tooSmallUnits} unit(s) worth ${exact(p.tooSmall)}, too small to claim (each share must exceed one transaction fee)` : ''}${p.openUnits ? `; ${p.openUnits} unit(s) in the open epoch, priced when it closes` : ''}.`];
  } catch (e) { return [`Pending rewards: unreadable here (${e.message.split('\n')[0]}).`]; }
}

async function balance() {
  const { payer, transport, council } = await wallet(), key = payer.publicKey.toBase58();
  const lamports = (await transport.getAccount(payer.publicKey))?.lamports ?? 0;
  console.log([`Relay key (the payout wallet): ${key}`, `Balance: ${exact(lamports)}`, ...await pendingLines(council, key),
    `To take out everything above a ${exact(DEFAULT_KEEP)} float: ${command('withdraw', '--to <your-wallet>')} (a dry run; add --yes to send).`].join('\n'));
}

/** Everything above the float, from the relay key to the operator's wallet. A dry run without --yes. */
async function withdraw() {
  const to = option('to');
  if (!to) stop(`Use: ${command('withdraw', '--to <your-wallet-address> [--keep 0.2] [--yes]')}`);
  let keep; try { keep = option('keep') === undefined ? DEFAULT_KEEP : parseSol(option('keep'), '--keep'); } catch (e) { stop(e.message); }
  const { payer, transport, council } = await wallet(), key = payer.publicKey.toBase58();
  // The pending rewards first (the epoch scan can be slow on a public RPC), then the plan from the
  // balance as it is now; sendWithdraw reads it once more just before it sends.
  const pending = await pendingLines(council, key);
  let plan; try { plan = await planWithdraw(transport, { from: key, to, keep }); } catch (e) { if (e.refused) stop(`Withdraw refused: ${e.message}. Nothing was sent.`); throw e; }
  console.log([`Relay key: ${key}`, `Balance: ${exact(plan.balance)}`, ...pending,
    `Withdraw ${exact(plan.amount)} to ${plan.to} (fee ${exact(plan.fee)}); ${exact(plan.keep)} stays on the relay key.`].join('\n'));
  if (plan.keep < MIN_START) console.log(`Note: a relay needs ${exact(MIN_START)} to start; with ${exact(plan.keep)} left, fund it again before the next start.`);
  if (!flag('yes')) { console.log('Dry run: nothing was sent. Check the address, then run again with --yes to send it.'); return; }
  let signature; try { signature = await sendWithdraw(transport, plan, payer); } catch (e) { if (e.refused) stop(`Withdraw refused: ${e.message}. Nothing was sent.`); throw e; }
  console.log(`Sent: ${signature}`);
}

const HELP = `Artifact Council relay
  npm run init       create .env and the operator key (sends nothing)
  npm run check      check settings, key, RPC, program, funds and registration
  npm run preview    a read-only relay at http://127.0.0.1:8899/v2 (no domain or funds needed)
  npm start          check, then register (once), serve and crank
  npm run gateway    the same as a hosted gateway (needs COLONY_USERNAME and COLONY_API_KEY)
  npm run seat       the optional attestor seat (status, join, activate, leave, withdraw)
  npm run balance    what the relay key (your payout wallet) holds and is still owed
  npm run withdraw -- --to <wallet> [--keep 0.2] [--yes]
                     send everything above the float to your own wallet (a dry run without --yes)
With Docker: docker compose run --rm cli <command> (preview: docker compose run --rm --service-ports preview; start: docker compose up -d, or docker compose up -d relay-host behind this host's own proxy)`;

try {
  const [command = 'help', arg] = process.argv.slice(2).filter(a => !a.startsWith('--') && !['host', 'rpc', 'url', 'to', 'keep', 'funder'].some(o => a === option(o)));
  if (command !== 'init') loadEnv();
  const mode = arg || process.env.AC_MODE || 'relay';
  if (command === 'init') init({ rpc: option('rpc'), url: option('url') });
  else if (command === 'check') { const r = await check(mode); if (r.ok && r.facts.address) console.log(['', 'Next steps:', ...nextSteps({ publicUrl: settings().publicUrl, port: Number(process.env.AC_PORT || 8899), facts: r.facts, mode }).map(l => `  - ${l}`)].join('\n')); process.exitCode = r.ok ? 0 : 1; }
  else if (command === 'preview') await preview();
  else if (command === 'start') await start(mode);
  else if (command === 'seat') await seat(arg || 'status');
  else if (command === 'balance') await balance();
  else if (command === 'withdraw') await withdraw();
  else if (command === 'help') console.log(HELP);
  else stop(`Unknown command ${command}.\n${HELP}`);
} catch (e) {
  console.error(e instanceof Stop ? `\n${e.message}` : `\nError: ${e?.message?.split('\n')[0] ?? e}`);
  process.exit(1);
}
