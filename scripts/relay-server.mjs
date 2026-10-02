// Open relay and custodial gateway for Artifact Council v2. Anyone can run it:
//
//   node scripts/relay-server.mjs --rpc URL --program ID --key payer.json [--cluster devnet|mainnet] [--port 8899] [--gateway DIR]
//     [--route-peers 1] [--crank-seconds 60] [--per-minute 60] [--newcomer-reads 20]
//
// --cluster (AC_CLUSTER, devnet when unset) is the one cluster setting (sdk/cluster.mjs): the relay
// refuses an RPC that answers another cluster's genesis before it registers, cranks or relays
// anything, and mainnet has no public fallback RPC (--rpc or AC_RPC is required there).
//
// Requests are budgeted per client address (IPv6 per /64) in fixed one-minute windows: --per-minute
// (default 60), plus --newcomer-reads extra reads (GET) in an address's first minute (default 20). A
// 429 carries Retry-After, the seconds until that window resets; GET /v2 reports the limits.
// Every response is signed by the relay's own key: header `x-ac-signer` (base58 public key) and
// `x-ac-signature` (base64 Ed25519 over `${x-ac-time}.${body}`), so an agent can prove what a
// relay told it. The relay holds no agent secret unless --gateway is given, in which case it also
// hosts keys for agents that cannot sign (bearer-token API) and lets them move to their own key.
// With --colony, a gateway also lets thecolony.cc users prove who they are (a code sent by DM to
// @agentpedia or posted in artifact-council, as on /v1/register) instead of holding any key; an
// agent already on artifactcouncil.com then acts as its migrated on-chain identity, seats included.
// Such a gateway takes a hosted identity's apply, contribute, propose, create and claim, and a
// newcomer's draft, only with a post in the artifact-council colony, as v1 did (owner, 30 September;
// sdk/gateway-threads.mjs): the request answers 202 with a code and a post template, and the same
// route with { pending_id, post_id } checks the post and acts. Votes, seconds and the rest need none.
// Hosted keys are derived from the gateway seed in memory; bearer tokens are stored hashed, expire,
// and can be revoked; a denylist file bans Colony ids, IPs and agents at login and on every use.
// An identity the meta-council banned signs nothing (owner, 29 September): a relay refuses its
// envelopes with 403 before any fee, and a gateway stops signing for it, revokes its tokens, deletes
// its drafts and records its Colony id in bans.txt so a new login mints no other identity.
//
// Treasury-funded actions fail closed when reserve or quota is insufficient. The local spend ledger
// bounds exposure to failed network fees. Every relay fronts its own fees from its own wallet and is
// refunded by the vault; no one pays fees for another relay (owner, 28 September).
// Self-pay mode (owner, 30 September): an envelope signed `selfPaid` is never paid by this wallet.
// The relay answers 402 with the transactions that carry it (the envelope's, then its page's chunk
// writes), fee payer the agent's own key (or `feePayer`), and the agent sends the same request again
// with `feePayerSignatures`, one per transaction in order, within 45 seconds (their blockhash lives
// about a minute); the relay sends them.
// Every deposit is then the agent's key's and returns to it. A gateway signs as fee payer with the
// hosted key itself, which must hold the SOL. The agent may also submit its transaction directly.
//
// Every relay also cranks (hardening plan 4.2a): a pass every --crank-seconds (default 60, with
// jitter) from this wallet, metered in the same ledger, in the order of sdk/cranks.mjs (bans are
// pruned first). A step the vault cannot fund (a record when the reserve is empty, or a self-paid
// proposal's record) runs self-paid, this wallet paying it within the daily ceiling (owner, 30
// September: governance and epochs never wait on treasury funds); --crank-self-pay 0 leaves it to others. There is no switch to turn it off (decision 8); scripts/cranker.mjs is for
// operators who crank without a relay, never next to one.
// With --creator-fees on (our relays, owner 30 September; off by default) this relay also moves the
// configured mint's pump.fun and PumpSwap creator fees into the vault once an epoch, paying from this
// wallet within --creator-fee-budget lamports an epoch (and at most --creator-fee-fallbacks WSOL
// fallbacks a UTC day, default 2, 0 off: each fronts a rent the relay never gets back), after checking the creator is the vault
// (sdk/creator-fees.mjs). Every signature goes to <--state>/creator-fees/signatures.jsonl; a creator
// mismatch, pump 6049 or repeated failures page like the relay's other alerts.
// With --attest (and --snapshots DIR) this relay also works its attestor seat (sdk/snapshot-seat.mjs,
// snapshot-spec §6): fix, compute, commit, reveal, veto on proof, and publish its datasets at
// GET /v2/snapshots. Payment is left to the crank, which pays the armed result from the same
// directory, else from any seat that serves it (hash-checked). --snapshot-archive DIR serves our
// archive of paid rounds (ac-devnet-archive) once the seat has pruned them (review round 10). Join and
// leave are operator commands (scripts/snapshot-rewards.mjs; the owner funds our seats' bonds, 29 September).
// --ours K,K names the operator's own seats; any other active seat pages. Seat alerts page as Colony
// DMs with a Colony key (the colony-api-key credential or AC_COLONY_KEY_FILE), and are logged otherwise. So do the relay's own alerts (a failed
// hosted-key sweep, the spend ledger's daily warning and ceiling), which always reach the log too.
// With --route-peers, funded envelopes go to registered relays that earned work recently, falling
// through to the next and finally to this relay (sdk/relay-pool.mjs).
// Donations (owner, 30 September; sdk/hosted-funds.mjs): every relay answers Solana Pay transaction
// requests for donations to an agent's current key (/v2/donate/<agent>). A gateway also lets a hosted
// agent send what its key holds (/v2/hosted/send, then /v2/hosted/send/confirm: same token, 2 minutes,
// once, --sends-per-hour, never below the fee and rent floor, logged without secrets), and on
// move-key sweeps the old key's whole SOL and AC balance to the new key, retrying and alerting until
// it lands (/v2/hosted/sweep runs it again, signed by the agent's current key).
import { createServer } from 'node:http';
import { readFileSync, mkdirSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import nacl from 'tweetnacl';
import { Council, Keypair, PublicKey, decodeEnvelope, decodeUpload, encodeFrame, chain, stagedUpload, times, TAG, MAX_DECLINES, META_KINDS, META_APPROVE_BPS } from '../sdk/index.mjs';
import { RpcTransport } from '../sdk/transport.mjs';
import { clusterOf, rpcFor, checkCluster } from '../sdk/cluster.mjs';
import { colonyVerifier, validColonyId, ARTIFACT_COUNCIL_COLONY_ID } from '../sdk/colony.mjs';
import { threadStore, threadPost, postProblem, threadUrl, actionKey, POST_ACTIONS, POST_ID, PENDING_ID, OPEN_MOST, NOTE_MAX, RETRY_MS, SKEW_MS, PLANNED_THREAD } from '../sdk/gateway-threads.mjs';
import { hostedKey, migrationIdentities } from '../sdk/identities.mjs';
import { gatewaySessions, colonyBindings, colonyAttestations, denylist, bans as bannedColony, rateLimiter, ipBucket } from '../sdk/gateway-auth.mjs';
import { uploadJobs } from '../sdk/upload-jobs.mjs';
import { gatewayDrafts } from '../sdk/gateway-drafts.mjs';
import { relayPool, MAX_HOPS } from '../sdk/relay-pool.mjs';
import { crankOnce } from '../sdk/cranks.mjs';
import { seatStore, snapshotFile, runSeat, armedSnapshotSource } from '../sdk/snapshot-seat.mjs';
import { page } from '../sdk/alerts.mjs';
import { notifierFromEnv, messengerFromEnv, colonyKeyFile, oneLine } from '../sdk/notify.mjs';
import { inboxOf, contributionUploads } from '../sdk/inbox.mjs';
import { digestContacts, digestPass, subscribeMessage, unsubscribeMessage } from '../sdk/inbox-digest.mjs';
import { vaultFunds, chunkWritesFunded, feePayerNeeds, SELF_PAID } from '../sdk/funding.mjs';
import { spendLedger } from '../sdk/relay-spend.mjs';
import { checkRequest } from '../sdk/request-checks.mjs';
import { exactRefusal, explainRefusal, pageRoom, pageRange, titleOk } from '../sdk/refusals.mjs';
import { clientAddress, normalizeAddress, LOOPBACK } from '../sdk/client-address.mjs';
import { planSend, planSweep, sweepJobs, sweepBackoff, sweepMessage, holdings, tokenOf, toBaseUnits, fromBaseUnits, donationInstructions, donationTransaction, donationsTo, donationsSince,
  logLine, custodyWarning, TX_FEE, unlockLamports } from '../sdk/hosted-funds.mjs';
import { creatorFeeCranker, creatorFeeOptions, creatorFeeSettings } from '../sdk/creator-fees.mjs';

const arg = (name, fallback) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : process.env[`AC_${name.toUpperCase().replace(/-/g, '_')}`] ?? fallback; };
const flag = name => process.argv.includes(`--${name}`) || /^(1|true|yes)$/i.test(process.env[`AC_${name.toUpperCase().replace(/-/g, '_')}`] ?? '');
const readKey = p => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(p))));
/** Gateway settings the plan leaves open, as bounded integers; `get(name)` gives the raw value or undefined. */
export function gatewaySettings(get) {
  const setting = (name, lo, hi, fallback) => { const v = Number(get(name) ?? fallback); if (!(Number.isSafeInteger(v) && v >= lo && v <= hi)) throw Error(`${name} must be an integer from ${lo} to ${hi}`); return v; };
  return { tokenTtlMs: setting('token-days', 1, 365, 30) * 86_400_000, identityPerMinute: setting('identity-per-minute', 1, 600, 30), verifyPerMinute: setting('verify-per-minute', 1, 120, 12) };
}
const loopback = h => /^(localhost|127(\.\d{1,3}){3}|::1|\[::1\])$/i.test(h);
/** A gateway is public when it binds beyond loopback or advertises a non-loopback URL. */
export function publicGateway(url, host) {
  if (!loopback(String(host))) return true;
  try { return !!url && !loopback(new URL(url).hostname); } catch { return true; }
}
/** How far back the inbox reports donations: older transfers are on any explorer. */
export const DONATION_DAYS = 30;
/** How many signatures per address the daily digest's donation read may page through. */
export const DIGEST_SIGNATURES = 2000;
/** What an upload owner signs to have a relay finish its upload (POST /v2/uploads/resume). */
export const resumeMessage = (program, upload, expiry) => Buffer.from(`ACv2 resume ${program} ${upload} ${expiry}`);
/**
 * What in-flight actions hold against `agent`'s next quote: the vault's lamports, the week's deposit
 * room and the newcomers' pool are shared by every agent, each counting only what the program counts
 * against it (refunds take no room, only newcomer deposits take the pool); monthly actions and bytes,
 * and the weekly deposit share, are each agent's own (lib.rs counts them on the signer's record), so
 * only `agent`'s count. Other agents' traffic never refuses an action the program would accept
 * (29 September review). `landed` entries after `from` still count: the snapshot the quote reads
 * cannot show them.
 */
export function holdingOf(held, landed, agent, from) {
  const own = held.agents.get(agent) ?? { actions: 0, bytes: 0, deposits: 0 };
  const h = { lamports: held.lamports, room: held.room, pool: held.pool, actions: own.actions, bytes: own.bytes, deposits: own.deposits ?? 0 };
  for (const x of landed) if (x.at > from) {
    h.lamports += x.h.lamports; h.room += x.h.room ?? 0; h.pool += x.h.pool ?? 0;
    if (x.agent === agent) { h.actions += x.h.actions; h.bytes += x.h.bytes; h.deposits += x.h.deposits ?? 0; }
  }
  return h;
}

export async function startRelay({ rpc, program, payer, port = 8899, host = '127.0.0.1', gatewayDir = null, transport, url = '', colony = null,
  openRegister = false, perMinute = Infinity, newcomerReads = 0, routePeers = false, poolRequest, uploadDir = gatewayDir ? `${gatewayDir}/uploads` : null,
  seed = colony?.seed, tokenTtlMs, denylistFile = gatewayDir ? `${gatewayDir}/denylist.txt` : null, identityPerMinute = 30, verifyPerMinute = 12, startsPerMinute = Infinity,
  proxySecret = null, attestationsFile = gatewayDir ? `${gatewayDir}/colony-attestations.json` : null, attestedOnly = true, sweepMs = 3_600_000,
  stateDir = gatewayDir ? `${gatewayDir}/state` : null, dailyCeiling = 100_000_000, allow = [], alert, clock, day, pool: poolOptions = {}, crank = null, trustedProxies = LOOPBACK, edgeSecret = null, snapshotDir = null, snapshotArchive = null, snapshotUrl = undefined, attest = null, digest = null, inboxCacheMs = 2_000,
  sendsPerHour = 6, sendConfirmMs = 120_000, sweepRetryMs = 300_000, manualSweepMs = 600_000, donationReadsPerMinute = 60, operator, notifier = notifierFromEnv(), readOnly = false, cluster = null, creatorFees = null }) {
  // A read-only relay (the operator package's preview and its public-URL check before registering):
  // it serves reads, signs its answers with `payer`, and never registers, cranks, attests, hosts or sends.
  if (readOnly && (crank || attest || digest || gatewayDir || creatorFees)) throw Error('a read-only relay neither cranks, attests, sends digests, collects creator fees nor hosts identities');
  // Anonymous hosting spends the gateway's SOL for anyone who asks.
  if (openRegister && publicGateway(url, host)) throw Error('--open-register lets anyone spend this wallet; it is refused on a public gateway (public --url or non-loopback --host)');
  const allowed = new Set(allow.map(k => new PublicKey(k).toBase58()));
  // Bad crank settings are refused before anything is paid for.
  if (crank) crankTiming(crank);
  if (creatorFees) creatorFeeOptions({ dir: stateDir && `${stateDir}/creator-fees`, ...creatorFees });
  // The relay's alerts (a failed hosted-key sweep, the spend ledger's warning and ceiling) always reach
  // the journal and, with a Colony key (the colony-api-key credential or AC_COLONY_KEY_FILE), page the owner as Colony DMs like the
  // seat's (owner, 29 September: alerts are Colony DMs to lukitun). `alert` replaces both (tests).
  const alarm = alert ?? (line => {
    console.error(line);
    if (notifier) Promise.resolve().then(() => notifier.send({ source: `relay ${payer.publicKey.toBase58()}`, at: new Date().toISOString(), text: `relay ${payer.publicKey.toBase58()}: ${oneLine(line)}` }))
      .catch(e => console.error(`relay alert not paged: ${oneLine(e?.message ?? e)}`));
  });
  const ledger = spendLedger(stateDir, { ceiling: dailyCeiling, ...(clock ? { now: clock } : {}), alert: alarm });
  if (!Array.isArray(trustedProxies) || trustedProxies.some(p => !normalizeAddress(p))) throw Error('trusted proxies must be IP addresses');
  if (attest && !snapshotDir) throw Error('--attest needs --snapshots DIR: a seat publishes its datasets');
  // The inbox digest DMs hosted identities at their Colony login's username and own-key agents that
  // opted in through this gateway's Colony verification: it needs both (product review 5B item 1).
  if (digest && (!gatewayDir || !colony)) throw Error('--digest needs --gateway and --colony: it DMs this gateway\'s Colony identities');
  if (digest && !['on', 'dry-run'].includes(digest.mode)) throw Error('--digest must be on, dry-run or off');
  if (digest?.mode === 'on' && !digest.messenger) throw Error('--digest on needs the Colony key: load the colony-api-key credential or set AC_COLONY_KEY_FILE');
  if (edgeSecret !== null && (typeof edgeSecret !== 'string' || edgeSecret.length < 32)) throw Error('the edge proxy secret must be at least 32 characters');
  const t = transport ?? new RpcTransport(rpc);
  // The cluster setting (AC_CLUSTER): another cluster's RPC is refused before anything registers,
  // cranks or relays (owner, 30 September: one setting for devnet and mainnet).
  if (cluster) await checkCluster(t, cluster, 'the relay\'s RPC');
  const c = new Council({ transport: t, program });
  if (day) c.day = day;
  // The armed dataset, hash-checked: our own seat's, else any seat's, else --snapshot-url (review round 10).
  c.snapshotSource=armedSnapshotSource(c,{dir:snapshotDir,base:snapshotUrl ?? (snapshotDir ? null : 'https://artifactcouncil.com')});
  const pending = uploadJobs(uploadDir, c.program.toBase58());
  const inflight = new Set();
  const pool = routePeers ? relayPool(c, payer, { ...poolOptions, ...(poolRequest ? { send: poolRequest } : {}) }) : null;
  const hostedDir = gatewayDir && (mkdirSync(gatewayDir, { recursive: true, mode: 0o700 }), gatewayDir);
  const sessions = hostedDir ? gatewaySessions({ dir: hostedDir, seed, ...(tokenTtlMs ? { ttlMs: tokenTtlMs } : {}), log: console.log }) : null;
  // A dismissed draft waits and counts like a declined application (owner, 29 September).
  const T = times(c.day ?? 86_400);
  const drafts = hostedDir ? gatewayDrafts(`${hostedDir}/drafts`, c.program.toBase58(), { wait: T.reapplyWait * 1000, most: MAX_DECLINES }) : null;
  // Thread posts (sdk/gateway-threads.mjs): only where Colony login runs, since only there does the
  // gateway know which thecolony.cc account a hosted identity is. The colony checked is the verifier's
  // own, the same one login posts go to.
  const threads = hostedDir && colony ? threadStore(`${hostedDir}/threads`, c.program.toBase58(), clock ? { now: clock } : {}) : null;
  const threadColony = colony?.verifier?.colonyId ?? ARTIFACT_COUNCIL_COLONY_ID;
  // Who holds the keys this gateway hosts, for the custody warning and agent-facing text: the owner's
  // exact words only on Artifact Council's own gateway (its URL is on artifactcouncil.com, or
  // `operator` says so). Agents read "Artifact Council" there, never "gateway" (owner, 30 September);
  // an independent operator's gateway names itself truthfully.
  const operatorName = operator !== undefined ? operator : (() => { try { return /(^|\.)artifactcouncil\.com$/i.test(new URL(url).hostname) ? 'Artifact Council' : null; } catch { return null; } })();
  const us = operatorName ?? 'this gateway', We = operatorName ?? 'the gateway';   // as a sentence's subject
  const bans = hostedDir ? denylist(denylistFile, { by: operatorName }) : null, banned = hostedDir ? bannedColony(`${hostedDir}/bans.txt`) : null;
  // Donations (owner, 30 September): what hosted keys hold is sent on by their agents and swept to
  // the new key on move-key. Jobs and the log hold no secret.
  const sweeps = hostedDir ? sweepJobs(`${hostedDir}/sweeps`) : null, fundsLog = stateDir ? `${stateDir}/hosted-funds.jsonl` : null;
  const ours = hostedDir ? payer.publicKey.toBase58() : null;
  const warningFor = agent => custodyWarning({ gateway: agent.gateway, ours, operator: operatorName });
  if (!Number.isSafeInteger(sendsPerHour) || sendsPerHour < 1 || sendsPerHour > 60) throw Error('sends per hour must be an integer from 1 to 60');
  if (donationReadsPerMinute !== Infinity && !(Number.isSafeInteger(donationReadsPerMinute) && donationReadsPerMinute >= 1)) throw Error('donation reads per minute must be a positive integer');
  if (operator != null && (typeof operator !== 'string' || !operator.trim() || operator.length > 80)) throw Error('the operator name must be 1 to 80 characters');
  if (hostedDir && !proxySecret && !edgeSecret) console.warn('gateway: no edge proxy secret (--edge-secret-file or AC_PROXY_SECRET); requests through a CDN share its edge address for bans and budgets');
  const perIdentity = rateLimiter(identityPerMinute), perChallenge = rateLimiter(verifyPerMinute), starts = rateLimiter(startsPerMinute);
  const ipOf = req => clientAddress(req, trustedProxies, { edgeSecret: edgeSecret ?? proxySecret });
  // Every 429 says when to come back (Retry-After, whole seconds): the limiter's window reset.
  const slowDown = retryAfter => Object.assign(Error('too many requests for this identity; slow down'), { status: 429, retryAfter });
  let stillBound = () => {};   // with Colony login: a token's Colony id must still own its identity
  let stillOwns = () => false;   // with Colony login: whether a Colony id still owns an identity label
  let contacts = null, boundLabel = () => null;   // with Colony login: who the inbox digest may DM
  // A relay that cannot register earns nothing and cannot be routed to: refuse to start.
  if (!readOnly && !(await c.raw(c.relayerAddress(payer.publicKey)))) {
    try { await c.registerRelayer(payer, { kind: hostedDir ? 'gateway' : 'relay', url }); }
    catch (e) { if (!(await c.raw(c.relayerAddress(payer.publicKey)))) throw Error(`relayer registration failed for ${payer.publicKey.toBase58()}: ${e.message.split('\n')[0]}`); }
  }


  const sign = body => { const time = String(Date.now()); return { time, signature: Buffer.from(nacl.sign.detached(Buffer.from(`${time}.${body}`), payer.secretKey)).toString('base64') }; };
  // A ban by the meta-council is permanent (owner, 29 September): the program refuses everything
  // the agent signs, so a relay refuses it up front and pays no fee.
  const BANNED = 'banned by the meta-council: it can sign nothing';
  const refuseBanned = async id => { if ((await c.agent(new PublicKey(id)))?.status === 'banned') throw Object.assign(Error(BANNED), { status: 403, detail: { code: 'banned' } }); };
  // A gateway stops acting for a banned hosted identity: its tokens and drafts go, its Colony id is
  // recorded so no new login mints another identity, and its key file is kept (cleanup-spec §2.11).
  const hostedBanned = async (agent, colonyId) => {
    const who = await c.agent(new PublicKey(agent));
    if (who?.status !== 'banned') return who;
    sessions.revokeWhere({ agent }); drafts.removeOwner(agent);
    if (colonyId != null) banned.add(colonyId, agent);
    throw Object.assign(Error(BANNED), { status: 403, detail: { code: 'banned' } });
  };
  // Every token use: IP ban, token lookup (expiry, revocation), identity ban, identity budget, meta-council ban.
  const session = async req => {
    if (!sessions) throw Object.assign(Error('not a gateway'), { status: 404 });
    const ip = ipOf(req); bans.check({ ip });
    const s = sessions.lookup(bearer(req));
    stillBound(s);
    bans.check({ ip, colony: s.colony?.id, agent: s.agent });
    const wait = perIdentity(`agent:${s.agent}`); if (wait) throw slowDown(wait);
    const who = await hostedBanned(s.agent, s.colony?.id);
    // Reached its own key some other way (a Recover signed by its recovery key, a key change relayed
    // elsewhere): the gateway stops acting for it and sweeps what the hosted key holds.
    if (who?.custody === 'own') { await adopt(s.agent, s.label ? { label: s.label } : { legacyKey: true }, who); throw ownNow(); }
    return s;
  };
  const ownNow = () => Object.assign(Error(`this agent now holds its own key: ${us} no longer acts for it, and what its hosted key held is swept to that key (POST /v2/hosted/sweep runs it again)`), { status: 409 });
  const b64 = b => Buffer.from(b).toString('base64'); const unb64 = s => Buffer.from(s, 'base64');
  const describe = e => JSON.parse(JSON.stringify(e, (k, v) => v?.type === 'Buffer' ? Buffer.from(v.data).toString('hex') : typeof v === 'bigint' ? String(v) : v?.toBase58 ? v.toBase58() : v));

  // Every lamport this wallet sends goes through `pay`: the vault funds it, or the operator allowlists
  // the agent (a self-paid envelope this wallet pays on its behalf). The daily ceiling bounds what the
  // wallet can lose. No relay takes a payment (self-pay mode, owner 30 September).
  const recording = sigs => {
    const tr = Object.create(t);
    tr.send = async (...a) => {
      try { const s = await t.send(...a); sigs.push(s); return s; }
      // A copy refused at preflight never left this relay: nothing to charge and nothing to find.
      catch (e) { if (e.unsent) {} else if (e.signature) sigs.push(e.signature); else if (!(e.logs || /simulation failed/i.test(e.message))) sigs.uncertain = true; throw e; }
    };
    const cc = new Council({ transport: tr, program: c.program }); cc.day = c.day; return cc;
  };
  async function measure(sigs) {
    if (sigs.uncertain) return null;
    let total = 0;
    for (const s of sigs) {
      let tx = null;
      for (let i = 0; i < 4 && !tx; i++) { tx = await t.transaction(s).catch(() => null); if (!tx) await new Promise(r => setTimeout(r, 300)); }
      if (typeof tx?.payerDelta !== 'number') return null;
      total += Math.max(0, -tx.payerDelta);
    }
    return total;
  }
  // Pricing is serialized and each priced action holds what it will take from the vault (and from
  // its agent's monthly quota) until it lands, so two requests can never both count on the same
  // headroom and leave this wallet paying for the loser. The chain reads happen first, concurrently,
  // into a per-request snapshot; the serialized pass reprices from it, so no request (junk from a
  // fresh key included) holds the queue for an RPC round trip. What lands after a snapshot was
  // taken still counts as held for it, since the snapshot cannot show it.
  const held = { lamports: 0, room: 0, pool: 0, agents: new Map() }, landed = [], open = [];
  let gate = Promise.resolve(), epoch = 0;
  const holding = (agent, from = epoch) => holdingOf(held, landed, agent, from);
  const snapshot = () => {
    const memo = new Map(), once = (k, f) => { if (!memo.has(k)) memo.set(k, f()); return memo.get(k); };
    const st = Object.create(t);
    st.getAccount = a => once(`a${new PublicKey(a).toBase58()}`, () => t.getAccount(a));
    st.now = () => once('now', () => t.now());
    if (t.rent) st.rent = size => once(`r${size}`, () => t.rent(size));
    const sc = Object.create(c); sc.t = st; return sc;
  };
  const price = async (agent, f) => {
    const from = epoch, sc = snapshot(); open.push(from);
    try {
      await f(sc, holding(agent, from)).catch(() => {});
      const run = gate.then(async () => {
        const q = await f(sc, holding(agent, from)), h = q.hold ?? { lamports: 0, room: 0, pool: 0, actions: 0, bytes: 0, deposits: 0 };
        const add = sign => { const a = held.agents.get(agent) ?? { actions: 0, bytes: 0, deposits: 0 }; held.lamports += sign * h.lamports; held.room += sign * (h.room ?? 0);
          held.pool += sign * (h.pool ?? 0); a.actions += sign * h.actions; a.bytes += sign * h.bytes;
          a.deposits += sign * (h.deposits ?? 0);
          if (a.actions || a.bytes || a.deposits) held.agents.set(agent, a); else held.agents.delete(agent); };
        // `sent` false only when nothing reached the chain; otherwise the take may be on chain already.
        add(1); let done = false; q.release = (sent = true) => { if (!done) { done = true; add(-1); if (sent && open.length) landed.push({ at: ++epoch, agent, h }); } };
        return q;
      });
      gate = run.catch(() => {});
      return await run;
    } finally { open.splice(open.indexOf(from), 1); const min = Math.min(...open); while (landed.length && !(landed[0].at > min)) landed.shift(); }
  };
  // Attached payments are gone (self-pay mode, owner 30 September): a request that still carries one
  // is refused before anything is read or sent, and told how an agent pays for itself now.
  const NO_PAYMENTS = 'relays take no payment (attached payments ended with self-pay mode, 30 September): to pay for an action yourself, sign it self-paid ("selfPaid": true in /v2/prepare) and sign the transactions the 402 returns as their fee payer (skill.md section 2.1)';
  const refusePayment = body => { if (body.payment !== undefined) throw Object.assign(Error(NO_PAYMENTS), { status: 400 }); };
  // A quote never names this wallet: no one pays a relay. A self-paid one names its fee payer's key and
  // `needs`, what that key must hold (sdk/funding.mjs `feePayerNeeds`).
  const quote = f => ({ funded: f.funded, reason: f.reason, worst: f.worst, fee: f.fee, refund: f.refund, deposits: f.deposits,
    ...(f.selfPaid ? { selfPaid: true, feePayer: f.feePayer, needs: f.needs } : {}) });
  async function pay({ funding, agent }, act) {
    const sigs = [];
    try {
      // A self-paid envelope reaches here only for an allowlisted agent, this wallet paying for it.
      if(!funding.funded&&!(funding.selfPaid&&allowed.has(agent)))throw Object.assign(Error(`the vault does not fund this action: ${funding.reason}`),{status:402,detail:{funding:quote(funding)}});
      // A funded action risks only what a moved chain would leave this wallet paying (its `atRisk`).
      const exposure = funding.funded ? funding.atRisk ?? funding.worst : funding.worst;
      const ticket = ledger.reserve(funding.worst, { exposure });
      try { return await act(recording(sigs)); }
      finally { ledger.settle(ticket, await measure(sigs)); }
    } finally { funding.release?.(sigs.length > 0 || !!sigs.uncertain); }
  }

  // The sweep of a hosted key that moved to its own key: its whole SOL and AC go to the agent's
  // current key. The hosted key pays the fee when it can; otherwise this wallet does, metered in the
  // ledger like a crank. A failure is retried with backoff and alerted; the agent can run it again.
  const sweeping = new Set();
  async function runSweep(agent) {
    const job = sweeps?.get(agent);
    if (!job) throw Object.assign(Error(`${us} never hosted this agent's key`), { status: 404 });
    if (sweeping.has(agent)) return { ...job, status: 'running' };
    sweeping.add(agent);
    try {
      const who = await c.agent(new PublicKey(agent));
      if (who?.custody !== 'own') throw Error('the chain does not show this agent holding its own key yet');
      const key = sessions.keyOf(job.legacyKey ? { legacyKey: true, agent } : { label: job.label });
      if (!key || key.publicKey.toBase58() !== job.from) throw Error('the old hosted key is not available here');
      // A gateway-paid sweep repays the gateway; only an agent's first sweep may leave it short, by at
      // most two fees (AC on a key with no SOL cannot repay the new key's token account otherwise).
      const plan = await planSweep(t, { from: key.publicKey, to: new PublicKey(who.signer), cfg: await c.config(), gateway: payer.publicKey, maxLoss: job.done ? 0 : 2 * TX_FEE });
      let signature = null;
      if (plan?.ixs.length) {
        if (plan.payer === 'hosted') signature = await t.send(plan.ixs, key);
        else {
          const worst = plan.cost, ticket = ledger.reserve(worst, { exposure: worst });
          let sent = null, known;
          try { signature = sent = await t.send(plan.ixs, payer, [key]); }
          catch (e) { sent = e.signature ?? null; if (e.unsent || (!sent && e.logs)) known = 0; throw e; }
          finally { ledger.settle(ticket, known ?? (sent ? await measure([sent]) : null)); }
        }
      }
      const result = { signature, to: who.signer, sol: plan?.sol ?? 0, ac: String(plan?.ixs.length ? plan.ac : 0n), dust: plan?.dust ?? 0, paidBy: plan?.payer ?? null,
        ...(plan && !plan.ixs.length ? { left: { sol: plan.dust, ac: String(plan.ac ?? 0n), sendOld: unlockLamports(plan.dust, await t.rent(0)) } } : {}) };
      logLine(fundsLog, { event: 'sweep', agent, from: job.from, ...result });
      return sweeps.update(agent, { status: 'done', lastError: null, next: 0, result, done: Date.now() });
    } catch (e) {
      const attempts = (job.attempts ?? 0) + 1, error = String(e?.message ?? e).split('\n')[0];
      if (attempts === 1 || attempts % 5 === 0) alarm(`AC_ALERT hosted-sweep agent=${agent} from=${job.from} attempts=${attempts} error=${JSON.stringify(error)}`);
      logLine(fundsLog, { event: 'sweep-failed', agent, from: job.from, attempts, error });
      return sweeps.update(agent, { status: 'pending', attempts, lastError: error, next: Date.now() + sweepBackoff(attempts) });
    } finally { sweeping.delete(agent); }
  }
  const sweepView = j => j && { status: j.status, from: j.from, to: j.result?.to ?? j.to, ...(j.result ? { moved: { sol: j.result.sol, ac: j.result.ac }, signature: j.result.signature, dust: j.result.dust } : {}),
    // What could not move without leaving the gateway paying for it: the agent unlocks it.
    ...(j.result?.left && (j.result.left.sol || j.result.left.ac !== '0') ? { left: j.result.left, unlock: `fund your new key (at least its rent-exempt minimum) and create its AC token account, or send the old key ${j.result.left.sendOld !== undefined ? `${j.result.left.sendOld.toLocaleString('en-US')} lamports` : `two fees (${(2 * TX_FEE).toLocaleString('en-US')} lamports)${j.result.left.sol > 0 ? '' : ' plus its rent-exempt minimum'}`}; then run the sweep again` } : {}),
    ...(j.status === 'pending' ? { attempts: j.attempts, error: j.lastError, retryAt: j.next ? new Date(j.next).toISOString() : null } : {}),
    again: 'POST /v2/hosted/sweep { agent, time, signature } signed by your current key over "ACv2 sweep <program> <agent> <time>"' };
  // A hosted send is quoted, then confirmed with the same token within `sendConfirmMs`: the
  // confirmation binds the exact asset, recipient and amount, and works once.
  const sendQuotes = new Map(), sendTimes = new Map(), sendingNow = new Set();
  const sendBudget = agent => { const now = Date.now(), list = (sendTimes.get(agent) ?? []).filter(x => now - x < 3_600_000); sendTimes.set(agent, list);
    return list.length < sendsPerHour ? 0 : Math.ceil((list[0] + 3_600_000 - now) / 1000); };
  const hostedFunds = async h => {
    const who = await c.agent(new PublicKey(h.agent));
    if (who && who.custody !== 'hosted') throw Object.assign(Error('this agent now holds its own key: its hosted balance is swept to that key (POST /v2/hosted/sweep runs it again)'), { status: 409 });
    return who;
  };
  // Accepts a signed envelope, checks it, pays for it, and finishes any upload it began.
  async function localRelay({ message, signatures }, c) {
    const m = unb64(message); const env = decodeEnvelope(m);
    if (!new PublicKey(env.program).equals(c.program)) throw Object.assign(Error('envelope is bound to another program'), { status: 400 });
    if (env.expiry <= Math.floor(await t.now())) throw Object.assign(Error('envelope expired'), { status: 400 });
    if (env.preferred !== '11111111111111111111111111111111' && env.preferred !== payer.publicKey.toBase58()) throw Object.assign(Error('envelope names another relay'), { status: 409 });
    const sigs = signatures.map(s => ({ key: new PublicKey(s.key), signature: unb64(s.signature) }));
    const signature = await c.submit({ message: m, signatures: sigs }, payer);   // verifies signatures before paying
    let writes = 0, refusedText = null;
    const staged = stagedUpload(env);
    if (staged) {
      const job = pending.get(staged.root.toString('hex'));
      if (job) {
        // The begin has landed: its nonce is used and its upload exists. A program refusal of the text
        // itself is reported with that success, never as if nothing happened.
        try { await c.writeChunks(new PublicKey(staged.upload), job.writes, payer); writes = job.writes.length; }
        catch (e) { if (!e.refused) throw e; refusedText = 'the program refused the page text (invalid UTF-8, more than 12,000 characters, or over 48,000 bytes); the upload stays unusable and its deposit returns when it expires or is cancelled'; }
        pending.remove(staged.root.toString('hex'));
      }
    }
    // An action that began an upload names it, so the answer alone is enough to contribute it.
    return { signature, agent: env.agent, nonce: env.nonce, action: env.action.type, chunkWrites: writes, relay: payer.publicKey.toBase58(),
      ...(staged ? { upload: staged.upload } : {}), ...(refusedText ? { textWritten: false, chunkWritesRefused: refusedText } : {}) };
  }
  // A hosted Register is vault-funded from the newcomers' pool when a trusted gateway relays it, yet
  // proves only the new key's own signature: relayed for an outside key, it would register it free
  // as `custody: hosted` under a gateway that never held it. This gateway's own identities join by a
  // member's `second` with join.hosted (plan 4.2b), so no relayed or prepared Register is hosted
  // (review round 8).
  const refuseHostedRegister = action => { if (action.type === 'register' && action.hosted)
    throw Object.assign(Error('a hosted identity is registered only by its gateway, through a member\'s second (join.hosted); register your own key with hosted false'), { status: 403 }); };
  // `onSend`: called once every check has passed, just before the envelope goes out (a thread request
  // records that it may land from then on). A member's second that registers a hosted newcomer here
  // settles that newcomer's other drafts (`joined`).
  async function relay(body, opts) {
    const result = await relayEnvelope(body, opts);
    joined(body.message);
    return result;
  }
  async function relayEnvelope(body, { onSend } = {}) {
    const message=unb64(body.message), env=decodeEnvelope(message);
    // A member's second of a hosted newcomer's draft, sent with the member's signature alone, gets the
    // newcomer's co-signature here: the draft is its consent (owner, 30 September).
    if(drafts&&Array.isArray(body.signatures)&&body.signatures.length===1&&env.action.type==='second'&&env.action.join?.hosted){const co=await consentFor(env,message);if(co)body={...body,signatures:[...body.signatures,co]};}
    refuseHostedRegister(env.action);
    if(!new PublicKey(env.program).equals(c.program)||env.expiry<=Math.floor(await t.now())) throw Object.assign(Error('wrong deployment or expired envelope'),{status:400});
    if(!Array.isArray(body.signatures)||!body.signatures.length||body.signatures.length>3) throw Object.assign(Error('expected one to three signatures'),{status:400});
    const signers=body.signatures.map(s=>String(s?.key)), hops=body.hops??0;
    if(!Number.isSafeInteger(hops)||hops<0)throw Object.assign(Error('hops must be a non-negative integer'),{status:400});
    // Verify before forwarding public signed actions to another operator: a bad signature, or one by a
    // key that cannot sign for this agent, is the caller's error (400) and never reaches simulation.
    await c.instructions({message,signatures:body.signatures.map(s=>({key:new PublicKey(s.key),signature:unb64(s.signature)}))},payer).catch(e=>{throw e.status?e:Object.assign(e,{status:400});});
    if(env.action.type!=='register'){
      await refuseBanned(env.agent);
      const who=await c.agent(env.agent);
      const must=env.action.type==='recover'?who?.recovery:who?.signer;
      if(who&&must&&signers[0]!==must)throw Object.assign(Error(`the first signature must be by the agent's ${env.action.type==='recover'?'recovery':'current'} key`),{status:400});
    }
    const staged=stagedUpload(env);
    if(body.uploadFrame!==undefined){
      if(!staged||typeof body.uploadFrame!=='string')throw Object.assign(Error('unexpected upload frame'),{status:400});
      const frame=unb64(body.uploadFrame), rebuilt=chain(frame);
      if(frame.length!==staged.len||!rebuilt.root.equals(staged.root))throw Object.assign(Error('upload frame does not match signed fingerprint'),{status:409});
      pending.set(staged.root.toString('hex'),rebuilt.writes);
    }
    const job=staged?pending.get(staged.root.toString('hex')):null;
    const packet={message:body.message,signatures:body.signatures.map(s=>({key:s.key,signature:s.signature})),hops,
      ...(job?{uploadFrame:Buffer.concat(job.writes.map(w=>w.chunk)).toString('base64')}: {})};
    if(env.selfPaid)return selfPaidRelay(body,env,message,signers,staged,job,packet);
    // A used nonce can only be recovered, never paid for again.
    const stale=((await c.agent(env.agent))?.nonce??0)>env.nonce, refuseStale=()=>{throw Object.assign(Error('this envelope\'s nonce is already used'),{status:409});};
    // Two submissions of one agent nonce at once: the second could only fail on chain, at this wallet's cost.
    const slot=`${env.agent}:${env.nonce}`;if(inflight.has(slot))throw Object.assign(Error('an envelope for this agent nonce is already being submitted'),{status:409});
    inflight.add(slot);let result,funding=null;
    try{
      funding=stale?null:await price(env.agent,(c,h)=>vaultFunds(c,env,{payer:payer.publicKey,signatures:body.signatures.length,chunkWrites:job?.writes.length??0,held:h}));
      // A rule the envelope breaks for certain is named before it is sent. Only an action this relay
      // would pay for is worth the reads: an unfunded one from a stranger is a 402 without them.
      // Refused here, nothing was sent: its hold is released as unsent, never as landed for open snapshots.
      if(funding&&(env.action.type==='register'||funding.funded||funding.refused||funding.selfPaid||allowed.has(env.agent)))await refuseExact(env.agent,env.action,env.accounts,body.signatures.length).catch(e=>{funding.release?.(false);throw e;});
      const local=()=>pay({funding,agent:env.agent},cc=>localRelay(packet,cc));
      if(!stale)onSend?.();
      // An envelope another relay forwarded (hops) is never forwarded again: no loops between pools.
      result=stale?(pool?await pool.submit(packet,refuseStale,{route:false}):refuseStale()):pool&&funding.funded?await pool.submit(packet,local,{route:hops<MAX_HOPS}):await local();
    }catch(e){
      // The program refuses with one bare error whatever the rule; once it has, say which rule it was.
      if(ruled(e)){const reason=await explainRefusal(c,env.agent,env.action,env.accounts,{signatures:body.signatures.length,selfPaid:env.selfPaid,preferred:env.preferred,payer:payer.publicKey}).catch(()=>null);if(reason)e.detail={...e.detail,reason};}
      throw e;
    }finally{inflight.delete(slot);funding?.release?.();}
    if(job&&result.recovered){
      const upload=new PublicKey(staged.upload);
      try{
        const f=await price(env.agent,(c,h)=>chunkWritesFunded(c,upload,job.writes.length,{payer:payer.publicKey,held:h}));
        await pay({funding:f,agent:env.agent},cc=>cc.writeChunks(upload,job.writes,payer));
        result.chunkWrites=job.writes.length;result.uploadRecoveredBy=payer.publicKey.toBase58();
      }catch(e){if(e.status!==402)throw e;result.chunkWritesRefused=e.message;}
    }
    if(job&&result.chunkWrites>0)pending.remove(staged.root.toString('hex'));
    // Page text is never on chain until its chunks are written. Without a frame this relay wrote none:
    // say so, rather than answer as if the page were stored.
    if(staged&&!job)return{...result,textWritten:false,next:'the page text was not written: POST /v2/uploads/resume with the text, or send the uploadFrame from /v2/prepare with the relay request next time'};
    return result;
  }
  /**
   * Self-pay mode (owner, 30 September): this wallet signs nothing and pays nothing. Without
   * `feePayerSignatures` the relay checks the program's exact rules and answers 402 with the
   * transactions to sign (fee payer `feePayer`, by default the envelope's first signer); with them, it
   * sends those same transactions in order (the envelope's, then the page's chunk writes). They share
   * one blockhash, which lives about a minute (150 blocks): they wait here 45 seconds, and a batch
   * whose blockhash has already expired is never sent.
   */
  const selfPaidPending = new Map(), SELF_PAID_TTL = 45_000;
  async function selfPaidRelay(body, env, message, signers, staged, job, packet) {
    const n = body.signatures.length, key = body.message;
    const funding = await vaultFunds(c, env, { payer: payer.publicKey, signatures: n, chunkWrites: job?.writes.length ?? 0 });
    if (funding.refused) throw Object.assign(Error(`the program's rules refuse this action: ${funding.reason}`), { status: 409, detail: { refusedByProgram: true, reason: funding.reason, before: 'signing' } });
    await refuseExact(env.agent, env.action, env.accounts, n, true, { preferred: env.preferred, payer: body.feePayer ?? signers[0] });
    // An agent on this operator's allowlist is paid for by this wallet, as a wallet paying on its
    // behalf: the operator's own choice, within its daily ceiling. Its deposits return to this wallet.
    if (allowed.has(env.agent) && body.feePayer === undefined && body.feePayerSignatures === undefined) {
      const slot = `${env.agent}:${env.nonce}`; if (inflight.has(slot)) throw Object.assign(Error('an envelope for this agent nonce is already being submitted'), { status: 409 });
      inflight.add(slot);
      try { return await pay({ funding, agent: env.agent }, cc => localRelay(packet, cc)); } finally { inflight.delete(slot); }
    }
    const feePayer = new PublicKey(body.feePayer ?? signers[0]);
    // Only a key not registered yet (a register) joins free by the thecolony.cc sign-in instead.
    await feePayerCanPay(feePayer, funding, { free: env.action.type === 'register' ? FREE_WAY : OWN_FREE });
    const now = Date.now();
    for (const [k, v] of selfPaidPending) if (now - v.at > SELF_PAID_TTL) selfPaidPending.delete(k);
    if (body.feePayerSignatures === undefined) {
      if (selfPaidPending.size >= 10_000) throw Object.assign(Error('too many self-paid transactions are waiting for signatures; retry shortly'), { status: 503 });
      const txs = await c.selfPaidTransactions({ message, signatures: body.signatures.map(s => ({ key: new PublicKey(s.key), signature: unb64(s.signature) })) }, feePayer,
        { writes: job?.writes ?? [], upload: staged?.upload });
      selfPaidPending.set(key, { at: now, feePayer: feePayer.toBase58(), txs });
      throw Object.assign(Error(SELF_PAID), { status: 402, detail: { funding: { ...quote(funding), feePayer: feePayer.toBase58() }, transactions: txs.map(x => ({ message: b64(x.message) })) } });
    }
    const built = await signedFor(key, feePayer, body.feePayerSignatures);
    let signature;
    try { signature = await t.sendBuilt(built[0]); }
    catch (e) {
      if (e.expired) throw Object.assign(Error(EXPIRED), { status: 409 });
      if (ruled(e)) { const reason = await explainRefusal(c, env.agent, env.action, env.accounts, { signatures: n, selfPaid: true, preferred: env.preferred, payer: feePayer }).catch(() => null); if (reason) e.detail = { ...e.detail, reason }; }
      throw e;
    }
    // The envelope landed: whatever happens to the page's chunk writes is reported with that success.
    let writes = 0, refusedText = null;
    for (const w of built.slice(1)) {
      try { await t.sendBuilt(w); writes++; }
      catch (e) {
        if (e.expired) { refusedText = `the envelope landed but its blockhash expired after ${writes} of ${built.length - 1} chunk writes: POST /v2/uploads/resume with the text to finish the page, your key paying`; break; }
        if (!e.refused) throw e;
        refusedText = 'the program refused the page text (invalid UTF-8, more than 12,000 characters, or over 48,000 bytes); the upload stays unusable and its deposit returns to your key when it expires or is cancelled'; break;
      }
    }
    if (job) pending.remove(staged.root.toString('hex'));
    return { signature, agent: env.agent, nonce: env.nonce, action: env.action.type, selfPaid: true, feePayer: feePayer.toBase58(), chunkWrites: writes,
      ...(refusedText ? { upload: staged.upload, textWritten: false, chunkWritesRefused: refusedText } : {}),
      ...(staged && !job ? { textWritten: false, next: 'the page text was not written: POST /v2/uploads/resume with the text, or send the uploadFrame from /v2/prepare with the relay request next time' } : {}) };
  }
  const EXPIRED = 'these self-paid transactions\' blockhash has expired (they last about a minute): send the request without feePayerSignatures for fresh ones, and sign them within 45 seconds';
  /** The transactions waiting under `key` for `feePayer`, each with its signature from `given`; never
   *  a batch whose shared blockhash the cluster no longer accepts (review, 30 September). */
  async function signedFor(key, feePayer, given) {
    const entry = selfPaidPending.get(key);
    if (!entry || entry.feePayer !== feePayer.toBase58() || Date.now() - entry.at > SELF_PAID_TTL) throw Object.assign(Error('no self-paid transactions for this request and fee payer are waiting (they last 45 seconds): send the request without feePayerSignatures for fresh ones'), { status: 409 });
    if (!Array.isArray(given) || given.length !== entry.txs.length || given.some(x => typeof x !== 'string')) throw Object.assign(Error(`feePayerSignatures must be ${entry.txs.length} base64 signatures, one per transaction in order`), { status: 400 });
    const built = entry.txs.map((x, i) => ({ ...x.sign(unb64(given[i])), ixs: x.ixs, feePayer: x.feePayer, latest: x.latest }));
    selfPaidPending.delete(key);
    if (built.length && t.blockhashValid && !await t.blockhashValid(built[0].latest)) throw Object.assign(Error(EXPIRED), { status: 409 });
    return built;
  }
  /** A self-paid upload's missing chunk writes (resume), fee payer its owner's key: 402 with the
   *  transactions to sign, then sent once signed. */
  async function selfPaidWrites(body, address, upload, writes, funding, owner) {
    const feePayer = new PublicKey(body.feePayer ?? owner), key = `resume:${address.toBase58()}:${upload.written}`;
    // A self-paid upload's writes are its owner's to pay: nothing costs less.
    await feePayerCanPay(feePayer, funding);
    if (body.feePayerSignatures === undefined) {
      const txs = await c.selfPaidTransactions(null, feePayer, { writes, upload: address, from: upload.written });
      selfPaidPending.set(key, { at: Date.now(), feePayer: feePayer.toBase58(), txs });
      throw Object.assign(Error(funding.reason), { status: 402, detail: { funding: { ...quote(funding), feePayer: feePayer.toBase58() }, transactions: txs.map(x => ({ message: b64(x.message) })) } });
    }
    let sent = 0;
    for (const w of await signedFor(key, feePayer, body.feePayerSignatures)) {
      try { await t.sendBuilt(w); sent++; }
      catch (e) { if (e.expired) throw Object.assign(Error(`${EXPIRED} (${sent} chunk writes landed; resume again for the rest)`), { status: 409 }); throw e; }
    }
  }
  /** A self-paid action's fee payer (owner, 30 September) must hold the quote and keep either nothing or
   *  a rent-exempt balance, checked after each of the action's transactions as the runtime checks it:
   *  when chunk writes follow, it keeps a rent-exempt balance (sdk/funding.mjs `feePayerNeeds`).
   *  Otherwise 402 names the address to fund and what it needs, and nothing is sent. A relay's or a
   *  gateway's own wallet never pays. `free`: what costs nothing instead, where something does. */
  async function feePayerCanPay(feePayer, funding, { hosted = false, free = null } = {}) {
    const from = new PublicKey(feePayer).toBase58(), need = funding.worst, n = funding.transactions ?? 1;
    const [balance, floor] = await Promise.all([t.getAccount(new PublicKey(feePayer)).then(a => a?.lamports ?? 0), t.rent(0)]);
    const left = balance - need, needs = feePayerNeeds(need, n, floor);
    const what = n > 1 ? `${needs}: the ${need} its ${n} transactions take, and the rent-exempt minimum of ${floor} left after them (the network refuses a transaction that leaves the key with less than that minimum but more than nothing, and a key left with nothing cannot pay the transactions that follow)`
      : `${need}, leaving either nothing or at least ${floor}`;
    const instead = hosted || !free ? '' : free === FREE_WAY ? '. No SOL? Join free instead: sign in with your thecolony.cc account (see free)' : '. No SOL? Most actions need none (see free)';
    if (balance < needs || (left > 0 && left < floor)) throw Object.assign(Error(`a self-paid action is paid by ${hosted ? 'its hosted key' : 'its fee payer\'s key'} as fee payer, never by ${hosted ? (operatorName ? `${operatorName}'s wallet` : 'the gateway') : 'a relay'} or the vault: ${from} holds ${balance} lamports and this needs ${what}. Send SOL to that address (a donation from anyone works) and retry${instead}`),
      { status: 402, detail: { funding: { ...quote(funding), feePayer: from }, payFrom: from, needs, ...(free ? { free } : {}) } });
  }
  const hostedCanPay = (key, funding) => feePayerCanPay(key.publicKey, funding, { hosted: true, free: HOSTED_FREE });
  // What a 402 "your key cannot pay" says costs nothing instead (onboarding trial, 30 September). The
  // thecolony.cc sign-in only for a key not registered yet: for a registered agent it would be another
  // identity, without its seats, so a registered agent is told what the vault still pays for.
  const FREE_WAY = `The free way in needs no SOL: sign in with your thecolony.cc account (${colony ? 'POST /v2/colony/start { "colony_username": "<you>" } on this API' : 'POST https://gateway.artifactcouncil.com/v2/colony/start { "colony_username": "<you>" }'}; every step: https://artifactcouncil.com/join.md). ${colony ? us.replace(/^this/, 'This') : 'Artifact Council'} then holds a key for you, and you can move to your own key later, keeping your seats.`;
  const OWN_FREE = 'Most actions need no SOL: prepare them without "selfPaid" and the vault pays while it can. Founding an artifact while you hold no council seat always needs SOL: apply to a council first.';
  const HOSTED_FREE = 'Most actions need no SOL: send them without "selfPaid" and the vault pays while it can. Founding an artifact without a council seat always needs SOL on your hosted key: apply to a council first, or have someone donate to your agent id.';
  // A refusal by the program's own rules: its failure log names this program's invalid argument.
  const ruled = e => !!e?.refused && !!e.logs?.some(l => l === `Program ${c.program.toBase58()} failed: invalid program argument`);
  // Only a rule that stays broken until the action executes (sdk/refusals.mjs) refuses in advance;
  // one that others or time can change is named only after the program refused.
  async function refuseExact(agent, action, accounts, signatures, selfPaid = false, more = {}) {
    const reason = await exactRefusal(c, agent, action, accounts, { signatures, selfPaid, ...more }).catch(() => null);
    if (reason) throw Object.assign(Error(`the program's rules refuse this action: ${reason}`), { status: 409, detail: { refusedByProgram: true, reason, before: 'signing' } });
  }
  // A request the SDK cannot plan (an unknown or removed action, a missing seat or target) is the
  // caller's to fix: 400. A network or RPC failure while planning stays a relay-side 502.
  const planned = async (id, body, { hosted = false } = {}) => { await pageAdvice(id, body, hosted); return c.plan(id, body).catch(e => { throw e.status || e.rpc || e.cause || e.name !== 'Error' ? e : Object.assign(e, { status: 400 }); }); };
  // A contribute says what to send instead when it cannot be made (live trial, 30 September): a member's
  // page is a content proposal (the program takes contributions from non-members only), and a
  // contribution offers a staged upload, not text. A hosted member proposes its page with its text.
  async function pageAdvice(id, body, hosted) {
    if (body.type !== 'contribute' || body.artifact === undefined) return;
    const art = await c.artifact(new PublicKey(body.artifact)).catch(() => null), me = new PublicKey(id).toBase58();
    const begin = `{ "type": "begin", "text": "<page>" } (its answer names the upload)`;
    if (art?.members.some(m => m.id === me)) {
      const page = Number.isSafeInteger(body.page) ? body.page : `<${pageRange(art)}>`, title = typeof body.title === 'string' ? JSON.stringify(body.title) : '"<title>"';
      const source = body.upload !== undefined ? `"upload": "${body.upload}"` : hosted ? '"text": "<page>"' : '"upload": "<upload>"';
      throw Object.assign(Error(`you sit on this council, so your page is a content proposal, not a contribution: send ${body.upload === undefined && !hosted ? `${begin}, then ` : ''}`
        + `{ "type": "propose", "artifact": "${body.artifact}", "payload": { "kind": "content", "page": ${page}, "title": ${title}, ${source} } }`
        + (hosted && threads ? ', which answers 202 with a post to publish, then { "pending_id", "post_id" } as for apply' : '')), { status: body.upload === undefined ? 400 : 409 });
    }
    if (body.upload === undefined && body.text !== undefined)
      throw Object.assign(Error(`a contribute offers a staged upload, not text: send ${begin} first, then { "type": "contribute", "artifact": "${body.artifact}", "upload": "<upload>" }`), { status: 400 });
  }
  /** The text of a hosted member's page proposal sent with its text (payload.text, no upload), or null.
   *  The gateway stages it (a begin) when the proposal is sent, then proposes that upload. */
  const pageText = body => {
    const p = body.type === 'propose' ? body.payload : null;
    if (!p || typeof p !== 'object' || p.kind !== 'content' || p.text === undefined) return null;
    if (p.upload !== undefined) throw Object.assign(Error('a content proposal names its page by "text" or by "upload", not both'), { status: 400 });
    if (typeof p.text !== 'string') throw Object.assign(Error('payload.text must be the page, as a string'), { status: 400 });
    try { encodeFrame(p.text); } catch (e) { throw Object.assign(Error(e.message), { status: 400 }); }
    return p.text;
  };
  /** Only a member proposes a page to its council (anyone else is told how to offer one), and only
   *  a page and title the program takes as the artifact stands. */
  async function pageAuthor(agent, body) {
    const art = await c.artifact(new PublicKey(body.artifact)).catch(() => null);
    if (!art) throw Object.assign(Error('no such artifact'), { status: 404 });
    if (!art.members.some(m => m.id === agent)) throw Object.assign(Error('only its members propose pages to a council: offer yours with { "type": "contribute", "artifact", "upload" } after { "type": "begin", "text": "<page>" }'), { status: 409 });
    // The page and title are checked here, before any post or begin (review, 30 September): the
    // program checks them only at the propose, after the begin has landed and the post is published.
    const p = body.payload;
    if (!Number.isSafeInteger(p.page)) throw Object.assign(Error(`payload.page must be the page's number: ${pageRange(art)}`), { status: 400 });
    if (p.page < 1 || p.page > pageRoom(art).last) throw Object.assign(Error(`this artifact takes page ${pageRange(art)}; not page ${p.page}`), { status: 409 });
    if (p.title !== undefined && !titleOk(p.title)) throw Object.assign(Error('payload.title must be a string of at most 64 characters (128 bytes)'), { status: 400 });
  }
  async function prepare(body) {
    const agent = new PublicKey(body.agent);
    await refuseBanned(agent);
    const plan = await planned(agent, body);
    refuseHostedRegister(plan.action);
    const preferred = body.preferred ? new PublicKey(body.preferred) : plan.preferred;
    await refuseExact(agent, plan.action, plan.accounts, undefined, !!plan.selfPaid, { preferred });
    // Unsigned preparation never allocates storage. Carry the frame with the signed relay request.
    // The seat the caller named for a create or claim (openapi `seat`), not the relay's pick (review round 5).
    const message = await c.message(agent, plan.action, plan.accounts, { nonce: plan.nonce, seat: plan.seat, preferred, selfPaid: plan.selfPaid });
    // Priced for every signature the program verifies: a setKey that changes or clears a set recovery
    // key carries that key's consent as a third (sdk/funding.mjs `envelopeSignatures`, 28 September).
    const funding = await vaultFunds(c, message, { payer: payer.publicKey, chunkWrites: plan.writes?.length ?? 0, held: holding(agent.toBase58()) }).catch(() => null);
    // A post in the artifact-council colony is recommended, never required, of an own-key agent: the
    // message to sign is the same either way (owner, 30 September).
    const advice = await postAdvice(agent, body).catch(() => null);
    return { message: b64(message), envelope: describe(decodeEnvelope(message)), ...(funding ? { funding: quote(funding) } : {}), ...(advice ? { advice } : {}),
      ...(plan.writes ? { uploadFrame: b64(Buffer.concat(plan.writes.map(w => w.chunk))) } : {}),
      ...(plan.content ? { content: plan.content.toString('hex'), upload: plan.upload.toBase58() } : {}),
      ...(plan.proposal ? { proposal: plan.proposal.toBase58() } : {}), ...(plan.artifact ? { artifact: plan.artifact.toBase58() } : {}) };
  }
  // ---- Auto-consent (owner, 30 September: "draft = consent") --------------------------------------
  // A hosted newcomer's saved draft means "admit me if a member seconds it". When a member's second
  // matches the draft exactly (what /v2/hosted/prepare-second prepares for that member), the gateway
  // adds the newcomer's co-signature itself, at the moment the second is submitted, so the newcomer
  // need not be online. Removing the draft withdraws the consent at once, and so do its lapse (7 days),
  // a ban, and the identity leaving the Colony account that saved the draft. /v2/hosted/cosign still
  // approves by hand (an own-key newcomer, a revival).
  const CONSENT_LIFE = 900 + 60;   // an envelope's usual 15 minutes (sdk/index.mjs), and a minute of clock skew
  /** A draft's thread, as its second carries it and its owner and members see it. With Colony login,
   *  only one set from the draft's checked post (`post`): a draft saved before posts were checked holds
   *  a thread its owner chose, and keeps working without it (DESIGN 1.8). Elsewhere, the owner's own. */
  const draftThread = d => threads && !d.post ? '' : d.thread ?? '';
  const draftSecond = (d, seconder, selfPaid) => ({ agent: seconder, type: 'second', artifact: d.artifact, author: d.owner,
    join: { hosted: true, handle: d.handle }, ...(d.type === 'contribute' ? { text: d.text, title: d.title, page: d.page } : {}), thread: draftThread(d), preferred: payer.publicKey.toBase58(),
    ...(selfPaid ? { selfPaid: true } : {}) });
  /** Whether `env` seconds draft `d` exactly: every signed field but the expiry is what this gateway prepares for its seconder. */
  const secondsDraft = async (env, d) => {
    const expected = decodeEnvelope(unb64((await prepare(draftSecond(d, env.agent, env.selfPaid))).message));
    return JSON.stringify(describe({ ...env, expiry: 0 })) === JSON.stringify(describe({ ...expected, expiry: 0 }));
  };
  /** How a draft records its consent: the saving session's identity and Colony account. */
  const consentOf = h => ({ ...(h.label ? { label: h.label } : { legacyKey: true }), colony: h.colony?.id != null ? String(h.colony.id) : null });
  /** The key of draft `d`'s owner while its consent holds: not banned here or by the meta-council, and
   *  still owned by the Colony account that saved the draft. */
  const consentKey = d => {
    const cs = d?.consent; if (!cs || !sessions) return null;
    if (bans.banned({ colony: cs.colony ?? undefined, agent: d.owner }) || (cs.colony != null && (banned.has(cs.colony) || !stillOwns(cs.label, cs.colony)))) return null;
    const key = sessions.keyOf(cs.legacyKey ? { legacyKey: true, agent: d.owner } : { label: cs.label });
    return key && key.publicKey.toBase58() === d.owner ? key : null;
  };
  /** The hosted newcomer's co-signature for `env` (a member's second with join.hosted over `message`), or null. */
  async function consentFor(env, message) {
    if (!drafts || env.action.type !== 'second' || !env.action.join?.hosted) return null;
    try {
      const author = env.action.author, type = env.action.payload.kind === 'content' ? 'contribute' : 'apply';
      // Only for an envelope of the usual 15 minutes: a co-signature on a longer-lived one could be
      // used after the newcomer withdrew its draft.
      if (env.expiry > Math.floor(await t.now()) + CONSENT_LIFE) return null;
      if (await c.agent(new PublicKey(author))) return null;   // registered: no longer a newcomer
      const d = drafts.own(author).find(x => x.artifact === env.accounts[0] && x.type === type), key = consentKey(d);
      if (!key || !(await secondsDraft(env, d))) return null;
      return { key: author, signature: b64(nacl.sign.detached(message, key.secretKey)) };
    } catch { return null; }
  }
  // ---- A registered newcomer's other drafts (real-platform trial, 30 September) -------------------
  // A newcomer may save two drafts of each type. A member's second of one registers it, and from then
  // its other drafts no longer stand for consent (the program co-signs only for a key with no record),
  // so no member could second them. Each remaining application is sent on chain as the agent's own
  // application: the saved draft is its consent to apply, and its post stays the application's thread.
  // A page is not sent: on chain it is a staged upload and then an offer, or a proposal once the agent
  // sits on that council, a choice that depends on where the agent now sits. It stays with the step
  // to take (`registered.next`), shown in the agent's drafts and inbox, and members no longer see it.
  // An application the program would refuse (a slot in use, a decline's wait) is kept the same way.
  // Run when this gateway relays the second, and again whenever the agent's drafts, inbox, requests or
  // sign-in are read here (a second relayed elsewhere); one run per agent at a time.
  const promoting = new Map(), sending = new Set();
  /** A relayed envelope: when it is a second that registered a hosted newcomer, the draft it seconded
   *  has done its work, and the newcomer's other drafts are settled. */
  function joined(message) {
    if (!drafts) return;
    try {
      const env = decodeEnvelope(unb64(message)), a = env.action;
      if (a.type !== 'second' || !a.join?.hosted) return;
      const author = new PublicKey(a.author).toBase58(), type = a.payload?.kind === 'content' ? 'contribute' : 'apply';
      for (const d of drafts.own(author)) if (d.artifact === new PublicKey(env.accounts[0]).toBase58() && d.type === type) drafts.remove(author, d.id);
      promote(author);
    } catch (e) { console.error(`gateway: a newcomer's drafts were not settled: ${e.message}`); }
  }
  const promote = agent => {
    if (!drafts || !sessions) return Promise.resolve();
    let run = promoting.get(agent);
    if (!run) {
      run = promoteDrafts(agent).catch(e => console.error(`gateway: a registered newcomer's drafts were not settled: ${e.message}`)).finally(() => promoting.delete(agent));
      promoting.set(agent, run);
    }
    return run;
  };
  const REGISTERED_NEXT = 'You are registered now, so send every request to POST /v2/hosted/act (drafts are for agents not registered yet).';
  /** What a registered agent does itself with draft `d`, which the gateway could not send for it. */
  async function draftNext(d, agent, reason) {
    const art = await c.artifact(new PublicKey(d.artifact)).catch(() => null), post = threads ? ' It answers 202 with a post to publish, then { "pending_id", "post_id" }.' : '';
    const drop = ` Or drop this draft: POST /v2/hosted/drafts { "remove": "${d.id}" }.`;
    if (d.type === 'apply') return `This application could not be sent for you${reason ? ` (${reason})` : ''}. ${REGISTERED_NEXT} Apply there once the cause is gone: { "type": "apply", "artifact": "${d.artifact}" }.${post}${drop}`;
    const page = JSON.stringify({ kind: 'content', page: d.page, title: d.title, text: '<your page>' });
    return `This page was not sent: a page on chain is sent by you. ${REGISTERED_NEXT} `
      + (art?.members.some(m => m.id === agent) ? `You sit on this council, so propose it: { "type": "propose", "artifact": "${d.artifact}", "payload": ${page} }.`
        : `Offer it (a page gives no seat): { "type": "begin", "text": "<your page>" }, then { "type": "contribute", "artifact": "${d.artifact}", "upload": "<the upload it names>" }.`) + post + drop;
  }
  async function promoteDrafts(agent) {
    if (!drafts.own(agent).some(d => !d.registered)) return;
    const who = await c.agent(new PublicKey(agent));
    if (!who || who.custody !== 'hosted' || who.status === 'banned') return;
    const mark = async (d, reason) => drafts.note(d.id, 'registered', { at: new Date(wall()).toISOString(), next: await draftNext(d, agent, reason) });
    const drop = id => { try { drafts.remove(agent, id); } catch {} };
    // The chain as of now: an application already open there (the one the second answered, or one
    // sent before whose confirmation was lost) is done, and never sent twice.
    const open = new Set((who.applications ?? []).map(x => new PublicKey(x.artifact).toBase58()));
    for (const { id } of drafts.own(agent).filter(d => !d.registered)) {
      // Read again just before signing: the owner may have removed the draft (withdrawn its consent)
      // while an earlier one was being sent.
      const d = drafts.get(id);
      if (!d || d.owner !== agent || d.registered) continue;
      if (d.type === 'apply' && open.has(d.artifact)) { drop(d.id); continue; }
      const key = d.type === 'apply' ? consentKey(d) : null;
      if (!key) { await mark(d, d.type === 'apply' ? 'its consent no longer holds' : null); continue; }
      // From here until it is settled the draft is being sent: a remove answers 409 (see POST /v2/hosted/drafts).
      sending.add(d.id);
      try {
        const now = Math.floor(await t.now());
        try {
          await hostedAct({ agent, key }, { type: 'apply', artifact: d.artifact });
        } catch (e) {
          const reason = e?.detail?.reason ?? String(e?.message ?? e).split('\n')[0];
          // The application the second answered (its membership vote is open), or a seat already held: done.
          if (/membership vote on this council is still open|already a member of this council/.test(reason)) drop(d.id);
          // The program refused it (a slot in use, a decline's wait): the agent takes the step itself.
          else if (e?.detail?.refusedByProgram || ruled(e)) await mark(d, reason);
          // Anything else (an RPC error, a lost confirmation, the vault short, a price hold) may pass:
          // the draft stays, and the next read tries again after checking the chain.
          else console.error(`gateway: a registered newcomer's application was not sent, tried again later: ${reason}`);
          continue;
        }
        // Its post stays its thread: the artifact view, the inbox and a member's second find it.
        const thread = draftThread(d);
        if (threads && thread) {
          const slot = slotsFor(await c.agent(new PublicKey(agent)).catch(() => null), { type: 'apply', artifact: d.artifact })[0];
          try { threads.addNote('applications', `${d.artifact} ${agent}`, { thread, request: d.id, agent, slotAt: slot?.at ?? null, from: now - 1800, until: now + 1800 }); }
          catch (e) { console.error(`gateway: a thread was not indexed: ${e.message}`); }
        }
        drop(d.id);
      } finally { sending.delete(d.id); }
    }
  }
  /** A draft as its owner and members see it: the consent record and the post marker stay at the gateway. */
  const shown = d => { if (!d) return d; const { consent, post, ...rest } = d; return { ...rest, thread: draftThread(d), autoConsent: !!consent }; };
  const NEWCOMER_NEXT = `Saved. Your draft is your consent: when a council member seconds it, ${us} co-signs for you, which registers you and opens the council's vote on your application or page. You need not be online. ${threads ? 'Watch your post\'s comments and ' : 'Check '}POST /v2/hosted/drafts {}; remove the draft ({ "remove": "<id>" }) to withdraw. A draft lapses after 7 days (then you may draft again).`;
  // A hosted key leaves the gateway only through move-key, which records the sweep of what it holds
  // before the key change is sent (owner, 30 September: nothing stays in our custody).
  const refuseKeyChange = type => { if (type === 'setKey' || type === 'recover') throw Object.assign(Error('a key change goes through POST /v2/hosted/prepare-key and POST /v2/hosted/move-key, which sweep what the hosted key holds to the new key'), { status: 409 }); };
  // A hosted identity this gateway holds that reached its own key by any path (move-key, a Recover
  // signed by its recovery key, a key change relayed elsewhere): its sweep job is recorded from the
  // chain, its tokens and recovery secrets go, and the sweep starts. `rec` names how the gateway
  // derives its key ({ label } | { legacyKey: true }).
  async function adopt(agent, rec, who, { run = true } = {}) {
    if (!sweeps || who?.custody !== 'own' || !rec) return null;
    const key = sessions.keyOf(rec.legacyKey ? { legacyKey: true, agent } : { label: rec.label });
    if (!key || key.publicKey.toBase58() !== agent) return null;
    let job = sweeps.get(agent);
    if (!job || job.status === 'moving') job = sweeps.put({ agent, from: agent, ...(rec.legacyKey ? { legacyKey: true } : { label: rec.label }), to: who.signer, created: job?.created ?? Date.now() });
    sessions.revokeWhere({ agent }); sessions.forget(agent);
    if (run && job.status === 'pending' && !sweeping.has(agent)) runSweep(agent).catch(() => {});
    return job;
  }
  // How this gateway derives an agent's key, for an adoption without a token: its anonymous record,
  // legacy key file or live tokens, else a Colony label that derives to it.
  let labelSearch = () => null;
  const recordOf = agent => sessions?.recordOf(agent) ?? (l => l ? { label: l } : null)(labelSearch(agent));
  // Gateway: the agent never sees a key; the gateway signs on its behalf. `onSend(env)`: called once
  // every check has passed, just before the envelope goes out (a thread request's record).
  async function hostedAct(h, body, { onSend, onStaged } = {}) {
    const key = h.key, id = new PublicKey(h.agent);
    const identity = await c.agent(id);
    if (!identity) throw Object.assign(Error('this newcomer is not registered; save a draft and ask a member to second it'), { status: 409 });
    if (identity.custody !== 'hosted') throw Object.assign(Error('this agent now holds its own key'), { status: 409 });
    // A member's page sent with its text: staged first (a begin, which takes no post), then proposed.
    // `onStaged` gets the request with its upload, so a retry proposes that upload, never stages again.
    // (Should the begin's answer be lost after it landed, a retry stages the text once more; the
    // unused upload's deposit returns when it expires.)
    if (body.message === undefined && pageText(body) !== null) {
      await pageAuthor(h.agent, body);
      const { text, ...payload } = body.payload;
      const staged = await hostedAct(h, { type: 'begin', text, ...(body.selfPaid === true ? { selfPaid: true } : {}) });
      if (staged.textWritten === false) throw Object.assign(Error(staged.chunkWritesRefused), { status: 409, detail: { upload: staged.upload } });
      body = { ...body, payload: { ...payload, upload: staged.upload } };
      onStaged?.(body);
      return { ...await hostedAct(h, body, { onSend }), upload: staged.upload };
    }
    const own = m => ({ key: key.publicKey.toBase58(), signature: b64(nacl.sign.detached(m, key.secretKey)) });
    if (body.message !== undefined) {
      const m = unb64(String(body.message)); const env = decodeEnvelope(m);
      if (env.agent !== h.agent) throw Object.assign(Error('not this agent\'s envelope'), { status: 400 });
      refuseKeyChange(env.action.type);
      // What takes a post here is sent only as a request, never prepared elsewhere and brought back.
      if (threads && POST_ACTIONS.includes(env.action.type)) throw Object.assign(Error(`a ${env.action.type} goes through this route as a request (with its post), not as a prepared message`), { status: 400 });
      // A hosted newcomer's draft is its consent: a second that matches it exactly needs no cosignature.
      const co = body.cosignature ?? await consentFor(env, m);
      if (!co || typeof co.key !== 'string' || typeof co.signature !== 'string') throw Object.assign(Error('a prepared envelope is submitted here with its cosignature (from POST /v2/hosted/cosign, or the co-signer\'s own key). A hosted newcomer\'s draft stands in for it only for a second that matches the draft exactly, while the draft exists'), { status: 400 });
      // Self-paid (a hosted member's self-paid join second): the hosted key is the fee payer, never this wallet.
      if (env.selfPaid) {
        const signed = { message: m, signatures: [{ key: key.publicKey, signature: nacl.sign.detached(m, key.secretKey) }, { key: new PublicKey(co.key), signature: unb64(co.signature) }] };
        await refuseBanned(id);
        // The page's chunk writes are this key's to pay too: the quote it must hold includes them.
        const staged = stagedUpload(env), frame = staged && body.uploadFrame ? chain(unb64(String(body.uploadFrame))) : null;
        if (frame && !frame.root.equals(staged.root)) throw Object.assign(Error('upload frame does not match signed fingerprint'), { status: 409 });
        const funding = await vaultFunds(c, m, { payer: payer.publicKey, chunkWrites: frame?.writes.length ?? 0 });
        if (funding.refused) throw Object.assign(Error(`the program's rules refuse this action: ${funding.reason}`), { status: 409, detail: { refusedByProgram: true, reason: funding.reason, before: 'signing' } });
        await refuseExact(h.agent, env.action, env.accounts, 2, true, { preferred: env.preferred, payer: key.publicKey });
        await hostedCanPay(key, funding);
        let signature;
        try { signature = await c.submit(signed, key); }
        catch (e) { if (ruled(e)) { const reason = await explainRefusal(c, h.agent, env.action, env.accounts, { signatures: 2, selfPaid: true, preferred: env.preferred, payer: key.publicKey }).catch(() => null); if (reason) e.detail = { ...e.detail, reason }; } throw e; }
        joined(b64(m));
        if (frame) await c.writeChunks(new PublicKey(staged.upload), frame.writes, key);
        return { signature, agent: h.agent, nonce: env.nonce, action: env.action.type, selfPaid: true, feePayer: key.publicKey.toBase58(), chunkWrites: frame?.writes.length ?? 0 };
      }
      return relay({ message: b64(m), signatures: [own(m), { key: co.key, signature: co.signature }], ...(body.uploadFrame ? { uploadFrame: body.uploadFrame } : {}) });
    }
    refuseKeyChange(body.type);
    const plan = await planned(id, body, { hosted: true });
    refuseKeyChange(plan.action?.type);
    if (plan.cosigner) throw Object.assign(Error('prepare this action, have its co-signer approve the exact message at /v2/hosted/cosign (or sign with its own key), then submit message and cosignature'), { status: 400 });
    const env = await c.envelope(key, plan.action, plan.accounts, { agent: id, nonce: plan.nonce, seat: plan.seat, selfPaid: plan.selfPaid });
    // A self-paid action (any action with "selfPaid", and always a founding without a seat; owner,
    // 30 September) is paid by the hosted key itself as fee payer, never by the gateway or the vault.
    // The program's exact rules are checked first, so nothing refused is ever sent at its cost.
    if (plan.selfPaid) {
      const signed = decodeEnvelope(env.message);
      await refuseBanned(id);
      const funding = await vaultFunds(c, env.message, { payer: payer.publicKey, chunkWrites: plan.writes?.length ?? 0 });
      if (funding.refused) throw Object.assign(Error(`the program's rules refuse this action: ${funding.reason}`), { status: 409, detail: { refusedByProgram: true, reason: funding.reason, before: 'signing' } });
      await refuseExact(h.agent, signed.action, signed.accounts, env.signatures.length, true);
      await hostedCanPay(key, funding);
      onSend?.(env);
      let signature;
      try { signature = await c.submit(env, key); }
      catch (e) { if (ruled(e)) { const reason = await explainRefusal(c, h.agent, signed.action, signed.accounts, { signatures: env.signatures.length, selfPaid: true }).catch(() => null); if (reason) e.detail = { ...e.detail, reason }; } throw e; }
      if (plan.writes) await c.writeChunks(plan.upload, plan.writes, key);
      return { signature, agent: h.agent, nonce: signed.nonce, action: signed.action.type, selfPaid: true, feePayer: key.publicKey.toBase58(), chunkWrites: plan.writes?.length ?? 0,
        ...(plan.proposal ? { proposal: plan.proposal.toBase58() } : {}), ...(plan.artifact ? { artifact: plan.artifact.toBase58() } : {}),
        ...(plan.content ? { upload: plan.upload.toBase58(), content: plan.content.toString('hex') } : {}) };
    }
    if(plan.writes) pending.set(plan.content.toString('hex'),plan.writes);
    const result = await relay({message:b64(env.message),signatures:env.signatures.map(s=>({key:s.key.toBase58(),signature:b64(s.signature)}))}, { onSend: () => onSend?.(env) });
    return { ...result, ...(plan.proposal ? { proposal: plan.proposal.toBase58() } : {}), ...(plan.artifact ? { artifact: plan.artifact.toBase58() } : {}),
      ...(plan.content ? { upload: plan.upload.toBase58(), content: plan.content.toString('hex') } : {}) };
  }
  // ---- Thread posts (owner, 30 September; sdk/gateway-threads.mjs) -------------------------------
  // On a Colony gateway a hosted identity's apply, contribute, propose, create and claim, and a
  // newcomer's draft, each take a post in the artifact-council colony. The request answers 202 with a
  // code and a post template and changes nothing; the same route with { pending_id, post_id } checks
  // the post (one unauthenticated read of it on thecolony.cc) and acts. A post, once verified, stays
  // the request's thread: an action that fails after it is retried with { pending_id } for 24 hours,
  // with no new post, and never submitted twice (the chain is read first when an answer was lost).
  const wall = clock ?? Date.now, threadBusy = new Set();
  const isoMs = ms => new Date(ms).toISOString(), clone = v => JSON.parse(JSON.stringify(v));
  const needsPost = body => !!threads && body.message === undefined && POST_ACTIONS.includes(body.type);
  const colonyLogin = h => { if (!h.colony?.id) throw Object.assign(Error('applying, contributing, proposing, founding and claiming here take a post by your thecolony.cc account, and this identity has no thecolony.cc sign-in'), { status: 403 }); };
  const noThread = body => { if (body.thread !== undefined) throw Object.assign(Error(`leave out thread: ${We} sets it from your post on thecolony.cc`), { status: 400 }); };
  const noteOf = body => {
    if (body.note === undefined) return '';
    if (typeof body.note !== 'string' || [...body.note].length > NOTE_MAX) throw Object.assign(Error(`note must be text of at most ${NOTE_MAX} characters`), { status: 400 });
    return body.note.trim();
  };
  const threadDetail = r => ({ pending_id: r.id, step: r.status, ...(r.thread ? { thread_url: r.thread, retry_until: isoMs(r.verified + RETRY_MS) } : { expires_at: isoMs(threads.expiry(r)) }) });
  const postPending = (r, extra = {}) => Object.assign({ step: 'post_pending', pending_id: r.id, verification_code: r.code, expires_at: isoMs(threads.expiry(r)),
    post_template: { colony_id: threadColony, post_type: 'discussion', title: r.template.title, body: r.template.body },
    then: `Publish post_template on thecolony.cc: POST https://thecolony.cc/api/v1/posts with your Colony token and these four fields (you may edit the title and body, but keep the verification code). Then, before expires_at, POST /v2/hosted/${r.route} { "pending_id": "${r.id}", "post_id": "<the id thecolony.cc returns>" }.`,
    ...extra }, { [STATUS]: 202 });
  /** What a post says about request `r`, read from the chain: names, settings, a page's first 1,000
   *  characters (`text`: the one read that pages through transaction history). Best effort. */
  async function factsFor(r, { text = true } = {}) {
    const f = {}, pk = x => new PublicKey(x).toBase58(), artifactOf = x => c.artifact(new PublicKey(x)).catch(() => null);
    let art = null;
    if (r.artifact) { art = await artifactOf(r.artifact); f.artifact = { address: pk(r.artifact), name: art?.name ?? '' }; }
    const page = async upload => {
      f.upload = pk(upload);
      try {
        const u = await c.read(new PublicKey(upload), decodeUpload); f.chars = u.chars;
        if (text && u.complete) { const chars = [...(await c.textFromTransactions(new PublicKey(upload), u.len, u.root)).toString('utf8')]; f.chars = chars.length; f.preview = chars.slice(0, 1000).join(''); }
      } catch {}
    };
    if (r.type === 'contribute') await page(r.upload);
    if (r.type === 'create') { f.name = r.name ?? ''; f.title = r.title ?? ''; await page(r.upload); }
    if (r.type === 'propose') {
      const p = r.payload ?? {};
      if (p.kind === 'content') { f.page = p.page ?? 1; f.title = p.title ?? '';
        if (p.upload !== undefined) await page(p.upload); else if (typeof p.text === 'string') { const chars = [...p.text]; f.chars = chars.length; f.preview = chars.slice(0, 1000).join(''); } }
      if (p.kind === 'link') { const to = await artifactOf(p.to); f.target = { address: pk(p.to), name: to?.name ?? '' }; }
      if (p.kind === 'kick' || p.kind === 'ban') f.subject = { id: pk(p.agent), handle: (await c.agent(new PublicKey(p.agent)).catch(() => null))?.handle ?? '' };
      if (p.kind === 'settings') f.changes = Object.entries(p.patch ?? {}).map(([k, v]) => `${k} ${art?.settings?.[k] ?? '?'} → ${v}`);
      if (p.kind === 'global') { const g = (await c.config().catch(() => null))?.g ?? {}; f.changes = Object.entries(p.patch ?? {}).map(([k, v]) => `${k} ${g[k] ?? '?'} → ${v}`); }
      if (p.kind === 'trustGateway') { f.key = pk(p.key); f.trusted = p.trusted !== false; }
      if (p.kind === 'pause') f.on = p.on !== false;
      if (art) f.rules = { windowDays: art.settings.WINDOW_DAYS, rejectBps: art.settings.REJECT_BPS, kickHours: art.settings.KICK_CONFIRM_HOURS,
        approveBps: META_KINDS.includes(p.kind) ? Math.max(art.settings.APPROVE_BPS, META_APPROVE_BPS) : art.settings.APPROVE_BPS };
    }
    return f;
  }
  /** A new request for `route` ('act' or 'drafts'), or the same one again: a repeat of an action still
   *  waiting for its post answers that request (same pending_id and code; its note, a draft's text or
   *  who pays taken from the repeat, so an agent may edit before posting), and one already verified is
   *  to be finished, not redone. */
  async function ask(h, route, request, note, facts, extra = {}) {
    const key = actionKey(route, request), colonyId = String(h.colony.id);
    // This identity's open requests, checked before the chain reads (to refuse early) and again after
    // them, with nothing awaited between that check and the write: step 1 sent several times at once
    // still makes at most OPEN_MOST requests, and one request (one pending_id and code) per action.
    const check = () => {
      const mine = threads.open(h.agent), same = mine.find(r => r.key === key && r.route === route && r.colony?.id === colonyId);
      if (same && same.status !== 'waiting') throw Object.assign(Error(`you already posted for this request: finish it with POST /v2/hosted/${route} { "pending_id": "${same.id}" } (no new post), or cancel it with { "pending_id": "${same.id}", "cancel": true } (then a new request needs a new post)`), { status: 409, detail: threadDetail(same) });
      if (!same && mine.length >= OPEN_MOST) throw Object.assign(Error(`at most ${OPEN_MOST} requests may wait for a post or a retry at once: finish one, or cancel it with { "pending_id", "cancel": true }`), { status: 429 });
      return same;
    };
    check();
    const f = await facts(), same = check();
    const code = same?.code ?? `AC-${randomBytes(10).toString('hex').toUpperCase()}`, kind = route === 'act' && request.type === 'propose' ? request.payload.kind : request.type;
    const template = threadPost(kind, { ...f, code, who: h.colony.username, agent: h.agent, note });
    if (same) return postPending(threads.update(same, { request, template }), { repeated: true, ...extra });
    return postPending(threads.create({ agent: h.agent, colony: { id: colonyId, username: h.colony.username }, route, request, key, code, kind, template }), extra);
  }
  // Step 1 on /v2/hosted/act: the checks act would make, and the program's certain refusals, before
  // any code is issued, so nobody is asked to post for an action that would surely be refused.
  async function askAct(h, body) {
    colonyLogin(h);
    const id = new PublicKey(h.agent), identity = await c.agent(id);
    if (!identity) throw Object.assign(Error('this newcomer is not registered; save a draft and ask a member to second it'), { status: 409 });
    if (identity.custody !== 'hosted') throw Object.assign(Error('this agent now holds its own key'), { status: 409 });
    noThread(body); const note = noteOf(body);
    const { note: _note, pending_id: _id, post_id: _post, cancel: _cancel, ...rest } = body, request = clone(rest);
    // A page sent with its text is staged at step 2: step 1 checks its author and its begin.
    const text = pageText(request);
    if (text !== null) await pageAuthor(h.agent, request);
    // A proposal is planned with its thread, which step 2 adds from the post: its bytes are deposit.
    const plan = await planned(id, text !== null ? { type: 'begin', text, ...(request.selfPaid === true ? { selfPaid: true } : {}) }
      : { ...clone(request), ...(request.type === 'propose' ? { thread: PLANNED_THREAD } : {}) }, { hosted: true });
    if (plan.cosigner) throw Object.assign(Error('prepare this action, have its co-signer approve the exact message at /v2/hosted/cosign (or sign with its own key), then submit message and cosignature'), { status: 400 });
    const message = await c.message(id, plan.action, plan.accounts, { nonce: plan.nonce, seat: plan.seat, selfPaid: plan.selfPaid }), env = decodeEnvelope(message);
    const funding = await vaultFunds(c, message, { payer: payer.publicKey, held: holding(h.agent) }).catch(() => null);
    if (funding?.refused) throw Object.assign(Error(`the program's rules refuse this action: ${funding.reason}`), { status: 409, detail: { refusedByProgram: true, reason: funding.reason, before: 'signing' } });
    await refuseExact(h.agent, env.action, env.accounts, 1, !!plan.selfPaid);
    if (plan.selfPaid && funding) await hostedCanPay(h.key, funding);
    return ask(h, 'act', request, note, () => factsFor(request), funding ? { funding: quote(funding) } : {});
  }
  // Step 2 on either route: { pending_id, post_id } (or, once verified, { pending_id } to retry,
  // { pending_id, selfPaid: true } to retry with the hosted key paying, { pending_id, cancel: true }).
  async function prove(h, body, route) {
    if (typeof body.pending_id !== 'string' || !PENDING_ID.test(body.pending_id)) throw Object.assign(Error('pending_id must be the 32-character id from the first answer'), { status: 400 });
    if (body.post_id !== undefined && (typeof body.post_id !== 'string' || !POST_ID.test(body.post_id))) throw Object.assign(Error('post_id must be the id thecolony.cc returned for your post'), { status: 400 });
    colonyLogin(h);
    let r = threads.get(body.pending_id, h.agent);
    // Another identity's request, or one bound to another Colony account, is as unknown as a made-up id.
    if (!r || r.agent !== h.agent || r.route !== route || r.colony?.id !== String(h.colony.id)) throw Object.assign(Error('no request waiting under this pending_id: start again'), { status: 404 });
    if (r.status === 'done') return Object.assign({ ...r.answer, replayed: true }, { [UNCHANGED]: true });
    if (threadBusy.has(r.id)) throw Object.assign(Error('this request is being submitted by another call: wait for its answer'), { status: 409 });
    threadBusy.add(r.id);
    try {
      if (body.cancel === true) return await cancelThread(h, r);
      if (r.status === 'waiting') {
        if (body.post_id === undefined) throw Object.assign(Error('post_id is required: the id thecolony.cc returned when you published the post'), { status: 400 });
        r = await verifyPost(h, r, body.post_id);
      } else if (body.post_id !== undefined && body.post_id !== r.post_id) throw Object.assign(Error('this request is bound to another post'), { status: 409, detail: threadDetail(r) });
      return route === 'act' ? await actOn(h, r, body) : await saveDraft(h, r);
    } finally { threadBusy.delete(r.id); }
  }
  // The post: at most `verifyPerMinute` checks a minute per request, one thecolony.cc read each.
  async function verifyPost(h, r, postId) {
    const wait = perChallenge(`thread:${r.id}`); if (wait) throw Object.assign(Error('checking too often; wait a few seconds'), { status: 429, retryAfter: wait });
    if (typeof colony.verifier.post !== 'function') throw Object.assign(Error(`${us} cannot read thecolony.cc posts at present`), { status: 503 });
    const got = await colony.verifier.post(postId);
    if (got.down) throw Object.assign(Error('thecolony.cc did not answer; nothing was used up: try again shortly'), { status: 503 });
    const problem = got.missing ? 'post not found: pass the id from the POST /posts answer'
      : postProblem(got.post, { postId, colonyId: threadColony, authorId: h.colony.id, code: r.code, since: r.created - SKEW_MS, artifactCouncil: threadColony === ARTIFACT_COUNCIL_COLONY_ID });
    if (problem) throw Object.assign(Error(problem), { status: 409, detail: threadDetail(r) });
    if (!threads.usePost(postId, r.id)) throw Object.assign(Error('this post already backs another request: publish a new post for this one'), { status: 409, detail: threadDetail(r) });
    return threads.update(r, { status: 'verified', post_id: postId, thread: threadUrl(postId), verified: wall() });
  }
  // Whether a failed submission surely did not land: refused before it went out (a 4xx of ours), or
  // refused by the program, which lands nothing, and in either case its nonce still unused. Anything
  // else (a timeout, a lost answer) may have. A refusal can be of one copy while another landed it: a
  // relay pool's peer may land the envelope and its answer fail (recover()'s 409 while the node cannot
  // read that transaction yet), or this relay's own copy be refused for the nonce the peer used.
  const unsent = e => !!(e?.unsent || e?.refused || e?.logs || (e?.status >= 400 && e?.status < 500));
  /** Whether request `r`'s envelope nonce is used on chain, or the chain cannot say: then it may have landed. */
  const nonceUsed = async (h, r) => { const who = await c.agent(new PublicKey(h.agent)).catch(() => undefined); return who === undefined || (who?.nonce ?? 0) > r.submit.nonce; };
  const aboutThread = (e, r) => {
    const again = `POST /v2/hosted/${r.route} { "pending_id": "${r.id}" }`;
    const next = e?.status === 402 ? `your post still counts: retry with { "pending_id": "${r.id}", "selfPaid": true } once your hosted key holds what funding.worst says (anyone can send it SOL), or later with ${again}`
      // The chain may never tell (its recent history has moved past the submission): a retry helps only
      // after a passing read failure, so say what to do when it does not.
      : e?.unknown ? `retry once with ${again} in a minute; if this answer comes back, the chain can no longer tell: check your inbox (GET /v2/agents/${r.agent}/inbox) for the action, then cancel with POST /v2/hosted/${r.route} { "pending_id": "${r.id}", "cancel": true } (a new request needs a new post)`
      : r.status === 'submitting' ? `your post still counts: retry with ${again}; ${We} reads the chain first and never submits twice`
      : `your post still counts: once the cause is gone, retry with ${again} (no new post) before retry_until`;
    if (e && typeof e === 'object') e.detail = { ...e.detail, ...threadDetail(r), next };
    return e;
  };
  /** The envelope of a request left `submitting` (its answer lost): { landed: signature | null } when
   *  the chain shows it, { open: expiry } while it could still land, {} when it never will (expired
   *  with its nonce unused, or its nonce went to another action), { unknown: true } when the chain
   *  cannot tell. Nothing is sent again unless it surely never landed. */
  async function settle(h, r) {
    const s = r.submit, id = new PublicKey(h.agent), want = Buffer.concat([Buffer.from([1]), unb64(s.message)]), program = c.program.toBase58();
    const recent = t.recentTransactions ? await t.recentTransactions(c.agentAddress(id)).catch(() => null) : null;
    const hit = recent?.find(tx => tx && !tx.error && tx.instructions?.some(ix => ix.program === program && Buffer.from(ix.data).equals(want)));
    if (hit) return { landed: hit.signature };
    const [who, now] = await Promise.all([c.agent(id), t.now()]);
    // Its nonce unused: it can land only before its expiry.
    if ((who?.nonce ?? 0) <= s.nonce) return Math.floor(now) < s.expiry ? { open: s.expiry } : {};
    // Its nonce is used: by this envelope if its effect is on chain, or if the history read above
    // (the agent record's latest transactions) is whole back past its signing and does not show it.
    // How far back it is whole comes from the signatures themselves, never from the list's length: a
    // failed or unreadable transaction is left out of the list, not out of the history.
    if (await landedEffect(h, r)) return { landed: null };
    const signed = s.expiry - 900, covered = !!recent && (recent.complete === true || (recent.after != null && recent.after < signed));
    return covered ? {} : { unknown: true };
  }
  /** Whether request `r`'s action is visible on chain: its proposal (this proposer, this thread), its
   *  own application or contribution slot, or its artifact with this agent as member. */
  async function landedEffect(h, r) {
    const q = r.request, me = h.agent;
    try {
      if (q.type === 'propose') { const p = r.submit.proposal ? await c.proposal(new PublicKey(r.submit.proposal)).catch(() => null) : null; return !!p && p.proposer === me && p.thread === r.thread; }
      if (q.type === 'apply' || q.type === 'contribute') return !!(await ownSlot(h, r));
      const where = q.type === 'create' ? r.submit.artifact : q.artifact;
      return !!where && !!(await c.artifact(new PublicKey(where)).catch(() => null))?.members.some(m => m.id === me);
    } catch { return false; }
  }
  /** The application or contribution slots of request `q`'s artifact (or upload) on the agent's record. */
  const slotsFor = (a, q) => { const key = x => new PublicKey(x).toBase58();
    return (q.type === 'apply' ? a?.applications.filter(x => x.artifact === key(q.artifact)) : a?.contributions.filter(x => x.upload === key(q.upload) && x.artifact === key(q.artifact))) ?? []; };
  /** The slot request `r` made, if any: one made while its envelope could land, never the one that was
   *  there before it went out (`submit.before`: the program refuses an application or offer beside it,
   *  so a repeat lands only once that slot has gone, as a new one). */
  const ownSlot = async (h, r) => slotsFor(await c.agent(new PublicKey(h.agent)), r.request).find(x => x.at !== r.submit?.before && inLife(x.at, lifeOf(r.submit))) ?? null;
  async function actOn(h, r, body) {
    if (r.status === 'submitting') {
      const s = await settle(h, r);
      if ('landed' in s) return finish(h, r, recoveredAnswer(h, r, s));
      if (s.open) throw aboutThread(Object.assign(Error(`still settling: the earlier submission can land until ${isoMs(s.open * 1000)}; retry after that`), { status: 409 }), r);
      if (s.unknown) throw aboutThread(Object.assign(Error('the chain does not tell whether the earlier submission landed: check your inbox, then retry or cancel'), { status: 409, unknown: true }), r);
      // It never landed: its note goes, and it is sent again below.
      r = threads.update(r, { status: 'verified', submit: null }); unnoteThread(h, r);
    }
    // Planned again, with the post's URL as a proposal's thread (apply, contribute, create and claim
    // have no field for it: their thread is kept here).
    const request = { ...clone(r.request), ...(body.selfPaid === true ? { selfPaid: true } : {}), ...(r.request.type === 'propose' ? { thread: r.thread } : {}) };
    let sent = false;
    try {
      // An application's or offer's slot already on chain (a repeat's): never taken for this one's landing.
      const before = ['apply', 'contribute'].includes(r.request.type) ? slotsFor(await c.agent(new PublicKey(h.agent)), r.request)[0]?.at ?? null : null;
      const result = await hostedAct(h, request, { onStaged: next => { r = threads.update(r, { request: { ...clone(r.request), payload: next.payload } }); }, onSend: env => {
        const e = decodeEnvelope(env.message); sent = true;
        r = threads.update(r, { status: 'submitting', submit: { message: b64(env.message), nonce: e.nonce, expiry: e.expiry, at: wall(),
          ...(e.action.type === 'propose' ? { proposal: e.accounts[1] } : {}), ...(e.action.type === 'create' ? { artifact: e.accounts[0] } : {}), ...(before != null ? { before } : {}) } });
        try { noteThread(h, r); } catch (x) { console.error(`gateway: a thread was not indexed: ${x.message}`); }
      } });
      return await finish(h, r, result);
    } catch (e) {
      // Surely not landed: back to verified, and its note goes (an earlier request's stays as it was).
      // With its nonce used it stays submitting, and the next try settles it from the chain.
      if (sent && unsent(e) && !(await nonceUsed(h, r))) { r = threads.update(r, { status: 'verified', submit: null }); try { unnoteThread(h, r); } catch (x) { console.error(`gateway: a thread note was not removed: ${x.message}`); } }
      throw aboutThread(e, r);
    }
  }
  // A lost answer settled from the chain: the transaction's signature when the recent history shows it
  // (`landed` null: only its effect is on chain, the transaction is older than that history).
  const recoveredAnswer = (h, r, s) => ({ ...(s.landed ? { signature: s.landed } : {}), agent: h.agent, nonce: r.submit.nonce, action: r.request.type, recovered: true,
    ...(r.submit.proposal ? { proposal: r.submit.proposal } : {}), ...(r.submit.artifact ? { artifact: r.submit.artifact } : {}) });
  async function finish(h, r, result) {
    const answer = { step: 'submitted', pending_id: r.id, thread_url: r.thread, ...result };
    try { await remember(h, r, result); } catch (e) { console.error(`gateway: a thread was not indexed: ${e.message}`); }
    threads.update(r, { status: 'done', done: wall(), answer, submit: null });
    return answer;
  }
  /** The thread of what landed, for the artifact view, the inbox and a member's second. An application
   *  or contribution is matched by its slot's time, so a later one never shows an earlier one's post. */
  async function remember(h, r, result) {
    const q = r.request, art = q.artifact ? new PublicKey(q.artifact).toBase58() : null;
    if (q.type === 'apply' || q.type === 'contribute') noteThread(h, r, (await ownSlot(h, r))?.at ?? null);
    else if (q.type === 'create' && result.artifact) threads.note('artifacts', result.artifact, { thread: r.thread, agent: h.agent, kind: 'create' });
    else if (q.type === 'claim') threads.note('artifacts', art, { thread: r.thread, agent: h.agent, kind: 'claim' });
  }
  /** Where request `q`'s application or contribution notes are kept in the thread index. */
  const indexKey = (h, q) => q.type === 'apply' ? ['applications', `${new PublicKey(q.artifact).toBase58()} ${h.agent}`] : ['contributions', `${new PublicKey(q.artifact).toBase58()} ${new PublicKey(q.upload).toBase58()}`];
  /** Request `r`'s note of its application's or contribution's post: first as its envelope goes out
   *  (from then on it may land, so a member's second, the artifact view and the inbox find the post even
   *  while the answer is lost and the agent has not retried), then with its slot's time once it landed.
   *  The note names its envelope's life, so it matches only a slot made while that envelope could land;
   *  each request has its own, so a repeat the program refuses takes nothing from the one that landed. */
  function noteThread(h, r, slotAt = null) {
    const q = r.request; if (r.route !== 'act' || (q.type !== 'apply' && q.type !== 'contribute')) return;
    const [kind, key] = indexKey(h, q);
    threads.addNote(kind, key, { thread: r.thread, request: r.id, agent: h.agent, slotAt, ...lifeOf(r.submit) });
  }
  /** Request `r`'s note goes: its envelope surely never landed. (A draft's request has none.) */
  function unnoteThread(h, r) {
    const q = r.request; if (r.route !== 'act' || (q.type !== 'apply' && q.type !== 'contribute')) return;
    const [kind, key] = indexKey(h, q);
    threads.dropNote(kind, key, r.id);
  }
  // When an envelope could land, in chain seconds: until its expiry, from its signing (15 minutes
  // before) less 15 minutes for the gateway's clock against the chain's.
  const lifeOf = s => s?.expiry ? { from: s.expiry - 1800, until: s.expiry } : {};
  const inLife = (at, life) => life.until != null && at >= life.from && at <= life.until;
  /** The post of `agent`'s slot made at `at`, from its notes: the one noted with that slot's time, else
   *  the newest whose envelope could have landed then. */
  const slotThread = (notes, agent, at) => { const mine = notes.filter(n => n.agent === agent);
    return (mine.find(n => n.slotAt != null && n.slotAt === at) ?? mine.find(n => n.slotAt == null && inLife(at, n)))?.thread ?? null; };
  async function cancelThread(h, r) {
    let maybe = false;
    if (r.status === 'submitting') {
      const s = await settle(h, r);
      // It landed after all: the request is done, not cancelled.
      if ('landed' in s) return finish(h, r, recoveredAnswer(h, r, s));
      if (s.open) throw aboutThread(Object.assign(Error(`the earlier submission can still land until ${isoMs(s.open * 1000)}: cancel after that`), { status: 409 }), r);
      maybe = !!s.unknown;
    }
    // A request that never landed leaves no note; one the chain cannot tell about keeps its own.
    if (!maybe) unnoteThread(h, r);
    threads.remove(r);
    return Object.assign({ pending_id: r.id, cancelled: true, ...(r.post_id ? { post: 'your post stays used: a new request needs a new post' } : {}) }, { [UNCHANGED]: true });
  }
  // Drafts (a hosted newcomer: no key, so no record to act from). The route's own checks, now.
  async function draftable(h, body) {
    const artifact = new PublicKey(body.artifact).toBase58(), a = await c.artifact(artifact);
    // An artifact with no members has nobody to answer: it is claimed, not applied to (29 September).
    if (a.empty) throw Object.assign(Error('this artifact has no members: it takes no drafts until a seated agent claims it'), { status: 409 });
    // A one-member artifact takes applications only: that is how it admits its second member (28 September).
    if (!a.active && !(a.members.length === 1 && body.type !== 'contribute')) throw Object.assign(Error('council is inactive (a one-member artifact takes applications only)'), { status: 409 });
    if (await c.agent(new PublicKey(h.agent))) throw Object.assign(Error(`registered agents submit applications and contributions on chain: send { "type": "apply", "artifact": "${artifact}" } (or a contribution) to POST /v2/hosted/act`), { status: 409 });
    // A contribution's page and title as the program checks them at the second that opens its vote
    // (governance.rs `open`): a draft no member could second is refused before its post (review, 30 September).
    if (body.type === 'contribute') {
      const page = body.page ?? 1;
      if (!Number.isSafeInteger(page)) throw Object.assign(Error(`page must be the page's number: ${pageRange(a)}`), { status: 400 });
      if (page < 1 || page > pageRoom(a).last) throw Object.assign(Error(`this artifact takes page ${pageRange(a)}; not page ${page}`), { status: 409 });
      if (body.title !== undefined && !titleOk(body.title)) throw Object.assign(Error('title must be a string of at most 64 characters (128 bytes)'), { status: 400 });
    }
    return artifact;
  }
  async function saveDraft(h, r) {
    try {
      await draftable(h, r.request);
      const answer = { step: 'saved', pending_id: r.id, thread_url: r.thread, draft: shown(drafts.put(h.agent, { ...r.request, thread: r.thread, post: r.post_id, consent: consentOf(h) })), next: NEWCOMER_NEXT };
      threads.update(r, { status: 'done', done: wall(), answer });
      return answer;
    } catch (e) { throw aboutThread(e, r); }
  }
  /** A hosted member's second of an application or contribution this gateway recorded carries its post
   *  as the thread, unless the member names one. */
  async function withThread(body) {
    if (!threads || body.type !== 'second' || body.message !== undefined || body.thread !== undefined || !body.artifact || !body.author) return body;
    const q = { type: body.upload ? 'contribute' : 'apply', artifact: body.artifact, ...(body.upload ? { upload: body.upload } : {}) }, author = new PublicKey(body.author).toBase58();
    const [kind, key] = indexKey({ agent: author }, q), notes = threads.notes(kind, key);
    const slot = notes.length ? slotsFor(await c.agent(new PublicKey(author)), q)[0] : null;
    const thread = slot ? slotThread(notes, author, slot.at) : null;
    return thread ? { ...body, thread } : body;
  }
  /** Own-key agents (owner, 30 September): a post is recommended, never required; /v2/prepare says so
   *  and gives the template (no code: such a post proves nothing and nothing checks it). */
  async function postAdvice(agent, body) {
    const kind = body.type === 'propose' ? body.payload?.kind : body.type;
    if (!['apply', 'contribute', 'create', 'claim'].includes(body.type) && !(body.type === 'propose' && !body.thread)) return null;
    const me = await c.agent(agent).catch(() => null), id = agent.toBase58();
    const template = threadPost(kind, { ...await factsFor(body, { text: false }), code: null, at: `agent ${me?.handle ? oneLine(me.handle).slice(0, 32) : `${id.slice(0, 4)}…${id.slice(-4)}`}`, agent: id });
    const text = body.type === 'propose'
      ? 'Recommended, not required: publish post_template in the artifact-council colony on thecolony.cc (POST https://thecolony.cc/api/v1/posts), then prepare this again with "thread": "https://thecolony.cc/post/<its id>", so members discuss your proposal where they look for it.'
      : body.type === 'create' || body.type === 'claim'
        ? 'Recommended, not required: announce it with post_template in the artifact-council colony on thecolony.cc (POST https://thecolony.cc/api/v1/posts). That is where your artifact finds its second member.'
        : 'Recommended, not required: publish post_template in the artifact-council colony on thecolony.cc (POST https://thecolony.cc/api/v1/posts). Members discuss it there, and the member who seconds it can pass its URL as "thread".';
    return { post: 'recommended', text, post_template: { colony_id: threadColony, post_type: 'discussion', ...template } };
  }
  // Listings: one tag-filtered read shared by all requests for a few seconds, served in pages. Any
  // successful write through this relay drops it. Every artifact with a member is listed: an active
  // council, or one waiting for its second member, labelled so (owner, 30 September; `?status=active`
  // or `?status=waiting` for one kind). `?claimable=1` lists the unclaimed ones instead: no members,
  // never artifact 0 (owner, 29 September). Any artifact stays readable at its address.
  // A route answers 200 unless its value names another status (STATUS: a thread request's 202), and a
  // value marked UNCHANGED (a replayed or cancelled request) changed nothing a listing shows.
  const NEXT = Symbol('next'), STATUS = Symbol('status'), UNCHANGED = Symbol('unchanged'), listings = new Map(), READ_ONLY_POSTS = ['/v2/inbox/stop', '/v2/inbox/stop/confirm', '/v2/hosted/drafts', '/v2/hosted/queue', '/v2/hosted/cosign', '/v2/hosted/prepare-second', '/v2/hosted/dismiss', '/v2/prepare', '/v2/uploads/resume', '/v2/colony/start', '/v2/hosted/prepare-key', '/v2/inbox/subscribe', '/v2/inbox/confirm', '/v2/inbox/unsubscribe', '/v2/hosted/digest',
    '/v2/hosted/send', '/v2/hosted/send/confirm', '/v2/hosted/sweep'];
  const READ_ONLY_PREFIXES = ['/v2/donate/'];
  const claimable = a => a.empty && a.id !== 0;
  const WAITING = 'waiting for a second member';
  const standing = a => a.members.length >= 2 ? { status: 'active' } : a.members.length === 1 ? { status: 'waiting', label: WAITING } : { status: 'unclaimed' };
  // Reads by name (owner, 30 September): an agent that asks for /v2/artifacts/receipt-schema is given
  // "Receipt Schema", or told exactly what to do next. A name matches exactly, ignoring case; failing
  // that, as a slug (letters and digits, the rest hyphens).
  const ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
  const folded = x => String(x).normalize('NFKC').trim().toLowerCase(), slug = x => folded(x).replace(/[^\p{L}\p{N}]+/gu, '-').replace(/^-+|-+$/g, '');
  const nameMatches = (a, text) => folded(a.name).includes(folded(text)) || (!!slug(text) && slug(a.name).includes(slug(text)));
  const artifactRow = a => ({ address: a.address, id: a.id, name: a.name, members: a.members.length, ...standing(a) });
  const FIND = 'GET /v2/artifacts lists every artifact with its address, or GET /v2/artifacts?search=<text> finds one by part of its name; then read it at GET /v2/artifacts/<address>';
  async function artifactAt(ref) {
    if (ADDRESS.test(ref)) {
      let key = null; try { key = new PublicKey(ref); } catch {}
      if (key && (await c.raw(key))?.data?.[0] === TAG.ARTIFACT) return key;
    }
    const all = await listing(TAG.ARTIFACT), shownRef = oneLine(ref).slice(0, 100);
    let hits = all.filter(a => folded(a.name) === folded(ref));
    if (!hits.length && slug(ref)) hits = all.filter(a => slug(a.name) === slug(ref));
    if (hits.length === 1) return new PublicKey(hits[0].address);
    if (hits.length) throw Object.assign(Error(`${hits.length} artifacts are named "${shownRef}": read one by its address, GET /v2/artifacts/<address>`), { status: 409, detail: { matches: hits.sort((x, y) => x.id - y.id).map(artifactRow) } });
    const near = all.filter(a => nameMatches(a, ref)).sort((x, y) => x.id - y.id).slice(0, 5);
    throw Object.assign(Error(`no artifact ${ADDRESS.test(ref) ? 'at this address' : `named "${shownRef}"`}: ${FIND}`), { status: 404, detail: { see: 'GET /v2/artifacts', ...(near.length ? { didYouMean: near.map(artifactRow) } : {}) } });
  }
  const listing = tag => {
    const hit = listings.get(tag); if (hit && Date.now() - hit.at < 15_000) return hit.value;
    const value = c.all(tag); listings.set(tag, { at: Date.now(), value }); value.catch(() => listings.delete(tag)); return value;
  };
  const paged = (req, items, key, parse) => {
    const q = new URL(req.url, 'http://relay').searchParams, limit = q.has('limit') ? Number(q.get('limit')) : 100;
    if (!Number.isInteger(limit) || limit < 1 || limit > 500) throw Object.assign(Error('limit must be an integer from 1 to 500'), { status: 400 });
    const after = q.has('after') ? parse(q.get('after')) : null;
    if (after === undefined) throw Object.assign(Error('after must be the cursor from x-ac-next'), { status: 400 });
    const rest = items.filter(x => after === null || key(x) > after).sort((x, y) => key(x) < key(y) ? -1 : key(x) > key(y) ? 1 : 0);
    const page = rest.slice(0, limit);
    return Object.assign(page, { [NEXT]: rest.length > limit ? String(key(page.at(-1))) : null });
  };
  // The inbox reads near-current state: requests share one read per account kind, in flight or
  // finished less than `inboxCacheMs` ago (2 seconds by default), so any number of callers costs the
  // RPC at most one program-wide read per kind per interval and cannot starve the crank's reads. A
  // ballot just cast leaves the inbox within that interval.
  const inflightReads = new Map();
  const fresh = tag => {
    const cur = inflightReads.get(tag);
    if (cur && (!cur.done || Date.now() - cur.done < inboxCacheMs)) return cur.value;
    const entry = { done: 0 };
    entry.value = c.all(tag).then(v => { entry.done = Date.now(); return v; }, e => { inflightReads.delete(tag); throw e; });
    inflightReads.set(tag, entry);
    return entry.value;
  };
  const artifactCursor = v => /^(0|[1-9]\d{0,15})$/.test(v) ? Number(v) : undefined, agentCursor = v => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v) ? v : undefined;
  // GET /v2 lists exactly the routes this relay serves: gateway routes only on a gateway, anonymous
  // registration only where it is open, snapshots only where a seat publishes them (review 5A.8).
  const served = key => !(key.includes(' /v2/hosted/') && !hostedDir) && !(key === 'POST /v2/hosted/register' && !openRegister) && !(key === 'GET /v2/snapshots' && !snapshotDir);
  const endpoints = () => Object.keys(routes).filter(served).flatMap(k => k === 'GET /v2/artifacts' ? [k, 'GET /v2/artifacts?status=waiting', 'GET /v2/artifacts?claimable=1', 'GET /v2/artifacts?search=<text>'] : [k]);
  // Donations to `me` (a decoded agent) since `since`, at most DONATION_DAYS back (an older `since`,
  // such as a digest window pinned by an incomplete read, is read from then, so it moves on). One read
  // per current key (the key's own transactions and the program's, such as holder payouts, never
  // counted as transfers), cached 30 s and filtered by `since` in memory, so a later `since` inside the
  // window costs no extra read. A public read lists the newest 25 transfers of its window. What a
  // read costs, for each of the key and its AC account: one getSignaturesForAddress per 1,000
  // signatures and one getTransaction per signature it reaches (skipped ones included), up to its
  // signature budget.
  // - A public read covers the whole DONATION_DAYS window and pages through at most 100 signatures
  //   per address: at most ~202 RPC calls. Fresh ones count against the relay-wide budget
  //   (`donationReadsPerMinute`): at most ~12,000 calls a minute at the default 60.
  // - The digest's own read (`internal`, not counted there) covers only the window it serves (since
  //   the recipient's last complete read, at most DONATION_DAYS back) and pages through up to
  //   DIGEST_SIGNATURES per address, so a key busy with its own transactions does not keep its window
  //   pinned: at most ~4,004 RPC calls a key; about one per transaction the key saw in its window
  //   otherwise (a holder's payouts and its own actions: tens a day). It keeps every transfer of its
  //   window, not only the newest 25, so a window with more gifts than one DM lists is still read in
  //   full: the DM lists the oldest and later digests the rest, none twice (review, 30 September:
  //   the newest 25 alone were listed again every day and the older ones never).
  //   runDigest reads each recipient at most once a daily period and at most DIGEST_LIMITS.perRun × 3
  //   (150) keys a pass: at most ~600,000 calls a pass, reached only if every key it reads has 2,000
  //   transactions at each address in its window. A shallow cached read does not stand in for it.
  const donationCache = new Map(), donationReads = rateLimiter(donationReadsPerMinute);
  const donationsOf = async (me, since, config, { internal = false } = {}) => {
    const k = me.signer, floor = Math.floor(Date.now() / 1000) - DONATION_DAYS * 86_400;
    since = Math.max(since, floor);
    const from = internal ? since : floor;
    let hit = donationCache.get(k);
    if (!(hit && Date.now() - hit.at < 30_000 && since >= hit.from && (hit.deep || !internal))) {
      for (const [x, v] of donationCache) if (Date.now() - v.at >= 30_000) donationCache.delete(x);
      const wait = !internal && donationReads('donations');
      if (wait) throw Object.assign(Error('too many donation reads on this relay right now; try again shortly'), { status: 429, retryAfter: wait });
      // Keys this agent used before (a hosted agent's id is its old hosted key): sweeps from them are not gifts, on any relay.
      hit = { at: Date.now(), from, deep: internal, value: donationsTo(t, { owner: me.signer, cfg: config, program: c.program, since: from, limit: internal ? Infinity : 25, signatures: internal ? DIGEST_SIGNATURES : 100,
        exclude: [payer.publicKey.toBase58()], own: [...new Set([me.id, ...(sweeps?.sources(me.id) ?? [])])].filter(x => x !== me.signer) }) };
      donationCache.set(k, hit); hit.value.catch(() => donationCache.delete(k));
    }
    return donationsSince(await hit.value, since, internal ? Infinity : 25);
  };
  const seatsOf = async id => (await listing(TAG.ARTIFACT)).filter(a => a.members.some(m => m.id === id));
  // Threads this gateway keeps (gateway-threads.mjs): an application's or a contribution's, by its slot's time.
  const applicationThread = (artifact, agent, at) => { const t = threads ? slotThread(threads.notes('applications', `${artifact} ${agent}`), agent, at) : null; return t ? { thread: t } : {}; };
  const contributionThread = (artifact, agent, upload, at) => { const t = threads ? slotThread(threads.notes('contributions', `${artifact} ${upload}`), agent, at) : null; return t ? { thread: t } : {}; };
  const routes = {
    'GET /v2': async () => ({ protocol: 'Artifact Council v2', program: c.program.toBase58(), relay: payer.publicKey.toBase58(), kind: hostedDir ? 'gateway' : 'relay', ...(readOnly ? { readOnly: true } : {}),
      // Where to start, and every endpoint's parameters (onboarding trial, 30 September).
      docs: { start: 'https://artifactcouncil.com/join.md', reference: 'https://artifactcouncil.com/skill.md' }, openapi: 'https://artifactcouncil.com/openapi.json',
      // colony-thread-posts-v1: apply, contribute, propose, create and claim through /v2/hosted/act, and
      // newcomer drafts, take a post in the artifact-council colony (owner, 30 September).
      capabilities: ['signed-upload-frames-v1', 'vault-funding-402-v1', 'relay-hops-v1', ...(pool ? ['relay-pool-v1'] : []), ...(threads ? ['colony-thread-posts-v1'] : [])], spend: ledger.status(),
      ...(cranker ? { crank: cranker.status() } : {}), ...(digester ? { digest: digester.status() } : {}),
      limits: { perMinute: perMinute === Infinity ? null : perMinute, newcomerReads: perMinute === Infinity ? 0 : newcomerReads, window: 'fixed, 60 s, per client address (IPv6 per /64)', retryAfter: true,
        ...(hostedDir ? { perIdentityPerMinute: identityPerMinute } : {}), ...(colony ? { verifyChecksPerMinute: verifyPerMinute } : {}),
        ...(threads ? { postChecksPerMinute: verifyPerMinute, openPostRequests: OPEN_MOST } : {}) },
      ...(threads ? { threads: { colony_id: threadColony, ...(threadColony === ARTIFACT_COUNCIL_COLONY_ID ? { colony: 'https://thecolony.cc/c/artifact-council' } : {}), needsPost: POST_ACTIONS, drafts: true, waitMinutes: 60, retryHours: 24 } } : {}),
      endpoints: endpoints() }),
    'GET /v2/relays': async () => pool ? pool.status() : { relays: [], fallback: payer.publicKey.toBase58(), policy: 'direct relay' },
    'POST /v2/prepare': (req, body) => prepare(body),
    // Only the upload's owner may have this relay finish it: its current key signs
    // resumeMessage(program, upload, expiry), or its hosted bearer token on this gateway.
    'POST /v2/uploads/resume': async (req, body) => {
      refusePayment(body);
      const address = new PublicKey(body.upload), upload = await c.read(address, decodeUpload), now = await t.now();
      let signers = [], hostedKey = null;
      if (req.headers.authorization) {
        const h = await session(req);
        if (h.agent !== upload.owner) throw Object.assign(Error('not this agent\'s upload'), { status: 403 });
        hostedKey = h.key; signers = [h.key.publicKey.toBase58()];
        if ((await c.agent(upload.owner))?.custody !== 'hosted') throw Object.assign(Error('this agent now holds its own key; sign the resume with it'), { status: 403 });
      }
      else {
        const owner = await c.agent(upload.owner), expiry = Number(body.expiry), sig = typeof body.signature === 'string' ? unb64(body.signature) : Buffer.alloc(0);
        if (!owner || !Number.isSafeInteger(expiry) || expiry <= now || expiry > now + 900 || sig.length !== 64
          || !nacl.sign.detached.verify(resumeMessage(c.program.toBase58(), address.toBase58(), expiry), sig, new PublicKey(owner.signer).toBuffer()))
          throw Object.assign(Error('resume needs the upload owner\'s signature over resumeMessage(program, upload, expiry), expiry within 15 minutes'), { status: 401 });
        signers = [owner.signer];
      }
      const frame = encodeFrame(body.text), rebuilt = chain(frame);
      if (!rebuilt.root.equals(upload.root) || frame.length !== upload.len) throw Object.assign(Error('text does not match signed upload fingerprint'), { status: 409 });
      if (upload.expires <= now) throw Object.assign(Error('upload expired'), { status: 409 });
      let at = 0, missing = 0;
      for (const x of rebuilt.writes) { if (at >= upload.written) missing++; at += x.chunk.length; }
      if (missing) {
        // A self-paid upload's writes are paid by its owner's key as fee payer (30 September): an own
        // key signs the 402's transactions; a hosted key signs them here, from the SOL it holds. Nothing
        // costs less (a resume has no "selfPaid" to leave out), so the 402 offers no `free` either way.
        const funding = await price(upload.owner, (c, h) => chunkWritesFunded(c, address, missing, { payer: payer.publicKey, held: h }));
        if (funding.selfPaid) {
          funding.release?.(false);
          if (hostedKey) { await feePayerCanPay(hostedKey.publicKey, funding, { hosted: true }); await c.writeChunks(address, rebuilt.writes, hostedKey); }
          else await selfPaidWrites(body, address, upload, rebuilt.writes, funding, signers[0]);
        } else await pay({ funding, agent: upload.owner }, cc => cc.writeChunks(address, rebuilt.writes, payer));
      }
      const current = await c.read(address, decodeUpload);
      return { upload: address.toBase58(), complete: current.complete, written: current.written };
    },
    'POST /v2/relay': (req, body) => { refusePayment(body); return relay(body.signatures ? body : { message: body.message, signatures: [{ key: decodeEnvelope(unb64(body.message)).agent, signature: body.signature }], hops: body.hops }); },
    'GET /v2/snapshots': async req => {
      if (!snapshotDir) throw Object.assign(Error('this relay does not publish snapshots'), { status: 404 });
      const { status, body } = snapshotFile(snapshotDir, new URL(req.url, 'http://relay').search, snapshotArchive);
      if (status !== 200) throw Object.assign(Error(body.error), { status });
      return body;
    },
    'GET /v2/artifacts': async req => {
      const q = new URL(req.url, 'http://relay').searchParams, unclaimed = q.get('claimable') === '1', status = q.get('status'), search = q.get('search');
      if (status !== null && !['active', 'waiting'].includes(status)) throw Object.assign(Error('status must be active or waiting'), { status: 400 });
      if (search !== null && (!search.trim() || search.length > 128)) throw Object.assign(Error('search must be 1 to 128 characters of an artifact\'s name'), { status: 400 });
      // A search looks through every artifact (unclaimed ones too, marked so) unless status or claimable narrows it.
      const kind = unclaimed ? claimable : status !== null ? a => standing(a).status === status : search !== null ? () => true : a => a.members.length >= 1;
      const wanted = a => kind(a) && (search === null || nameMatches(a, search));
      const page = paged(req, (await listing(TAG.ARTIFACT)).filter(wanted), a => a.id, artifactCursor);
      return Object.assign(page.map(a => ({ address: a.address, id: a.id, name: a.name, members: a.members.length, active: a.active, ...standing(a), claimable: claimable(a), pages: a.pages, history: a.history })), { [NEXT]: page[NEXT] });
    },
    'GET /v2/artifacts/:address': async (req, body, ref) => {
      const view = await c.view(await artifactAt(ref)), members = new Set(view.members.map(m => m.id)), out = await c.banned();
      // The counted roster (owner, 29 September, D4): a seat or ballot counts while its id is seated.
      const ballot = p => { const voters = p.roster.filter(id => members.has(id));
        return { ...p, voters, awaiting: p.status === 'voting' ? voters.filter(id => !p.ballots.some(b => b.voter === id)) : [] }; };
      // Every application must be answered, seconded or declined, before it expires (owner, 29 September).
      // `open`: it can still be seconded or declined; a slot past its expiry waits only for the crank.
      const applications = [], now = Math.floor(await t.now());
      for (const a of await listing(TAG.AGENT)) for (const s of a.applications) if (s.artifact === view.address)
        applications.push({ agent: a.id, handle: a.handle, at: s.at, expires: s.at + T.applicationTtl, open: now < s.at + T.applicationTtl, declines: (await c.declines(view.address, a.id))?.count ?? 0,
          ...applicationThread(view.address, a.id, s.at) });
      // The founding's or claim's post, made through this gateway, while its author still sits here.
      const founding = threads?.thread('artifacts', view.address);
      return describe({ ...view, ...standing(view), claimable: claimable(view), ...(founding && view.members.some(m => m.id === founding.agent) ? { thread: founding.thread } : {}),
        proposals: view.proposals.map(ballot), applications: applications.sort((x, y) => x.at - y.at),
        awaitingPrune: view.members.filter(m => out.has(m.id)).map(m => m.id) });
    },
    // `address` is an artifact's identity in /v2/artifacts; an agent's identity is `id`, and the account
    // holding its record is `record`, so one name never means two things.
    'GET /v2/agents': async req => { const page = paged(req, await listing(TAG.AGENT), a => a.id, agentCursor); return Object.assign(describe(page.map(({ address, ...a }) => ({ ...a, record: address }))), { [NEXT]: page[NEXT] }); },
    'GET /v2/agents/:address': async (req, body, address) => {
      const agent = await c.agent(new PublicKey(address));
      if (!agent) throw Object.assign(Error('agent not found'), { status: 404 });
      // A banned agent's seats wait only for the crank to prune them: none are shown.
      const seats = agent.status === 'banned' ? [] : await seatsOf(address);
      return describe({ ...agent, seats: seats.map(a => ({ address: a.address, name: a.name, active: a.active })) });
    },
    // What the agent owes its councils and when, from chain state (product review 5B item 1): votes it
    // has not cast, applications to answer, kicks to confirm, its missed-vote count per council and
    // the first deadline that would remove it if left unanswered, and its own open business.
    'GET /v2/agents/:address/inbox': async (req, body, address) => {
      const id = new PublicKey(address).toBase58();
      // Its drafts saved before it was registered: the remaining applications go on chain first, and
      // the chain is read after that, so the answer shows them (the drafts are gone by then).
      if (drafts?.own(id).some(d => !d.registered)) { await promote(id); inflightReads.delete(TAG.AGENT); inflightReads.delete(TAG.ARTIFACT); }
      const [config, artifacts, agents, proposals, now] = await Promise.all([c.config(), fresh(TAG.ARTIFACT), fresh(TAG.AGENT), fresh(TAG.PROPOSAL), t.now()]);
      const me = agents.find(a => a.id === id);
      // A hosted newcomer has no record until a member seconds one of its drafts: say so, not "not found"
      // (real-platform trial, 30 September: agents read that as a wrong id).
      if (!me) throw Object.assign(Error(`this id is not registered yet (no agent has it on chain), so it has no inbox: a newcomer is registered when a council member seconds one of its drafts.${sessions ? ' Your drafts and what waits on them: POST /v2/hosted/drafts {} with your token.' : ''}`), { status: 404, detail: { registered: false } });
      const seated = new Set(artifacts.filter(a => a.members.some(m => m.id === id)).map(a => a.address));
      const uploads = await contributionUploads(c, agents.filter(a => a.id === id || a.contributions.some(s => seated.has(s.artifact))));
      const inbox = inboxOf(id, { config, artifacts, agents, proposals, uploads }, { now: Math.floor(now), day: c.day ?? 86_400 });
      // The posts this gateway recorded for applications and contributions (a proposal's is on chain).
      if (threads) {
        for (const x of inbox.applications) Object.assign(x, applicationThread(x.artifact, x.applicant, x.at));
        for (const x of inbox.own.applications) Object.assign(x, applicationThread(x.artifact, id, x.at));
        for (const x of [...inbox.contributions.map(y => [y, y.contributor]), ...inbox.own.contributions.map(y => [y, id])]) Object.assign(x[0], contributionThread(x[0].artifact, x[1], x[0].upload, x[0].at));
      }
      // `?donations=1[&since=UNIX]`: transfers to the agent's current key since then (7 days by default), from public chain history.
      const q = new URL(req.url, 'http://relay').searchParams;
      if (q.get('donations') === '1') {
        const asked = q.has('since') ? Number(q.get('since')) : Math.floor(now) - 7 * 86_400;
        if (!Number.isSafeInteger(asked) || asked < 0) throw Object.assign(Error('since must be a unix time in seconds'), { status: 400 });
        // At most DONATION_DAYS back: older history is on any explorer.
        const since = Math.max(asked, Math.floor(now) - DONATION_DAYS * 86_400);
        const list = await donationsOf(me, since, config);
        inbox.donations = [...list];
        inbox.donationsSince = new Date(since * 1000).toISOString();
        // A read cut short (a busy key: more transfers or signatures than one read takes) may miss older
        // donations of the window. The reply says so, and from when the list is complete when known: an
        // array's own `truncated` would not survive JSON.
        inbox.donationsTruncated = !!list.truncated;
        if (list.truncated && Number.isFinite(list.completeAfter)) inbox.donationsCompleteAfter = new Date(list.completeAfter * 1000).toISOString();
        if (me.custody === 'hosted') inbox.donationsWarning = warningFor(me);
      }
      // What this gateway could not send for it (a page, or an application the program refused).
      const left = drafts ? drafts.own(id).filter(d => d.registered) : [];
      if (left.length) inbox.drafts = left.map(d => ({ id: d.id, artifact: d.artifact, type: d.type, next: d.registered.next }));
      return inbox;
    },
    // Solana Pay transaction request for a donation (owner, 30 September): GET names the payee; POST
    // { account } answers an unsigned transaction the donor's wallet signs and pays: SOL, or AC with
    // the recipient's token account created when missing. The recipient is the agent's current key.
    'GET /v2/donate/:address': async () => ({ label: 'Artifact Council donation', icon: 'https://artifactcouncil.com/favicon.svg' }),
    'POST /v2/donate/:address': async (req, body, address) => {
      const agent = await c.agent(new PublicKey(address));
      if (!agent) throw Object.assign(Error('agent not found'), { status: 404 });
      if (agent.status === 'banned') throw Object.assign(Error(BANNED), { status: 403, detail: { code: 'banned' } });
      const q = new URL(req.url, 'http://relay').searchParams, asset = String(q.get('asset') ?? 'SOL').toUpperCase(), cfg = await c.config();
      if (!['SOL', 'AC'].includes(asset)) throw Object.assign(Error('asset must be SOL or AC'), { status: 400 });
      let donor; try { donor = new PublicKey(body.account); } catch { throw Object.assign(Error('account must be the donor\'s base58 address'), { status: 400 }); }
      if (donor.toBase58() === agent.signer) throw Object.assign(Error('the donor is the agent\'s own key'), { status: 400 });
      const decimals = asset === 'SOL' ? 9 : tokenOf(cfg)?.decimals ?? 0, amount = toBaseUnits(q.get('amount') ?? '', decimals);
      // SOL to a key that holds none must leave it rent-exempt, or the donor's wallet fails opaquely.
      if (asset === 'SOL') {
        const has = (await t.getAccount(new PublicKey(agent.signer)))?.lamports ?? 0, rentMin = await t.rent(0);
        if (has + Number(amount) < rentMin) throw Object.assign(Error(`this agent's key holds no SOL yet: donate at least ${fromBaseUnits(BigInt(rentMin - has), 9)} SOL so its account is rent-exempt`), { status: 400, detail: { minimum: fromBaseUnits(BigInt(rentMin - has), 9) } });
      }
      const ixs = donationInstructions({ donor, recipient: agent.signer, asset, amount, cfg });
      const who = agent.handle ? `@${agent.handle}` : `${agent.id.slice(0, 4)}…${agent.id.slice(-4)}`;
      return { transaction: donationTransaction(ixs, donor, await t.blockhash()),
        message: `Donate ${fromBaseUnits(amount, decimals)} ${asset} to ${who} on Artifact Council.${agent.custody === 'hosted' ? ` Hosted agent: ${agent.gateway === ours && operatorName ? operatorName : `the operator of gateway ${agent.gateway}`} holds this key and any funds sent to it.` : ''}` };
    },
    'POST /v2/hosted/register': async (req, body) => {
      if (!hostedDir) throw Object.assign(Error('not a gateway'), { status: 404 });
      // Anonymous hosting spends the gateway's SOL for anyone; a public gateway admits keyless
      // agents through /v2/colony instead.
      if (!openRegister) throw Object.assign(Error('anonymous hosting is closed here: claim your Artifact Council identity with your thecolony.cc account via POST /v2/colony/start'), { status: 403 });
      // Open registration is for local testing: a request relayed by a proxy is from the public.
      if (req.headers['x-forwarded-for'] || req.headers.forwarded || req.headers['x-real-ip'] || !loopback(String(req.socket.remoteAddress).replace(/^::ffff:/, '')))
        throw Object.assign(Error('anonymous hosting is open only to local clients'), { status: 403 });
      bans.check({ ip: ipOf(req) });
      const label = `hosted:${randomBytes(16).toString('hex')}`, key = hostedKey(seed, label);
      // Login is off chain; a council member creates the first record by seconding.
      // The label lives only at the gateway; the recovery secret is what renews an expired session.
      const recovery = sessions.recoverable({ label }), { token, expires } = sessions.issue({ label });
      return { agent: key.publicKey.toBase58(), token, token_expires_at: new Date(expires).toISOString(), recovery, custody: 'hosted', registered: false, gateway: payer.publicKey.toBase58() };
    },
    // An anonymous identity (no Colony login to fall back on) renews its session with its recovery
    // secret: the one from register, or for an agent hosted before tokens expired, its old token.
    'POST /v2/hosted/renew': async (req, body) => {
      if (!hostedDir) throw Object.assign(Error('not a gateway'), { status: 404 });
      const ip = ipOf(req); bans.check({ ip });
      const { key, issue } = sessions.recover(body.agent, body.recovery), agent = key.publicKey.toBase58();
      bans.check({ ip, agent });
      const wait = perIdentity(`agent:${agent}`); if (wait) throw slowDown(wait);
      const who = await c.agent(key.publicKey);
      if (who?.custody === 'own') { await adopt(agent, sessions.recordOf(agent), who); sessions.revokeWhere({ agent }); sessions.forget(agent); throw ownNow(); }
      await hostedBanned(agent, null);
      const { token, expires } = issue();
      return { agent, token, token_expires_at: new Date(expires).toISOString(), custody: 'hosted' };
    },
    'POST /v2/hosted/drafts': async (req, body) => {
      const h = await session(req);
      if (body.remove) {
        // A draft being sent on chain right now (its owner was registered) can no longer be withdrawn.
        if (sending.has(body.remove)) { const d = drafts.get(body.remove); throw Object.assign(Error(`this draft is being sent on chain for you now, so it is an application in a moment: see GET /v2/agents/${h.agent}/inbox (own.applications); to take it back, POST /v2/hosted/act { "type": "withdraw", "target": "${d?.artifact ?? '<artifact address>'}" }`), { status: 409 }); }
        drafts.remove(h.agent, body.remove); return { removed: body.remove };
      }
      if (threads && body.pending_id !== undefined) return prove(h, body, 'drafts');
      // Registered since its drafts were saved: its remaining applications go on chain first.
      await promote(h.agent);
      if (!body.artifact) {
        const own = drafts.own(h.agent).map(shown), registered = !!(await c.agent(new PublicKey(h.agent)));
        return { drafts: own, registered, ...(registered ? { next: `${REGISTERED_NEXT} Your applications are on chain: GET /v2/agents/${h.agent}/inbox lists them (own.applications) with what waits on you.${own.length ? ' Each draft left here says in registered.next what to do with it.' : ''}` } : {}) };
      }
      const artifact = await draftable(h, body);
      // Without Colony login the draft is saved at once, its thread the newcomer's own (never a checked post's).
      if (!threads) { const { post: _post, ...own } = body; return { draft: shown(drafts.put(h.agent, { ...own, artifact, handle: h.colony?.username ?? body.handle ?? '', consent: consentOf(h) })), next: NEWCOMER_NEXT }; }
      // With Colony login a draft takes a post in the artifact-council colony, like an application on
      // chain (owner, 30 September); the gateway sets its thread from that post.
      colonyLogin(h); noThread(body);
      const note = noteOf(body), fields = clone({ artifact, type: body.type, ...(body.type === 'contribute' ? { text: body.text } : {}), title: body.title, page: body.page, handle: h.colony.username });
      // One application or contribution, one thread: an edit of a draft whose post was checked keeps it
      // (one saved before posts were checked takes a post like a new draft).
      const posted = drafts.own(h.agent).find(d => d.artifact === artifact && d.type === body.type && d.post && d.thread);
      if (posted) return { draft: shown(drafts.put(h.agent, { ...fields, thread: posted.thread, post: posted.post, consent: consentOf(h) })), thread_url: posted.thread, next: NEWCOMER_NEXT };
      drafts.check(h.agent, fields);
      return ask(h, 'drafts', fields, note, async () => {
        const a = await c.artifact(new PublicKey(artifact)).catch(() => null), f = { newcomer: true, gateway: payer.publicKey.toBase58(), host: operatorName ?? (url ? `the gateway at ${url}` : 'my gateway'),
          artifact: { address: artifact, name: a?.name ?? '' } };
        if (fields.type === 'contribute') { const chars = [...fields.text]; Object.assign(f, { chars: chars.length, preview: chars.slice(0, 1000).join(''), title: fields.title ?? '', page: fields.page ?? 1 }); }
        return f;
      });
    },
    'POST /v2/hosted/queue': async (req, body) => {
      const h = await session(req), artifact = new PublicKey(body.artifact).toBase58(), a = await c.artifact(artifact);
      // A one-member artifact's founder reviews applications to admit its second member (28 September).
      if (!a.members.some(m => m.id === h.agent) || !(a.active || a.members.length === 1)) throw Object.assign(Error('active council membership required'), { status: 403 });
      // A registered newcomer's draft stands for no consent, so it is not a member's to second: its
      // application goes on chain (promote), and what cannot is its owner's to send.
      const list = drafts.list(artifact).filter(d => !d.registered && (a.active || d.type !== 'contribute'));
      const registered = new Set((await Promise.all([...new Set(list.map(d => d.owner))].map(async o => (await c.agent(new PublicKey(o)).catch(() => null)) ? o : null))).filter(Boolean));
      for (const o of registered) promote(o);
      return { drafts: list.filter(d => !registered.has(d.owner)).map(shown) };
    },
    'POST /v2/hosted/prepare-second': async (req, body) => {
      const h = await session(req), d = drafts.get(body.draft);
      if (!d) throw Object.assign(Error('draft not found or expired'), { status: 404 });
      if (d.registered || await c.agent(new PublicKey(d.owner))) {
        promote(d.owner);
        throw Object.assign(Error(`this newcomer is registered now, so its draft stands for no consent: ${d.type === 'apply' && !d.registered ? 'its application goes on chain as its own; answer it from your inbox (applications)' : 'it sends this request on chain itself'}`), { status: 409 });
      }
      const a = await c.artifact(d.artifact);
      // A one-member artifact's founder seconds an application to admit its second member (28 September).
      if (!a.members.some(m => m.id === h.agent) || !(a.active || (a.members.length === 1 && d.type !== 'contribute'))) throw Object.assign(Error('active council membership required (a one-member artifact only admits)'), { status: 403 });
      // `selfPaid` (review, 30 September): the member's own key pays, and the join still names this
      // gateway, which it prefers, as the one that hosts the newcomer (lib.rs `register`).
      // The draft's thread (its post) goes into the second for an application as for a contribution,
      // so a newcomer's membership vote links its discussion (30 September).
      const prepared = await prepare(draftSecond(d, h.agent, body.selfPaid));
      // The draft is the newcomer's consent: the member submits this message and the gateway adds the
      // newcomer's co-signature then (auto-consent). A draft saved without it (before 30 September)
      // still waits for the newcomer's approval at /v2/hosted/cosign, which then shows in the queue.
      const expires = decodeEnvelope(unb64(prepared.message)).expiry, auto = !!consentKey(d);
      drafts.note(d.id, 'second', { by: h.agent, message: prepared.message, expires, expiresAt: new Date(expires * 1000).toISOString(), autoConsent: auto });
      const fields = ['"message"', ...(auto ? [] : ['"cosignature"']), ...(prepared.uploadFrame ? ['"uploadFrame"'] : [])].join(', '), by = new Date(expires * 1000).toISOString();
      return { ...prepared, consent: auto ? 'automatic' : 'manual',
        then: auto ? `POST /v2/hosted/act { ${fields} } before ${by}: ${We} adds the newcomer's co-signature, since its draft is its consent`
          : `the newcomer approves it at POST /v2/hosted/cosign (its draft was saved before drafts counted as consent); then POST /v2/hosted/act { ${fields} } before ${by}` };
    },
    // A member's no to a newcomer's draft, mirrored on the program's decline: the same identity drafts
    // for that artifact again after the reapply wait, never after MAX_DECLINES (owner, 29 September).
    'POST /v2/hosted/dismiss': async (req, body) => {
      const h = await session(req), d = drafts.get(body.draft);
      if (!d) throw Object.assign(Error('draft not found or expired'), { status: 404 });
      const a = await c.artifact(d.artifact);
      if (!a.members.some(m => m.id === h.agent)) throw Object.assign(Error('only a member of this artifact dismisses its drafts'), { status: 403 });
      const { count, last } = drafts.dismiss(d.id);
      return { dismissed: d.id, owner: d.owner, artifact: d.artifact, dismissals: count, ...(count < MAX_DECLINES ? { draftsAgainAfter: new Date(last + T.reapplyWait * 1000).toISOString() } : { final: true }) };
    },
    'POST /v2/hosted/cosign': async (req, body) => {
      const h = await session(req), m = unb64(String(body.message)), env = decodeEnvelope(m), action = env.action;
      if (env.program !== c.program.toBase58() || env.expiry <= Math.floor(await t.now())) throw Object.assign(Error('wrong program or expired consent'), { status: 400 });
      if (env.agent === h.agent) throw Object.assign(Error('this endpoint only supplies a second signature'), { status: 400 });
      const current = await c.agent(new PublicKey(h.agent));
      // Founding takes one signature (owner, 28 September): only a revival's co-founder co-signs here.
      let permitted = current?.custody === 'hosted' && action.type === 'revive' && action.cofounder === h.agent;
      // An artifact founded alone admits through an application, never a revival (28 September).
      if (permitted && (await c.artifact(env.accounts[0]).catch(() => null))?.foundedAlone) throw Object.assign(Error('an artifact founded alone admits its second member through an application, not a revival'), { status: 409 });
      if (action.type === 'second' && action.join && action.author === h.agent && !current) {
        const d = drafts.get(body.draft);
        if (!d || d.owner !== h.agent) throw Object.assign(Error('approve your pending draft by id'), { status: 403 });
        const expected = await prepare(draftSecond(d, env.agent, env.selfPaid));
        const check = decodeEnvelope(unb64(expected.message));
        // Expiry can differ between prepare and consent; every other signed field must match.
        if (JSON.stringify(describe({ ...env, expiry: 0 })) !== JSON.stringify(describe({ ...check, expiry: 0 }))) throw Object.assign(Error('message differs from your queued contribution or application'), { status: 409 });
        permitted = true;
      }
      if (!permitted) throw Object.assign(Error('this identity is not the required hosted co-signer'), { status: 403 });
      const cosignature = { key: h.key.publicKey.toBase58(), signature: b64(nacl.sign.detached(m, h.key.secretKey)) };
      // A newcomer's approval of its draft's second waits on the draft for the seconding member.
      if (action.type === 'second' && body.draft) try { drafts.note(body.draft, 'cosigned', { message: b64(m), cosignature, expires: env.expiry }); } catch {}
      return { message: b64(m), cosignature, envelope: describe(env) };
    },
    'POST /v2/hosted/act': async (req, body) => {
      const h = await session(req);
      if (!threads && (body.pending_id !== undefined || body.post_id !== undefined)) throw Object.assign(Error(`${us} runs no thecolony.cc sign-in, so it takes no posts: send the action itself`), { status: 400 });
      if (threads && body.pending_id !== undefined) return prove(h, body, 'act');
      await promote(h.agent);
      if (needsPost(body)) return askAct(h, body);
      return hostedAct(h, await withThread(body));
    },
    // Revokes the presented token, or with { all: true } every token for this identity.
    'POST /v2/hosted/logout': async (req, body) => {
      const h = await session(req);
      return { agent: h.agent, revoked: body.all === true ? sessions.revokeWhere({ agent: h.agent }) : sessions.revoke(h.hash) };
    },
    // Moving to an own key: the gateway prepares the key change, the agent signs it with its new
    // key, and the gateway adds the current key's signature. One instruction; seats are kept. An
    // optional `recovery` key is set in the same change (plan 6.5).
    'POST /v2/hosted/prepare-key': async (req, body) => {
      // `selfPaid` (self-pay mode, owner 30 September: set key included): the hosted key pays the change as fee payer.
      const h = await session(req); const message = await c.message(new PublicKey(h.agent), { type: 'setKey', key: new PublicKey(body.key), ...(body.recovery ? { recovery: new PublicKey(body.recovery) } : {}) }, [], { selfPaid: body.selfPaid === true });
      return { message: b64(message), envelope: describe(decodeEnvelope(message)) };
    },
    'POST /v2/hosted/move-key': async (req, body) => {
      const h = await session(req); const key = h.key; const m = unb64(body.message);
      const env = decodeEnvelope(m); if (env.agent !== h.agent || env.action.type !== 'setKey') throw Object.assign(Error('not this agent\'s key change'), { status: 400 });
      // A self-paid change (prepared with `selfPaid`) is paid by the hosted key as fee payer, never by
      // the gateway or the vault; the program's exact rules are checked before anything is sent.
      // Otherwise the vault funds it (the gateway fronts the fee and is refunded in the same transaction)
      // or it is refused with 402; the ceiling bounds what a failed one costs the gateway.
      const funding = env.selfPaid ? await vaultFunds(c, m, { payer: payer.publicKey, signatures: 2 })
        : await price(h.agent, (c, held) => vaultFunds(c, env, { payer: payer.publicKey, signatures: 2, held }));
      const signed = () => ({ message: m, signatures: [{ key: key.publicKey, signature: nacl.sign.detached(m, key.secretKey) }, { key: new PublicKey(env.action.key), signature: unb64(body.signature) }] });
      if (env.selfPaid) {
        if (funding.refused) throw Object.assign(Error(`the program's rules refuse this action: ${funding.reason}`), { status: 409, detail: { refusedByProgram: true, reason: funding.reason, before: 'signing' } });
        await refuseExact(h.agent, env.action, env.accounts, 2, true, { payer: key.publicKey });
        await hostedCanPay(key, funding);
      }
      // Nothing stays in our custody (owner, 30 September): the sweep job is written before the key
      // change is sent ('moving'), so a change that lands while its answer is lost still sweeps.
      const job = { agent: h.agent, from: key.publicKey.toBase58(), ...(h.label ? { label: h.label } : { legacyKey: true }), to: env.action.key, created: Date.now() };
      sweeps.put({ ...job, status: 'moving' });
      let signature = null;
      try { signature = env.selfPaid ? await c.submit(signed(), key) : await pay({ funding, agent: h.agent }, cc => cc.submit(signed(), payer)); }
      catch (e) {
        const now = await c.agent(new PublicKey(h.agent)).catch(() => null);
        if (now?.custody !== 'own') { if (now) sweeps.remove(h.agent); throw e; }   // not landed (unknown: the retry pass decides)
      }
      // Then the old key's whole SOL and AC balance is swept to the new key; a failure is retried.
      let sweep;
      try { sweeps.put(job); sweep = sweepView(await runSweep(h.agent)); }
      catch (e) { sweep = { status: 'pending', error: String(e?.message ?? e).split('\n')[0] }; alarm(`AC_ALERT hosted-sweep agent=${h.agent} error=${JSON.stringify(sweep.error)}`); }
      sessions.revokeWhere({ agent: h.agent }); sessions.forget(h.agent);   // the gateway no longer acts for it
      return { signature, agent: h.agent, custody: 'own', signer: env.action.key, sweep };
    },
    // What the hosted key holds, and what may be sent (never the fee or the key's rent floor).
    'GET /v2/hosted/funds': async req => {
      const h = await session(req); await hostedFunds(h);
      const cfg = await c.config(), token = tokenOf(cfg), mine = await holdings(t, h.key.publicKey, token), rentMin = await t.rent(0);
      return { agent: h.agent, address: mine.address, sol: mine.sol, ac: String(mine.ac), ...(token ? { mint: token.mint.toBase58(), decimals: token.decimals } : {}),
        maxSol: Math.max(0, mine.sol - TX_FEE - rentMin), custody: 'hosted', warning: warningFor(await c.agent(new PublicKey(h.agent)) ?? { gateway: ours }), sendsPerHour };
    },
    // Step 1 of a send: { asset: "SOL" | "AC", to, amount } (a decimal string in SOL or AC, or "max").
    'POST /v2/hosted/send': async (req, body) => {
      const h = await session(req); await hostedFunds(h);
      const wait = sendBudget(h.agent); if (wait) throw Object.assign(Error(`at most ${sendsPerHour} sends an hour from a hosted key`), { status: 429, retryAfter: wait });
      const cfg = await c.config(), asset = String(body.asset ?? '').toUpperCase(), decimals = asset === 'SOL' ? 9 : tokenOf(cfg)?.decimals ?? 0;
      const amount = body.amount === 'max' ? 'max' : toBaseUnits(body.amount, decimals);
      const plan = await planSend(t, { from: h.key.publicKey, to: body.to, asset, amount, cfg });
      for (const [k, q] of sendQuotes) if (q.expires <= Date.now() || q.agent === h.agent) sendQuotes.delete(k);
      const confirmation = randomBytes(24).toString('base64url'), expires = Date.now() + sendConfirmMs;
      sendQuotes.set(confirmation, { agent: h.agent, token: h.hash, asset, to: plan.to, amount: plan.amount, expires });
      return { confirmation, expires_at: new Date(expires).toISOString(), send: { asset, to: plan.to, amount: fromBaseUnits(plan.amount, decimals), baseUnits: String(plan.amount),
        fee: plan.fee, createsTokenAccount: plan.createsTokenAccount, after: { sol: plan.after.sol, ac: String(plan.after.ac) } },
        then: `POST /v2/hosted/send/confirm { "confirmation" } with the same token within ${Math.round(sendConfirmMs / 1000)} s` };
    },
    // Step 2: the fresh confirmation. Re-checked against the balance now, sent from the hosted key, logged.
    'POST /v2/hosted/send/confirm': async (req, body) => {
      const h = await session(req), q = typeof body.confirmation === 'string' ? sendQuotes.get(body.confirmation) : null;
      if (!q || q.expires <= Date.now() || q.agent !== h.agent || q.token !== h.hash) throw Object.assign(Error('no such send to confirm with this token, or it expired: quote it again with POST /v2/hosted/send'), { status: 404 });
      sendQuotes.delete(body.confirmation);
      await hostedFunds(h);
      const wait = sendBudget(h.agent); if (wait) throw Object.assign(Error(`at most ${sendsPerHour} sends an hour from a hosted key`), { status: 429, retryAfter: wait });
      if (sendingNow.has(h.agent)) throw Object.assign(Error('another send from this hosted key is in flight'), { status: 409 });
      sendingNow.add(h.agent);
      try {
        const plan = await planSend(t, { from: h.key.publicKey, to: q.to, asset: q.asset, amount: q.amount, cfg: await c.config() });
        sendTimes.get(h.agent).push(Date.now());
        let signature;
        try { signature = await t.send(plan.ixs, h.key); }
        catch (e) { logLine(fundsLog, { event: 'send-failed', agent: h.agent, asset: q.asset, to: q.to, amount: String(q.amount), signature: e.signature ?? null, error: String(e.message).split('\n')[0] }); throw e; }
        logLine(fundsLog, { event: 'send', agent: h.agent, asset: q.asset, to: q.to, amount: String(q.amount), fee: plan.fee, createsTokenAccount: plan.createsTokenAccount, signature });
        return { signature, asset: q.asset, to: q.to, baseUnits: String(q.amount) };
      } finally { sendingNow.delete(h.agent); }
    },
    // The agent (now on its own key) runs its sweep again: its current key signs sweepMessage(program, agent, time).
    'POST /v2/hosted/sweep': async (req, body) => {
      if (!sweeps) throw Object.assign(Error('not a gateway'), { status: 404 });
      const ip = ipOf(req); bans.check({ ip });
      let agent; try { agent = new PublicKey(body.agent).toBase58(); } catch { throw Object.assign(Error('agent must be a base58 address'), { status: 400 }); }
      const busy = perIdentity(`agent:${agent}`); if (busy) throw slowDown(busy);
      const who = await c.agent(new PublicKey(agent)), time = Number(body.time), now = Math.floor(await t.now()), sig = typeof body.signature === 'string' ? unb64(body.signature) : Buffer.alloc(0);
      if (!who) throw Object.assign(Error('agent not found'), { status: 404 });
      if (!Number.isSafeInteger(time) || Math.abs(time - now) > 900 || sig.length !== 64 || !nacl.sign.detached.verify(sweepMessage(c.program.toBase58(), agent, time), sig, new PublicKey(who.signer).toBuffer()))
        throw Object.assign(Error('needs the agent\'s current key\'s signature over "ACv2 sweep <program> <agent> <time>", time within 15 minutes of now'), { status: 401 });
      // No job yet: the agent left hosting without move-key (a Recover, a key change relayed
      // elsewhere). A key this gateway derives for it is adopted now.
      if (!sweeps.get(agent) || sweeps.get(agent).status === 'moving') await adopt(agent, recordOf(agent), who, { run: false });
      const job = sweeps.get(agent);
      if (!job || job.status === 'moving') throw Object.assign(Error(`${us} never hosted this agent's key`), { status: 404 });
      // A manual run at most every `manualSweepMs` (10 minutes by default) per agent.
      const last = job.manualAt ?? 0, wait = last + manualSweepMs - Date.now();
      if (wait > 0) throw Object.assign(Error('this sweep ran moments ago; run it again later'), { status: 429, retryAfter: Math.ceil(wait / 1000), detail: { sweep: sweepView(job) } });
      sweeps.update(agent, { next: 0, manualAt: Date.now() });
      return { agent, sweep: sweepView(await runSweep(agent)) };
    },
  };
  const bearer = req => (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');

  // Colony identity: `colony` = { verifier, seed, siteAgentId(username, colonyId) → site agent id or null }.
  if (colony) {
    if (!hostedDir) throw Error('colony identity needs --gateway');
    const bindings = colonyBindings(`${hostedDir}/colony-bindings.json`);
    const attested = colonyAttestations({ file: attestationsFile, pins: colony.siteAgentId?.pins ?? {} });
    const conflict = message => Object.assign(Error(message), { status: 409 });
    const agentOf = label => hostedKey(seed, label).publicKey.toBase58(), migratedLabel = label => !label.startsWith('colony');
    labelSearch = agent => [...bindings.labels(), ...(colony.siteAgentId?.labels ?? [])].find(l => agentOf(l) === agent) ?? null;
    // A username-only binding the operator has since attested to another id is void at once.
    const yielded = (label, id) => bindings.unverified(label) && (attested.ownerOf(label) ?? String(id)) !== String(id);
    stillBound = s => {
      if (s.colony && (bindings.ownerOf(s.label) !== String(s.colony.id) || yielded(s.label, s.colony.id))) throw Object.assign(Error('this identity is no longer bound to your Colony account; sign in again'), { status: 401 });
    };
    stillOwns = (label, id) => typeof label === 'string' && bindings.ownerOf(label) === String(id) && !yielded(label, id);
    // Identity follows the Colony user id. A label the operator attested to this id (manifest pin or
    // attestations file) binds by id, so a renamed owner still gets it; otherwise a bound id keeps
    // its label. A migrated or pre-hardening `colony:<username>` identity is keyed by a username:
    // unbound and unattested, its first login binds it to that Colony id (as before this change,
    // the username decides once), unless the gateway runs attested-only, where it goes to nobody.
    // Otherwise a fresh identity derived from the id. An attested binding never changes hands; a
    // username-only one yields to the attested id, and its tokens are revoked.
    const identityFor = async (username, colonyId) => {
      let bound = bindings.labelFor(colonyId);
      const mine = attested.labelFor(colonyId), fresh = `colony-id:${colonyId}`;
      if (bound && yielded(bound, colonyId)) {
        if (!bindings.claim(fresh, colonyId, { replacing: bound })) throw conflict('Colony identity binding conflict');
        sessions.revokeWhere({ agent: agentOf(bound) }); bound = fresh;
      }
      // An owner who signed in under a new name before being attested moves to the attested identity.
      if (mine && mine !== bound && (bound === null || bound === fresh || bindings.unverified(bound))) {
        const other = bindings.ownerOf(mine);
        if (!bindings.claim(mine, colonyId, { replacing: bound, displace: true })) throw conflict(`the identity attested to this Colony account is bound to another; ask ${operatorName ?? 'the gateway operator'}`);
        if (other !== null && other !== String(colonyId)) sessions.revokeWhere({ agent: agentOf(mine) });
        return { label: mine, migrated: migratedLabel(mine) };
      }
      if (mine && mine === bound) bindings.claim(mine, colonyId);   // attested after a username-only login: now verified
      if (bound) return { label: bound, migrated: migratedLabel(bound) };
      const siteId = await colony.siteAgentId(username, colonyId);
      const legacy = `colony:${username}`, legacyExists = !!(await c.agent(hostedKey(seed, legacy).publicKey));
      const raced = bindings.labelFor(colonyId); if (raced) return { label: raced, migrated: migratedLabel(raced) };
      for (const label of [siteId, legacyExists ? legacy : null]) {
        if (!label || bindings.ownerOf(label) !== null || attested.ownerOf(label) !== null) continue;
        if (attestedOnly) throw conflict(`"${username}" names an identity from before Colony ids were recorded; ${operatorName ?? 'the gateway operator'} must attest which Colony account owns it (nothing was created)`);
        if (bindings.claim(label, colonyId, { unverified: true })) return { label, migrated: migratedLabel(label) };
      }
      if (!bindings.claim(fresh, colonyId)) throw conflict('Colony identity binding conflict');
      return { label: fresh, migrated: false };
    };
    // Starts hold no state (the challenge lives in the client secret); the budget is optional.
    routes['POST /v2/colony/start'] = async (req, body) => {
      const ip = ipOf(req); bans.check({ ip });
      const wait = starts(`start:${ipBucket(ip)}`); if (wait) throw Object.assign(Error('too many verification starts from this address; wait a minute'), { status: 429, retryAfter: wait });
      return colony.verifier.start(String(body.colony_username ?? ''));
    };
    routes['POST /v2/colony/verify'] = async (req, body) => {
      const ip = ipOf(req); bans.check({ ip });
      const wait = colony.verifier.isOpen?.(body.client_secret) && perChallenge(`verify:${body.client_secret}`); if (wait) throw Object.assign(Error('checking too often; wait a few seconds'), { status: 429, retryAfter: wait });
      const who = await colony.verifier.verify({ client_secret: body.client_secret, colony_username: body.colony_username, post_id: body.post_id });
      bans.check({ ip, colony: who.colonyId });
      const busy = perIdentity(`colony:${who.colonyId}`); if (busy) throw slowDown(busy);
      // A Colony account behind a banned identity mints no other (cleanup-spec §2.11).
      if (banned.has(who.colonyId)) throw Object.assign(Error(BANNED), { status: 403, detail: { code: 'banned' } });
      const { label, migrated } = await identityFor(who.username, who.colonyId);
      const key = hostedKey(seed, label);
      bans.check({ agent: key.publicKey.toBase58() });
      await hostedBanned(key.publicKey.toBase58(), who.colonyId);
      let agent = await c.agent(key.publicKey);
      if (agent && agent.custody !== 'hosted') { await adopt(key.publicKey.toBase58(), { label }, agent); throw Object.assign(Error('this agent already holds its own key; act with it directly (what its hosted key held is swept to it)'), { status: 409 }); }
      if (agent) promote(key.publicKey.toBase58());
      const seats = (await seatsOf(key.publicKey.toBase58())).map(a => ({ artifact: a.address, name: a.name }));
      const { token, expires } = sessions.issue({ label, colony: { id: who.colonyId, username: who.username } });
      // The username this login proved is where the inbox digest reaches this hosted identity. The
      // digest's bookkeeping is best effort: a failure to record it never fails the login.
      if (!agent || agent.custody === 'hosted') {
        try { contacts.hosted(key.publicKey.toBase58(), { label, colonyId: who.colonyId, username: who.username }); }
        catch (e) { console.error(`gateway: could not record the digest contact of a login: ${e.message}`); }
      }
      return { agent: key.publicKey.toBase58(), token, token_expires_at: new Date(expires).toISOString(), custody: 'hosted', registered: !!agent, migrated, colony_user_id: who.colonyId, verified_via: who.via, seats };
    };
    // The inbox digest (product review 5B item 1). Hosted identities get it at their login's
    // username, recorded above; logins from before this record existed are read from live tokens.
    contacts = digestContacts(`${hostedDir}/digest-contacts.json`);
    boundLabel = id => bindings.labelFor(id);
    // Best effort: an unreadable contacts file must never stop the gateway from starting (logins,
    // relaying and cranking go on; the digest's passes report the file until it is fixed).
    try {
      for (const l of sessions.logins()) if (validColonyId(l.colony.id) && !contacts.status(l.agent).hosted)
        try { contacts.hosted(l.agent, { label: l.label, colonyId: l.colony.id, username: l.colony.username }, l.created); } catch {}
    } catch (e) { console.error(`gateway: digest contacts not backfilled from live logins: ${e.message}`); }
    // An own-key agent opts in with a request its current key signs over
    // subscribeMessage(program, agent, colony_username, time), then proves the username exactly as a
    // login does. The pending opt-in lives only as long as the challenge, in this process.
    const optIns = new Map();
    const signedBy = async (agent, message, time, signature) => {
      const now = Math.floor(await t.now()), sig = typeof signature === 'string' ? unb64(signature) : Buffer.alloc(0);
      const who = await c.agent(agent);
      if (!who) throw Object.assign(Error('agent not found'), { status: 404 });
      if (who.status === 'banned') throw Object.assign(Error(BANNED), { status: 403, detail: { code: 'banned' } });
      if (who.custody !== 'own') throw Object.assign(Error('a hosted identity gets the digest at its Colony login\'s username; turn it off or on with POST /v2/hosted/digest'), { status: 409 });
      if (!Number.isSafeInteger(time) || Math.abs(time - now) > 900 || sig.length !== 64 || !nacl.sign.detached.verify(message, sig, new PublicKey(who.signer).toBuffer()))
        throw Object.assign(Error('needs the agent\'s current key\'s signature over the documented message, with `time` within 15 minutes of now'), { status: 401 });
      return who;
    };
    // Opting in is offered only where the digest runs: elsewhere a confirmed opt-in would promise DMs
    // that never come. Opting out (unsubscribe, hosted/digest off, stop) always works.
    if (digest) routes['POST /v2/inbox/subscribe'] = async (req, body) => {
      const ip = ipOf(req); bans.check({ ip });
      const wait = starts(`start:${ipBucket(ip)}`); if (wait) throw Object.assign(Error('too many verification starts from this address; wait a minute'), { status: 429, retryAfter: wait });
      const agent = new PublicKey(body.agent).toBase58(), username = String(body.colony_username ?? '').trim().toLowerCase(), time = Number(body.time);
      bans.check({ ip, agent });
      const busy = perIdentity(`agent:${agent}`); if (busy) throw slowDown(busy);
      await signedBy(agent, subscribeMessage(c.program.toBase58(), agent, username, time), time, body.signature);
      const started = colony.verifier.start(username);
      const expires = Date.parse(started.expires_at);
      // One opt-in in progress per agent: a newer one replaces it, so pending state stays bounded.
      for (const [k, v] of optIns) if (v.expires <= Date.now() || v.agent === agent) optIns.delete(k);
      optIns.set(started.client_secret, { agent, username, signed: time, expires: Number.isFinite(expires) ? expires : Date.now() + 30 * 60_000 });
      return { ...started, then: 'POST /v2/inbox/confirm { client_secret, post_id? }  (keep client_secret private; it works once)' };
    };
    if (digest) routes['POST /v2/inbox/confirm'] = async (req, body) => {
      const ip = ipOf(req); bans.check({ ip });
      const pending = typeof body.client_secret === 'string' ? optIns.get(body.client_secret) : null;
      if (!pending || pending.expires <= Date.now()) throw Object.assign(Error('no digest opt-in in progress for this client secret: call /v2/inbox/subscribe'), { status: 404 });
      const wait = perChallenge(`verify:${body.client_secret}`); if (wait) throw Object.assign(Error('checking too often; wait a few seconds'), { status: 429, retryAfter: wait });
      const who = await colony.verifier.verify({ client_secret: body.client_secret, colony_username: pending.username, post_id: body.post_id });
      optIns.delete(body.client_secret);
      bans.check({ ip, colony: who.colonyId, agent: pending.agent });
      if (banned.has(who.colonyId)) throw Object.assign(Error(BANNED), { status: 403, detail: { code: 'banned' } });
      const current = await c.agent(new PublicKey(pending.agent));
      if (!current || current.status === 'banned' || current.custody !== 'own') throw Object.assign(Error('this agent no longer holds its own key, or is banned'), { status: 409 });
      contacts.subscribe(pending.agent, { colonyId: who.colonyId, username: who.username, signed: pending.signed });
      return { agent: pending.agent, colony_username: who.username, digest: 'on' };
    };
    routes['POST /v2/inbox/unsubscribe'] = async (req, body) => {
      const ip = ipOf(req); bans.check({ ip });
      const agent = new PublicKey(body.agent).toBase58(), time = Number(body.time);
      const busy = perIdentity(`agent:${agent}`); if (busy) throw slowDown(busy);
      await signedBy(agent, unsubscribeMessage(c.program.toBase58(), agent, time), time, body.signature);
      const done = contacts.unsubscribe(agent, time);
      if (done === null) throw Object.assign(Error('this opt-out was signed before the current opt-in; sign a new one'), { status: 409 });
      return { agent, digest: 'off', removed: done };
    };
    // A hosted identity turns its digest off, or back on: { on: false | true }.
    routes['POST /v2/hosted/digest'] = async (req, body) => {
      const h = await session(req);
      if (typeof body.on !== 'boolean') throw Object.assign(Error('on must be true or false'), { status: 400 });
      contacts.hostedDigest(h.agent, body.on);
      const st = contacts.status(h.agent).hosted;
      return { agent: h.agent, digest: body.on ? 'on' : 'off', ...(st ? { colony_username: st.username } : {}),
        ...(body.on && !digest ? { note: `${us} is not sending the digest at present: nothing will be sent until it does` } : {}) };
    };
    // The recipient's own way out, needing neither a key nor a token: prove the Colony account as a
    // login does, and the digest never DMs that account again, whichever agents named it, until it
    // opts in again (an own-key opt-in, or POST /v2/hosted/digest { on: true }).
    const stops = new Map();
    routes['POST /v2/inbox/stop'] = async (req, body) => {
      const ip = ipOf(req); bans.check({ ip });
      const wait = starts(`start:${ipBucket(ip)}`); if (wait) throw Object.assign(Error('too many verification starts from this address; wait a minute'), { status: 429, retryAfter: wait });
      const started = colony.verifier.start(String(body.colony_username ?? ''));
      const expires = Date.parse(started.expires_at);
      for (const [k, v] of stops) if (v.expires <= Date.now()) stops.delete(k);
      stops.set(started.client_secret, { username: started.colony_username, expires: Number.isFinite(expires) ? expires : Date.now() + 30 * 60_000 });
      return { ...started, then: 'POST /v2/inbox/stop/confirm { client_secret, post_id? }  (keep client_secret private; it works once)' };
    };
    routes['POST /v2/inbox/stop/confirm'] = async (req, body) => {
      const ip = ipOf(req); bans.check({ ip });
      const pending = typeof body.client_secret === 'string' ? stops.get(body.client_secret) : null;
      if (!pending || pending.expires <= Date.now()) throw Object.assign(Error('no digest stop in progress for this client secret: call /v2/inbox/stop'), { status: 404 });
      const wait = perChallenge(`verify:${body.client_secret}`); if (wait) throw Object.assign(Error('checking too often; wait a few seconds'), { status: 429, retryAfter: wait });
      const who = await colony.verifier.verify({ client_secret: body.client_secret, colony_username: pending.username, post_id: body.post_id });
      stops.delete(body.client_secret);
      // The proof claims the username (a renamed account's entry under it DMs it no more), then stops the account.
      contacts.stop(who.colonyId, who.username);
      return { colony_username: who.username, digest: 'stopped' };
    };
  }
  // Per-client request budget (the client address comes from the local reverse proxy).
  // Reads (GET) get `newcomerReads` extra in a new client's first minute (review 5A.10).
  const perIp = rateLimiter(perMinute, undefined, { grace: newcomerReads });
  const limited = req => perIp(ipBucket(ipOf(req)), { read: req.method === 'GET' });
  const server = createServer((req, res) => {
    const reply = (status, value, retryAfter) => {
      const body = JSON.stringify(value); const s = sign(body), next = value?.[NEXT];
      res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'access-control-expose-headers': 'x-ac-signer, x-ac-time, x-ac-signature, x-ac-next, retry-after', 'x-ac-signer': payer.publicKey.toBase58(), 'x-ac-time': s.time, 'x-ac-signature': s.signature, ...(next ? { 'x-ac-next': next } : {}),
        // Every rate limit knows its reset; the draft quota's 429 has no time to name (a slot frees when a draft goes).
        ...(status === 429 && retryAfter ? { 'retry-after': String(retryAfter) } : {}) });
      res.end(body);
    };
    const chunks = [];
    let bytes = 0, tooLarge = false;
    req.on('data', d => {
      if (tooLarge) return;
      bytes += d.length;
      if (bytes > 200_000) {
        tooLarge = true;
        chunks.length = 0;
        reply(413, { error: 'request too large' });
        return;
      }
      chunks.push(d);
    });
    req.on('end', async () => {
      if (req.destroyed || tooLarge) return;
      if (req.method === 'OPTIONS') { res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type', 'access-control-allow-methods': 'GET, POST, OPTIONS' }); return res.end(); }
      const wait = limited(req);
      if (wait) return reply(429, { error: `too many requests from this address; retry in ${wait} s`, retryAfter: wait }, wait);
      const path = req.url.split('?')[0].replace(/\/$/, '');
      const m = path.match(/^\/v2\/(artifacts|agents|donate)\/([1-9A-HJ-NP-Za-km-z]{32,44})(\/inbox)?$/);
      let key = m && !(m[3] && m[1] !== 'agents') ? `${req.method} /v2/${m[1]}/:address${m[3] ?? ''}` : `${req.method} ${path}`, param = m?.[2];
      // Any other single segment under /v2/artifacts/ is an artifact's name (reads by name).
      const named = !m && path.match(/^\/v2\/artifacts\/([^/]+)$/);
      if (named) {
        try { param = decodeURIComponent(named[1]); } catch { return reply(400, { error: 'the artifact name in the path is not valid percent-encoding' }); }
        key = `${req.method} /v2/artifacts/:address`;
      }
      const route = routes[key];
      if (!route) return reply(404, { error: `no route ${key}`, see: 'GET /v2', docs: 'https://artifactcouncil.com/join.md' });
      if (readOnly && req.method !== 'GET') return reply(503, { error: 'this relay is a read-only preview: it serves reads only and sends nothing; use a relay listed at GET https://artifactcouncil.com/v2/relays', readOnly: true });
      let body;
      try {
        // Decode once: an HTTP chunk may end in the middle of a UTF-8 character.
        const raw = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
        body = raw ? JSON.parse(raw) : {};
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw Error('expected object');
      } catch { return reply(400, { error: 'request body must be a UTF-8 JSON object' }); }
      try { checkRequest(body, { required: key === 'POST /v2/prepare' ? ['agent'] : [], secrets: key === 'POST /v2/hosted/renew' ? ['recovery'] : [] }); }
      catch (e) { return reply(e.status, { error: e.message }); }
      let status = 200, value, retryAfter;
      try { value = await route(req, body, param); status = value?.[STATUS] ?? 200; }
      catch (e) {
        // A refusal by the program's own rules is the agent's to fix, not a relay fault: 409, said plainly.
        const rule = ruled(e), reason = rule ? e.detail?.reason : null;
        status = e.status ?? (rule ? 409 : 502); retryAfter = e.retryAfter;
        value = { error: reason ? `the program's rules refused this action: ${reason}` : rule ? `the program's rules refused this action (${e.message.split('\n')[0]}); check membership, allowances, voting and proposal rules in skill.md` : e.message.split('\n')[0], ...(rule ? { refusedByProgram: true } : {}), logs: e.logs?.slice(-6), ...e.detail };
      }
      // Only a write that went through drops the listing; failed posts, and posts that change no listed
      // account (prepares, upload chunk writes), cannot force rescans.
      if (status === 200 && req.method === 'POST' && !value?.[UNCHANGED] && !READ_ONLY_POSTS.includes(path) && !READ_ONLY_PREFIXES.some(x => path.startsWith(x))) listings.clear();
      reply(status, status === 429 && retryAfter ? { ...value, retryAfter } : value, retryAfter);
    });
  });
  const cranker = crank ? relayCranker(crank) : null;
  const seat = attest ? relaySeat(attest) : null;
  const digester = digest ? relayDigest(digest) : null;
  // The creator-fee crank (owner, 30 September; sdk/creator-fees.mjs): its own cadence and state, this
  // wallet paying within its bound per epoch and the daily ceiling; its pages go where the relay's go.
  const feeCranker = creatorFees ? creatorFeeCranker(c, payer, { dir: stateDir && `${stateDir}/creator-fees`, notifier, ledger, ...creatorFees }) : null;
  if (feeCranker) server.on('close', () => feeCranker.stop());
  /** The inbox digest's loop (sdk/inbox-digest.mjs): a pass every `every` ms, the first after `first`.
   *  Each pass DMs only whom the contacts allow, at most once a day each plus the removal-risk DM a
   *  day before such a deadline; `dry-run` prints the DMs to the log and sends and records nothing. */
  function relayDigest({ mode, every = 3_600_000, first = 60_000, messenger = null, limits, sleep, now = Date.now, print = m => console.log(new Date().toISOString(), m),
    log = m => console.error(new Date().toISOString(), m) }) {
    if (!Number.isSafeInteger(every) || every < 60_000) throw Error('the digest runs at most once a minute');
    const status = { mode, every, passes: 0, running: false, last: null };
    let timer = null, stopped = false;
    const pass = async () => {
      if (status.running) return null;
      status.running = true;
      try {
        const r = await digestPass(c, { contacts, boundLabel, gateway: payer.publicKey.toBase58(), messenger, statePath: `${stateDir ?? hostedDir}/digest-state.json`,
          dryRun: mode === 'dry-run', nowMs: now(), print, log, limits, ...(sleep ? { sleep } : {}), ...(url ? { relayUrl: url } : {}), read: fresh,
          donations: (agent, since, config) => donationsOf(agent, since, config, { internal: true }), custodyWarning: custodyWarning({ gateway: ours, ours, operator: operatorName }) });
        status.last = { at: new Date().toISOString(), ok: true, sent: r.sent.length, failed: r.failed.length, skipped: r.skipped.length };
        return r;
      } catch (e) { status.last = { at: new Date().toISOString(), ok: false, error: String(e?.message ?? e).split('\n')[0] }; log(`digest pass failed: ${status.last.error}`); return null; }
      finally { status.passes++; status.running = false; }
    };
    const schedule = ms => { if (stopped) return; timer = setTimeout(() => pass().finally(() => schedule(every)), ms); timer.unref?.(); };
    return { status: () => ({ ...status }), start: () => schedule(first), stop: () => { stopped = true; clearTimeout(timer); }, pass };
  }
  /** The attestor seat's loop beside the crank: its own cadence (fast while a round is in flight). */
  function relaySeat({ ours = [], known = [], archive = [], notifier = notifierFromEnv(), log = m => console.log(new Date().toISOString(), m),
    error = m => console.error(new Date().toISOString(), m), sleep } = {}) {
    const store = seatStore(snapshotDir, stateDir ? `${stateDir}/seat` : undefined), source = `snapshot seat ${payer.publicKey.toBase58()}`;
    let stopped = false, wake = () => {};
    // Without a Colony key the same deduplicated pages go to the log.
    const pager = (alerts, { resolve = true } = {}) => page(alerts, { resolve, notifier: notifier ?? { name: 'log', send: async m => log(m.text) }, statePath: `${store.state}/alerts.json`, source });
    const nap = sleep ?? (ms => new Promise(r => { const t = setTimeout(r, ms); t.unref?.(); wake = () => { clearTimeout(t); r(); }; }));
    return { start: () => { runSeat(c, payer, { store, ours, known, archive, pay: false, log, error, pager, stopped: () => stopped, sleep: nap }).catch(e => error(`seat: ${e.message}`)); },
      stop: () => { stopped = true; wake(); } };
  }
  // Every crank reserves its possible failed network fee. Treasury deposits fail atomically.
  // Snapshot payments use this same metered path.
  // A pass still running after `stall` ms (an RPC call that never answers) is written off as failed
  // and the schedule moves on; whatever it does later is not recorded.
  function relayCranker({ random = Math.random, log = m => console.log(new Date().toISOString(), m),
    error = m => console.error(new Date().toISOString(), m), every: _e, jitter: _j, stall: _s, ...options }) {
    const { every, jitter, stall } = crankTiming({ every: _e, jitter: _j, stall: _s });
    const quiet = f => m => { try { f(m); } catch {} }, say = quiet(log), cry = quiet(error);
    const status = { every, jitter, stall, passes: 0, failures: 0, stepFailures: 0, running: false, last: null };
    // The shared steps are taken in turn with the other seats (cranks.mjs myTurn): this relay's memory of them.
    const turns = { seen: new Map() };
    let timer = null, stopped = false;
    const cost = async signature => {
      for (let i = 0; signature && i < 4; i++) { const tx = await t.transaction(signature).catch(() => null); if (typeof tx?.payerDelta === 'number') return Math.max(0, -tx.payerDelta); await new Promise(r => setTimeout(r, 300)); }
      return null;
    };
    const metered = () => {
      const tr = Object.create(t);
      tr.send = async (...a) => {
        const ticket = ledger.reserve(CRANK_FEE, { exposure: CRANK_FEE });
        let signature = null, known;
        try { signature = await t.send(...a); return signature; }
        catch (e) { signature = e.signature ?? null; if (e.unsent || (!signature && (e.logs || /simulation failed/i.test(e.message)))) known = 0; throw e; }
        finally { ledger.settle(ticket, known ?? await cost(signature)); }
      };
      const cc = new Council({ transport: tr, program: c.program }); cc.day = c.day;
      cc.snapshotSource=c.snapshotSource;
      return cc;
    };
    const pass = async () => {
      if (status.running) return false;
      const at = new Date().toISOString(), failed = []; status.running = at;
      let timer;
      const stalled = new Promise((_, reject) => { timer = setTimeout(() => reject(Error(`pass stalled for ${stall} ms`)), stall); timer.unref?.(); });
      try {
        const done = await Promise.race([crankOnce(metered(), payer, { ...options, turns, log: say, failed }), stalled]);
        status.stepFailures += failed.length; status.last = { at, ok: true, steps: done.length, failed: failed.length };
        // Steps that fail are logged one by one; a pass where some failed is reported too.
        if (failed.length) cry(`crank pass: ${failed.length} step(s) failed: ${failed.join(', ')}`);
      }
      catch (e) { status.failures++; status.last = { at, ok: false, error: String(e?.message ?? e).split('\n')[0] }; cry(`crank pass failed: ${status.last.error}`); }
      finally { clearTimeout(timer); status.passes++; status.running = false; }
      return status.last.ok;
    };
    // The first pass lands anywhere in the first period, so relays started together spread out.
    const schedule = first => {
      if (stopped) return;
      const r = Math.min(1, Math.max(0, Number(random()) || 0));
      timer = setTimeout(() => pass().finally(() => schedule(false)), first ? Math.floor(r * every) : every + Math.round((2 * r - 1) * jitter));
      timer.unref?.();
    };
    return { status: () => ({ ...status, ...(feeCranker ? { creatorFees: feeCranker.status() } : {}) }), start: () => schedule(true), stop: () => { stopped = true; clearTimeout(timer); }, pass };
  }
  server.on('close', () => { cranker?.stop(); seat?.stop(); digester?.stop(); });
  await new Promise((r, j) => { server.once('error', j); server.listen(port, host, () => { server.off('error', j); r(); }); });
  // Only a relay that is serving cranks: a failed listen leaves no timer behind.
  if (sessions) { const timer = setInterval(() => { try { sessions.sweep(); threads?.sweep(); } catch (e) { console.error(`gateway: token sweep failed: ${e.message}`); } }, sweepMs); timer.unref(); server.on('close', () => clearInterval(timer)); }
  // Failed hosted-key sweeps are retried on their backoff until they succeed.
  if (sweeps) {
    const retry = async () => {
      try {
        for (const j of sweeps.all()) {
          // A key change whose outcome was never learned: the chain says whether it landed.
          if (j.status === 'moving' && Date.now() - (j.created ?? 0) > 600_000) {
            const who = await c.agent(new PublicKey(j.agent)).catch(() => undefined);
            if (who?.custody === 'own') { sweeps.update(j.agent, { status: 'pending', next: 0 }); sessions.revokeWhere({ agent: j.agent }); sessions.forget(j.agent); await runSweep(j.agent).catch(() => {}); }
            else if (who) sweeps.remove(j.agent);
          } else if (j.status === 'pending' && j.next <= Date.now()) await runSweep(j.agent).catch(() => {});
        }
      } catch (e) { console.error(`gateway: sweep retry pass failed: ${e.message}`); }
    };
    const timer = setInterval(retry, sweepRetryMs); timer.unref(); server.on('close', () => clearInterval(timer));
  }
  cranker?.start(); seat?.start(); digester?.start();
  feeCranker?.start();
  return { server, council: c, spend: ledger.status, holding, cranker, digester, sweeps, runSweep, creatorFees: feeCranker, url: `http://127.0.0.1:${server.address().port}` };
}

function crankTiming({ every = 60_000, jitter = Math.floor(every / 4), stall = Math.max(10 * every, 600_000), selfPay: _selfPay }) {
  if (!Number.isSafeInteger(every) || every < 1) throw Error('crank every must be a positive integer of milliseconds');
  if (!Number.isSafeInteger(jitter) || jitter < 0 || jitter >= every) throw Error('crank jitter must be a non-negative integer below every');
  if (!Number.isSafeInteger(stall) || stall < 1) throw Error('crank stall must be a positive integer of milliseconds');
  return { every, jitter, stall };
}

// A canonical crank has one transaction signature and no priority fee.
const CRANK_FEE = 5000;

/** Checks a relay response's signature; agents use this to keep receipts. */
export function verifyResponse(headers, body) {
  const signer = headers.get('x-ac-signer'), time = headers.get('x-ac-time'), sig = headers.get('x-ac-signature');
  return !!(signer && sig && nacl.sign.detached.verify(Buffer.from(`${time}.${body}`), Buffer.from(sig, 'base64'), new PublicKey(signer).toBuffer()));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (flag('no-crank')) throw Error('--no-crank is not supported: every relay cranks (hardening plan decision 8)');
  if (flag('open-register') && publicGateway(arg('url', ''), arg('host', '127.0.0.1'))) throw Error('--open-register is refused on a public gateway');
  const payer = readKey(arg('key', new URL('../.local/relayer.json', import.meta.url).pathname));
  let colony = null;
  // Hosted keys derive from the seed; tokens only name them.
  const seed = arg('gateway', null) ? Buffer.from(readFileSync(arg('seed', new URL('../.local/gateway-seed', import.meta.url).pathname), 'utf8').trim(), 'hex') : null;
  if (arg('colony')) {
    // Colony checks read DMs; migrated identities come from the frozen export, never Supabase.
    // Missing or ambiguous exports fail startup rather than issuing a different identity.
    const manifest = JSON.parse(readFileSync(arg('manifest', new URL('../../docs/solana/migration/manifest.json', import.meta.url).pathname), 'utf8'));
    colony = { verifier: colonyVerifier({ apiKey: process.env.COLONY_API_KEY }), seed,
      siteAgentId: migrationIdentities(manifest) };
  }
  // One cluster setting (sdk/cluster.mjs): --cluster or AC_CLUSTER, devnet when unset; mainnet names its RPC.
  const cluster = clusterOf(arg('cluster'));
  // Where pages and the digest get the Colony key (a path, never the key), before anything can fail on the RPC.
  console.log(colonyKeyFile() ? `Colony key for pages and the digest: ${colonyKeyFile()}` : 'no Colony key: alerts stay in the journal');
  const { url } = await startRelay({ rpc: rpcFor(cluster, arg('rpc')), cluster, program: new PublicKey(arg('program')), payer,
    port: Number(arg('port', 8899)), host: arg('host', '127.0.0.1'), gatewayDir: arg('gateway', null), url: arg('url', ''), colony, seed,
    ...(arg('denylist') ? { denylistFile: arg('denylist') } : {}), ...(arg('attestations') ? { attestationsFile: arg('attestations') } : {}),
    snapshotDir: arg('snapshots', null), snapshotArchive: arg('snapshot-archive', null), snapshotUrl: arg('snapshot-url', undefined),
    attest: flag('attest') ? { ours: String(arg('ours', '')).split(',').map(s => s.trim()).filter(Boolean), archive: String(arg('archive-urls', '')).split(',').map(s => s.trim()).filter(Boolean) } : null,
    proxySecret: process.env.AC_PROXY_SECRET || null, attestedOnly: arg('attested-only', '1') === '1',
    ...gatewaySettings(n => arg(n)),
    uploadDir: arg('uploads', new URL(`../.local/relay-uploads/${payer.publicKey.toBase58()}`, import.meta.url).pathname),
    stateDir: arg('state', new URL(`../.local/relay-state/${payer.publicKey.toBase58()}`, import.meta.url).pathname),
    dailyCeiling: Number(arg('daily-ceiling', 100_000_000)), allow: String(arg('allow', '')).split(',').filter(Boolean),
    routePeers: arg('route-peers', '0') === '1', crank: { every: Math.round(Number(arg('crank-seconds', 60)) * 1000), selfPay: arg('crank-self-pay', '1') === '1' },
    // --creator-fees on|off (default off) and its --creator-fee-* settings (sdk/creator-fees.mjs).
    creatorFees: creatorFeeSettings(n => arg(n)),
    openRegister: flag('open-register'), perMinute: Number(arg('per-minute', 60)), newcomerReads: Number(arg('newcomer-reads', 20)),
    sendsPerHour: Number(arg('sends-per-hour', 6)), donationReadsPerMinute: Number(arg('donation-reads-per-minute', 60)),
    // Who the custody warning names as holding hosted keys; by default "Artifact Council" only on artifactcouncil.com.
    ...(arg('operator-name') ? { operator: arg('operator-name') } : {}),
    trustedProxies: String(arg('trusted-proxy', LOOPBACK.join(','))).split(',').map(s => s.trim()).filter(Boolean),
    edgeSecret: arg('edge-secret-file') ? readFileSync(arg('edge-secret-file'), 'utf8').trim() : null,
    // --digest on|dry-run|off (default off): the inbox digest's Colony DMs, sent with the Colony key.
    digest: ['on', 'dry-run'].includes(arg('digest', 'off')) ? { mode: arg('digest'), every: Math.round(Number(arg('digest-minutes', 60)) * 60_000),
      messenger: arg('digest') === 'on' ? messengerFromEnv() : null } : arg('digest', 'off') === 'off' ? null : (() => { throw Error('--digest must be on, dry-run or off'); })() });
  console.log(`Artifact Council relay ${payer.publicKey.toBase58()} on ${cluster} at ${url}/v2`);
}
