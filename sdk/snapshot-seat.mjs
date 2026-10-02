// A relay's attestor seat at work (snapshot-spec §5–6, with the owner's answers of 29 September): the
// one module the relay and the cranker run with `--attest` (runSeat beside their crank). Each pass, for the distribution in flight:
//   1. Fix: once the slot `SNAP_SLOTS` after the close has a slot hash, draw the snapshot slot, unless
//      someone already has.
//   2. Compute: the canonical source at the end of S* (getProgramAccounts rolled back over getBlock
//      pre-balances, snapshot-source.mjs), checked against the supply invariant; source, evidence and
//      dataset staged atomically in the private directory, where they persist across restarts, and
//      published only once commits close: served earlier, any seat could commit to our result without
//      computing it (29 September).
//   3. Commit with a fresh salt kept on disk before the commit is sent; a seat not ready by the end of
//      the commit window skips the round and alerts (missing one round is harmless).
//   4. Reveal right after commits close.
//   5. Veto only on a proven mismatch: an armed result other than ours, ours computed at the same slot
//      and passing the invariant. Never because ours is missing or an RPC failed: that alerts. The veto
//      goes first in the pass and escalates its priority fee; the relay pays what exceeds its refund. A
//      veto sends the round's pot to the carry and the next round runs at the normal quorum (owner,
//      29 September: no strict mode).
//   6. Verify the others: every other candidate of the round is fetched from its revealers, checked
//      against its commitment and compared with ours, holder by holder; any difference alerts.
//   7. Confirm and pay: once the armed result is confirmed equal to ours and the checking delay has
//      passed, pay it from our own bytes.
// Seats are optional (a relay without one still relays on ~0.2 SOL). Seat management: join is a
// deliberate operator command (the owner funds our two seats' bonds, 29 September), and our launch
// seats are seated active by the setup key before FinishSetup (owner, 30 September: holders are paid
// from the first day); a pass activates a matured seat when the admission rate allows, and pages on
// everything a seat's operator must know.
// Alerts are { rule, key, message } for alerts.mjs `page` (Colony DMs to the owner, 29 September).
import { readFileSync, writeFileSync, renameSync, mkdirSync, existsSync, readdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { SYSVAR_SLOT_HASHES_PUBKEY } from '@solana/web3.js';
import { TAG, SNAPSHOT, times, quorum, verdictOf, vetoedOf, commitHash, decodeEpoch, decodeRelayer, sha256 } from './layout.mjs';
import { parseSnapshot, fixSnapshot, commitSnapshot, revealSnapshot, vetoSnapshot, activateSeat, distributeSnapshot, newSalt, snapshotBody } from './snapshots.mjs';
import { captureSource, snapshotFromSource, sourceBytes, roundOf } from './snapshot-source.mjs';
import { LIMITS } from './alerts.mjs';
import { myTurn } from './cranks.mjs';

/** Escalating veto priority fees in lamports, each attempt given `VETO_WAIT` seconds to land. */
export const VETO_FEES = [100_000, 1_000_000, 10_000_000, 50_000_000];
export const VETO_WAIT = 12;
/** How long a one-off event (a veto, an unpaid round) stays open as an alert. */
export const EVENT_SECS = 3600;
/** Pass cadence: fast while a distribution is in flight, slow otherwise. */
export const FAST_MS = 5_000, SLOW_MS = 30_000, RETRY_SECS = 30;
/** The Fix's line between the seats (review, 2 October): it needs the slot hash of `SNAP_SLOTS` after
 *  the close, which the slot hashes sysvar keeps for 512 slots (about 205 s) after that slot, and must
 *  land inside the fix window (5 minutes from the close), so the usual TURN_SECS per place (120 s) let no
 *  seat past the second in line ever fix a round. Here each place waits FIX_TURN_SECS more (several fast
 *  passes) and none more than FIX_TURN_CAP, so every seat sends inside both, with room for its
 *  transaction to land; a build with shorter days scales both to its fix window (`fixTurn`). The line
 *  keeps the same order on every relay (an outside one runs this code too, with its own list of ours),
 *  so it is not reordered to put our seats first: two relays would then each think it goes first. */
export const FIX_TURN_SECS = 30, FIX_TURN_CAP = 120;
export const fixTurn = (day = 86_400) => { const w = times(day).fixWindow; return { wait: Math.min(FIX_TURN_SECS, w / 10), cap: Math.min(FIX_TURN_CAP, w * 0.4) }; };
/** Published rounds and private seat records kept on disk. */
export const KEEP_ROUNDS = 5 * 48;

const hex = b => Buffer.from(b).toString('hex');
const b58 = k => (k.publicKey ?? k).toBase58?.() ?? String(k);
function atomic(path, bytes, mode) {
  const tmp = `${path}.${randomBytes(4).toString('hex')}.tmp`;
  writeFileSync(tmp, bytes, mode ? { mode } : {}); renameSync(tmp, path);
}

/**
 * A seat's files. `dir` is published (GET /v2/snapshots serves `n.json`, `source-n.json` and
 * `evidence-n.json`); `state` is private (mode 0700): the salt of each commit lives there until its
 * reveal, the round's files are staged there until commits close, and the seat's events. The dataset
 * is written last, so its presence means a complete round.
 */
export function seatStore(dir, state = join(dir, '.seat')) {
  mkdirSync(dir, { recursive: true, mode: 0o755 }); mkdirSync(state, { recursive: true, mode: 0o700 });
  const rec = n => join(state, `seat-${n}.json`), read = (p, d) => { try { return JSON.parse(readFileSync(p, 'utf8')); } catch { return d; } };
  const names = n => [`source-${n}.json`, `evidence-${n}.json`, `${n}.json`], bytes = p => { try { return readFileSync(p); } catch { return null; } };
  return {
    dir, state,
    record: n => read(rec(n), { epoch: n }),
    save: (n, r) => atomic(rec(n), JSON.stringify(r), 0o600),
    /** Source, evidence, then the dataset, kept private. */
    stage(n, source, evidence, dataset) {
      const [s, e, d] = names(n).map(f => join(state, `stage-${f}`));
      atomic(s, sourceBytes(source), 0o600); atomic(e, JSON.stringify(evidence) + '\n', 0o600); atomic(d, dataset, 0o600);
    },
    /** Moves a staged round to the published directory, the dataset last; a copy, so `state` may sit
     *  on another filesystem. The staged dataset, whose presence alone makes a later pass publish
     *  again, is removed first, so a stop between the removals never leaves it without its source; a
     *  staged file an interrupted earlier publish already removed is published already, and is kept
     *  (review, 30 September: one stop between the removals made every later pass throw). */
    publish(n) {
      const staged = f => join(state, `stage-${f}`), [data] = names(n).slice(-1);
      if (!existsSync(staged(data))) return;
      for (const f of names(n)) if (existsSync(staged(f)) || !existsSync(join(dir, f))) atomic(join(dir, f), readFileSync(staged(f)));
      for (const f of [data, ...names(n).slice(0, -1)]) try { unlinkSync(staged(f)); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    },
    dataset: n => bytes(join(dir, `${n}.json`)) ?? bytes(join(state, `stage-${n}.json`)),
    source: n => read(join(dir, `source-${n}.json`), null) ?? read(join(state, `stage-source-${n}.json`), null),
    events: () => read(join(state, 'events.json'), []),
    event(e) { const all = this.events(); all.push(e); atomic(join(state, 'events.json'), JSON.stringify(all.slice(-200)), 0o600); },
    /** Drops what is `keep` rounds older than `n`: public files and private records. */
    prune(n, keep = KEEP_ROUNDS) {
      for (const [d, re] of [[dir, /^(?:source-|evidence-)?(\d+)\.json$/], [state, /^(?:seat-|stage-(?:source-|evidence-)?)(\d+)\.json$/]])
        for (const f of readdirSync(d)) { const m = re.exec(f); if (m && Number(m[1]) + keep < n) unlinkSync(join(d, f)); }
    },
  };
}

/** GET /v2/snapshots?epoch=n[&source=1|&evidence=1] from a seat's published directory (§5.2), as
 *  relay-server answers it; a dataset or source the seat pruned (KEEP_ROUNDS) from `archive`, our
 *  archive of paid rounds (review round 10). Returns { status, body }. */
export function snapshotFile(dir, query, archive = null) {
  const q = new URLSearchParams(query), epoch = Number(q.get('epoch'));
  if (!q.has('epoch') || !Number.isSafeInteger(epoch) || epoch < 0) return { status: 400, body: { error: 'invalid epoch' } };
  const prefix = q.get('source') === '1' ? 'source-' : q.get('evidence') === '1' ? 'evidence-' : '';
  for (const d of [dir, prefix === 'evidence-' ? null : archive].filter(Boolean))
    try { return { status: 200, body: { base64: readFileSync(join(d, `${prefix}${epoch}.json`)).toString('base64') } }; } catch {}
  return { status: 404, body: { error: 'snapshot data not published' } };
}
/** Hosts a seat never fetches from: loopback, private, link-local and other local names, and any IP
 *  literal (a relay registers a name). A registered URL is anyone's to set, so it must not turn our
 *  seats into a client of our own services (29 September review). */
const localHost = h => h === 'localhost' || /\.(localhost|local|internal)$/.test(h) || /^\[.*\]$/.test(h) || /^\d+(\.\d+){3}$/.test(h) || !h.includes('.');
/**
 * Epoch `n`'s file (`part` '' for the dataset, 'source' or 'evidence') from a relay's `/v2/snapshots`
 * at `base` (its registered URL): HTTPS to a public name, no redirects, the body capped at
 * `BODY_LIMIT` (29 September review). `local` admits loopback over HTTP, for tests and an operator's
 * own relay only.
 */
export async function fetchSnapshotFile(base, n, { part = '', fetch = globalThis.fetch, timeoutMs = 15_000, local = false } = {}) {
  const u = new URL('/v2/snapshots', base); u.searchParams.set('epoch', String(n)); if (part) u.searchParams.set(part, '1');
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (local ? u.protocol !== 'https:' && !loopback : u.protocol !== 'https:' || localHost(u.hostname)) throw Error(`snapshot source ${u.host} is not a public HTTPS host`);
  const r = await fetch(u, { signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
  if (!r.ok) throw Error(`${u.host} has no ${part || 'dataset'} for epoch ${n} (${r.status})`);
  return snapshotBody(r);
}
/** The registered URLs of the seats whose stance is result `hash` of epoch `n`: its revealers, while
 *  their stances are unsettled. */
export async function revealers(c, n, hash) {
  const seats = (await c.all(TAG.ATTESTOR)).filter(a => a.stance.epoch1 === n + 1 && a.stance.hash.equals(hash));
  const relays = new Map((await c.all(TAG.RELAYER)).map(r => [r.key, r.url]));
  return seats.map(a => ({ relay: a.relay, url: relays.get(a.relay) || null }));
}
/**
 * Candidate `cand`'s dataset from the first of its revealers (then `extra` bases, our archive last)
 * whose bytes match its commitment: parsed, with the base it came from. Null when none serves it.
 */
export async function candidateDataset(c, cand, { extra = [], fetch } = {}) {
  const bases = [...(await revealers(c, cand.epoch, cand.hash)).map(r => r.url).filter(Boolean), ...extra];
  for (const base of bases) {
    try {
      const bytes = await fetchSnapshotFile(base, cand.epoch, { fetch });
      if (!sha256(bytes).equals(cand.dataset)) continue;
      const s = parseSnapshot(c, bytes);
      if (s.result.equals(cand.hash)) return { snapshot: s, from: base };
    } catch {}
  }
  return null;
}
/** The registered URLs of every seat, in any state. */
export async function seatUrls(c) {
  const relays = new Map((await c.all(TAG.RELAYER)).map(r => [r.key, r.url]));
  return [...new Set((await c.all(TAG.ATTESTOR)).map(a => relays.get(a.relay)).filter(Boolean))];
}
/**
 * Epoch `n`'s dataset whose result is `hash`, with its source when that hashes to the dataset's
 * `sourceHash`: from `dir` (our archive, or a seat's own directory), then the result's revealers
 * while their stances are unsettled, then every seat, then `extra` (snapshot-spec §5.2: every
 * revealer, hash-checked; review round 10). Null when nobody serves it.
 */
export async function servedDataset(c, n, hash, { dir = null, extra = [], fetch = globalThis.fetch } = {}) {
  const read = (base, part) => fetchSnapshotFile(base, n, { part, fetch, timeoutMs: 30_000 });
  const tries = dir ? [part => readFileSync(join(dir, `${part ? `${part}-` : ''}${n}.json`))] : [];
  const bases = [...new Set([...(await revealers(c, n, hash)).map(r => r.url).filter(Boolean), ...await seatUrls(c), ...extra])];
  for (const base of bases) tries.push(part => read(base, part));
  for (const get of tries) {
    try {
      const dataset = await get(''), s = parseSnapshot(c, dataset);
      if (!s.result.equals(hash)) continue;
      const source = await Promise.resolve().then(() => get('source')).catch(() => null);
      return { dataset, source: source && sha256(source).toString('hex') === s.sourceHash ? JSON.parse(source.toString('utf8')) : null };
    } catch {}
  }
  return null;
}
/**
 * `c.snapshotSource` for a relay or cranker: the armed result's dataset from `dir` (a seat's own),
 * else from any seat that serves it, else `base`; never bytes of another result (review round 10).
 */
export function armedSnapshotSource(c, { dir = null, base = null, fetch } = {}) {
  if (base && new URL(base).protocol !== 'https:') throw Error('snapshot source requires HTTPS');
  return async epoch => {
    const armed = (await c.book())?.armed;
    if (!armed) throw Error(`epoch ${epoch} has no armed result`);
    const found = await servedDataset(c, epoch, armed, { dir, extra: base ? [base] : [], fetch });
    if (!found) throw Error(`no seat serves epoch ${epoch}'s armed dataset`);
    return found.dataset;
  };
}
/** Holder by holder, how dataset `b` differs from `a`: owners only one lists, and shared owners whose
 *  balance differs. */
export function datasetDiff(a, b) {
  const ma = new Map(a.entries.map(e => [e.owner, e.weight])), mb = new Map(b.entries.map(e => [e.owner, e.weight]));
  const d = { missing: [], extra: [], weight: [] };
  for (const [o, w] of ma) if (!mb.has(o)) d.missing.push(o); else if (mb.get(o) !== w) d.weight.push({ owner: o, ours: w, theirs: mb.get(o) });
  for (const o of mb.keys()) if (!ma.has(o)) d.extra.push(o);
  d.slot = a.slot === b.slot ? null : { ours: a.slot, theirs: b.slot };
  return d;
}
const diffText = d => [d.slot && `slot ${d.slot.theirs} (ours ${d.slot.ours})`, d.missing.length && `${d.missing.length} of our holders missing`,
  d.extra.length && `${d.extra.length} holders we do not have`, d.weight.length && `${d.weight.length} balances differ (first ${d.weight[0].owner}: ours ${d.weight[0].ours}, theirs ${d.weight[0].theirs})`]
  .filter(Boolean).join('; ') || 'no holder difference: pot, fee or reserve parameters differ';

/** The slot of the newest entry in the SlotHashes sysvar: `Fix` can draw once it reaches the target. */
async function newestHashed(c) {
  const a = await c.t.getAccount(SYSVAR_SLOT_HASHES_PUBKEY);
  return a && a.data.length >= 16 && a.data.readBigUInt64LE(0) > 0n ? Number(a.data.readBigUInt64LE(8)) : -1;
}
/** Whether the admission rate lets one more new seat activate at `now` (snapshots.rs `admit`); a seat
 *  that was active before returns outside it (owner, 29 September). */
/** Whether the chain's own clock is past `commitEnd`, never the host's: a host clock ahead of the
 *  cluster's would publish our dataset while copiers can still commit to it (review round 3). A
 *  transport that cannot tell the chain's time says no; the next pass tries again. */
export async function commitsClosed(t, commitEnd) {
  const at = t.chainNow ? await t.chainNow() : await t.now();
  return at !== null && at !== undefined && Math.floor(at) >= commitEnd;
}
/** Whether `book` is epoch `e`'s round after its Fix: its snapshot slot lies in the window drawn from
 *  that epoch's close (snapshots.rs `snap_slot`). A book before the Fix, or of another round, is not. */
export const ofRound = (book, e) => !!book?.commitEnd && book.snapSlot >= e.closeSlot && book.snapSlot < e.closeSlot + SNAPSHOT.SNAP_SLOTS;
export function admits(book, now, day) {
  const count = book.admDay === Math.floor(now / day) ? book.admCount : 0;
  return count < Math.max(1, Math.floor(book.active / 4));
}

/**
 * One pass of `relay`'s seat. Options:
 *   store      seatStore of this seat (required);
 *   ours       relay keys of the operator's own seats: any other active seat pages once, as an
 *              outside seat (acknowledge it by adding it to `known`);
 *   compute    (c, { epoch, slot }) → { source, evidence } | null: the canonical source (default the
 *              JSON-RPC capture; tests pass their own);
 *   vetoFees, vetoWait, vetoTransport: the veto's escalation (defaults above; a fresh short-lived
 *              RpcTransport on the seat's RPC);
 *   pay        false leaves payment to the crank that runs beside the seat;
 *   archive    extra bases to fetch other candidates' datasets from (our archive);
 *   float      alarm level of the relay wallet: the operator wallets' (0.1 SOL), below the float setup
 *              funds under 0.2 SOL (review round 10); the bond is held by the program, not the wallet.
 * Returns { done: [step names], alerts: [{ rule, key, message }] }. Steps that fail are logged and
 * alerted, never thrown: a seat's pass must not stop the relay's crank.
 */
export async function seatPass(c, relay, { store, ours = [], known = [], compute = captureSource, vetoFees = VETO_FEES, vetoWait = VETO_WAIT, vetoTransport, pay = true,
  float = LIMITS.floatLamports, fetch, archive = [], log = () => {}, turns = null } = {}) {
  if (!store) throw Error('a seat needs its snapshot store');
  const me = b58(relay), done = [], alerts = [], day = c.day ?? 86_400, T = times(day);
  const alert = (rule, key, message) => alerts.push({ rule, key: `${rule}:${key}`, message });
  // A step another relay raced to first (`raced` says so after the failure) is no alert.
  const step = async (name, f, raced = async () => false) => {
    try { const r = await f(); done.push(name); log(name); return r ?? true; }
    catch (e) { log(`${name}: ${e.message.split('\n')[0]}`); if (!await raced().catch(() => false)) alert('seat-step-failed', name, `${me}: ${name} failed: ${e.message.split('\n')[0]}`); return false; }
  };
  const now = Math.floor(await c.t.now());
  let [cfg, book, seat] = await Promise.all([c.config(), c.book(), c.attestor(relay.publicKey)]);

  // ---- the seat itself ----------------------------------------------------------------------------
  const lamports = (await c.t.getAccount(relay.publicKey))?.lamports ?? 0;
  if (lamports < float) alert('seat-float', me, `seat relay ${me} holds ${(lamports / 1e9).toFixed(4)} SOL, under its ${(float / 1e9).toFixed(2)} SOL float`);
  if (!seat) {
    // Join needs relay work credited in the last CREDIT_EVERY work keys (the program's check). Until
    // the relay has it nobody can act, so it only logs: the cutover runs --attest before our seats
    // can join (review round 10).
    const w = (await c.maybe(c.relayerAddress(relay.publicKey), decodeRelayer))?.work[0];
    if (w?.units > 0 && w.epoch + SNAPSHOT.CREDIT_EVERY >= cfg.workKey) alert('seat-missing', me, `relay ${me} holds no attestor seat: join it (snapshot-rewards.mjs join)${cfg.setup !== '11111111111111111111111111111111' ? ', or, before FinishSetup, have the setup key seat it active at once (snapshot-rewards.mjs genesis)' : ''}`);
    else log(`relay ${me} holds no attestor seat and cannot join until it has relay work credited in the last ${SNAPSHOT.CREDIT_EVERY} epochs`);
  } else if (seat.state === 'pending' || seat.state === 'pruned') {
    if (seat.state === 'pruned') alert('seat-pruned', me, `seat ${me} was pruned (none of its last ${SNAPSHOT.PARTICIPATION} rounds paid its result); it may activate again after ${new Date(seat.until * 1000).toISOString()}`);
    const ripe = seat.state === 'pending' ? now >= seat.joined + T.maturity : now >= seat.until;
    // A pruned seat returns outside the daily admissions (owner, 29 September), on the bond frozen at
    // its Join (owner, 30 September).
    if (ripe && book && (seat.state === 'pruned' || admits(book, now, day)) && await step(`activate seat ${me}`, () => activateSeat(c, relay))) seat = await c.attestor(relay.publicKey);
  }
  if (book) {
    if (cfg.mint !== '11111111111111111111111111111111' && book.active < SNAPSHOT.MIN_SEATS)
      alert('seats-short', 'book', `${book.active} active attestor seat${book.active === 1 ? '' : 's'}: under ${SNAPSHOT.MIN_SEATS}, holder income waits in the carry`);
    const mine = new Set([...ours, ...known, me]);
    for (const a of await c.all(TAG.ATTESTOR)) if (a.state === 'active' && !mine.has(a.relay)) alert('outside-seat', a.relay, `outside attestor seat ${a.relay} is active (${book.active} active, quorum ${quorum(book.active)})`);
  }

  // ---- rounds that ended since the last pass ------------------------------------------------------
  for (const f of readdirSync(store.state)) {
    const m = /^seat-(\d+)\.json$/.exec(f); if (!m) continue;
    const n = Number(m[1]), r = store.record(n);
    // Over only by a book no older than the one that tied the record to its round: a later round
    // began, or this one ended and nothing replaced it. A config or book read from a node behind the
    // round never publishes it while commits are open (review round 8).
    if (r.ended || n === cfg.distributing || !book || r.dists === undefined || !(book.dists > r.dists || (book.dists === r.dists && !book.deadline))) continue;
    store.publish(n);
    const paid = verdictOf(book, n);
    if (vetoedOf(book, n)) store.event({ at: now, rule: 'round-unpaid', key: n, message: `epoch ${n} was vetoed (result ${hex(vetoedOf(book, n))}): its pot went to the carry` });
    else if (!paid) store.event({ at: now, rule: 'round-unpaid', key: n, message: `epoch ${n} ended unpaid (no result armed in time, or left unpaid): its pot went to the carry` });
    else if (r.result && hex(paid) !== r.result) store.event({ at: now, rule: 'paid-differs', key: n, message: `epoch ${n} paid result ${hex(paid)}, not ours ${r.result}` });
    store.save(n, { ...r, ended: now });
    store.prune(n);
  }
  for (const e of store.events()) if (now < e.at + EVENT_SECS) alert(e.rule, e.key, e.message);

  // ---- the distribution in flight -----------------------------------------------------------------
  if (cfg.distributing === null || !book) return { done, alerts };
  const n = cfg.distributing, e = await c.read(c.epochAddress(n), decodeEpoch);
  const eligible = seat?.state === 'active' && seat.seated < book.dists;
  let r = store.record(n);
  const save = patch => { r = { ...r, ...patch }; store.save(n, r); };
  // 1. Fix.
  if (!book.commitEnd) {
    // Taken in turn with the other seats (cranks.mjs myTurn), on the Fix's short line: only one of them
    // fixes a round, and any of them in time.
    const seats = (await c.all(TAG.ATTESTOR)).filter(a => a.state === 'active').map(a => a.relay), fix = fixTurn(day);
    if (now < book.deadline && await newestHashed(c) >= e.closeSlot + SNAPSHOT.SNAP_SLOTS && (!turns || myTurn(`fix epoch ${n}`, me, seats, now, turns.seen, fix.wait, fix.cap)) && await step(`fix epoch ${n}`, () => fixSnapshot(c, relay), async () => !!(await c.book()).commitEnd)) book = await c.book();
    if (!book.commitEnd) book = await c.book();
    if (!book.commitEnd) return { done, alerts };
  }
  // A book read from a node still on an earlier round is not this round's: the next pass reads again.
  if (!ofRound(book, e)) return { done, alerts };
  if (r.dists !== book.dists) save({ dists: book.dists });
  // 2. Compute: needed to commit, and to check the others even after a missed commit.
  const round = { mint: cfg.mint, ...roundOf(e, book) };
  let s = null;
  const bytes = store.dataset(n);
  if (bytes) {
    try { s = parseSnapshot(c, bytes); if (s.epoch !== n || s.slot !== book.snapSlot) s = null; } catch { s = null; }
  }
  // A failed capture is retried at most every RETRY_SECS: each costs a token-program scan.
  if (!s && !(r.failedAt && now < r.failedAt + RETRY_SECS)) {
    try {
      const got = await compute(c, { epoch: n, slot: book.snapSlot });
      if (got) {
        s = snapshotFromSource(c, got.source, round);
        store.stage(n, got.source, got.evidence ?? {}, s.bytes);
        save({ slot: s.slot, result: hex(s.result), dataset: hex(s.dataset), computed: now, failed: null, failedAt: null });
        done.push(`compute epoch ${n}`); log(`compute epoch ${n}: ${s.count} holders, result ${hex(s.result)}`);
      }
    } catch (err) {
      save({ failed: err.message.split('\n')[0], failedAt: now });
      log(`compute epoch ${n}: ${r.failed}`);
      alert(/invariant/.test(err.message) ? 'invariant-failed' : 'compute-failed', n, `epoch ${n}: our snapshot at slot ${book.snapSlot} failed: ${r.failed}. This seat neither commits nor vetoes it`);
    }
  }
  // 3. Commit, the salt on disk first.
  const committed = seat?.commit.epoch1 === n + 1;
  if (eligible && !committed && now < book.commitEnd && s) {
    const salt = r.salt ? Buffer.from(r.salt, 'hex') : newSalt();
    if (!r.salt) save({ salt: hex(salt) });
    if (await step(`commit epoch ${n}`, () => commitSnapshot(c, relay, s, salt))) seat = await c.attestor(relay.publicKey);
  } else if (eligible && !committed && now >= book.commitEnd) {
    if (!r.late) save({ late: now });
    alert('commit-missed', n, `seat ${me} did not commit to epoch ${n}${r.failed ? `: ${r.failed}` : s ? '' : ': its snapshot was not ready'}`);
  }
  // 4. Reveal: only what this seat committed to.
  if (eligible && seat.commit.epoch1 === n + 1 && seat.stance.epoch1 !== n + 1 && now >= book.commitEnd && now < book.revealEnd && s && r.salt) {
    if (!commitHash({ relay: relay.publicKey, epoch: n, result: s.result, salt: Buffer.from(r.salt, 'hex') }).equals(seat.commit.hash))
      alert('commit-lost', n, `seat ${me}: its commit for epoch ${n} does not open with the result and salt on disk; it cannot reveal`);
    else await step(`reveal epoch ${n}`, () => revealSnapshot(c, relay, s, Buffer.from(r.salt, 'hex')));
  }
  book = await c.book();
  // Commits are closed: the round's files go public for the others to check (step 6). Only by a book
  // of this round after its Fix: one read from a node behind the Fix says commitEnd 0, which is not
  // "closed" (review round 8).
  if (ofRound(book, e) && await commitsClosed(c.t, book.commitEnd)) store.publish(n);
  // 5. Veto only on a proven mismatch, before anything slow.
  if (book.armed && s && !book.armed.equals(s.result) && s.slot === book.snapSlot && !r.vetoed) {
    const why = !eligible ? 'this seat is not eligible for the round' : seat.credit < 1 ? 'this seat has no veto credit' : seat.stance.epoch1 === n + 1 && seat.stance.hash.equals(book.armed) ? 'this seat revealed it'
      : now >= book.ready ? 'the checking delay is over' : e.leavesPaid > 0 ? 'payment has begun' : null;
    if (why) alert('veto-impossible', n, `epoch ${n}: armed result ${hex(book.armed)} differs from ours ${hex(s.result)}, and ${why}`);
    else {
      const sig = await veto(c, relay, n, book.armed, { fees: vetoFees, wait: vetoWait, transport: vetoTransport, log });
      save({ vetoed: sig ? now : null });
      store.event({ at: now, rule: sig ? 'veto-sent' : 'veto-failed', key: n, message: sig ? `seat ${me} vetoed epoch ${n}'s armed result ${hex(book.armed)} (ours ${hex(s.result)}): ${sig}`
        : `seat ${me} could not land its veto of epoch ${n}'s armed result ${hex(book.armed)} in time` });
      if (sig) done.push(`veto epoch ${n}`);
      const ev = store.events().at(-1); alert(ev.rule, ev.key, ev.message);
    }
  }
  // 6. Verify the other candidates.
  const cands = (await c.all(TAG.CANDIDATE)).filter(k => k.epoch === n);
  for (const k of cands) {
    if (s && k.hash.equals(s.result)) continue;
    if (!s) { if (book.armed?.equals(k.hash)) alert('armed-unverified', n, `epoch ${n}: result ${hex(k.hash)} is armed and this seat has no snapshot of its own to check it: no veto`); continue; }
    if (!r.checked?.[hex(k.hash)]) {
      const theirs = await candidateDataset(c, k, { extra: archive, fetch });
      save({ checked: { ...r.checked, [hex(k.hash)]: theirs ? diffText(datasetDiff(s, theirs.snapshot)) : 'dataset not served by its revealers' } });
    }
    alert('candidate-differs', `${n}:${hex(k.hash)}`, `epoch ${n}: candidate ${hex(k.hash)} (${k.signers} signer${k.signers === 1 ? '' : 's'}) differs from ours ${hex(s.result)}: ${r.checked[hex(k.hash)]}`);
  }
  // 7. Confirm and pay.
  if (book.armed && s && book.armed.equals(s.result)) {
    if (!r.confirmed) save({ confirmed: now });
    if (pay && now >= book.ready && !cfg.pause) await step(`pay epoch ${n}`, () => distributeSnapshot(c, relay, { source: async () => s.bytes }));
  }
  return { done, alerts };
}

/**
 * Archives every paid round the book's verdict ring still names: its dataset (and source, when served)
 * pulled from every seat's registered URL and `extra` bases until one serves bytes whose result is the
 * paid one (snapshot-spec §5.2: from all revealers, not only ours). Returns the epochs archived now.
 */
export async function archiveRounds(c, dir, { extra = [], fetch = globalThis.fetch } = {}) {
  mkdirSync(dir, { recursive: true });
  const book = await c.book(); if (!book) return [];
  const bases = [...new Set([...await seatUrls(c), ...extra])], done = [];
  for (const v of book.verdicts) {
    const n = v.epoch1 - 1; if (v.epoch1 === 0 || v.vetoed || existsSync(join(dir, `${n}.json`))) continue;
    for (const base of bases) {
      try {
        const bytes = await fetchSnapshotFile(base, n, { fetch });
        if (!parseSnapshot(c, bytes).result.equals(v.hash)) continue;
        try {
          const src = await fetchSnapshotFile(base, n, { part: 'source', fetch });
          if (sha256(src).toString('hex') === parseSnapshot(c, bytes).sourceHash) atomic(join(dir, `source-${n}.json`), src);
        } catch {}
        atomic(join(dir, `${n}.json`), bytes); done.push(n); break;
      } catch {}
    }
  }
  return done;
}

/** Sends the veto, escalating its priority fee while the result is still armed and vetoable. Returns
 *  the landed signature, or null. An attempt that did not confirm in time may still land after a
 *  dearer one is sent: every earlier signature is checked before each attempt and at the end, so a
 *  veto that landed is neither escalated past nor reported as failed (29 September review). */
export async function veto(c, relay, n, hash, { fees = VETO_FEES, wait = VETO_WAIT, transport, log = () => {} } = {}) {
  const fast = transport ?? (c.t.url ? new (await import('./transport.mjs')).RpcTransport(c.t.url, { commitment: c.t.commitment, builds: 1, polls: wait }) : c.t);
  const pending = [];
  const landed = async () => {
    for (const sig of pending) if (await Promise.resolve(fast.transaction?.(sig)).then(tx => !!tx && !tx.error, () => false)) return sig;
    return null;
  };
  for (const fee of fees) {
    const early = await landed(); if (early) return early;
    const book = await c.book(), cfg = await c.config();
    if (cfg.distributing !== n || !book.armed?.equals(hash)) return landed();
    try { const sig = await vetoSnapshot(c, relay, n, hash, { priorityFee: fee, transport: fast }); log(`veto epoch ${n} (priority ${fee})`); return sig; }
    catch (err) {
      log(`veto epoch ${n} (priority ${fee}): ${err.message.split('\n')[0]}`);
      if (err.signature && !err.refused) pending.push(err.signature);
      if (err.refused && !err.unsent) return landed();
    }
  }
  return landed();
}

/**
 * Runs `seatPass` every FAST_MS while a distribution is in flight and SLOW_MS otherwise, paging its
 * alerts through `pager(alerts, { resolve })` (alerts.mjs `page` with a Colony notifier). Never throws
 * on a pass; a pass that fails (an RPC error) pages `seat-pass-failed` with the last good pass's alerts
 * and `resolve: false`, so a condition it never re-checked is not reported cleared.
 */
export async function runSeat(c, relay, { stopped = () => false, sleep = ms => new Promise(r => setTimeout(r, ms)), pager = async () => {}, error = () => {}, turns = { seen: new Map() }, ...options } = {}) {
  let last = [];
  for (;;) {
    let fast = false, alerts = [], resolve = true;
    try {
      ({ alerts } = await seatPass(c, relay, { ...options, turns }));
      last = alerts;
      fast = (await c.config()).distributing !== null;
    } catch (e) {
      // An RPC error (or any failure outside a step) is paged, never only logged (owner, 30 September:
      // "Seat software must alert on RPC errors"). The pass re-checked nothing, so the last good pass's
      // alerts are kept and nothing open is resolved.
      const me = relay.publicKey?.toBase58?.() ?? String(relay), why = String(e?.message ?? e).split('\n')[0];
      error(why);
      resolve = false;
      alerts = [...last.filter(a => a.rule !== 'seat-pass-failed'), { rule: 'seat-pass-failed', key: `seat-pass-failed:${me}`, message: `seat ${me}: its pass failed (RPC error?): ${why}` }];
    }
    await pager(alerts, { resolve }).catch(e => error(`paging: ${e.message}`));
    if (stopped()) return;
    await sleep(fast ? FAST_MS : SLOW_MS);
    if (stopped()) return;
  }
}
