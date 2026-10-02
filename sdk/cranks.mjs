// One pass over every time-based step the protocol has. Anyone can run it; none of it needs a
// server of ours. Each step is idempotent and skipped when there is nothing to do.
import { createHash } from 'node:crypto';
import { TAG, times, counted, kickDeadline, decodeEpoch, decodeUpload } from './layout.mjs';
import { expireSnapshot, pruneSeat, prunable, closeCandidate, distributeSnapshot } from './snapshots.mjs';

/** How long a relay that is not first in line for a shared step waits, per place in line, before it does
 *  the step itself (owner, 1 October: both relays paid the same holder batch at once and the loser's
 *  transaction failed, 39 of 90 on devnet). Longer than a relay's crank period (60 s plus up to 15 s of
 *  jitter), so the first in line has had its pass. */
export const TURN_SECS = 120;
const place = (step, key) => createHash('sha256').update(`${step}\n${key}`).digest('hex');
/**
 * Whether relay `me` does the shared `step` now. `relays` are the active seats' relay keys, ordered for
 * this step by sha256(step, key), so no relay is always first; a relay outside them waits behind them
 * all. The first in line goes at once; the n-th once `step` has waited n x `wait` seconds since this
 * relay first saw it due. `seen` is this relay's memory across passes (a Map). A step name that changes
 * with progress starts the wait again, so a relay that stops mid-way is taken over. No place waits more
 * than `cap` seconds: a step that must land within a deadline (a round's Fix) caps the line to it.
 */
export function myTurn(step, me, relays, now, seen, wait = TURN_SECS, cap = Infinity) {
  const rank = rankOf(step, me, relays);
  forget(seen, now);
  if (!seen.has(step)) seen.set(step, now);
  return rank === 0 || now - seen.get(step) >= Math.min(rank * wait, cap);
}
const rankOf = (step, me, relays) => {
  const order = [...new Set(relays)].sort((a, b) => (place(step, a) < place(step, b) ? -1 : 1));
  return order.includes(me) ? order.indexOf(me) : order.length;
};
/** Memory older than a day is forgotten. */
const forget = (seen, now) => { for (const [k, v] of seen) if (now - (v?.at ?? v) > 86_400) seen.delete(k); };
/**
 * Whether relay `me` sends the next payment batch of a round (`step`, one name per round) with the
 * payment cursor at `cursor`; asked before every batch (review, 2 October: a turn drawn once per pass
 * let the other relay's next pass draw again on a moved cursor and race every remaining batch). The
 * relay that last moved the cursor keeps the turn until the round is paid. Every other relay defers while
 * the cursor moves: it waits its place in line x `wait` (at least one `wait`, so the first in line
 * coming back never races the one that took over) since it last saw the cursor move; so when the one
 * paying stops, the next in line takes over after that wait. `paidBatch(step, cursor, now, seen)` records a
 * batch this relay landed (the cursor it left). `seen` is the same Map `myTurn` uses.
 */
export function payTurn(step, me, relays, cursor, now, seen, wait = TURN_SECS) {
  const rank = rankOf(step, me, relays);
  forget(seen, now);
  const was = seen.get(step);
  // A cursor already moved when first seen (this relay restarted mid-round) counts as another's progress.
  if (!was || typeof was !== 'object') seen.set(step, { cursor, at: now, mine: false, moved: cursor > 0 });
  else if (was.cursor !== cursor) seen.set(step, { cursor, at: now, mine: false, moved: true });
  const s = seen.get(step);
  if (s.mine) return true;
  const r = s.moved ? Math.max(1, rank) : rank;
  return r === 0 || now - s.at >= r * wait;
}
export const paidBatch = (step, cursor, now, seen) => seen.set(step, { cursor, at: now, mine: true, moved: true });

const clears = (a, r, of, ab, rb) => of > 0 && a * 10000 > of * ab && r * 10000 < of * rb;
const NONE = '11111111111111111111111111111111';
/** A claim transaction's one signature: a share worth no more than this is never claimed (payout.mjs reports it so). */
export const CLAIM_FEE = 5000;
/** A claim earns no refund: each relay claims only its own share of `e`, and only one worth more than its fee. */
const claimable = (e, w) => w.epoch === e.workKey && w.units > 0 && !w.claimed && Math.floor(e.relayerPool * w.units / Math.max(1, e.work)) > CLAIM_FEE;

/**
 * Whether the program would resolve `p` now (governance.rs `resolve`): its window closed, it clears
 * early on its counted roster (roster ∩ members, owner 29 September D4), or it is void: made before
 * the artifact's last claim, no counted seat left, or its charged agent, applicant or seconded
 * author banned. `banned` is the set of banned ids.
 */
export function resolvable(p, art, now, banned) {
  // The roster never lists the proposer (nor a kick's or ban's target).
  const { approve, reject, seats } = counted(p, art), k = p.payload.kind;
  const voided = p.created < art.claimed || seats === 0 || (p.charged !== NONE && banned.has(p.charged))
    || (k === 'membership' && banned.has(p.payload.agent)) || (k === 'content' && p.seconded && banned.has(p.proposer));
  return { voided, due: now >= p.closes, early: !voided && clears(approve, reject, seats, p.approveBps, p.rejectBps) };
}

/**
 * The pass, in order (cleanup-spec §3 WP-B2, snapshot-spec §6.3, owner 29 September):
 * 1. prune every seat of every banned agent, so resolves see pruned members;
 * 2. expire applications left unanswered past `APPLICATION_TTL`;
 * 3. resolve due, early or void proposals; expire lapsed kick confirmations;
 * 4. snapshot housekeeping: expire a lapsed round, prune silent seats, close the epoch, pay an armed
 *    round (with `source`, else the client's `snapshotSource`), close finished candidates;
 * 5. claim this payer's relayer work, retire epochs, apply global settings, expire uploads.
 * Names of steps that failed are pushed onto `failed`.
 *
 * `selfPay` (default on; owner, 30 September): a housekeeping step the program refuses as an ordinary
 * refunded crank (the vault cannot fund a record, or the payer is no relayer; a self-paid proposal's
 * record never needs it: its escrow repays whoever cranks it) is sent again as self-paid housekeeping: the vault funds what it can, the payer
 * the rest and its own fee, nothing refunded. Governance and epochs never wait on treasury funds.
 * Names of steps run self-paid are pushed onto `selfPaid`.
 *
 * `turns` ({ seen: Map }, kept by the caller across passes): the shared snapshot and epoch steps (close an
 * epoch, pay a round, close a candidate, retire an epoch) are taken in turn between the active seats
 * (`myTurn`; a round's payment batch by batch, `payTurn`), so two relays never send the same one at once. Without it every step goes at once.
 */
export async function crankOnce(c, payer, { log = () => {}, failed = [], source = c.snapshotSource, selfPay = true, selfPaid = [], turns = null } = {}) {
  const now = Math.floor(await c.t.now()), T = times(c.day ?? 86_400), done = [];
  const seats = turns ? (await c.all(TAG.ATTESTOR)).filter(s => s.state === 'active').map(s => s.relay) : [];
  const turn = name => !turns || myTurn(name, payer.publicKey.toBase58(), seats, now, turns.seen);
  // `f(opts)`: tried as an ordinary crank first, then self-paid when the program refused that.
  const step = async (name, f) => {
    try {
      try { await f({}); }
      catch (e) { if (!selfPay || !e.refused) throw e; await f({ selfPaid: true }); selfPaid.push(name); log(`${name}: run self-paid`); }
      done.push(name); log(name); return true;
    } catch (e) { failed.push(name); log(`${name}: ${e.message.split('\n')[0]}`); return false; }
  };
  const agents = await c.all(TAG.AGENT), banned = new Set(agents.filter(a => a.status === 'banned').map(a => a.id));
  let arts = await c.all(TAG.ARTIFACT);
  // 1. A banned member counts on chain until pruned (critic C14); artifact 0 keeps its last member.
  for (const a of arts) {
    let left = a.members.length;
    for (const m of a.members) if (banned.has(m.id) && (a.id !== 0 || left > 1) && await step(`prune ${m.id} from ${a.address}`, o => c.pruneBanned(a.address, m.id, payer, o))) left--;
  }
  // 2. Each member seated before an expired application is charged a skip (D3).
  for (const a of agents) for (const s of a.applications) if (now >= s.at + T.applicationTtl)
    await step(`expire application of ${a.id} to ${s.artifact}`, o => c.expireApplication(s.artifact, a.id, payer, o));
  if (banned.size || agents.some(a => a.applications.length)) arts = await c.all(TAG.ARTIFACT);
  const byAddress = new Map(arts.map(a => [a.address, a]));
  // 3. A kick's window that closed inside a pause lapses a full window after the lift (review round 7).
  const paused = await c.config();
  for (const p of await c.all(TAG.PROPOSAL)) {
    const art = byAddress.get(p.artifact);
    if (p.status === 'voting' && art) {
      // A newcomer's contribution begins its upload with the second: no early verdict until the text has landed.
      const landed = async () => p.payload.kind !== 'content' || (await c.maybe(p.payload.upload, decodeUpload))?.complete;
      const { voided, due, early } = resolvable(p, art, now, banned);
      if (voided || due || (early && await landed())) await step(`resolve ${p.address}`, o => c.resolve(p.address, payer, o));
    }
    if (p.status === 'confirmation_pending' && now >= kickDeadline(paused, p, now)) await step(`expire ${p.address}`, o => c.expire(p.address, payer, o));
  }
  // 4. An epoch closes while a distribution runs (rewards.rs `close_epoch`).
  let cfg = await c.config(), book = await c.book();
  if (cfg.distributing !== null && book && now >= book.deadline) await step(`expire round ${cfg.distributing}`, o => expireSnapshot(c, payer, o));
  // A seat silent, or revealing only unpaid results, for PARTICIPATION rounds (snapshots.rs `Prune`).
  if (book) {
    [cfg, book] = await Promise.all([c.config(), c.book()]);
    for (const s of await c.all(TAG.ATTESTOR)) if (prunable(s, book, cfg.distributing)) await step(`prune seat ${s.relay}`, o => pruneSeat(c, s.relay, payer, o));
  }
  // Due `EPOCH_LEN` after it started (rewards.rs; `times().epoch` for this build).
  if (now >= cfg.epochStart + T.epoch && turn(`close epoch ${cfg.epoch}`)) await step(`close epoch ${cfg.epoch}`, o => c.closeEpoch(payer, o));
  [cfg, book] = await Promise.all([c.config(), c.book()]);
  if (cfg.distributing !== null && book?.armed && now >= book.ready && !cfg.pause && source) {
    // Asked again before every batch (payTurn): the relay paying keeps the turn; each batch another
    // relay lands starts this one's wait again.
    const name = `distribute epoch ${cfg.distributing}`, me = payer.publicKey.toBase58();
    const payNow = !turns ? null : async cursor => payTurn(name, me, seats, cursor, Math.floor(await c.t.now()), turns.seen);
    const landed = !turns ? undefined : async cursor => paidBatch(name, cursor, Math.floor(await c.t.now()), turns.seen);
    const cursor = (await c.maybe(c.epochAddress(cfg.distributing), decodeEpoch))?.leavesPaid ?? 0;
    if (!payNow || await payNow(cursor)) await step(name, o => distributeSnapshot(c, payer, { source, turn: payNow, landed, ...o }));
  }
  const distributing = (await c.config()).distributing;
  for (const k of await c.all(TAG.CANDIDATE)) if (k.epoch !== distributing && turn(`close candidate ${k.address}`)) await step(`close candidate ${k.address}`, o => closeCandidate(c, k.epoch, k.hash, payer, o));
  // 5.
  const me = payer.publicKey.toBase58(), mine = (await c.all(TAG.RELAYER)).filter(r => r.key === me);
  for (const e of await c.all(TAG.EPOCH)) {
    for (const r of mine) for (const w of r.work) if (claimable(e, w)) await step(`claim work ${e.n} for ${r.key}`, () => c.claimWork(e.n, r.key, payer));
    const fresh = await c.maybe(c.epochAddress(e.n), decodeEpoch);
    if (fresh && (await c.config()).distributing !== e.n && (fresh.claimedWork === fresh.work || fresh.relayerPaid === fresh.relayerPool || now >= fresh.end + T.day) && turn(`retire epoch ${e.n}`)) await step(`retire epoch ${e.n}`, o => c.retire(e.n, payer, o));
  }
  cfg = await c.config();
  if (cfg.pending.some(q => q.at <= now)) await step('apply global settings', o => c.applyGlobal(payer, o));
  // A self-paid upload's expiry is never refunded (owner, 30 September): only the payer it returns to cranks it.
  const vault = c.vault.toBase58();
  for (const u of await c.all(TAG.UPLOAD)) if (u.locked === NONE && now >= u.expires && (u.funder === vault || u.funder === me))
    await step(`expire upload ${u.address}`, o => c.expireUpload(u.address, payer, o));
  return done;
}

/**
 * Runs a pass every `every` ms until `once` or `stopped()`; a failed pass is reported, never
 * fatal. Resolves true when the last pass completed without throwing. With `register` ({ kind,
 * url }), a pass first registers the payer as a relayer when it is not one: the program refunds and
 * accepts housekeeping only from a registered relayer, and registering is permissionless (29
 * September review).
 */
export async function runCranker(c, payer, { every = 30_000, once = false, stopped = () => false, sleep = ms => new Promise(r => setTimeout(r, ms)), log = () => {}, error = () => {}, register = null, turns = { seen: new Map() }, ...options } = {}) {
  if (!Number.isFinite(every) || every < 0) throw Error('every must be a non-negative number of milliseconds');
  const pass = async () => {
    if (register && !(await c.raw(c.relayerAddress(payer.publicKey)))) {
      await c.registerRelayer(payer, register); log(`registered ${payer.publicKey.toBase58()} as a relayer`);
    }
    return crankOnce(c, payer, { ...options, turns, log });
  };
  for (;;) {
    let ok = true;
    await pass().catch(e => { ok = false; error(e.message); });
    if (once || stopped()) return ok;
    // Always pace scans, including when work was done, to avoid a busy RPC loop.
    await sleep(every);
    if (stopped()) return ok;
  }
}
