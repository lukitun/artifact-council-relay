// Holder snapshots signed by relays (src/snapshots.rs; snapshot-spec §4–5 with the owner's answers of
// 29 September). A relay may hold an attestor seat. For each epoch being distributed every seat
// builds the canonical dataset at the slot `Fix` drew, commits to its result (salted, bound to its
// key), and reveals it once commits close; quorum(N) identical reveals arm it, any seat holding a veto
// credit may veto it within the checking delay (the round's pot then goes to the carry), and after
// the delay anyone pays it. The seats are trusted, as a quorum, for each snapshot's correctness and
// completeness; Merkle proofs authenticate the committed dataset, not Solana history itself.
//
// A dataset (version 3) lists, in owner order, each holder whose share is paid this round: owner,
// balance and amount. Shares come from every counted balance (at least MIN_HOLDER, ordinary on-curve
// owners, exclusions left out): the pot, less the round's fee reserve and a fee per paid leaf, split
// pro rata by balance. A share under MIN_PAYOUT gets no leaf and stays in the pot, which returns to
// the next round (owner decision, 27 September); so does a leaf the program cannot send when paid.
import { PublicKey, TransactionInstruction, SYSVAR_SLOT_HASHES_PUBKEY } from '@solana/web3.js';
import { sha256, ZERO, decodeEpoch, decodeCandidate, encodeSnapshotOp, leafHash, nodeHash, resultHash, commitHash, verdictOf, vetoedOf, agedOut, SNAPSHOT } from './layout.mjs';
import { randomBytes } from 'node:crypto';
import { snapshotFunds } from './funding.mjs';
const pk = k => new PublicKey(k?.publicKey ?? k);
const meta = (k, writable = true, signer = false) => ({ pubkey: pk(k), isWritable: writable, isSigner: signer });
/** Proof length for `count` leaves padded to a power of two (snapshots.rs `depth`). */
export const depth = count => count <= 1 ? 0 : Math.ceil(Math.log2(count));

/**
 * Pro-rata shares of `pot` (what the round distributes: the epoch's pot less its fee reserve) over
 * every counted balance. Pass one reserves a fee for every counted holder and keeps the shares that
 * reach `minPayout`; pass two splits the pot less a fee for each kept leaf only, so each kept share
 * only grows. Then every amount plus a fee per leaf (at least one) fits, as the program checks.
 */
export function shares({ pot, fee, minPayout, balances }) {
  const total = balances.reduce((s, b) => s + b.weight, 0n);
  if (total === 0n) return { total, leaves: [] };
  const P = BigInt(pot), F = BigInt(fee), M = BigInt(minPayout);
  const first = P - BigInt(balances.length) * F;
  const kept = first > 0n ? balances.filter(b => first * b.weight / total >= M) : [];
  const second = P - BigInt(Math.max(1, kept.length)) * F;
  return { total, leaves: kept.map(b => ({ ...b, amount: second * b.weight / total })) };
}

const u64 = v => { const n = BigInt(v); if (n < 0n || n > 0xffffffffffffffffn) throw Error('value out of u64 range'); return n; };
/** The tree, root, proofs, dataset hash and result hash of a version-3 document (its `entries` in
 *  canonical order). */
function build(c, doc) {
  const entries = doc.entries.map(e => ({ owner: pk(e.owner).toBase58(), weight: u64(e.weight).toString(), amount: u64(e.amount).toString() }));
  for (let i = 0; i < entries.length; i++) {
    if (!PublicKey.isOnCurve(pk(entries[i].owner).toBuffer()) || BigInt(entries[i].weight) === 0n || BigInt(entries[i].amount) === 0n) throw Error('invalid snapshot leaf');
    if (i && Buffer.compare(pk(entries[i - 1].owner).toBuffer(), pk(entries[i].owner).toBuffer()) >= 0) throw Error('snapshot leaves must be unique and in owner order');
  }
  if (entries.length > SNAPSHOT.MAX_LEAVES) throw Error('snapshot bounds');
  if (!entries.length !== (BigInt(doc.weight) === 0n)) throw Error('a snapshot commits weight exactly when it has leaves');
  const amount = entries.reduce((s, e) => s + BigInt(e.amount), 0n), fee = u64(doc.fee), pot = u64(doc.pot), reserve = u64(doc.reserve);
  // snapshots.rs Reveal: every committed share, a fee for every payment there can be, and the round's
  // fee reserve fit the pot.
  if (amount + BigInt(Math.max(1, entries.length)) * fee + reserve > pot) throw Error('snapshot amounts and fees exceed the pot');
  const document = { version: 3, program: c.program.toBase58(), mint: pk(doc.mint).toBase58(), epoch: doc.epoch, slot: doc.slot, sourceHash: doc.sourceHash ?? null,
    pot: pot.toString(), reserve: reserve.toString(), fee: fee.toString(), minPayout: u64(doc.minPayout).toString(), minHolder: u64(doc.minHolder).toString(),
    weight: BigInt(doc.weight).toString(), entries };
  if (!Number.isSafeInteger(document.epoch) || document.epoch < 0 || !Number.isSafeInteger(document.slot) || document.slot < 0) throw Error('snapshot bounds');
  const bytes = Buffer.from(JSON.stringify(document) + '\n');
  const leaf = (e, i) => leafHash({ program: c.program, mint: document.mint, epoch: document.epoch, slot: document.slot, index: i, owner: e.owner, weight: e.weight, amount: e.amount });
  let level = entries.map(leaf);
  const width = 2 ** depth(entries.length);
  while (level.length < width) level.push(ZERO);
  const levels = [level];
  while (level.length > 1) { const next = []; for (let i = 0; i < level.length; i += 2) next.push(nodeHash(level[i], level[i + 1])); levels.push(next); level = next; }
  const s = { ...document, bytes, dataset: sha256(bytes), weight: BigInt(document.weight), amount, count: entries.length, root: entries.length ? level[0] : ZERO,
    proof(index) {
      if (!Number.isInteger(index) || index < 0 || index >= entries.length) throw Error('snapshot index');
      const out = []; for (let i = 0; i < levels.length - 1; i++) { out.push(levels[i][index ^ 1]); index = Math.floor(index / 2); } return out;
    } };
  s.result = resultHash({ program: c.program, mint: s.mint, epoch: s.epoch, slot: s.slot, root: s.root, dataset: s.dataset, weight: s.weight, amount: s.amount, count: s.count });
  return s;
}
/** Builds the dataset for `balances` ([{ owner, weight }], each owner once): counted balances, shares,
 *  leaves. `pot`, `reserve` and `fee` are the round's (snapshot-source.mjs `roundOf`). */
export function makeSnapshot(c, { mint, epoch, slot, pot, reserve = 0, fee, minPayout, minHolder = 0, balances, sourceHash = null }) {
  const seen = new Set(), floor = BigInt(minHolder) > 0n ? BigInt(minHolder) : 1n;
  const counted = balances.map(({ owner, weight }) => {
    owner = pk(owner).toBase58(); weight = u64(weight);
    if (seen.has(owner)) throw Error('duplicate snapshot owner'); seen.add(owner);
    if (!PublicKey.isOnCurve(pk(owner).toBuffer())) throw Error('snapshot owners are ordinary wallets');
    return { owner, weight };
  }).filter(b => b.weight >= floor).sort((a, b) => Buffer.compare(pk(a.owner).toBuffer(), pk(b.owner).toBuffer()));
  const { total, leaves } = shares({ pot: u64(pot) - u64(reserve), fee, minPayout, balances: counted });
  // No paid leaf commits no weight, whatever the holders held (snapshots.rs Reveal: count 0 is weight 0).
  return build(c, { mint, epoch, slot, sourceHash, pot, reserve, fee, minPayout, minHolder, weight: leaves.length ? total : 0n, entries: leaves });
}
/** Parsed datasets by program and dataset hash (review round 9): a seat passes every FAST_MS in the
 *  relay's own process and a crank on every pass, so a round's dataset is parsed (a synchronous
 *  rebuild of every leaf and the tree) once, not on each. The last few only; callers never mutate. */
const PARSED = new Map(), KEEP_PARSED = 4;
export function parseSnapshot(c, bytes) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  const id = `${c.program.toBase58()}:${sha256(bytes).toString('hex')}`, hit = PARSED.get(id);
  if (hit) return hit;
  const d = JSON.parse(bytes.toString('utf8'));
  if (d.version !== 3 || d.program !== c.program.toBase58()) throw Error('snapshot domain mismatch');
  const snapshot = build(c, d);
  if (!snapshot.bytes.equals(bytes)) throw Error('snapshot is not canonical');
  PARSED.set(id, snapshot);
  if (PARSED.size > KEEP_PARSED) PARSED.delete(PARSED.keys().next().value);
  return snapshot;
}

// ---- instructions (family 5) --------------------------------------------------------------------
/** `op.selfPaid`: self-paid housekeeping (owner, 30 September): no refund from the reserve or the pot. */
async function send(c, op, extra, payer, signers = []) {
  return c.send([new TransactionInstruction({ programId: c.program, data: encodeSnapshotOp(op), keys: [...await c.prefix(payer), ...extra] })], payer, signers);
}
const distributing = async c => { const n = (await c.config()).distributing; if (n === null) throw Error('no distribution is running'); return n; };
/** Takes a seat for `relay`, or tops one not active (pending, pruned or leaving) up to the current bond. The bond and
 *  the seat's rent come from `funder` (a co-signer that gets them back on withdrawal: the deployer
 *  funds our two seats, owner 29 September), else from the relay. The relay must have credited work
 *  in the last 48 work keys. */
export function joinSeat(c, relay, { funder } = {}) {
  return send(c, { type: 'join' }, [meta(c.bookAddress), meta(c.attestorAddress(relay.publicKey)), ...(funder ? [meta(funder.publicKey, true, true)] : [])], relay, funder ? [funder] : []);
}
/** Before FinishSetup only (owner, 30 September: holders are paid from the first day): the setup key
 *  seats the registered relay `relay`, active at once, outside the daily admissions, with its first veto
 *  credit. The setup key pays the seat's rent and the bond, and gets them back on the seat's withdrawal,
 *  and the book's rent on the first seat, which it never gets back (no instruction closes the book).
 *  After FinishSetup every seat joins with `joinSeat` and matures for 7 days. */
export function genesisSeat(c, setupKey, relay) {
  const r = pk(relay);
  return c.setup({ type: 'seat', relay: r }, [c.bookAddress, c.attestorAddress(r), c.relayerAddress(r)], setupKey);
}
/** `genesisSeat` for several relays, all or nothing up front: every relay is checked before anything is
 *  sent, so a refusal (setup finished, not the setup key, no mint, not registered) seats nobody. A relay
 *  that already holds a seat is skipped, so the same command reruns after a partial run. Returns one
 *  entry per relay: `{ relay, signature }` or `{ relay, skipped }`. */
export async function genesisSeats(c, setupKey, relays) {
  const keys = [...new Set(relays.map(r => pk(r).toBase58()))].map(k => new PublicKey(k)), plan = [];
  for (const relay of keys) {
    const seat = await c.attestor(relay);
    if (seat) { plan.push({ relay, skipped: `already holds a seat (${seat.state})` }); continue; }
    const q = await snapshotFunds(c, 'genesis', { payer: setupKey.publicKey, relay });
    if (q.refused) throw Error(`${relay.toBase58()}: ${q.reason}; nothing was sent`);
    plan.push({ relay });
  }
  const out = [];
  for (const p of plan) out.push(p.skipped ? { relay: p.relay.toBase58(), skipped: p.skipped } : { relay: p.relay.toBase58(), signature: await genesisSeat(c, setupKey, p.relay) });
  return out;
}
/** Once `MATURITY` has passed since joining, within the admission rate, with a first veto credit; or `REJOIN` after a prune or a
 *  leave within `UNBOND`, outside it, with the credits it had (review round 3). */
export const activateSeat = (c, relay) => send(c, { type: 'activate' }, [meta(c.bookAddress), meta(c.attestorAddress(relay.publicKey))], relay);
export const leaveSeat = (c, relay) => send(c, { type: 'leave' }, [meta(c.bookAddress), meta(c.attestorAddress(relay.publicKey))], relay);
/** After `UNBOND`: the bond and rent return to whoever funded the seat. */
export async function withdrawSeat(c, relay) {
  const a = await c.attestor(relay.publicKey); if (!a) throw Error('no seat');
  return send(c, { type: 'withdraw' }, [meta(c.bookAddress), meta(c.attestorAddress(relay.publicKey)), ...(a.funder !== relay.publicKey.toBase58() ? [meta(a.funder)] : [])], relay);
}
/** Whether anyone may prune seat `s` (snapshots.rs `prunable`): active, and none of its last
 *  `PARTICIPATION` distributions over paid its result, silent and revealing rounds counted alike
 *  (owner, 29 September: junk-revealing seats; one count since review round 3), an unsettled stance
 *  whose round is over counted; a vetoed armed result counts neither way (29 September review), nor
 *  does a stance whose epoch aged out of the ring (snapshot-spec 4.7; review, 30 September). */
export function prunable(s, book, distributing) {
  if (s.state !== 'active') return false;
  const m = s.stance.epoch1, over = m !== 0 && m - 1 !== distributing, paid = over && !!verdictOf(book, m - 1)?.equals(s.stance.hash);
  const pending = over && !paid && !vetoedOf(book, m - 1)?.equals(s.stance.hash) && !agedOut(book, m - 1);
  const silent = Math.max(0, book.dists - s.partDist - (distributing !== null ? 1 : 0));
  return (paid ? 0 : s.unpaid) + (pending ? 1 : 0) + silent >= SNAPSHOT.PARTICIPATION;
}
/** Anyone: an active seat that is `prunable` loses its place. */
export const pruneSeat = (c, relay, payer, { selfPaid } = {}) => send(c, { type: 'prune', selfPaid }, [meta(c.bookAddress), meta(c.attestorAddress(relay))], payer);
/** Anyone registered, once the slot `SNAP_SLOTS` after the close has a slot hash: draws the snapshot slot. */
export async function fixSnapshot(c, payer, { selfPaid } = {}) {
  return send(c, { type: 'fix', selfPaid }, [meta(c.bookAddress), meta(c.epochAddress(await distributing(c))), meta(SYSVAR_SLOT_HASHES_PUBKEY, false)], payer);
}
/** A fresh salt for a seat's commit: the seat keeps it until it reveals. */
export const newSalt = () => randomBytes(32);
/** Commits `relay`'s seat to snapshot `s` with `salt`; nobody learns the result until it reveals. */
export function commitSnapshot(c, relay, s, salt) {
  const commit = commitHash({ relay: relay.publicKey, epoch: s.epoch, result: s.result, salt });
  return send(c, { type: 'commit', commit }, [meta(c.bookAddress), meta(c.epochAddress(s.epoch)), meta(c.attestorAddress(relay.publicKey))], relay);
}
/** Reveals the committed result once commits close; the first revealer of a result pays its candidate
 *  account and gets it back on `closeCandidate`. */
export function revealSnapshot(c, relay, s, salt) {
  return send(c, { type: 'reveal', salt, root: s.root, dataset: s.dataset, weight: s.weight, amount: s.amount, count: s.count },
    [meta(c.bookAddress), meta(c.epochAddress(s.epoch)), meta(c.attestorAddress(relay.publicKey)), meta(c.candidateAddress(s.epoch, s.result))], relay);
}
/** Vetoes the armed result `hash` of `epoch` within the checking delay: spends a credit and sends the
 *  round's pot to the carry (no strict mode, owner 29 September). `priorityFee` (lamports, paid by the
 *  relay above its refund) and `transport` let a watcher escalate a veto that must land in time. */
export async function vetoSnapshot(c, relay, epoch, hash, { priorityFee = 0, transport = c.t } = {}) {
  const ix = new TransactionInstruction({ programId: c.program, data: encodeSnapshotOp({ type: 'veto' }),
    keys: [...await c.prefix(relay), meta(c.bookAddress), meta(c.epochAddress(epoch)), meta(c.attestorAddress(relay.publicKey)), meta(c.candidateAddress(epoch, hash))] });
  return transport === c.t && !priorityFee ? c.send([ix], relay) : transport.send([ix], relay, [], { priorityFeeLamports: BigInt(priorityFee) });
}
/** Anyone, once no result armed in time or the armed one went unpaid: the pot returns to the carry. */
export async function expireSnapshot(c, payer, { selfPaid } = {}) {
  return send(c, { type: 'expire', selfPaid }, [meta(c.bookAddress), meta(c.epochAddress(await distributing(c)))], payer);
}
/** Anyone, once its round is over: the candidate's rent returns to its first revealer. */
export async function closeCandidate(c, epoch, hash, payer, { selfPaid } = {}) {
  const address = c.candidateAddress(epoch, hash), cand = await c.maybe(address, decodeCandidate);
  if (!cand) throw Error('no such candidate');
  return send(c, { type: 'close', selfPaid }, [meta(address), meta(cand.funder)], payer);
}
/** Pays leaves `index .. index + n` of the armed snapshot (for an empty snapshot, n = 0 ends it). */
export function payInstruction(c, s, index, n, prefix, { selfPaid } = {}) {
  const entries = s.entries.slice(index, index + n);
  return new TransactionInstruction({ programId: c.program,
    data: encodeSnapshotOp({ type: 'pay', selfPaid, index, leaves: entries.map((e, j) => ({ weight: e.weight, amount: e.amount, proof: s.proof(index + j) })) }),
    keys: [...prefix, meta(c.bookAddress), meta(c.epochAddress(s.epoch)), meta(c.candidateAddress(s.epoch, s.result)), ...entries.map(e => meta(e.owner))] });
}
export async function paySnapshot(c, s, index, n, payer, opts = {}) { return c.send([payInstruction(c, s, index, n, await c.prefix(payer), opts)], payer); }
/** Leaves per payment instruction that keep a version 1 transaction under 4,096 bytes. */
export const batchFor = count => Math.max(1, Math.min(12, Math.floor(2900 / (60 + 32 * depth(count)))));

/** The distribution in flight, as the book froze it: null when none runs. */
export async function currentRound(c) {
  const cfg = await c.config(); if (cfg.distributing === null) return null;
  const [book, e] = await Promise.all([c.book(), c.read(c.epochAddress(cfg.distributing), decodeEpoch)]);
  return { cfg, book, epoch: e };
}
/**
 * Pays the armed result's next leaves in index order, `batch` per transaction, until `maxPayments`
 * leaves or the end. The dataset comes from `source` and must match the armed candidate byte for
 * byte. A batch another relay landed first is skipped, not retried. `turn(cursor)`, when given, is asked
 * before every batch and stops the payment when it says no (cranks.mjs payTurn); `landed(cursor)` hears
 * the cursor each batch this payer landed left.
 */
export async function distributeSnapshot(c, payer, { source = c.snapshotSource, maxPayments = 400, batch, selfPaid, turn = null, landed = async () => {} } = {}) {
  const round = await currentRound(c); if (!round) return { paid: 0 };
  const { cfg, book } = round, epoch = cfg.distributing;
  if (!book?.armed) return { paid: 0, waiting: 'snapshot quorum' };
  if (await c.t.now() < book.ready) return { paid: 0, waiting: 'public checking delay' };
  if (cfg.pause) return { paid: 0, waiting: 'paused by the meta-council' };
  if (!source) return { paid: 0, waiting: 'published snapshot data' };
  const onchain = await c.read(c.candidateAddress(epoch, book.armed), decodeCandidate);
  const s = parseSnapshot(c, await source(epoch));
  if (!s.result.equals(book.armed) || s.epoch !== epoch || s.mint !== cfg.mint || s.slot !== onchain.slot || !s.dataset.equals(onchain.dataset) || !s.root.equals(onchain.root)
    || s.weight !== onchain.weight || s.amount !== onchain.amount || s.count !== onchain.count) throw Error('published snapshot does not match the armed result');
  if (!s.count) { await paySnapshot(c, s, 0, 0, payer, { selfPaid }); return { paid: 0, complete: true }; }
  const k = batch ?? batchFor(s.count);
  let paid = 0;
  while (paid < maxPayments) {
    const e = await c.read(c.epochAddress(epoch), decodeEpoch);
    if ((await c.config()).distributing !== epoch || e.leavesPaid >= s.count) break;
    if (turn && !await turn(e.leavesPaid)) break;
    const n = Math.min(k, s.count - e.leavesPaid, maxPayments - paid);
    try { await paySnapshot(c, s, e.leavesPaid, n, payer, { selfPaid }); paid += n; await landed(e.leavesPaid + n); }
    catch (err) {
      // Another relay paid this batch first: carry on from the cursor it left.
      const now = await c.maybe(c.epochAddress(epoch), decodeEpoch);
      if (now && now.leavesPaid > e.leavesPaid) continue;
      throw err;
    }
  }
  return { paid, complete: (await c.config()).distributing !== epoch };
}
/** The most any /v2/snapshots response is read to: a dataset of `MAX_LEAVES` holders fits. */
export const BODY_LIMIT = 128 * 1024 * 1024;
/** A /v2/snapshots response's `base64` file, read as a stream and refused past `limit` bytes before it
 *  is parsed, so no server can make a relay buffer an unbounded body (29 September review). */
export async function snapshotBody(response, limit = BODY_LIMIT) {
  if (Number(response.headers?.get('content-length')) > limit) throw Error('snapshot response too large');
  const chunks = []; let length = 0;
  for await (const chunk of response.body ?? []) { length += chunk.length; if (length > limit) throw Error('snapshot response too large'); chunks.push(chunk); }
  const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (typeof body.base64 !== 'string') throw Error('snapshot response has no data');
  return Buffer.from(body.base64, 'base64');
}
