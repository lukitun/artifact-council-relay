// Byte layouts for the Artifact Council v2 protocol (mirrors src/state.rs, src/lib.rs, src/rewards.rs,
// src/setup.rs and src/snapshots.rs, Borsh). Every enum index, tag and size here is pinned to the
// program's own byte fixtures (test/fixtures/program-bytes.json) by test/layout.test.mjs.
// Dependency-free so the same code runs in Node, the browser and the verifier.
import { createHash } from 'node:crypto';

export const sha256 = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
export const ZERO = Buffer.alloc(32);
const ZERO_KEY = '11111111111111111111111111111111';
export const MAGIC = Buffer.from('ACv2\0\0\0\0', 'binary');
const U64_MAX = 0xffffffffffffffffn;

// ---- writer ------------------------------------------------------------------------------------
export class W {
  constructor() { this.parts = []; }
  raw(b) { this.parts.push(Buffer.from(b)); return this; }
  u8(n) { return this.raw([n & 255]); }
  bool(v) { return this.u8(v ? 1 : 0); }
  u16(n) { const b = Buffer.alloc(2); b.writeUInt16LE(n); return this.raw(b); }
  u32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return this.raw(b); }
  u64(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return this.raw(b); }
  i64(n) { const b = Buffer.alloc(8); b.writeBigInt64LE(BigInt(n)); return this.raw(b); }
  u128(n) { n = BigInt(n); return this.u64(n & U64_MAX).u64(n >> 64n); }
  key(k) { const b = keyBytes(k); if (b.length !== 32) throw Error('key must be 32 bytes'); return this.raw(b); }
  str(s) { const b = Buffer.from(s, 'utf8'); return this.u32(b.length).raw(b); }
  bytes(b) { return this.u32(b.length).raw(b); }
  vec(items, f) { this.u32(items.length); for (const x of items) f(this, x); return this; }
  done() { return Buffer.concat(this.parts); }
}
export const keyBytes = k => typeof k === 'string' ? Buffer.from(fromBase58(k)) : k?.toBuffer ? k.toBuffer() : Buffer.from(k);

// ---- reader ------------------------------------------------------------------------------------
export class R {
  constructor(b) { this.b = Buffer.from(b); this.o = 0; }
  take(n) { const s = this.b.subarray(this.o, this.o + n); if (s.length !== n) throw Error('truncated account'); this.o += n; return s; }
  u8() { return this.take(1)[0]; }
  bool() { const v = this.u8(); if (v > 1) throw Error('bad bool'); return v === 1; }
  u16() { return this.take(2).readUInt16LE(); }
  u32() { return this.take(4).readUInt32LE(); }
  u64() { return this.take(8).readBigUInt64LE(); }
  i64() { return Number(this.take(8).readBigInt64LE()); }
  n64() { return Number(this.u64()); }
  u128() { const lo = this.u64(), hi = this.u64(); return (hi << 64n) | lo; }
  key() { return base58(this.take(32)); }
  hash() { return Buffer.from(this.take(32)); }
  str() { return this.take(this.u32()).toString('utf8'); }
  bytes() { return Buffer.from(this.take(this.u32())); }
  vec(f) { return Array.from({ length: this.u32() }, () => f(this)); }
  arr(n, f) { return Array.from({ length: n }, () => f(this)); }
  option(f) { const o = this.u8(); if (o > 1) throw Error('bad option'); return o ? f(this) : null; }
}

// ---- base58 ------------------------------------------------------------------------------------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export function base58(bytes) {
  let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b);
  let out = ''; while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = '1' + out; }
  return out || '1';
}
export function fromBase58(text) {
  let n = 0n; for (const c of text) { const i = B58.indexOf(c); if (i < 0) throw Error(`not base58: ${text}`); n = n * 58n + BigInt(i); }
  const d = []; while (n > 0n) { d.unshift(Number(n % 256n)); n /= 256n; }
  for (const c of text) { if (c !== '1') break; d.unshift(0); }
  return Uint8Array.from(d);
}

// ---- tables shared with the program (state.rs) -------------------------------------------------
/** One table for every account tag, contiguous from 1 (29 September: the program id is new). */
export const TAG = { CONFIG: 1, AGENT: 2, RELAYER: 3, ARTIFACT: 4, PROPOSAL: 5, UPLOAD: 6, RECORD: 7, EPOCH: 8, BOOK: 9, CANDIDATE: 10, DECLINES: 11, ATTESTOR: 12 };
/** Exact account sizes (state.rs `*_SIZE`): each is borsh(largest value). */
export const SIZE = { CONFIG: 1_621, AGENT: 448, RELAYER: 191, ARTIFACT: 3_393, UPLOAD: 212, RECORD_BASE: 299, EPOCH: 153, BOOK_HEAD: 133, VERDICT: 40,
  BOOK: 133 + 240 * 40, ATTESTOR: 204, CANDIDATE: 189, DECLINES: 74, PROPOSAL_BASE: 271, PROPOSAL_SEAT: 65 };
/** Constant offsets of fixed fields, for `memcmp` filters: every account puts its fixed-size fields
 *  first (29 September). */
export const OFFSET = { CONFIG: { RESERVE: 396, WEEK: 428, WEEK_DEPOSITS: 436 }, AGENT: { STATUS: 130, DEPOSIT_WEEK: 172, WEEK_DEPOSITS: 180, APPLICATIONS: 188 } };
export const CHUNK = 3000, MAX_TEXT = 48000, MAX_CHARS = 12000, MAX_PAGES = 10, MAX_COUNCIL = 32, MAX_OPEN = 8, MAX_RECENT = 16, MAX_LINKS = 16,
  MAX_PENDING = 4, SPENT_WEEKS = 4, PAUSES = 4, MAX_HANDLE = 32, MAX_NAME = 128, MAX_TITLE = 128, MAX_THREAD = 96, MAX_URL = 96, META_APPROVE_BPS = 7_500;
/** The runtime's reserved account keys (treasury.rs `RESERVED`): read-only in every transaction, so
 *  no snapshot leaf names one and the program never pays one (29 September review). */
export const RESERVED_KEYS = ['AddressLookupTab1e1111111111111111111111111', 'BPFLoader1111111111111111111111111111111111', 'BPFLoader2111111111111111111111111111111111',
  'BPFLoaderUpgradeab1e11111111111111111111111', 'ComputeBudget111111111111111111111111111111', 'Config1111111111111111111111111111111111111',
  'Ed25519SigVerify111111111111111111111111111', 'Feature111111111111111111111111111111111111', 'LoaderV411111111111111111111111111111111111',
  'KeccakSecp256k11111111111111111111111111111', 'Secp256r1SigVerify1111111111111111111111111', 'StakeConfig11111111111111111111111111111111',
  'Stake11111111111111111111111111111111111111', '11111111111111111111111111111111', 'Vote111111111111111111111111111111111111111',
  'ZkE1Gama1Proof11111111111111111111111111111', 'ZkTokenProof1111111111111111111111111111111', 'SysvarC1ock11111111111111111111111111111111',
  'SysvarEpochRewards1111111111111111111111111', 'SysvarEpochSchedu1e111111111111111111111111', 'SysvarFees111111111111111111111111111111111',
  'Sysvar1nstructions1111111111111111111111111', 'SysvarLastRestartS1ot1111111111111111111111', 'SysvarRecentB1ockHashes11111111111111111111',
  'SysvarRent111111111111111111111111111111111', 'SysvarRewards111111111111111111111111111111', 'SysvarS1otHashes111111111111111111111111111',
  'SysvarS1otHistory11111111111111111111111111', 'SysvarStakeHistory1111111111111111111111111', 'NativeLoader1111111111111111111111111111111',
  'Sysvar1111111111111111111111111111111111111'];
/** Key changes (rotation, recovery) an agent may make a month, whatever else it spent (state.rs). */
export const KEY_CHANGES_PER_MONTH = 4;
/** An application stays open 30 days; after a decline the agent waits 2 days to apply there again,
 *  and never after the third (owner, 29 September). Constants, not settings. */
export const APPLICATION_TTL_DAYS = 30, REAPPLY_DAYS = 2, MAX_DECLINES = 3, NEWCOMER_UPLOAD_TTL_DAYS = 2;
export const G = ['FREE_PAGES', 'MONTH_ACTIONS', 'MONTH_BYTES', 'CAP_FLOOR', 'REFUND', 'REWARD_BPS', 'EPOCH_SECS', 'MIN_HOLDER', 'MIN_POT',
  'CAP_PER_AGENT', 'BURN_TOKENS', 'DELAY_SECS', 'COOLDOWN_SECS', 'KICK_COOLDOWN_SECS', 'UPLOAD_TTL', 'MONTH_SECONDS', 'NEWCOMER_MONTH_ACTIONS',
  'NEWCOMER_MONTH_UPLOADS', 'MONTH_CREATES', 'GATEWAY_WEEK_REGISTRATIONS', 'MIN_PAYOUT'];
export const C = ['WINDOW_DAYS', 'SKIPS', 'APPROVE_BPS', 'REJECT_BPS', 'KICK_CONFIRM_HOURS', 'ACCEPT_UNLOCKS'];
/** [minimum, maximum, default] of each council setting, in `C` order (state.rs COUNCIL_BOUNDS). */
export const COUNCIL_BOUNDS = [[1, 30, 7], [2, 12, 4], [6_000, 9_900, 6_900], [500, 5_000, 2_000], [24, 168, 48], [0, 1, 1]];
export const COUNCIL_DEFAULTS = COUNCIL_BOUNDS.map(b => b[2]);
const SOL = 1_000_000_000;
/**
 * The program's time constants for a build whose day lasts `day` seconds (120 in the short-days test
 * build): the epoch (fixed forever at half an hour, owner 27 September), the checking delay, the
 * snapshot windows and seat periods (snapshot-spec §1), the application and upload periods.
 */
export function times(day = 86_400) {
  const hour = Math.trunc(day / 24), minute = hour >= 60 ? Math.trunc(hour / 60) : 1;
  return { day, hour, minute, week: 7 * day, month: 30 * day, epoch: Math.trunc(hour / 2), checkDelay: Math.trunc(hour / 6) || 1,
    fixWindow: 5 * minute, commitWindow: 5 * minute, revealWindow: 3 * minute, payWindow: 7 * day, maturity: 7 * day, unbond: 7 * day, rejoin: day,
    applicationTtl: APPLICATION_TTL_DAYS * day, reapplyWait: REAPPLY_DAYS * day, newcomerUploadTtl: NEWCOMER_UPLOAD_TTL_DAYS * day };
}
/**
 * [minimum, maximum, default] of each global setting, in `G` order (state.rs GLOBAL_BOUNDS), for a
 * build whose day lasts `day` seconds. The one JS copy: refusals and relays read it from here.
 */
export function globalBounds(day = 86_400) {
  const epoch = times(day).epoch, frame = MAX_TEXT + 12;
  return [
    [3, 3, 3], [10, 100_000, 2_000], [frame, 10_000_000, 500_000], [SOL / 100, 1_000 * SOL, SOL], [10_000, 50_000, 10_002],
    [0, 10_000, 2_000], [epoch, epoch, epoch], [0, 1_000_000_000_000_000, 1_000_000_000], [0, 10 * SOL, SOL / 100],
    [0, 10 * SOL, SOL / 10], [100, 100_000, 1_000], [day, 14 * day, 2 * day], [day, 14 * day, 2 * day], [day, 30 * day, 6 * day],
    [day, 30 * day, 7 * day], [0, 100, 10], [0, 1_000, 20], [0, 50, 5], [1, 50, 3], [0, 10_000, 50], [5_001, SOL, 10_000],
  ];
}
/** Keys whose lower value spends less: a lowering applies at once (state.rs CHEAPER_LOWER). */
export const CHEAPER_LOWER = ['MONTH_ACTIONS', 'MONTH_BYTES', 'REFUND', 'MONTH_SECONDS', 'NEWCOMER_MONTH_ACTIONS', 'NEWCOMER_MONTH_UPLOADS', 'MONTH_CREATES',
  'GATEWAY_WEEK_REGISTRATIONS'];
export const STATUS = ['voting', 'passed', 'rejected', 'expired_no_consensus', 'confirmation_pending', 'confirmation_expired', 'aborted', 'stale'];
export const KINDS = ['content', 'membership', 'settings', 'kick', 'link', 'global', 'ban', 'trustGateway', 'pause'];
/** The meta-council's powers pass at `META_APPROVE_BPS` (governance.rs `meta_kind`). */
export const META_KINDS = ['global', 'ban', 'trustGateway', 'pause'];
/** Hashed into every artifact's chain: this table is final. There is no "emptied" kind. */
export const RECORD_KINDS = ['genesis', 'content', 'membership', 'settings', 'kick', 'link', 'global', 'unlock', 'imported', 'revive', 'ban', 'trust', 'pause', 'claim'];
/** An agent's standing (29 September): new until a council first admits it, member from then on,
 *  banned for good once the meta-council bans it. */
export const AGENT_STATUS = ['new', 'member', 'banned'];
/** An attestor seat's state (state.rs `seat`). */
export const SEAT_STATE = ['pending', 'active', 'leaving', 'pruned'];
/** Holder snapshots signed by relays (snapshot-spec §1, owner 29 September). */
export const SNAPSHOT = { SNAP_SLOTS: 150, PARTICIPATION: 4, MIN_SEATS: 2, MAX_CREDIT: 2, CREDIT_EVERY: 48, VERDICTS: 240, MAX_LEAVES: 1_000_000, BATCH: 8 };
/** Seats that must reveal one result to arm it: two thirds of N, never fewer than two (snapshots.rs). */
export const quorum = n => Math.max(SNAPSHOT.MIN_SEATS, Math.ceil(2 * n / 3));

/** A cap key's lowest current or pending value: a cut brakes the cap at once, a rise waits (plan 6.1). */
const lowest = (cfg, k) => Math.min(cfg.g[k], ...(cfg.pending ?? []).map(q => q.patch[k] ?? Infinity));
/** Plan 2.1, as the program evaluates it: the population cap, floored, within a quarter of the
 *  reserve as it stood before this week's spending. */
export function weeklyCap(cfg) {
  const grown = Math.max(lowest(cfg, 'CAP_FLOOR'), lowest(cfg, 'CAP_PER_AGENT') * cfg.eligible);
  return Math.min(grown, Math.floor((cfg.reserve + cfg.weekDeposits) / 4));
}
/** Five times the average vault spending of the completed weeks on record (up to four), never below
 *  CAP_FLOOR (owner, 29 September: "full dynamic", "1 sol start"; treasury.rs `reserve_target`). */
export function reserveTarget(cfg) {
  const n = Math.min(cfg.spentWeeks, SPENT_WEEKS), weeks = cfg.spent.slice(0, n);
  const average = n ? Math.floor(weeks.reduce((s, v) => s + v, 0) / n) : 0;
  return Math.max(5 * average, cfg.g.CAP_FLOOR);
}
/** The week's deposit room (the whole weekly cap since 29 September: fee refunds take no share of
 *  it), and the three quarters agents' own deposits may fill: proposals may use the rest, protocol
 *  records are never refused (28 September). */
export const depositRoom = cfg => weeklyCap(cfg);
export const agentsRoom = cfg => Math.floor(depositRoom(cfg) / 4) * 3;
/** The newcomers' one weekly pool, a quarter of the agents' part: every vault-funded deposit on the
 *  newcomer allowance draws on it (treasury.rs `newcomer_pool`, 29 September); members' shares
 *  divide the rest. */
export const newcomerPool = cfg => Math.floor(agentsRoom(cfg) / 4);
export const membersRoom = cfg => agentsRoom(cfg) - newcomerPool(cfg);
/** Each agent's fair share of the week (treasury.rs `agent_share`, `room_share`; owner, 28 September):
 *  its own deposits stop at its share of the members' part, everything it draws (its proposals and
 *  the records they reserve included) at its share of the whole room, the eligible counted as at
 *  least two. No floor. */
export const agentShare = cfg => Math.floor(membersRoom(cfg) / Math.max(2, cfg.eligible));
export const roomShare = cfg => Math.floor(depositRoom(cfg) / Math.max(2, cfg.eligible));
/** The bond an attestor seat locks (snapshots.rs `bond`, snapshot-spec D2): a sixteenth of the reserve
 *  target, or its share of 48 average pots across the active seats, whichever is more. Join prices it
 *  on the config with its week rolled (funding.mjs `rolled`). */
export function bond(cfg, active, potAvg) {
  const pots = BigInt(potAvg) * BigInt(SNAPSHOT.CREDIT_EVERY) / BigInt(Math.max(active, SNAPSHOT.MIN_SEATS));
  const floor = BigInt(Math.floor(reserveTarget(cfg) / 16));
  return Number(pots > floor ? (pots > U64_MAX ? U64_MAX : pots) : floor);
}
export const gIndex = name => { const i = G.indexOf(name); if (i < 0) throw Error(`unknown global setting ${name}`); return i; };
export const cIndex = name => { const i = C.indexOf(name); if (i < 0) throw Error(`unknown council setting ${name}`); return i; };
const index = (table, v, what) => { if (typeof v === 'number') return v; const i = table.indexOf(v); if (i < 0) throw Error(`unknown ${what} ${v}`); return i; };

// ---- instruction payloads ----------------------------------------------------------------------
export function encodePayload(w, p) {
  switch (p.kind) {
    case 'content': return w.u8(0).u8(p.page).key(p.upload).key(p.content).str(p.title ?? '');
    case 'membership': return w.u8(1).key(p.agent);
    case 'settings': return w.u8(2).vec(Object.entries(p.patch), (w, [k, v]) => w.u8(cIndex(k)).u32(v));
    case 'kick': return w.u8(3).key(p.agent);
    case 'link': return w.u8(4).key(p.to);
    case 'global': return w.u8(5).vec(Object.entries(p.patch), (w, [k, v]) => w.u8(gIndex(k)).u64(v));
    case 'ban': return w.u8(6).key(p.agent);
    case 'trustGateway': return w.u8(7).key(p.key).bool(p.trusted ?? true);
    case 'pause': return w.u8(8).bool(!!p.on);
    default: throw Error(`unknown proposal kind ${p.kind}`);
  }
}
export function decodePayload(r) {
  const k = r.u8();
  switch (k) {
    case 0: return { kind: 'content', page: r.u8(), upload: r.key(), content: r.hash(), title: r.str() };
    case 1: return { kind: 'membership', agent: r.key() };
    case 2: return { kind: 'settings', patch: Object.fromEntries(r.vec(r => [C[r.u8()], r.u32()])) };
    case 3: return { kind: 'kick', agent: r.key() };
    case 4: return { kind: 'link', to: r.key() };
    case 5: return { kind: 'global', patch: Object.fromEntries(r.vec(r => [G[r.u8()], r.n64()])) };
    case 6: return { kind: 'ban', agent: r.key() };
    case 7: return { kind: 'trustGateway', key: r.key(), trusted: r.bool() };
    case 8: return { kind: 'pause', on: r.bool() };
    default: throw Error(`unknown payload ${k}`);
  }
}
/** A proposal account's exact size (state.rs `proposal_size`): `thread` is its length in bytes. */
export const proposalSize = (roster, payload, thread) => SIZE.PROPOSAL_BASE + encodePayload(new W(), payload).done().length + thread + roster * SIZE.PROPOSAL_SEAT;

/** Signed actions (lib.rs `Action`), by index. */
export const ACTIONS = ['register', 'setKey', 'begin', 'create', 'propose', 'vote', 'confirm', 'cancelUpload', 'apply', 'withdraw', 'contribute', 'second',
  'revive', 'recover', 'decline', 'claim'];
export function encodeAction(w, a) {
  const i = ACTIONS.indexOf(a.type); if (i < 0) throw Error(`unknown action ${a.type}`);
  w.u8(i);
  switch (a.type) {
    case 'register': return w.str(a.handle ?? '').bool(!!a.hosted);
    // `recovery`: undefined keeps the recovery key, null or ZERO clears it, a key sets it.
    case 'setKey': w.key(a.key); return a.recovery === undefined ? w.u8(0) : w.u8(1).key(a.recovery ?? ZERO);
    case 'begin': return w.u32(a.len).key(a.root);
    case 'create': return w.str(a.name).str(a.title ?? '');
    case 'propose': encodePayload(w, a.payload); return w.str(a.thread ?? '');
    case 'vote': return w.bool(a.approve);
    case 'confirm': return w.bool(a.execute);
    case 'withdraw': return w.key(a.target);
    case 'second': { w.key(a.author);
      if (a.join) w.u8(1).str(a.join.handle ?? '').bool(!!a.join.hosted).u32(a.join.len ?? 0); else w.u8(0);
      encodePayload(w, a.payload); return w.str(a.thread ?? ''); }
    case 'revive': return w.key(a.cofounder);
    case 'recover': return w.key(a.key);
    default: return w;
  }
}
export function decodeAction(r) {
  const t = r.u8(), type = ACTIONS[t];
  switch (type) {
    case 'register': return { type, handle: r.str(), hosted: r.bool() };
    case 'setKey': { const key = r.key(), recovery = r.option(r => r.key()); return recovery === null ? { type, key } : { type, key, recovery }; }
    case 'begin': return { type, len: r.u32(), root: r.hash() };
    case 'create': return { type, name: r.str(), title: r.str() };
    case 'propose': return { type, payload: decodePayload(r), thread: r.str() };
    case 'vote': return { type, approve: r.bool() };
    case 'confirm': return { type, execute: r.bool() };
    case 'withdraw': return { type, target: r.key() };
    case 'second': { const author = r.key(), join = r.option(r => ({ handle: r.str(), hosted: r.bool(), len: r.u32() }));
      return { type, author, join, payload: decodePayload(r), thread: r.str() }; }
    case 'revive': return { type, cofounder: r.key() };
    case 'recover': return { type, key: r.key() };
    case 'cancelUpload': case 'apply': case 'contribute': case 'decline': case 'claim': return { type };
    default: throw Error(`unknown action ${t}`);
  }
}
/** `selfPaid` (self-pay mode, owner 30 September): the signed choice that the transaction's fee payer
 *  pays the fee and every deposit the action creates, nothing coming from the vault. */
export function encodeEnvelope(e) {
  const w = new W().raw(MAGIC).key(e.domain).key(e.program).key(e.agent).u64(e.nonce).i64(e.expiry).key(e.preferred ?? ZERO)
    .vec(e.accounts, (w, k) => w.key(k));
  return encodeAction(w, e.action).bool(!!e.selfPaid).done();
}
export function decodeEnvelope(bytes) {
  const r = new R(bytes);
  if (!r.take(8).equals(MAGIC)) throw Error('not an Artifact Council v2 envelope');
  const e = { domain: r.hash(), program: r.key(), agent: r.key(), nonce: r.n64(), expiry: r.i64(), preferred: r.key(), accounts: r.vec(r => r.key()) };
  e.action = decodeAction(r);
  e.selfPaid = r.bool();
  if (r.o !== r.b.length) throw Error('trailing bytes after envelope');
  return e;
}
/** The Ed25519 precompile's data verifying `pairs` ([{ key, signature }], in order) over bytes 1.. of
 *  instruction `index` (`messageLength` bytes): the count, a padding byte, one 14-byte offsets entry per
 *  pair, then each pair's key and signature. The one layout the SDK builds (`ed25519Instruction`), and
 *  the one an agent's key accepts as fee payer (`checkSelfPaidMessage`). */
export function ed25519Data(pairs, messageLength, index) {
  const off = 2 + 14 * pairs.length; const data = Buffer.alloc(off + 96 * pairs.length);
  data[0] = pairs.length;
  pairs.forEach(({ key, signature }, i) => {
    const o = 2 + 14 * i, at = off + 96 * i;
    data.writeUInt16LE(at + 32, o); data.writeUInt16LE(0xffff, o + 2); data.writeUInt16LE(at, o + 4); data.writeUInt16LE(0xffff, o + 6);
    data.writeUInt16LE(1, o + 8); data.writeUInt16LE(messageLength, o + 10); data.writeUInt16LE(index, o + 12);
    keyBytes(key).copy(data, at); Buffer.from(signature).copy(data, at + 32);
  });
  return data;
}
/** Permissionless cranks (rewards.rs `Crank`), by index: family 2. */
export const CRANK = ['resolve', 'expire', 'closeEpoch', 'claimWork', 'retire', 'applyGlobal', 'unwrap', 'expireUpload', 'expireApplication', 'pruneBanned'];
/** `selfPaid`: self-paid housekeeping (rewards.rs `crank`, owner 30 September): the data ends with the
 *  self-paid byte, the caller pays its fee and any deposit the vault cannot fund. */
export const encodeCrank = (name, { selfPaid = false } = {}) => { const i = CRANK.indexOf(name); if (i < 0) throw Error(`unknown crank ${name}`); return Buffer.from(selfPaid ? [2, i, 1] : [2, i]); };
/** Wallet-signed direct instructions (rewards.rs `Direct`), by index: family 3. */
export const DIRECT = ['registerRelayer', 'write', 'unlock'];
export function encodeDirect(d) {
  const i = DIRECT.indexOf(d.type); if (i < 0) throw Error(`unknown direct ${d.type}`);
  const w = new W().u8(3).u8(i);
  if (d.type === 'registerRelayer') w.u8(d.kind === 'gateway' ? 2 : 1).str(d.url ?? '');
  if (d.type === 'write') w.bytes(d.chunk).key(d.next);
  return w.done();
}
/** Setup and migration (setup.rs `Setup`), by index: family 4. */
export const SETUP = ['setMint', 'importAgent', 'importArtifact', 'importSeats', 'importUpload', 'importVersion', 'importLink', 'importDeclines',
  'importProvenance', 'trustGateway', 'finishMigration', 'finishSetup', 'seed', 'seat'];
/** An imported seat: { id, joined, skips, lastSkip } (skips carry over). */
const seat = (w, m) => w.key(m.id).i64(m.joined ?? 0).u8(m.skips ?? 0).i64(m.lastSkip ?? 0);
export function encodeSetup(s) {
  const i = SETUP.indexOf(s.type); if (i < 0) throw Error(`unknown setup ${s.type}`);
  const w = new W().u8(4).u8(i);
  switch (s.type) {
    case 'importAgent': return w.key(s.id).key(s.signer).key(s.gateway ?? ZERO).str(s.handle ?? '').i64(s.created ?? 0)
      .u8(index(AGENT_STATUS, s.status ?? 'new', 'agent status')).key(s.recovery ?? ZERO)
      .vec(s.applications ?? [], (w, a) => w.key(a.artifact).i64(a.at)).done();
    case 'importArtifact': return w.str(s.name).i64(s.created ?? 0).i64(s.claimed ?? 0).vec(s.members ?? [], seat)
      .vec(Object.entries(s.patch ?? {}), (w, [k, v]) => w.u8(cIndex(k)).u32(v)).u8(s.unlocked ?? 0).bool(!!s.foundedAlone)
      .vec(s.recent ?? [], (w, x) => w.key(x.hash).u8(index(KINDS, x.kind, 'kind')).u8(index(STATUS, x.status, 'status')).i64(x.at)).done();
    case 'importSeats': return w.vec(s.members, seat).done();
    case 'importUpload': return w.u64(s.nonce).u32(s.len).key(s.root).done();
    case 'importVersion': return w.u8(s.page).str(s.title ?? '').i64(s.time).key(s.source).done();
    case 'importLink': return w.key(s.source).done();
    case 'importDeclines': return w.key(s.agent).key(s.artifact).u8(s.count).i64(s.last).done();
    case 'importProvenance': return w.key(s.sourceProgram).key(s.sourceHead).u64(s.sourceRecords).done();
    // Marks the operator's own gateway trusted before setup finishes (owner decision, 27 September).
    case 'trustGateway': return w.key(s.key).done();
    // All reserve, never income (owner, 30 September).
    case 'seed': return w.u64(s.lamports).done();
    // Seats a registered relay active at once, until FinishSetup (owner, 30 September: holders paid from day 1).
    case 'seat': return w.key(s.relay).done();
    default: return w.done();
  }
}
export const encodeInit = ({ domain, setup, settings = {} }) =>
  new W().u8(0).key(domain).key(setup).vec(Object.entries(settings), (w, [k, v]) => w.u8(gIndex(k)).u64(v)).done();
/** Holder snapshots signed by relays (snapshots.rs `Op`), by index: family 5. */
export const SNAPSHOT_OPS = ['join', 'activate', 'leave', 'withdraw', 'fix', 'commit', 'reveal', 'veto', 'pay', 'expire', 'prune', 'close'];
export function encodeSnapshotOp(o) {
  const i = SNAPSHOT_OPS.indexOf(o.type); if (i < 0) throw Error(`unknown snapshot op ${o.type}`);
  const w = new W().u8(5).u8(i);
  if (o.type === 'commit') w.key(o.commit);
  if (o.type === 'reveal') w.key(o.salt).key(o.root).key(o.dataset).u128(o.weight).u64(o.amount).u64(o.count);
  if (o.type === 'pay') w.u64(o.index).vec(o.leaves, (w, l) => w.u64(l.weight).u64(l.amount).vec(l.proof, (w, h) => w.key(h)));
  // Self-paid housekeeping (owner, 30 September): the caller pays its own fee, never refunded.
  if (o.selfPaid) w.u8(1);
  return w.done();
}

// ---- snapshot hashes (snapshots.rs) --------------------------------------------------------------
const le64 = n => new W().u64(n).done();
/** sha256 over everything a result commits: program, mint, epoch and snapshot slot bind it to one round. */
export const resultHash = ({ program, mint, epoch, slot, root, dataset, weight, amount, count }) =>
  sha256(Buffer.from('AC_SNAPSHOT_RESULT_V1'), keyBytes(program), keyBytes(mint), le64(epoch), le64(slot), keyBytes(root), keyBytes(dataset),
    new W().u128(weight).done(), le64(amount), le64(count));
/** A seat's commitment, salted and bound to its relay key and the epoch: nobody can copy it. */
export const commitHash = ({ relay, epoch, result, salt }) =>
  sha256(Buffer.from('AC_SNAPSHOT_COMMIT_V1'), keyBytes(relay), le64(epoch), keyBytes(result), keyBytes(salt));
export const leafHash = ({ program, mint, epoch, slot, index, owner, weight, amount }) =>
  sha256(Buffer.from('AC_SNAPSHOT_LEAF_V2'), keyBytes(program), keyBytes(mint), le64(epoch), le64(slot), le64(index), keyBytes(owner), le64(weight), le64(amount));
export const nodeHash = (left, right) => sha256(Buffer.from('AC_SNAPSHOT_NODE_V2'), left, right);
/** The snapshot slot `Fix` draws: the close slot plus the slot hash's first eight bytes modulo the
 *  150-slot window (snapshot-spec D5). */
export const snapSlot = (closeSlot, slotHash) => Number(BigInt(closeSlot) + keyBytes(slotHash).readBigUInt64LE(0) % BigInt(SNAPSHOT.SNAP_SLOTS));

// ---- accounts ----------------------------------------------------------------------------------
function expect(r, t, name) { const got = r.u8(); if (got !== t) throw Error(`not a ${name} account (tag ${got})`); }
const nullIfMax = v => v === U64_MAX ? null : Number(v);
export function decodeConfig(b) {
  const r = new R(b); expect(r, TAG.CONFIG, 'config');
  const c = { domain: r.hash(), setup: r.key(), migrationOpen: r.bool(), mint: r.key(), tokenProgram: r.key(), decimals: r.u8(), pause: r.bool(), unpauseAt: r.i64(),
    pauses: r.arr(PAUSES, r => [r.i64(), r.i64()]) };
  c.g = Object.fromEntries(G.map(k => [k, r.n64()]));
  for (const k of ['artifacts', 'agents', 'eligible', 'reserve', 'liabilities', 'carryRelayer', 'carryHolder']) c[k] = r.n64();
  c.week = r.i64();
  for (const k of ['weekDeposits', 'weekNewcomers', 'weekSpent']) c[k] = r.n64();
  c.spent = r.arr(SPENT_WEEKS, r => r.n64()); c.spentWeeks = r.u8();
  for (const k of ['incomeTotal', 'spentTotal', 'paidTotal', 'epoch']) c[k] = r.n64();
  c.epochStart = r.i64(); c.epochWork = r.n64(); c.workFrom = r.n64(); c.distributing = nullIfMax(r.u64());
  // Stretches in which the reserve could not pay a decline (state.rs `shorts`, 29 September review).
  c.shorts = r.arr(PAUSES, r => [r.i64(), r.i64()]);
  // Stretches in which the reserve could not refund a ballot (state.rs `ballot_shorts`, review round 9).
  c.ballotShorts = r.arr(PAUSES, r => [r.i64(), r.i64()]);
  c.pending = r.vec(r => ({ patch: Object.fromEntries(r.vec(r => [G[r.u8()], r.n64()])), at: r.i64(), proposal: r.key() }));
  // Relay work carried forward (27 September): credited under an earlier epoch while `workFrom` is set.
  c.workKey = c.workFrom > 0 ? c.workFrom - 1 : c.epoch;
  c.weeklyCap = weeklyCap(c); c.reserveTarget = reserveTarget(c);
  return c;
}
export function decodeAgent(b) {
  const r = new R(b); expect(r, TAG.AGENT, 'agent');
  const a = { id: r.key(), signer: r.key(), recovery: r.key(), custody: r.u8() === 1 ? 'hosted' : 'own', gateway: r.key(), status: AGENT_STATUS[r.u8()],
    nonce: r.n64(), created: r.i64(), month: r.i64(), actions: r.u32(), bytes: r.n64(), creates: r.u8(), uploads: r.u8(), seconds: r.u8(), keys: r.u8(),
    recovers: r.u8(), depositWeek: r.i64(), weekDeposits: r.n64() };
  a.applications = r.arr(2, r => ({ artifact: r.key(), at: r.i64() })).filter(s => s.artifact !== ZERO_KEY);
  a.contributions = r.arr(2, r => ({ artifact: r.key(), upload: r.key(), at: r.i64() })).filter(s => s.artifact !== ZERO_KEY);
  a.handle = r.str();
  return a;
}
export function decodeRelayer(b) {
  const r = new R(b); expect(r, TAG.RELAYER, 'relayer');
  return { key: r.key(), kind: r.u8() === 2 ? 'gateway' : 'relay', trusted: r.bool(), regWeek: r.u32(), regs: r.u16(), registered: r.i64(), accrued: r.n64(),
    work: r.arr(2, r => ({ epoch: r.n64(), units: r.n64(), claimed: r.bool() })), url: r.str() };
}
/** The open proposals one member may hold (governance.rs `open_share`, review round 3). */
export const openShare = art => Math.max(1, Math.floor(MAX_OPEN / Math.max(1, art.members.length)));
/** `h` cut to at most `MAX_HANDLE` UTF-8 bytes on a character boundary: the program counts bytes,
 *  not UTF-16 units (lib.rs `register`, review round 3). */
export function clipHandle(h) {
  let out = '';
  for (const ch of String(h ?? '')) { if (Buffer.byteLength(out + ch) > MAX_HANDLE) break; out += ch; }
  return out;
}
export function decodeArtifact(b) {
  const r = new R(b); expect(r, TAG.ARTIFACT, 'artifact');
  const a = { id: r.n64(), created: r.i64(), claimed: r.i64(), pinned: r.u8(), pages: r.u8(), unlocked: r.u8(), foundedAlone: r.bool() };
  const council = r.arr(C.length, r => r.u32());
  a.settings = Object.fromEntries(C.map((k, i) => [k, a.pinned & (1 << i) ? council[i] : COUNCIL_DEFAULTS[i]]));
  a.settingsSource = Object.fromEntries(C.map((k, i) => [k, a.pinned & (1 << i) ? 'council' : 'platform_default']));
  a.versions = r.arr(MAX_PAGES, r => r.u32()); a.history = r.n64(); a.head = r.hash(); a.proposals = r.n64(); a.name = r.str();
  a.members = r.vec(r => ({ id: r.key(), skips: r.u8(), lastSkip: r.i64(), joined: r.i64(), open: r.u8() }));
  a.open = r.vec(r => ({ id: r.n64(), hash: r.hash() }));
  a.recent = r.vec(r => ({ hash: r.hash(), kind: KINDS[r.u8()], status: STATUS[r.u8()], at: r.i64() }));
  a.links = r.vec(r => r.key());
  // Raw membership, exactly as the program counts it: two or more is a council, one inactive, none
  // unclaimed (29 September). A banned member counts until the crank prunes it.
  a.active = a.members.length >= 2; a.empty = a.members.length === 0;
  return a;
}
export function decodeProposal(b) {
  const r = new R(b); expect(r, TAG.PROPOSAL, 'proposal');
  const p = { artifact: r.key(), id: r.n64(), proposer: r.key(), seconder: r.key(), charged: r.key(), chargedMonth: r.i64(), reserved: r.u32(), funder: r.key(),
    hash: r.hash(), created: r.i64(), closes: r.i64(), approveBps: r.u32(), rejectBps: r.u32(), kickWindow: r.i64(), skipLimit: r.u8(), baseVersion: r.u32(),
    confirmUntil: r.i64(), status: STATUS[r.u8()], payload: decodePayload(r), roster: r.vec(r => r.key()),
    ballots: r.vec(r => ({ voter: r.key(), approve: r.bool() })), thread: r.str() };
  p.seconded = p.seconder !== ZERO_KEY;
  p.approve = p.ballots.filter(b => b.approve).length;
  p.reject = p.ballots.filter(b => !b.approve).length;
  return p;
}
/** When a passed kick lapses (governance.rs `kick_deadline`, review round 7), as the program sees it
 *  at `now` (a lift that is due ends the running pause, lib.rs `Ctx::new`): its window's end, unless
 *  that fell inside a meta-council pause on record; then a full window after the lift, and never
 *  (Infinity) while the pause runs. */
export function kickDeadline(cfg, p, now) {
  const lifted = cfg.pause && cfg.unpauseAt && now >= cfg.unpauseAt;
  const pauses = lifted ? [[cfg.pauses[0][0], cfg.unpauseAt], ...cfg.pauses.slice(1)] : cfg.pauses, due = p.confirmUntil;
  const span = pauses.find(([from, until]) => from !== 0 && due >= from && (until === 0 || due < until));
  if (span) return span[1] === 0 ? Infinity : span[1] + p.kickWindow;
  const oldest = pauses.at(-1)[0];
  return oldest !== 0 && due < oldest ? oldest + p.kickWindow : due;
}
/** The counted roster (governance.rs `count`, owner 29 September, D4): a roster seat or a ballot
 *  counts only while its id is still a member of `artifact`. */
export function counted(p, artifact) {
  const member = new Set(artifact.members.map(m => m.id));
  return { approve: p.ballots.filter(b => b.approve && member.has(b.voter)).length, reject: p.ballots.filter(b => !b.approve && member.has(b.voter)).length,
    seats: p.roster.filter(id => member.has(id)).length };
}
/** An upload in progress: validation state only; the bytes live in its transactions. */
export function decodeUpload(b) {
  const r = new R(b); expect(r, TAG.UPLOAD, 'upload');
  return { owner: r.key(), nonce: r.n64(), funder: r.key(), len: r.u32(), written: r.u32(), next: r.hash(), root: r.hash(), complete: r.bool(),
    chars: r.u32(), locked: r.key(), expires: r.i64(), earns: r.bool(), newcomer: r.bool(), seconded: r.bool(), units: r.u32(), taken: r.i64(), carry: r.bytes() };
}
export function decodeRecord(b) {
  const bytes = Buffer.from(b); const r = new R(bytes); expect(r, TAG.RECORD, 'record');
  const rec = { artifact: r.key(), seq: r.n64(), kind: RECORD_KINDS[r.u8()], page: r.u8(), pageVersion: r.u32(), proposal: r.key(), subject: r.key(),
    content: r.hash(), data: r.hash(), approve: r.u16(), reject: r.u16(), ballots: r.hash(), time: r.i64(), slot: r.n64(), len: r.u32(), prev: r.hash(), title: r.str() };
  const end = r.o; rec.hash = r.hash();
  rec.computed = sha256(Buffer.from('AC_RECORD_2'), bytes.subarray(0, end));
  return rec;
}
export function decodeEpoch(b) {
  const r = new R(b); expect(r, TAG.EPOCH, 'epoch');
  const e = { n: r.n64(), start: r.i64(), end: r.i64() };
  for (const k of ['closeSlot', 'income', 'work', 'workKey', 'relayerPool', 'relayerPaid', 'claimedWork', 'pot', 'potPaid', 'leavesPaid', 'minHolder', 'minPayout']) e[k] = r.n64();
  e.funder = r.key();
  return e;
}
/** An applicant's declines by one artifact (29 September, D1). */
export function decodeDeclines(b) {
  const r = new R(b); expect(r, TAG.DECLINES, 'declines');
  return { artifact: r.key(), agent: r.key(), count: r.u8(), last: r.i64() };
}
/** The seats' shared state and, after its fields, the ring of verdicts: (epoch + 1, result) for a
 *  paid round, `vetoed` set for an armed result that was vetoed (snapshots.rs `VETOED`). */
export function decodeBook(b) {
  const r = new R(b); expect(r, TAG.BOOK, 'book');
  const k = { active: r.u32(), admDay: r.i64(), admCount: r.u32(), dists: r.n64(), potAvg: r.n64(), frozenN: r.u32(), snapSlot: r.n64(), commitEnd: r.i64(),
    revealEnd: r.i64(), deadline: r.i64(), armed: r.hash(), ready: r.i64(), fee: r.n64(), reserve: r.n64(), reserveUsed: r.n64() };
  if (k.armed.equals(ZERO)) k.armed = null;
  const ring = Buffer.from(b).subarray(SIZE.BOOK_HEAD);
  k.verdicts = ring.length >= SNAPSHOT.VERDICTS * SIZE.VERDICT ? new R(ring).arr(SNAPSHOT.VERDICTS, r => { const v = r.u64(); return { epoch1: Number(v & ~VETOED), vetoed: (v & VETOED) !== 0n, hash: r.hash() }; }) : [];
  return k;
}
const VETOED = 1n << 63n;
/** The paid result of `epoch` recorded in the book's ring, or null. */
export const verdictOf = (book, epoch) => { const v = book.verdicts[epoch % SNAPSHOT.VERDICTS]; return v?.epoch1 === epoch + 1 && !v.vetoed ? v.hash : null; };
/** The armed result of `epoch` that was vetoed, or null. */
export const vetoedOf = (book, epoch) => { const v = book.verdicts[epoch % SNAPSHOT.VERDICTS]; return v?.epoch1 === epoch + 1 && v.vetoed ? v.hash : null; };
/** Whether `epoch` has aged out of the ring: its slot holds a later epoch's verdict, so what its round
 *  paid is no longer known, and a stance on it clears with no effect (snapshots.rs `aged_out`). */
export const agedOut = (book, epoch) => (book.verdicts[epoch % SNAPSHOT.VERDICTS]?.epoch1 ?? 0) > epoch + 1;
export function decodeAttestor(b) {
  const r = new R(b); expect(r, TAG.ATTESTOR, 'attestor');
  return { relay: r.key(), funder: r.key(), state: SEAT_STATE[r.u8()], bond: r.n64(), joined: r.i64(), seated: r.n64(), until: r.i64(),
    commit: { epoch1: r.n64(), hash: r.hash() }, stance: { epoch1: r.n64(), hash: r.hash() }, credit: r.u8(), creditDist: r.n64(), partDist: r.n64(), unpaid: r.u8(), left: r.i64() };
}
export function decodeCandidate(b) {
  const r = new R(b); expect(r, TAG.CANDIDATE, 'candidate');
  return { epoch: r.n64(), hash: r.hash(), slot: r.n64(), root: r.hash(), dataset: r.hash(), weight: r.u128(), amount: r.u64(), count: r.n64(), signers: r.u32(),
    processed: r.u64(), funder: r.key() };
}
export const DECODERS = { [TAG.CONFIG]: decodeConfig, [TAG.AGENT]: decodeAgent, [TAG.RELAYER]: decodeRelayer, [TAG.ARTIFACT]: decodeArtifact,
  [TAG.PROPOSAL]: decodeProposal, [TAG.UPLOAD]: decodeUpload, [TAG.RECORD]: decodeRecord, [TAG.EPOCH]: decodeEpoch, [TAG.BOOK]: decodeBook,
  [TAG.CANDIDATE]: decodeCandidate, [TAG.DECLINES]: decodeDeclines, [TAG.ATTESTOR]: decodeAttestor };

// ---- text frames and upload chains -------------------------------------------------------------
/** A zstd frame (RFC 8878) holding one raw block: valid for any decoder, no compression assumed. */
export function encodeFrame(text) {
  const b = Buffer.from(text, 'utf8');
  if ([...text].length > MAX_CHARS || b.length > MAX_TEXT) throw Error('page exceeds 12,000 characters or 48,000 bytes');
  if (text.isWellFormed?.() === false) throw Error('text is not well-formed Unicode');
  const h = Buffer.alloc(12); Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0xa0]).copy(h); h.writeUInt32LE(b.length, 5);
  const block = (b.length << 3) | 1; h[9] = block & 255; h[10] = (block >> 8) & 255; h[11] = (block >> 16) & 255;
  return Buffer.concat([h, b]);
}
/** Decodes any frame made of raw and RLE blocks (the program itself accepts one raw block). */
export const fingerprint = text => chain(encodeFrame(text)).root;
export function decodeFrame(frame) {
  frame = Buffer.from(frame);
  if (frame.length < 12 || !frame.subarray(0, 5).equals(Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0xa0]))) throw Error('unsupported frame header');
  const size = frame.readUInt32LE(5); const out = []; let at = 9, n = 0;
  for (;;) {
    const h = frame[at] | frame[at + 1] << 8 | frame[at + 2] << 16; at += 3;
    const last = h & 1, kind = (h >> 1) & 3, len = h >> 3;
    if (kind === 0) { out.push(frame.subarray(at, at + len)); at += len; } else if (kind === 1) { out.push(Buffer.alloc(len, frame[at])); at += 1; } else throw Error('compressed blocks unsupported');
    n += len; if (last) break;
  }
  const text = Buffer.concat(out);
  if (at !== frame.length || n !== size || text.length !== size) throw Error('frame length mismatch');
  return text;
}
/** Splits a frame into protocol-size chunks and builds the reverse hash chain over them; the root
 *  is the text's canonical fingerprint on chain. */
export function chain(frame, chunkSize = CHUNK) {
  const chunks = []; for (let o = 0; o < frame.length; o += chunkSize) chunks.push(frame.subarray(o, o + chunkSize));
  const links = new Array(chunks.length + 1); links[chunks.length] = ZERO;
  for (let i = chunks.length - 1; i >= 0; i--) links[i] = sha256(chunks[i], links[i + 1]);
  return { root: links[0], writes: chunks.map((chunk, i) => ({ chunk, next: links[i + 1] })) };
}
