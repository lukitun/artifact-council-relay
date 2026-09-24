// Byte layouts for the Artifact Council v2 program (mirrors src/state.rs and src/lib.rs, Borsh).
// Dependency-free so the same code runs in Node, the browser and the verifier.
import { createHash } from 'node:crypto';

export const sha256 = (...parts) => { const h = createHash('sha256'); for (const p of parts) h.update(p); return h.digest(); };
export const ZERO = Buffer.alloc(32);
export const MAGIC = Buffer.from('ACv2\0\0\0\0', 'binary');

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

// ---- constants shared with the program ---------------------------------------------------------
export const TAG = { CONFIG: 11, AGENT: 2, RELAYER: 3, ARTIFACT: 4, PROPOSAL: 5, UPLOAD: 6, RECORD: 8, EPOCH: 9, HOLDER: 10 };
export const CHUNK = 3000, MAX_TEXT = 48000, MAX_CHARS = 12000, MAX_PAGES = 10;
export const G = ['FREE_PAGES', 'MONTH_ACTIONS', 'MONTH_BYTES', 'WEEKLY_CAP', 'REFUND', 'REWARD_BPS', 'EPOCH_SECS', 'MIN_HOLDER', 'MIN_POT',
  'RESERVE_TARGET', 'BURN_TOKENS', 'VOUCHES_REQUIRED', 'VOUCHES_PER_MONTH', 'GRANT_MIN_MEMBERS', 'DELAY_SECS', 'COOLDOWN_SECS',
  'KICK_COOLDOWN_SECS', 'UPLOAD_TTL', 'HOLDER_POT_CAP'];
export const C = ['WINDOW_DAYS', 'SKIPS', 'APPROVE_BPS', 'REJECT_BPS', 'KICK_CONFIRM_HOURS', 'ACCEPT_SPONSORED'];
export const COUNCIL_DEFAULTS = [7, 4, 6900, 2000, 48, 1];
/** pump.fun coin type, fixed at launch and recorded once with the mint. */
export const INCOME = ['unset', 'creator-fees', 'holder-rewards'];
export const STATUS = ['voting', 'passed', 'rejected', 'expired_no_consensus', 'confirmation_pending', 'confirmation_expired', 'aborted', 'stale'];
export const KINDS = ['content', 'membership', 'settings', 'kick', 'link', 'global', 'grant'];
export const RECORD_KINDS = ['genesis', 'content', 'membership', 'settings', 'kick', 'link', 'global', 'grant', 'sponsor', 'imported'];
export const gIndex = name => { const i = G.indexOf(name); if (i < 0) throw Error(`unknown global setting ${name}`); return i; };
export const cIndex = name => { const i = C.indexOf(name); if (i < 0) throw Error(`unknown council setting ${name}`); return i; };

// ---- instruction payloads ----------------------------------------------------------------------
export function encodePayload(w, p) {
  switch (p.kind) {
    case 'content': return w.u8(0).u8(p.page).key(p.upload).key(p.content).str(p.title ?? '');
    case 'membership': return w.u8(1).key(p.agent);
    case 'settings': return w.u8(2).vec(Object.entries(p.patch), (w, [k, v]) => w.u8(cIndex(k)).u32(v));
    case 'kick': return w.u8(3).key(p.agent);
    case 'link': return w.u8(4).key(p.to);
    case 'global': return w.u8(5).vec(Object.entries(p.patch), (w, [k, v]) => w.u8(gIndex(k)).u64(v));
    case 'grant': return w.u8(6).key(p.agent);
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
    case 6: return { kind: 'grant', agent: r.key() };
    default: throw Error(`unknown payload ${k}`);
  }
}
export function encodeAction(w, a) {
  switch (a.type) {
    case 'register': return w.u8(0).str(a.handle ?? '').bool(!!a.hosted);
    case 'setKey': return w.u8(1).key(a.key);
    case 'begin': return w.u8(2).u32(a.len).key(a.root);
    case 'create': return w.u8(3).str(a.name).str(a.title ?? '');
    case 'propose': encodePayload(w.u8(4), a.payload); return w.str(a.thread ?? '');
    case 'vote': return w.u8(5).bool(a.approve);
    case 'confirm': return w.u8(6).bool(a.execute);
    case 'vouch': return w.u8(7);
    case 'cancelUpload': return w.u8(8);
    default: throw Error(`unknown action ${a.type}`);
  }
}
export function decodeAction(r) {
  const t = r.u8();
  switch (t) {
    case 0: return { type: 'register', handle: r.str(), hosted: r.bool() };
    case 1: return { type: 'setKey', key: r.key() };
    case 2: return { type: 'begin', len: r.u32(), root: r.hash() };
    case 3: return { type: 'create', name: r.str(), title: r.str() };
    case 4: return { type: 'propose', payload: decodePayload(r), thread: r.str() };
    case 5: return { type: 'vote', approve: r.bool() };
    case 6: return { type: 'confirm', execute: r.bool() };
    case 7: return { type: 'vouch' };
    case 8: return { type: 'cancelUpload' };
    default: throw Error(`unknown action ${t}`);
  }
}
export function encodeEnvelope(e) {
  const w = new W().raw(MAGIC).key(e.domain).key(e.program).key(e.agent).u64(e.nonce).i64(e.expiry).key(e.preferred ?? ZERO)
    .vec(e.accounts, (w, k) => w.key(k));
  return encodeAction(w, e.action).done();
}
export function decodeEnvelope(bytes) {
  const r = new R(bytes);
  if (!r.take(8).equals(MAGIC)) throw Error('not an Artifact Council v2 envelope');
  const e = { domain: r.hash(), program: r.key(), agent: r.key(), nonce: r.n64(), expiry: r.i64(), preferred: r.key(), accounts: r.vec(r => r.key()) };
  e.action = decodeAction(r);
  if (r.o !== r.b.length) throw Error('trailing bytes after envelope');
  return e;
}
export const CRANK = ['resolve', 'expire', 'closeEpoch', 'tally', 'pay', 'claim', 'retire', 'applyGlobal', 'unwrap', 'expireUpload'];
export const encodeCrank = name => { const i = CRANK.indexOf(name); if (i < 0) throw Error(`unknown crank ${name}`); return Buffer.from([2, i]); };
export function encodeDirect(d) {
  const w = new W().u8(3);
  switch (d.type) {
    case 'registerRelayer': return w.u8(0).u8(d.kind === 'gateway' ? 2 : 1).str(d.url ?? '').done();
    case 'write': return w.u8(1).bytes(d.chunk).key(d.next).done();
    case 'registerHolder': return w.u8(2).done();
    case 'closeHolder': return w.u8(3).done();
    case 'withdraw': return w.u8(4).done();
    case 'sponsor': return w.u8(5).done();
    default: throw Error(`unknown direct ${d.type}`);
  }
}
export function encodeSetup(s) {
  const w = new W().u8(4);
  switch (s.type) {
    case 'setMint': return w.u8(0).u8(INCOME.indexOf(s.mode ?? 'creator-fees')).done();
    case 'importAgent': return w.u8(1).key(s.id).key(s.signer).key(s.gateway ?? ZERO).str(s.handle ?? '').bool(!!s.eligible).i64(s.created ?? 0).done();
    case 'seed': return w.u8(2).done();
    case 'importArtifact': return w.u8(3).str(s.name).vec(s.members, (w, [k, t]) => w.key(k).i64(t))
      .vec(Object.entries(s.patch ?? {}), (w, [k, v]) => w.u8(cIndex(k)).u32(v)).i64(s.created ?? 0).done();
    case 'importVersion': return w.u8(4).u8(s.page).str(s.title ?? '').i64(s.time).key(s.source).done();
    case 'importProposal': { encodePayload(w.u8(5), s.payload);
      return w.key(s.proposer).vec(s.roster, (w, k) => w.key(k)).vec(s.ballots, (w, [k, v]) => w.key(k).bool(v)).i64(s.created).i64(s.closes)
        .u8(STATUS.indexOf(s.status ?? 'voting')).i64(s.confirmUntil ?? 0).str(s.thread ?? '').done(); }
    case 'finishMigration': return w.u8(6).done();
    case 'finishSetup': return w.u8(7).done();
    case 'importLink': return w.u8(8).key(s.source).done();
    default: throw Error(`unknown setup ${s.type}`);
  }
}
export const encodeInit = ({ domain, setup, settings = {} }) =>
  new W().u8(0).key(domain).key(setup).vec(Object.entries(settings), (w, [k, v]) => w.u8(gIndex(k)).u64(v)).done();

// ---- accounts ----------------------------------------------------------------------------------
function expect(r, t, name) { const got = r.u8(); if (got !== t) throw Error(`not a ${name} account (tag ${got})`); }
export function decodeConfig(b) {
  const r = new R(b); expect(r, TAG.CONFIG, 'config');
  const c = { domain: r.hash(), setup: r.key(), migrationOpen: r.bool(), mint: r.key(), tokenProgram: r.key(), decimals: r.u8(), incomeMode: INCOME[r.u8()] };
  c.g = Object.fromEntries(G.map(k => [k, r.n64()]));
  c.pending = r.vec(r => ({ patch: Object.fromEntries(r.vec(r => [G[r.u8()], r.n64()])), at: r.i64(), proposal: r.key() }));
  for (const k of ['artifacts', 'agents', 'holders', 'reserve', 'liabilities', 'carryRelayer', 'carryHolder']) c[k] = r.n64();
  c.week = r.i64();
  for (const k of ['weekSpent', 'incomeTotal', 'spentTotal', 'paidTotal', 'epoch']) c[k] = r.n64();
  c.epochStart = r.i64(); c.epochLen = r.i64(); c.epochWork = r.n64(); c.distributing = r.u64();
  c.distributing = c.distributing === 0xffffffffffffffffn ? null : Number(c.distributing);
  return c;
}
export function decodeAgent(b) {
  const r = new R(b); expect(r, TAG.AGENT, 'agent');
  return { id: r.key(), signer: r.key(), custody: r.u8() === 1 ? 'hosted' : 'own', gateway: r.key(), nonce: r.n64(),
    eligible: ['no', 'seeded', 'vouched', 'council'][r.u8()], vouchers: r.vec(r => r.key()), vouchMonth: r.i64(), vouchesGiven: r.u8(),
    month: r.i64(), actions: r.u32(), bytes: r.n64(), created: r.i64(), handle: r.str() };
}
export function decodeRelayer(b) {
  const r = new R(b); expect(r, TAG.RELAYER, 'relayer');
  return { key: r.key(), kind: r.u8() === 2 ? 'gateway' : 'relay', work: r.arr(2, r => ({ epoch: r.n64(), units: r.n64(), claimed: r.bool() })),
    registered: r.i64(), url: r.str() };
}
export function decodeArtifact(b) {
  const r = new R(b); expect(r, TAG.ARTIFACT, 'artifact');
  const a = { id: r.n64(), name: r.str(), created: r.i64(), members: r.vec(r => ({ id: r.key(), skips: r.u8(), lastSkip: r.i64(), joined: r.i64() })) };
  const council = r.arr(6, r => r.u32()); const pinned = r.u8();
  a.settings = Object.fromEntries(C.map((k, i) => [k, pinned & (1 << i) ? council[i] : COUNCIL_DEFAULTS[i]]));
  a.settingsSource = Object.fromEntries(C.map((k, i) => [k, pinned & (1 << i) ? 'council' : 'platform_default']));
  a.pages = r.u8(); a.sponsored = r.u8(); a.versions = r.arr(MAX_PAGES, r => r.u32());
  a.history = r.n64(); a.head = r.hash(); a.proposals = r.n64();
  a.open = r.vec(r => ({ id: r.n64(), hash: r.hash() }));
  a.recent = r.vec(r => ({ hash: r.hash(), kind: KINDS[r.u8()], status: STATUS[r.u8()], at: r.i64() }));
  a.links = r.vec(r => r.key());
  return a;
}
export function decodeProposal(b) {
  const r = new R(b); expect(r, TAG.PROPOSAL, 'proposal');
  const p = { artifact: r.key(), id: r.n64(), proposer: r.key(), funder: r.key(), payload: decodePayload(r), hash: r.hash(), created: r.i64(), closes: r.i64(),
    approveBps: r.u32(), rejectBps: r.u32(), kickWindow: r.i64(), skipLimit: r.u8(), baseVersion: r.u32(), confirmUntil: r.i64(),
    status: STATUS[r.u8()], imported: r.bool(), roster: r.vec(r => r.key()), ballots: r.vec(r => ({ voter: r.key(), approve: r.bool() })), thread: r.str() };
  p.approve = p.ballots.filter(b => b.approve).length; p.reject = p.ballots.length - p.approve;
  return p;
}
/** An upload in progress: validation state only; the bytes live in its transactions. */
export function decodeUpload(b) {
  const r = new R(b); expect(r, TAG.UPLOAD, 'upload');
  return { owner: r.key(), nonce: r.n64(), funder: r.key(), len: r.u32(), written: r.u32(), next: r.hash(), root: r.hash(), complete: r.bool(),
    chars: r.u32(), carry: r.bytes(), locked: r.key(), expires: r.i64() };
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
  for (const k of ['income', 'work', 'relayerPool', 'relayerPaid', 'claimedWork', 'pot', 'potPaid', 'holdersExpected', 'tallied']) e[k] = r.n64();
  e.weight = r.u128(); e.positive = r.n64(); e.paid = r.n64(); e.funder = r.key(); e.minHolder = r.n64();
  return e;
}
export function decodeHolder(b) {
  const r = new R(b); expect(r, TAG.HOLDER, 'holder');
  return { owner: r.key(), token: r.key(), funder: r.key(), registered: r.n64(),
    tallied: r.n64(), weight: r.n64(), paid: r.n64(), accrued: r.n64() };
}
export const DECODERS = { [TAG.CONFIG]: decodeConfig, [TAG.AGENT]: decodeAgent, [TAG.RELAYER]: decodeRelayer, [TAG.ARTIFACT]: decodeArtifact,
  [TAG.PROPOSAL]: decodeProposal, [TAG.UPLOAD]: decodeUpload, [TAG.RECORD]: decodeRecord, [TAG.EPOCH]: decodeEpoch,
  [TAG.HOLDER]: decodeHolder };

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
