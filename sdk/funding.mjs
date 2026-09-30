// Whether the vault pays for an instruction, decided from current chain state the way the program
// decides it: lib.rs `signed` (the ban gate, standing, the monthly allowances and byte quota),
// treasury.rs `create`/`take`/`refund` (reserve and weekly deposit room, deposits before the refund;
// a refund has no weekly ceiling since 29 September, only the reserve), rewards.rs `crank`/`Write`
// (housekeeping refunds; chunk writes refunded only for a vault-funded upload) and snapshots.rs
// (distribution fees refunded from the pot). Relays call this before paying anything; nothing is
// sent here.
import { PublicKey } from '@solana/web3.js';
import * as L from './layout.mjs';
const { decodeEnvelope, decodeUpload, decodeRelayer, decodeArtifact, decodeProposal, decodeAgent, decodeEpoch, decodeCandidate,
  weeklyCap, reserveTarget, agentShare, roomShare, newcomerPool, counted, proposalSize, KEY_CHANGES_PER_MONTH } = L;
export const PER_SIGNATURE = 5000;
/** Deposit sizes the quotes price (state.rs `*_SIZE`, pinned through layout.mjs). */
export const SIZE = { AGENT: L.SIZE.AGENT, ARTIFACT: L.SIZE.ARTIFACT, UPLOAD: L.SIZE.UPLOAD, RECORD: L.SIZE.RECORD_BASE, DECLINES: L.SIZE.DECLINES,
  EPOCH: L.SIZE.EPOCH, BOOK: L.SIZE.BOOK, ATTESTOR: L.SIZE.ATTESTOR, CANDIDATE: L.SIZE.CANDIDATE };
/** Why the program refuses everything a banned agent signs (lib.rs `signed`, owner 29 September). */
export const BANNED = 'banned by the meta-council: a banned agent signs nothing, key changes and withdrawals included';
const bytes = s => Buffer.byteLength(s ?? '', 'utf8');
const rentOf = t => size => t.rent ? t.rent(size) : (size + 128) * 6960;
const weekOf = (c, now) => Math.floor(now / (7 * (c.day ?? 86400)));

/** `cfg` after treasury.rs `roll_week` at `now`: the spending ring the reserve target averages. The
 *  ring keeps the last `SPENT_WEEKS` completed weeks only: after that many idle weeks the finished
 *  week has left it too (review, 30 September). */
export function rolled(c, cfg, now) {
  const w = weekOf(c, now); if (w === cfg.week) return cfg;
  const gap = Math.min(Math.max(w - cfg.week, 1), L.SPENT_WEEKS + 1), spent = [...cfg.spent];
  for (let i = 0; i < gap; i++) { spent.unshift(i === 0 ? cfg.weekSpent : 0); spent.pop(); }
  return { ...cfg, spent, spentWeeks: Math.min(cfg.spentWeeks + gap, L.SPENT_WEEKS) };
}
// The book the program will see: reserve and this week's spending after roll_week, less what
// transactions already in flight (`held`, from this relay's own pending actions) will take first:
// `lamports` of the reserve (deposits and fee refunds), `room` of the week's deposit room (vault
// deposits of every class; refunds take none) and `pool` of the newcomers' pool (newcomer deposits
// only), as treasury.rs `take` and `refund` count them (29 September review).
// Agents' own deposits stop at three quarters of the deposit room and at the signer's share of it;
// proposals may use the whole room, within the signer's share of it; protocol records are never
// refused by it (treasury.rs, 28 September).
function book(c, cfg, now, held = {}) {
  const same = cfg.week === weekOf(c, now);
  const current = { ...cfg, weekDeposits: same ? cfg.weekDeposits : 0, weekNewcomers: same ? cfg.weekNewcomers : 0 };
  const depositCap = weeklyCap(current);
  return { reserve: cfg.reserve - (held.lamports ?? 0), deposits: current.weekDeposits + (held.room ?? 0), newcomers: current.weekNewcomers + (held.pool ?? 0), pool: newcomerPool(current),
    depositCap, agentCap: Math.floor(depositCap / 4) * 3, share: agentShare(current), roomShare: roomShare(current), agentSpent: 0, charged: 0, sharesProposals: true,
    refund: cfg.g.REFUND, paused: cfg.pause && !(cfg.unpauseAt && now >= cfg.unpauseAt) };
}
const within = (spans, due) => { const oldest = spans.at(-1)[0]; return spans.some(([from, until]) => from !== 0 && due >= from && (until === 0 || due < until)) || (oldest !== 0 && due < oldest); };
/** Whether an application due at `due` was unanswerable (governance.rs `unanswerable`; open imports
 *  too, review round 4), as the program sees it at `now`: a lift that is due ends the running pause.
 *  A short reserve waives nothing since self-pay mode: a decline can always be self-paid (review,
 *  30 September). */
export function unanswerable(cfg, due, now) {
  const lifted = cfg.pause && cfg.unpauseAt && now >= cfg.unpauseAt;
  const pauses = lifted ? [[cfg.pauses[0][0], cfg.unpauseAt], ...cfg.pauses.slice(1)] : cfg.pauses;
  return cfg.migrationOpen || (cfg.pause && !lifted) || within(pauses, due);
}
/** A deposit (treasury.rs `take`): within the reserve, the week's room (the agents' part for an
 *  agent's own) and the signer's weekly share; protocol records (and kicks, declines, and the
 *  meta-council's pause and bans) are never refused by the room. */
const take = (b, amount, kind = 'agent') => {
  // A kick, like a protocol record, is never refused by the room, but draws on its proposer's share.
  // A decline's record is counted in its decliner's share, never refused by it (owner, 29 September
  // review round). A newcomer's own deposit also stops at the newcomers' one weekly pool (29 September).
  const own = kind === 'agent' || kind === 'newcomer';
  const cap = own ? b.agentCap : b.depositCap, roomless = kind === 'protocol' || kind === 'kick' || kind === 'decline';
  const governs = kind === 'governance' || kind === 'kick';
  if (b.paused || amount > b.reserve || (!roomless && b.deposits + amount > cap)) return false;
  // The pool alone bounds a newcomer's own deposit, never a member's share (review round 6).
  if (kind === 'agent' && b.agentSpent + amount > b.share) { b.overShare = true; return false; }
  if (kind === 'newcomer' && b.newcomers + amount > b.pool) { b.poolFull = true; return false; }
  if (governs && b.sharesProposals && b.agentSpent + amount + (b.reserved ?? 0) > b.roomShare) { b.overShare = true; return false; }
  const shared = kind === 'agent' || (governs && b.sharesProposals) || kind === 'decline';
  b.reserve -= amount; b.deposits += amount; if (kind === 'newcomer') b.newcomers += amount;
  if (shared) { b.agentSpent += amount; b.charged += amount; } return true;
};
/** The meta-council's pause, bans and global patches allocate under its own pause (governance.rs
 *  `braking`; plan 6.1). */
const braking = (art, kind) => art.id === 0 && ['pause', 'ban', 'global'].includes(kind);
/** A fee refund (treasury.rs `refund`): no weekly ceiling (owner, 29 September), only the reserve. */
const pay = (b, amount) => { if (amount > b.reserve) return false; b.reserve -= amount; return true; };
// Chunk writes carry one signature and earn half the refund, only when the vault funded the upload.
function writes(b, count, vaultFunded, registered, perSignature) {
  let refund = 0, reason = null;
  for (let i = 0; i < count; i++) {
    const amount = Math.floor(b.refund / 2);
    if (!vaultFunded) reason ??= 'the upload deposit was not vault-funded, so chunk writes are not refunded';
    else if (!registered) reason ??= 'this relay is not a registered relayer';
    else { const ok = amount > 0 && pay(b, amount); if (ok) refund += amount; if (!ok || amount < perSignature) reason ??= 'the reserve cannot refund the chunk writes'; }
  }
  return { fee: count * perSignature, refund, reason };
}
const NO_KEY = '11111111111111111111111111111111';
const base58 = k => k == null ? NO_KEY : typeof k === 'string' ? k : k.toBase58 ? k.toBase58() : new PublicKey(k).toBase58();
/**
 * How many envelope signatures the program verifies for `action` by the agent whose record is
 * `agent` (lib.rs `signed`): the signer (or, for a recovery, the recovery key); a second key for a
 * key change or recovery (the new key), a revival (the co-founder) or a second with `join` (the
 * newcomer); and, when a setKey changes or clears a set recovery key, that recovery key's consent
 * (28 September). The program refunds the relay's signature on top of these.
 */
export function envelopeSignatures(action, agent) {
  if (action.type === 'register') return 1;
  const cosigner = ['setKey', 'recover', 'revive'].includes(action.type) || (action.type === 'second' && !!action.join);
  const set = agent ? base58(agent.recovery) : NO_KEY;
  const consent = action.type === 'setKey' && action.recovery !== undefined && set !== NO_KEY && base58(action.recovery) !== set;
  return 1 + (cosigner ? 1 : 0) + (consent ? 1 : 0);
}
/** Who signs `action`'s envelope, in the order the program verifies them (lib.rs `signed`). */
export function envelopeSigners(action, agent) {
  const n = envelopeSignatures(action, agent);
  const first = action.type === 'recover' ? 'the recovery key' : action.type === 'register' ? 'the new agent\'s key' : 'the agent\'s signing key';
  const second = { setKey: 'the new key', recover: 'the new key', revive: 'the co-founder', second: 'the newcomer' }[action.type];
  return [first, ...(n > 1 ? [second] : []), ...(n > 2 ? ['the set recovery key'] : [])];
}
/**
 * Why `signatures` envelope signatures are not the program's exact count for `action`, or null. The
 * Ed25519 check takes exactly as many as the program requires (lib.rs `verify`): one too many is
 * refused on chain like one too few, so it is refused here, naming the one to drop (29 September).
 */
export function signatureRule(action, agent, signatures) {
  if (signatures === undefined) return null;
  const need = envelopeSignatures(action, agent), who = envelopeSigners(action, agent);
  if (signatures === need) return null;
  if (signatures < need) return need === 3 && signatures === 2 && action.type === 'setKey'
    ? 'changing or clearing a set recovery key needs that recovery key\'s signature as well'
    : `the program verifies exactly ${need} envelope signature${need > 1 ? 's' : ''} for this ${action.type}: ${who.join(', ')}`;
  const drop = action.type === 'setKey' && need === 2 ? 'the recovery key\'s signature: this key change keeps the recovery key (or sets the first one), which needs no consent'
    : `the signature${signatures - need > 1 ? 's' : ''} after the ${['first', 'second', 'third'][need - 1]}`;
  return `the program verifies exactly ${need} envelope signature${need > 1 ? 's' : ''} for this ${action.type} (${who.join(', ')}), and refuses ${signatures}: drop ${drop}`;
}
/**
 * Why a storage action by an agent with no seat on an active council is refused (lib.rs `signed`):
 * standing is a seat on an active council, named as the envelope's last account. A one-member
 * artifact is no seat, with one exception (owner, 30 September): in an artifact founded or claimed
 * alone, its one member's own seat is the proof for seconding the membership of its second member,
 * and for nothing else. Claiming requires a seat (29 September); founding without one is self-paid
 * (30 September).
 */
export function seatRule(type, art, id) {
  if (type === 'second' && art && art.members.length === 1 && art.members[0].id === String(id))
    return art.foundedAlone && art.open?.length
      ? 'a one-member artifact admits one candidate at a time: a vote is already open there, and its member seconds no other membership until it resolves'
      : art.foundedAlone
      ? 'a one-member artifact only admits: its member\'s own seat (named last, the artifact itself) proves standing for seconding a membership application, never a contribution'
      : 'this one-member artifact was once a council: it is revived with a co-founder, and its member seconds with a seat on another active council (two or more members)';
  const doing = { second: 'seconding', propose: 'proposing', create: 'founding', claim: 'claiming' }[type] ?? 'reviving';
  return `${doing} needs a seat on an active council (two or more members), named as the envelope's last account`;
}
/** Whether `seat`, the envelope's last account, is `id`'s own seat on the artifact it founded or
 *  claimed alone, proving standing for a membership second there while nothing is open there (lib.rs
 *  `founder_seat`, 30 September): one candidate second member at a time. */
export function founderSeat(action, accounts, seat, id) {
  return action.type === 'second' && action.payload?.kind === 'membership' && accounts.length >= 2 && String(accounts[0]) === String(accounts.at(-1))
    && !!seat && seat.foundedAlone && seat.members.length === 1 && seat.open.length === 0 && seat.members[0].id === String(id);
}
/**
 * What a self-paid batch's fee payer must hold (self-pay mode, owner 30 September), `worst` being what
 * its `transactions` take from it. The runtime checks the fee payer's rent after each transaction: none
 * may leave it with less than the rent-exempt minimum `floor` but more than nothing, and a key left
 * with nothing pays no later transaction. One transaction may take the key to nothing. Several (an
 * envelope and its page's chunk writes, or a resume's chunk writes, each far below `floor`) leave it
 * holding at least `floor`: `worst + floor`.
 */
export const feePayerNeeds = (worst, transactions, floor) => transactions > 1 ? worst + floor : worst;
/** What a self-paid envelope's signer is told to do (owner, 30 September, self-pay mode): its own key
 *  (or a wallet signing for it) is the fee payer of every transaction, so every deposit it creates is
 *  its own and comes back to it. A relay never pays for it and takes no payment. */
export const SELF_PAID = 'this action is self-paid: your key (funding.feePayer) is the fee payer and pays every deposit it creates, which returns to it when the account closes; the vault pays nothing and nothing is refunded. Sign each of "transactions" (their message bytes, base64) with that key and send the same request again with "feePayerSignatures" in the same order, or submit the transaction yourself with that key as fee payer';
/**
 * A self-paid proposal's escrow (governance.rs `open`, review 30 September): what its payer pays into
 * it for everything its outcome costs, so no resolver, relay, vault or share pays: the record's rent,
 * a refund for each roster ballot and one for each crank (a kick's resolution, then its lapse).
 */
export async function escrowFor(c, cfg, { record, voters, kick = false }) {
  return await rentOf(c.t)(record) + voters * cfg.g.REFUND + Math.floor(cfg.g.REFUND / 2) * (kick ? 2 : 1);
}
/** What is left in a proposal's escrow: its lamports above its rent (lib.rs `Ctx::escrow_for`); 0
 *  for a vault-funded proposal, which has none. */
export async function escrowLeft(c, address, p) {
  if (!p || p.funder === c.vault.toBase58()) return 0;
  const a = await c.t.getAccount(new PublicKey(address));
  return a ? Math.max(0, a.lamports - await rentOf(c.t)(a.data.length)) : 0;
}
/** What of a self-paid proposal's escrow no refund may take while its record is still to be written:
 *  that record's rent (lib.rs `Ctx::escrow_for`, `escrow_keep`). */
export async function escrowKeep(c, p) {
  return p && p.funder !== c.vault.toBase58() && p.reserved > 0 ? await rentOf(c.t)(p.reserved) : 0;
}
/** What a hosted newcomer's self-paid join is told when no gateway hosts it (lib.rs `register`). */
export const HOSTED_JOIN = 'a hosted identity is hosted by a registered gateway: a self-paid join of a hosted newcomer prefers its gateway (the envelope\'s "preferred", which the relay names in its relayer slot; the SDK\'s `gateway` option), or is sent by that gateway as fee payer';
// A deposit an escrow repays (`escrow: true`) is fronted by the payer and repaid in the same
// instruction: in `worst`, never in `net`.
const result = (reason, fee, deposits, refund, extra = {}) => {
  const sum = ds => ds.reduce((s, d) => s + d.lamports, 0), paid = sum(deposits.filter(d => !d.vault && !d.escrow)), vault = sum(deposits.filter(d => d.vault));
  return { funded: !reason, reason, fee, deposits, refund, worst: fee + deposits.reduce((s, d) => s + d.lamports, 0), net: fee + paid - refund,
    hold: { lamports: vault + refund, room: vault, pool: sum(deposits.filter(d => d.vault && d.newcomer)), actions: 0, bytes: 0, deposits: 0 }, ...extra };
};

/**
 * `envelope` is the signed message bytes or a decoded envelope. `signatures` is how many envelope
 * signatures the Ed25519 instruction carries, by default as many as the program requires
 * (`envelopeSignatures`); any other count is refused, as the program refuses it; `chunkWrites` the
 * chunk transactions the relay will send after a Begin. Returns { funded, refused, reason, fee,
 * deposits, refund, worst, net, atRisk } in lamports: `worst` is the most the relay can be out of
 * pocket, `net` what it is out of pocket if chain state does not move before the transaction lands.
 * `held` is what the caller's own transactions still in flight will take first: { lamports } of
 * the reserve, { room } of the week's deposit room and { pool } of the newcomers' pool (`book`), and
 * this agent's { actions, bytes } of monthly quota and { deposits } of its weekly share of the deposit
 * room; `hold` in the result is what this action adds to it.
 */
export async function vaultFunds(c, envelope, { payer, signatures, chunkWrites = 0, now, perSignature = PER_SIGNATURE, held = {} } = {}) {
  const env = Buffer.isBuffer(envelope) || envelope instanceof Uint8Array ? decodeEnvelope(Buffer.from(envelope)) : envelope;
  const t = c.t, rent = rentOf(t);
  now ??= Math.floor(await t.now());
  const [cfg, registered] = await Promise.all([c.config(), payer ? c.maybe(c.relayerAddress(payer), decodeRelayer) : false]);
  const b = book(c, cfg, now, held);
  const a = env.action;
  const agent = a.type === 'register' ? null : await c.agent(env.agent);
  // Price the signatures the program verifies and refunds (lib.rs `signed`): exactly that many, or
  // the program refuses the transaction and the relay pays for it (29 September).
  const required = envelopeSignatures(a, agent);
  const wrong = agent ? signatureRule(a, agent, signatures) : null;
  signatures = required;
  const fee = perSignature * (1 + signatures);
  const deposits = [];
  const need = async (account, size) => Math.max(0, await rent(size) - ((await t.getAccount(account))?.lamports ?? 0));
  // Self-pay mode (lib.rs `signed`, owner 30 September): the envelope says its payer pays.
  if (env.selfPaid) return selfPaid(c, env, a, agent, { fee, need, rent, chunkWrites, perSignature, wrong, cfg, now });
  if (a.type === 'register') {
    const trusted = a.hosted && registered?.trusted && registered.kind === 'gateway' &&
      (registered.regWeek !== weekOf(c, now) || registered.regs < cfg.g.GATEWAY_WEEK_REGISTRATIONS);
    const vault = !!trusted && take(b, await rent(SIZE.AGENT), 'newcomer');
    const deposit = vault ? await rent(SIZE.AGENT) : await need(c.agentAddress(env.agent), SIZE.AGENT);
    deposits.push({ account: c.agentAddress(env.agent).toBase58(), bytes: SIZE.AGENT, lamports: deposit, vault, newcomer: true });
    const amount = Math.floor(b.refund * (1 + signatures) / 2), refund = trusted && pay(b, amount) ? amount : 0;
    return result(vault && refund >= fee ? null : trusted && b.poolFull ? 'the newcomers\' weekly pool of the deposit room is spent: a hosted sign-up waits for the week to renew, or pays its own registration'
      : 'registration requires own funds or a trusted gateway within its weekly quota: sign it self-paid ("selfPaid": true), your key paying', fee, deposits, refund, { refused: !trusted });
  }
  if (!agent) return result('agent is not registered', fee, deposits, 0);
  // The ban gate comes before everything the program prices (lib.rs `signed`, 29 September).
  if (agent.status === 'banned') return result(BANNED, fee, deposits, 0, { refused: true });
  if (wrong) return result(wrong, fee, deposits, 0, { refused: true });
  // What the signer already drew on its weekly share (treasury.rs `charge_agent`), plus what its own
  // deposits still in flight will draw first, so two quotes never count on the same headroom.
  b.agentSpent = (agent.depositWeek === weekOf(c, now) ? agent.weekDeposits : 0) + (held.deposits ?? 0);
  // Standing is membership (lib.rs `sits_on`): the envelope ends with an active council whose raw
  // members list the agent. A one-member artifact's seat counts only for its remaining member's
  // revival (28 September).
  const month = Math.floor(now / (30 * (c.day ?? 86400)));
  const seat = env.accounts.length ? await c.artifact(env.accounts.at(-1)).catch(() => null) : null;
  const founder = !!seat && !((seat.active || a.type === 'revive') && seat.members.some(m => m.id === String(env.agent))) && founderSeat(a, env.accounts, seat, env.agent);
  const standing = !!seat && (((seat.active || a.type === 'revive') && seat.members.some(m => m.id === String(env.agent))) || founder);
  const count = k => agent.month === month ? agent[k] ?? 0 : 0;
  const pending = held.actions ?? 0, used0 = count('bytes') + (held.bytes ?? 0);
  // The allowance the program draws on (lib.rs `signed`, 26, 27 and 29 September): a vote or a
  // decline is always accepted; a key change and a recovery have allowances of their own; storage
  // needs a seated agent's quota (founding and claiming within MONTH_CREATES), or for a newcomer's
  // upload its upload allowance; anything else draws on the agent's actions, or for a newcomer the
  // newcomer allowance. Past its allowance an action is refused.
  const free = a.type === 'vote' || a.type === 'decline', keyChange = a.type === 'setKey';
  const creates = a.type === 'create' || a.type === 'claim';
  const storage = ['begin', 'create', 'propose', 'second', 'revive', 'claim'].includes(a.type);
  const roomLeft = standing && count('actions') + pending < cfg.g.MONTH_ACTIONS;
  // A founding without a seat is self-paid or nothing (owner, 30 September): the envelope must say so.
  if (a.type === 'create' && !standing) return result(SELF_FOUNDING, fee, deposits, 0, { refused: true });
  const draw = free ? 'free'
    : a.type === 'recover' ? (count('recovers') + pending < KEY_CHANGES_PER_MONTH ? 'recovers' : null)
    : keyChange ? (count('keys') + pending < KEY_CHANGES_PER_MONTH ? 'keys' : null)
    : storage && standing ? (roomLeft && (!creates || count('creates') < cfg.g.MONTH_CREATES) ? 'agent' : null)
    : storage ? (a.type === 'begin' && count('uploads') + pending < cfg.g.NEWCOMER_MONTH_UPLOADS ? 'uploads' : null)
    : roomLeft ? 'agent'
    : !standing && count('actions') + pending < cfg.g.NEWCOMER_MONTH_ACTIONS ? 'newcomer' : null;
  if (!draw && storage && !standing && a.type !== 'begin')
    return result(seatRule(a.type, env.accounts.length ? await c.artifact(env.accounts[0]).catch(() => null) : null, env.agent), fee, deposits, 0, { refused: true });
  if (!draw) return result(`the program refuses this ${a.type}: the agent's monthly allowance for it is spent`, fee, deposits, 0, { refused: true });
  const within = draw === 'agent' || draw === 'uploads';
  const room = Math.max(0, cfg.g.MONTH_BYTES - used0);
  let budget = within ? standing ? room : Number.MAX_SAFE_INTEGER : 0, used = 0, quota = false;
  // ctx.create: the vault pays when the byte budget, the reserve and the week's room all allow. The
  // reserve books the whole rent even when the address already holds lamports (treasury.rs `create`,
  // review round 6), so a donated address is refused exactly like an empty one.
  // A lone founder's membership second on its own seat draws its own deposits (a `join`'s registration)
  // from the newcomers' pool: it is not counted as eligible yet (lib.rs `signed`, review 30 September).
  const create = async (account, size, charge = size, kind = standing && !founder ? 'agent' : 'newcomer') => {
    let vault = false, refused = false;
    // An account the program already made (a later decline's record) takes no deposit.
    const made = (await t.getAccount(account))?.data?.length > 0;
    if (!made && budget - used >= charge) { vault = take(b, await rent(size), kind); refused = !vault; if (standing || vault) used += size; }
    else if (!made) quota = true;
    const lamports = made ? 0 : vault ? await rent(size) : await need(account, size);
    deposits.push({ account: account.toBase58(), bytes: size, lamports, vault, ...(refused && { refused }), ...(kind === 'newcomer' && { newcomer: true }) });
    return vault;
  };
  const x = env.accounts, key = k => new PublicKey(k);
  let uploadVault = false;
  try {
    switch (a.type) {
      case 'begin': uploadVault = await create(key(x[0]), SIZE.UPLOAD, SIZE.UPLOAD + a.len); if (uploadVault || standing) used += a.len; break;
      case 'create': {
        // The founding upload closes into the artifact: its booked deposit, never more than its rent,
        // returns to the share first, unless the newcomers' pool carried it (lib.rs `Create`,
        // treasury.rs `deposit_of`; review round 7).
        const u = await c.read(key(x[1]), decodeUpload);
        if (u.funder === c.vault.toBase58() && !u.newcomer)
          b.agentSpent = Math.max(0, b.agentSpent - Math.min(await rent(SIZE.UPLOAD), (await t.getAccount(key(x[1])))?.lamports ?? 0));
        await create(key(x[0]), SIZE.ARTIFACT);
        await create(key(x[3]), SIZE.RECORD + bytes(a.title));
        break;
      }
      // A claim writes its CLAIM record, the claimer's own deposit; no artifact deposit (29 September).
      case 'claim': await create(key(x[1]), SIZE.RECORD); break;
      // A decline writes the applicant's declines record on its first decline: never refused by the
      // room, the share or the byte quota, only by the pause and the reserve (owner, 29 September
      // review round; governance.rs `decline`), and never counted in the decliner's monthly bytes.
      case 'decline': { const u = used; await create(key(x[2]), SIZE.DECLINES, 0, 'decline'); used = u; break; }
      case 'second': {
        if (a.join) {
          // A member seconds at most MONTH_SECONDS newcomers a month (governance.rs `second`; review round 7).
          if (count('seconds') >= cfg.g.MONTH_SECONDS)
            return result(`the program refuses this second: the member has seconded ${cfg.g.MONTH_SECONDS} newcomers this month, the most it may`, fee, deposits, 0, { refused: true });
          await create(key(x[2]), SIZE.AGENT);
          if (a.join.len) { uploadVault = await create(key(x[3]), SIZE.UPLOAD, SIZE.UPLOAD + a.join.len); used += a.join.len; }
        }
      } // falls through: both allocate a proposal and reserve its future record
      case 'propose': {
        const art = await c.artifact(key(x[0]));
        const kind = a.payload.kind;
        if (braking(art, kind)) b.paused = false;
        // The signer's share carries the deposit and the record it reserves; the meta-council's are exempt.
        b.sharesProposals = art.id !== 0;
        const record = SIZE.RECORD + (kind === 'content' ? bytes(a.payload.title) : 0);
        b.reserved = await rent(record);
        const proposer = a.type === 'second' ? String(a.author) : String(env.agent);
        // Neither the proposer nor a kick's or ban's target is on the roster (28 and 29 September).
        const target = kind === 'kick' || kind === 'ban' ? String(a.payload.agent) : null;
        const voters = art.members.filter(m => m.id !== proposer && m.id !== target).length;
        const size = proposalSize(voters, a.payload, bytes(a.thread));
        // Kicks, and the meta-council's pause and bans, are never refused by the room (29 September);
        // a kick still draws on its proposer's share.
        const roomless = art.id === 0 && ['pause', 'ban'].includes(kind);
        const funded = await create(key(x[1]), size, size, kind === 'kick' ? 'kick' : roomless ? 'protocol' : 'governance');
        // The program charges the signer's share the deposit and the record it reserves
        // (governance.rs `open`): the in-flight hold carries both, so a second quote sees the record.
        if (funded && b.sharesProposals) { b.agentSpent += b.reserved; b.charged += b.reserved; }
        used += record;
        if (!standing || used > budget) quota = true;
        break;
      }
      case 'revive': await create(key(x[1]), SIZE.RECORD); break;
      case 'confirm': {
        if (!a.execute) break;
        const [art, prop] = await Promise.all([c.artifact(key(x[0])), c.proposal(key(x[1]))]);
        // A kick made before the last claim, or whose charged agent is banned, confirms stale: no
        // record, no deposit (governance.rs `confirm`, review round 9).
        const charged = prop.charged !== NO_KEY ? await c.agent(prop.charged) : null;
        const stale = prop.created < art.claimed || charged?.status === 'banned';
        // The kick record draws on what the proposal reserved, never on the confirming member's quota:
        // a protocol record.
        if (!stale && prop.payload.kind === 'kick' && art.members.some(m => m.id === prop.payload.agent) && art.members.length > 1) {
          const lamports = await rent(SIZE.RECORD);
          // A self-paid kick's record: fronted by the payer, repaid from the kick's escrow (review, 30 September).
          if (prop.funder !== c.vault.toBase58()) deposits.push({ account: x[3].toString(), bytes: SIZE.RECORD, lamports, vault: false, escrow: true });
          else deposits.push({ account: x[3].toString(), bytes: SIZE.RECORD, lamports, vault: take(b, lamports, 'protocol') });
        }
        break;
      }
      default: break;
    }
  } catch (e) { return result(`cannot price this action: ${e.message}`, fee, deposits, 0); }
  // A ballot on a self-paid proposal is refunded from its escrow (lib.rs `credit`, review 30 September).
  // Never out of the part held for its record (`escrow_keep`).
  const escrow = a.type === 'vote' ? await c.proposal(x[1]).then(async p => Math.max(0, await escrowLeft(c, x[1], p) - await escrowKeep(c, p))).catch(() => 0) : 0;
  // earn(): an accepted action pays the relayer the full refund after its deposits, if the reserve allows.
  let refund = 0, reason = null, fromEscrow = false;
  if (!registered) reason = 'this relay is not a registered relayer: the program refuses funded actions it cannot refund';
  else if (quota) reason = 'monthly byte quota does not cover this action';
  else if (deposits.some(d => !d.vault && !d.escrow && (d.lamports > 0 || d.refused))) reason = b.overShare ? 'this agent has used its share of the week\'s deposit room'
    : b.poolFull ? 'the newcomers\' weekly pool of the deposit room is spent: it frees as newcomers\' uploads close, and renews with the week; a council seat gives an agent a share of its own'
    : `reserve or weekly cap cannot cover the deposits: ${SELF_PAID_HINT}`;
  if (registered) {
    const amount = Math.floor(b.refund * (1 + signatures) / 2);
    if (amount > 0 && amount <= escrow) { refund = amount; fromEscrow = true; }
    else if (amount > 0 && pay(b, amount)) refund = amount;
    if (!reason && refund < fee) reason = refund ? 'the fixed refund does not cover this transaction\'s fee' : `the reserve cannot refund the fee: the program refuses the action rather than charge its relay; ${SELF_PAID_HINT}`;
  }
  const w = writes(b, chunkWrites, uploadVault, registered, perSignature);
  reason ??= w.reason;
  // Atomic failure protects deposits. The relay ceiling must still reserve failed network fees.
  const r = result(reason, fee + w.fee, deposits, refund + w.refund, { chunkWrites });
  r.atRisk = fee + w.fee; // Failed transactions can lose fees, never treasury deposits.
  if (fromEscrow) { r.hold.lamports -= refund; r.escrowRefund = true; }
  r.hold.actions = draw === 'free' ? 0 : 1; r.hold.agent = agent.id; r.hold.bytes = used; r.hold.deposits = b.charged;
  return r;
}

/** What an agent is told when the treasury cannot fund its action (owner, 30 September). */
export const SELF_PAID_HINT = 'sign it self-paid ("selfPaid": true) and pay it with your own key, which is how everything works when the treasury is empty';
/** Why a founding without a seat is refused unless self-paid (lib.rs `signed`, owner 30 September). */
export const SELF_FOUNDING = 'founding without a seat on an active council is self-paid: sign the create (and the begin of its page) with "selfPaid": true, your own key paying the deposits and fees, or name a seat for a vault-funded founding';
/**
 * A self-paid envelope's quote (lib.rs `Draw::SelfPaid`/`Founds`, owner 30 September): its fee payer
 * pays the fee and every deposit it creates, and nothing is refunded or drawn from the vault, a share,
 * the newcomers' pool or a quota. `worst` is what the envelope and its `chunkWrites` take from the fee
 * payer's key, `needs` what that key must hold for them (`feePayerNeeds`), and `feePayer` the key a
 * relay makes the fee payer by default, the envelope's first signer (lib.rs `signed`): the new key
 * for a registration, the recovery key for a recovery (never the key it replaces), otherwise the
 * agent's signing key. `payTo` is absent: no relay is paid. The limits that are not about vault money
 * still hold: a founding or a claim counts one of MONTH_CREATES, a claim needs a seat, and the rest
 * (slots, seats, bans, frame caps) is `exactRefusal`'s.
 */
async function selfPaid(c, env, a, agent, { fee, need, rent, chunkWrites, perSignature, wrong, cfg, now }) {
  const x = env.accounts, key = k => new PublicKey(k), deposits = [];
  const refuse = reason => result(reason, fee, deposits, 0, { refused: true, selfPaid: true });
  const own = async (account, size) => { const made = (await c.t.getAccount(key(account)))?.data?.length > 0;
    deposits.push({ account: key(account).toBase58(), bytes: size, lamports: made ? 0 : await need(key(account), size), vault: false }); };
  if (a.type !== 'register') {
    if (!agent) return result('agent is not registered', fee, deposits, 0, { refused: true, selfPaid: true });
    if (agent.status === 'banned') return refuse(BANNED);
    if (wrong) return refuse(wrong);
  }
  const month = Math.floor(now / (30 * (c.day ?? 86400)));
  const creates = agent && agent.month === month ? agent.creates : 0;
  try {
    switch (a.type) {
      case 'register': await own(c.agentAddress(env.agent), SIZE.AGENT); break;
      case 'begin': await own(x[0], SIZE.UPLOAD); break;
      case 'create': {
        if (creates >= cfg.g.MONTH_CREATES) return refuse(`the program refuses this create: the agent has founded or claimed ${cfg.g.MONTH_CREATES} artifacts this month, the most it may`);
        const u = await c.maybe(key(x[1]), decodeUpload).catch(() => null);
        if (!u) return refuse('cannot price this action: the founding page\'s upload does not exist');
        if (u.funder === c.vault.toBase58()) return refuse('a self-paid founding takes a self-paid page: stage it with a self-paid begin ("selfPaid": true); an upload the vault or the newcomers\' pool funded is refused');
        await own(x[0], SIZE.ARTIFACT); await own(x[3], SIZE.RECORD + bytes(a.title));
        break;
      }
      case 'claim': {
        if (creates >= cfg.g.MONTH_CREATES) return refuse(`the program refuses this claim: the agent has founded or claimed ${cfg.g.MONTH_CREATES} artifacts this month, the most it may`);
        await own(x[1], SIZE.RECORD); break;
      }
      // A self-paid application writes the declines record its answer may need, if none exists yet
      // (governance.rs `apply`): its decline then takes no record from the reserve.
      case 'apply': await own(x[1], SIZE.DECLINES); break;
      case 'decline': await own(x[2], SIZE.DECLINES); break;
      case 'revive': await own(x[1], SIZE.RECORD); break;
      case 'second': {
        // A one-member artifact's member seconds only with a seat proof, self-paid or not (governance.rs
        // `second`, review 30 September): its own seat where it founded or claimed alone, else a seat
        // on another active council.
        const art = await c.artifact(key(x[0]));
        if (art.members.length === 1) {
          const seat = x.length > (a.payload.kind === 'content' ? 4 : 3) ? await c.artifact(key(x.at(-1))).catch(() => null) : null;
          const seated = !!seat && seat.active && seat.members.some(m => m.id === String(env.agent));
          if (!seated && !founderSeat(a, x, seat, env.agent)) return refuse(seatRule('second', art, env.agent));
        }
      }
      if (a.type === 'second' && a.join) {
        // A hosted identity is hosted by a registered gateway: a self-paid join prefers it (lib.rs
        // `register`), whoever pays; one the gateway sends as fee payer is priced as the vault's.
        if (a.join.hosted && (env.preferred === NO_KEY || (await c.maybe(c.relayerAddress(env.preferred), decodeRelayer).catch(() => null))?.kind !== 'gateway'))
          return refuse(HOSTED_JOIN);
        await own(x[2], SIZE.AGENT); if (a.join.len) await own(x[3], SIZE.UPLOAD);
      } // falls through
      case 'propose': {
        const art = await c.artifact(key(x[0])), kind = a.payload.kind;
        const proposer = a.type === 'second' ? String(a.author) : String(env.agent);
        const target = kind === 'kick' || kind === 'ban' ? String(a.payload.agent) : null;
        const voters = art.members.filter(m => m.id !== proposer && m.id !== target).length;
        await own(x[1], proposalSize(voters, a.payload, bytes(a.thread)));
        // The escrow paid into it for its outcome; what is not spent returns with its deposit.
        deposits.push({ account: key(x[1]).toBase58(), bytes: 0, escrowed: true, vault: false,
          lamports: await escrowFor(c, cfg, { record: SIZE.RECORD + (kind === 'content' ? bytes(a.payload.title) : 0), voters, kick: kind === 'kick' }) });
        break;
      }
      case 'confirm': if (a.execute) {
        // A self-paid kick's record is repaid from its escrow; another's is this payer's own.
        const p = await c.proposal(key(x[1])).catch(() => null);
        if (p && p.funder !== c.vault.toBase58()) deposits.push({ account: key(x[3]).toBase58(), bytes: SIZE.RECORD, lamports: await need(key(x[3]), SIZE.RECORD), vault: false, escrow: true });
        else await own(x[3], SIZE.RECORD);
      } break;
      default: break;
    }
  } catch (e) { return refuse(`cannot price this action: ${e.message}`); }
  const feePayer = a.type === 'register' ? String(env.agent) : a.type === 'recover' ? base58(agent.recovery) : agent.signer;
  const r = result(SELF_PAID, fee + chunkWrites * perSignature, deposits, 0, { selfPaid: true, chunkWrites, transactions: 1 + chunkWrites, feePayer });
  r.needs = feePayerNeeds(r.worst, r.transactions, await rent(0));
  r.funded = false; r.atRisk = 0; r.hold = { lamports: 0, room: 0, pool: 0, actions: 0, bytes: 0, deposits: 0 };
  return r;
}

/** What the relay tells an agent whose self-paid upload it finishes (resume, a recovered begin). */
export const SELF_PAID_WRITES = 'this upload is self-paid (its deposit is not the vault\'s), so its chunk writes are paid by its owner\'s key as fee payer and nothing is refunded: sign each of "transactions" with that key and send the same request again with "feePayerSignatures", or write the chunks yourself';
/** Chunk writes the relay would send for an existing upload (resume, recovered uploads). A self-paid
 *  upload's (not vault-funded) are quoted `selfPaid`, like its begin: its owner's key is their fee
 *  payer (30 September, self-pay mode), one transaction each (`needs`: `feePayerNeeds`). */
export async function chunkWritesFunded(c, upload, count, { payer, now, perSignature = PER_SIGNATURE, held = {} } = {}) {
  now ??= Math.floor(await c.t.now());
  const [cfg, u, registered] = await Promise.all([c.config(), c.read(upload, decodeUpload), payer ? c.maybe(c.relayerAddress(payer), decodeRelayer) : false]);
  const vaultFunded = u.funder === c.vault.toBase58();
  const w = writes(book(c, cfg, now, held), count, vaultFunded, registered, perSignature);
  if (vaultFunded) { const r = result(w.reason, w.fee, [], w.refund, { chunkWrites: count }); r.atRisk = r.worst; return r; }
  const owner = await c.agent(u.owner);
  const r = result(SELF_PAID_WRITES, w.fee, [], 0, { chunkWrites: count, transactions: count, selfPaid: true, feePayer: owner?.signer ?? u.owner });
  r.needs = feePayerNeeds(r.worst, count, await rentOf(c.t)(0));
  r.funded = false; r.atRisk = 0; r.hold = { lamports: 0, room: 0, pool: 0, actions: 0, bytes: 0, deposits: 0 };
  return r;
}

// ---- cranks and snapshot rounds -----------------------------------------------------------------
const clears = (a, r, of, ab, rb) => of > 0 && a * 10_000 > of * ab && r * 10_000 < of * rb;
const pk = k => new PublicKey(k);
const quote = ({ refused = null, reason = null, fee, refund = 0, deposits = [], work = 0, paid = 0 }) => {
  // A deposit an escrow repays is fronted by the payer: in `worst`, never in `net`.
  const vault = deposits.filter(d => d.vault), own = deposits.filter(d => !d.vault && !d.escrow), fronted = deposits.filter(d => d.escrow);
  const lamports = s => s.reduce((n, d) => n + d.lamports, 0);
  reason = refused ?? reason;
  return { funded: !reason, refused: !!refused, reason, fee, refund, deposits, work, worst: fee + lamports(own) + lamports(fronted), net: fee + lamports(own) + paid - refund,
    atRisk: fee, vaultDeposits: lamports(vault) };
};
/** What the program does with a resolution of `p` on `art` now (governance.rs `resolve`): whether it
 *  may run, and which accounts it writes. `agents` holds the records it reads (charged, subject,
 *  seconded author). */
function resolution(p, art, agents, now) {
  const banned = id => agents[id]?.status === 'banned';
  const kind = p.payload.kind;
  let voidp = p.created < art.claimed || (p.charged !== NO_KEY && banned(p.charged));
  if (kind === 'content' && p.seconded) voidp ||= banned(p.proposer);
  if (kind === 'membership') voidp ||= banned(p.payload.agent);
  const { approve, reject, seats } = counted(p, art);
  voidp ||= seats === 0;
  const closed = now >= p.closes, early = !voidp && clears(approve, reject, seats, p.approveBps, p.rejectBps);
  if (!early && !closed && !voidp) return { waits: true };
  const pass = !voidp && (early || clears(approve, reject, approve + reject, p.approveBps, p.rejectBps));
  const active = art.members.length >= 2;
  const live = pass && (active || (art.members.length === 1 && kind === 'membership'));
  return { pass, live, voidp };
}

/**
 * What a crank costs the relay that sends it (rewards.rs `crank`). `name` is a layout.mjs CRANK
 * name, `extra` the accounts after the prefix, as the SDK sends them. Every crank but ClaimWork is
 * housekeeping (`earn_protocol`): half the refund for its one signature, from the reserve, and it
 * runs unrefunded rather than refused when the reserve cannot cover it (29 September). The program
 * refuses housekeeping from a payer with no relayer record, which it could not refund. Resolve,
 * CloseEpoch and a failed membership vote's declines record draw protocol deposits from the vault;
 * `work` is the relay work units it credits: none for ClaimWork, ExpireUpload, or an expired
 * application that charged no skip (D5). Returns { funded, refused, reason, fee, refund, deposits,
 * work, worst, net, atRisk }; `funded` means refunded in full.
 */
export async function crankFunds(c, name, extra = [], { payer, now, perSignature = PER_SIGNATURE, held = {}, selfPaid = false } = {}) {
  const t = c.t, rent = rentOf(t), day = c.day ?? 86400;
  now ??= Math.floor(await t.now());
  const [cfg, registered] = await Promise.all([c.config(), payer ? c.maybe(c.relayerAddress(payer), decodeRelayer) : null]);
  const b = book(c, cfg, now, held), fee = perSignature, deposits = [];
  const need = async (account, size) => Math.max(0, await rent(size) - ((await t.getAccount(account))?.lamports ?? 0));
  // `reserved` false: a record no reservation holds never comes from the vault. A self-paid proposal's
  // records come out of its escrow (`escrow` left in it): the payer fronts them and is repaid.
  // `keep`: the record's rent a refund may not take while the record is still to be written.
  let escrow = null, keep = 0;
  const deposit = async (account, size, reserved = true) => { const lamports = await need(account, size);
    if (escrow !== null && lamports > 0) {
      // Only what the escrow still holds is repaid; any rest would be the payer's own (never, while
      // the program keeps the record's rent out of refunds).
      const back = Math.min(lamports, escrow); escrow -= back; keep = 0;
      deposits.push({ account: pk(account).toBase58(), bytes: size, lamports: back, vault: false, escrow: true });
      if (lamports > back) deposits.push({ account: pk(account).toBase58(), bytes: 0, lamports: lamports - back, vault: false });
      return;
    }
    deposits.push({ account: pk(account).toBase58(), bytes: size, lamports, vault: lamports === 0 || (reserved && take(b, lamports, 'protocol')) }); };
  const refuse = refused => quote({ refused, fee, deposits });
  let work = 1;
  try {
    switch (name) {
      case 'claimWork': {
        // No refund: each relay claims only its own share, and only one worth more than its fee.
        const [e, r] = await Promise.all([c.read(extra[0], decodeEpoch), c.read(extra[1], decodeRelayer)]);
        const w = r.work.find(w => w.epoch === e.workKey && w.units > 0 && !w.claimed);
        if (!w) return refuse('the relayer has no unclaimed work in this epoch');
        const amount = Math.floor(e.relayerPool * w.units / Math.max(1, e.work));
        return { ...quote({ fee, work: 0 }), reward: amount, funded: amount > fee, reason: amount > fee ? null : 'the share is worth less than the claim\'s fee' };
      }
      case 'resolve': {
        const [art, p] = await Promise.all([c.read(extra[0], decodeArtifact), c.read(extra[1], decodeProposal)]);
        if (p.status !== 'voting') return refuse(`the proposal is no longer voting (${p.status})`);
        if (p.funder !== c.vault.toBase58()) escrow = await escrowLeft(c, extra[1], p);
        const ids = [p.charged, p.proposer, p.payload.agent].filter(k => k && k !== NO_KEY);
        const agents = Object.fromEntries(await Promise.all(ids.map(async id => [id, await c.agent(id)])));
        const r = resolution(p, art, agents, now);
        if (r.waits) return refuse('the proposal is still voting and has not cleared early');
        // A passed kick only opens its confirmation window: its record's rent stays held for the confirm.
        if (r.live && p.payload.kind === 'kick') keep = await escrowKeep(c, p);
        if (braking(art, p.payload.kind)) b.paused = false;
        const record = L.SIZE.RECORD_BASE + (p.payload.kind === 'content' ? bytes(p.payload.title) : 0);
        const kind = p.payload.kind;
        if (kind === 'membership') {
          const admits = r.live && !art.members.some(m => m.id === p.payload.agent) && art.members.length < L.MAX_COUNCIL;
          // A vote that does not admit counts as a decline: the applicant's declines record, a protocol deposit (29 September, D1).
          if (admits) await deposit(extra[3], record, p.reserved >= record);
          else if (agents[p.payload.agent]?.status !== 'banned') await deposit(c.declinesAddress(p.artifact, p.payload.agent), SIZE.DECLINES);
        } else if (r.live && kind === 'content') {
          const u = await c.read(p.payload.upload, decodeUpload);
          if (!u.complete && now < p.closes && !r.voidp) return refuse('the upload\'s text is still arriving: no early verdict before it is complete');
          if (u.complete && art.versions[p.payload.page - 1] === p.baseVersion && p.payload.page <= art.pages + 1) await deposit(extra[3], record, p.reserved >= record);
        } else if (r.live && kind !== 'kick' && !(kind === 'ban' && agents[p.payload.agent]?.status === 'banned')) {
          // A passed kick only opens its confirmation window. A settings, link or global patch that no
          // longer fits resolves stale without its record: priced as written, the worst case.
          await deposit(extra[3], record, p.reserved >= record);
        }
        break;
      }
      case 'expire': {
        const p = await c.read(extra[1], decodeProposal);
        if (p.status !== 'confirmation_pending') return refuse(`only a kick awaiting confirmation expires (${p.status})`);
        if (p.funder !== c.vault.toBase58()) escrow = await escrowLeft(c, extra[1], p);
        if (now < L.kickDeadline(cfg, p, now)) return refuse('the kick\'s confirmation window is still open (a meta-council pause holds it open, and reopens it after the lift)');
        break;
      }
      case 'closeEpoch': {
        if (now < cfg.epochStart + cfg.g.EPOCH_SECS) return refuse('the epoch is not due to close yet');
        // The close recognises income first (treasury.rs `allocate`): half of it refills a reserve short
        // of its target before the epoch record and the refund are paid (owner, 29 September).
        const committed = cfg.reserve + cfg.liabilities + cfg.carryRelayer + cfg.carryHolder;
        const income = Math.max(0, await c.vaultBalance() - await rent(0) - committed);
        b.reserve += Math.min(Math.floor(income / 2), Math.max(0, reserveTarget(rolled(c, cfg, now)) - cfg.reserve));
        // The pause never stops a close (rewards.rs `close_epoch`, review round 9): only Pay.
        b.paused = false;
        await deposit(extra[0], SIZE.EPOCH);
        break;
      }
      case 'retire': {
        const e = await c.read(extra[0], decodeEpoch);
        if (cfg.distributing === e.n || !(e.claimedWork === e.work || e.relayerPaid === e.relayerPool || now >= e.end + day))
          return refuse('the epoch still has relayer work to claim, for a day after it ended');
        break;
      }
      case 'applyGlobal': if (!cfg.pending.some(q => q.at <= now)) return refuse('no global setting change is due'); break;
      // Anyone can make a vault-owned wrapped-SOL account for its rent: an unwrap earns no work unit.
      case 'unwrap': work = 0; break;
      case 'expireUpload': {
        // Expiry drops the work the upload held and earns none itself (29 September).
        const u = await c.read(extra[0], decodeUpload);
        if (u.locked !== NO_KEY || now < u.expires) return refuse('the upload is locked to a proposal or has not expired');
        // A self-paid upload's expiry is never refunded (rewards.rs `ExpireUpload`, owner 30 September):
        // its deposit returns to the payer that funded it.
        if (u.funder !== c.vault.toBase58()) return quote({ reason: 'a self-paid upload\'s expiry is never refunded: its deposit returns to the payer that funded it', fee });
        work = 0;
        break;
      }
      case 'expireApplication': {
        // One work unit only when it charges a skip: a member seated when the application arrived,
        // not charged a skip in the day before its expiry, no pause on now nor when it fell due
        // (governance.rs `expire_application`, D3, D5; owner, 29 September; review, 30 September).
        const [art, a] = await Promise.all([c.read(extra[0], decodeArtifact), c.read(extra[1], decodeAgent)]);
        const slot = a.applications.find(s => s.artifact === pk(extra[0]).toBase58());
        if (!slot) return refuse('the agent holds no application to this artifact');
        const due = slot.at + L.APPLICATION_TTL_DAYS * day;
        if (now < due) return refuse(`the application is open until ${new Date(due * 1000).toISOString()}`);
        const seated = art.members.some(m => m.id === a.id);
        work = !seated && !unanswerable(cfg, due, now) && art.members.some(m => m.joined <= slot.at && due >= m.lastSkip + day) ? 1 : 0;
        break;
      }
      case 'pruneBanned': {
        const [art, a] = await Promise.all([c.read(extra[0], decodeArtifact), c.read(extra[1], decodeAgent)]);
        if (a.status !== 'banned') return refuse('the agent is not banned');
        if (!art.members.some(m => m.id === a.id)) return refuse('the banned agent holds no seat here');
        if (art.id === 0 && art.members.length === 1) return refuse('the meta-council keeps its last member');
        break;
      }
      default: return refuse(`unknown crank ${name}`);
    }
  } catch (e) { return quote({ reason: `cannot price this crank: ${e.message}`, fee, deposits }); }
  // Self-paid housekeeping (rewards.rs `crank` with the self-paid byte, owner 30 September): the vault
  // funds what it would, the caller pays the rest and its own fee; no refund, no work, any payer.
  if (selfPaid) return { ...quote({ reason: SELF_PAID_CRANK, fee, deposits }), selfPaid: true };
  if (!registered) return refuse('this relay is not a registered relayer: the program refuses housekeeping it cannot refund (anyone may run it self-paid, paying its own fee)');
  if (deposits.some(d => !d.vault && !d.escrow)) return refuse(`the reserve cannot fund this crank's protocol deposits (or the meta-council's pause stops them): ${SELF_PAID_CRANK}`);
  // A crank of a self-paid proposal is refunded from its escrow and earns no work (lib.rs `credit`).
  const amount = Math.floor(b.refund / 2);
  if (escrow !== null && amount <= escrow - keep) return quote({ reason: amount < fee ? 'the fixed refund does not cover this transaction\'s fee' : null, fee, refund: amount, deposits, work: 0 });
  if (escrow !== null) work = 0;
  const refund = pay(b, amount) ? amount : 0;
  return quote({ reason: refund ? refund < fee ? 'the fixed refund does not cover this transaction\'s fee' : null : 'the reserve cannot refund it: housekeeping runs unrefunded',
    fee, refund, deposits, work });
}

/**
 * What a snapshot instruction costs the relay that sends it (snapshots.rs). `op` is a layout.mjs
 * SNAPSHOT_OPS name. Seat management (Join, Activate, Leave, Withdraw) is the relay's own business
 * and never refunded: Join pays the seat's rent and bond, returned on Withdraw, and the book's rent on
 * the first join, which is never returned (no instruction closes the book: `returned` leaves it out),
 * from `funder` when another key funds the seat (our two launch seats are genesis seats instead, below). Every distribution-phase transaction (Fix, Commit, Reveal, Veto,
 * Pay, Expire) is refunded from the pot, one frozen fee each, within the fee reserve frozen at the
 * close; past it the fee goes unrefunded without failing. A refund needs a registered relayer. Prune
 * and Close are housekeeping, refunded from the reserve. The first revealer of a result pays for its
 * candidate account, returned on Close. `leaves`: how many leaves a Pay carries. `op` 'genesis' is
 * the setup key's Setup::Seat of `relay` before FinishSetup (owner, 30 September).
 */
/** What a caller is told when housekeeping needs a deposit the vault cannot fund (owner, 30 September). */
export const SELF_PAID_CRANK = 'run it self-paid ("selfPaid": true: the crank data ends with the self-paid byte): the vault funds what it can, your key pays the rest and its own fee, nothing is refunded, and governance and epochs never wait on treasury funds';
/** What Withdraw gives back of a seat's deposits: the seat's rent and bond. The book's rent (`kept`) stays: no
 *  instruction closes the book. */
const seatReturned = deposits => deposits.reduce((n, d) => d.kept ? n : n + d.lamports, 0);
export async function snapshotFunds(c, op, { payer, funder, relay, leaves = 0, candidate, now, perSignature = PER_SIGNATURE, selfPaid = false } = {}) {
  const t = c.t, rent = rentOf(t);
  now ??= Math.floor(await t.now());
  const payerKey = payer ? pk(payer.publicKey ?? payer).toBase58() : null;
  const [cfg, registered, bk, own] = await Promise.all([c.config(), payerKey ? c.maybe(c.relayerAddress(payerKey), decodeRelayer) : null, c.book(),
    payerKey ? c.attestor(payerKey) : null]);
  const fee = perSignature, deposits = [];
  // Every seat instruction first settles the seat's previous stance: a paid result earns its one
  // work unit then (snapshots.rs `settle_seat`, owner 29 September).
  const st = own?.stance, settles = !!st?.epoch1 && st.epoch1 - 1 !== cfg.distributing && !!bk
    && Buffer.from(L.verdictOf(bk, st.epoch1 - 1) ?? []).equals(Buffer.from(st.hash)) ? 1 : 0;
  const need = async (account, size) => Math.max(0, await rent(size) - ((await t.getAccount(account))?.lamports ?? 0));
  const refuse = refused => quote({ refused, fee, deposits });
  const e = cfg.distributing === null ? null : await c.maybe(c.epochAddress(cfg.distributing), decodeEpoch);
  // A distribution fee: the frozen fee, while the fee reserve and the pot both hold it (snapshots.rs `pot_fee`).
  const potFee = () => {
    if (!bk || !e) return { refused: 'no distribution is running' };
    const room = bk.reserveUsed + bk.fee <= bk.reserve && e.potPaid + bk.fee <= e.pot;
    if (!room) return { reason: 'the round\'s fee reserve is spent: this fee goes unrefunded', refund: 0 };
    if (!registered) return { refused: 'this relay is not a registered relayer: the program refuses a distribution fee it cannot refund' };
    return { refund: bk.fee, reason: bk.fee < fee ? 'the frozen fee does not cover this transaction\'s fee' : null };
  };
  // Self-paid housekeeping: no refund from the reserve or the pot, no work, any payer (snapshots.rs).
  if (selfPaid && ['prune', 'close', 'fix', 'expire', 'pay'].includes(op)) {
    if (['fix', 'expire'].includes(op) && (!bk || !e)) return refuse('no distribution is running');
    if (op === 'pay' && (!bk?.armed || !e)) return refuse('no armed result to pay');
    return { ...quote({ reason: SELF_PAID_CRANK, fee }), selfPaid: true };
  }
  switch (op) {
    case 'genesis': {
      // Setup::Seat (owner, 30 September: holders are paid from the first day): before FinishSetup the
      // setup key (`payer`) seats the registered relay `relay`, active at once; it pays the seat's rent and
      // the bond, returned to it on Withdraw, and the book's rent on the first seat, never returned.
      if (cfg.setup === NO_KEY) return refuse('setup is finished: a new seat joins and matures for 7 days (snapshot-rewards.mjs join)');
      if (payerKey !== cfg.setup) return refuse('only the setup key seats a relay before FinishSetup');
      if (cfg.mint === NO_KEY) return refuse('snapshot rewards start once the mint is set');
      const r = relay ? pk(relay.publicKey ?? relay).toBase58() : null;
      if (!r || !await c.maybe(c.relayerAddress(r), decodeRelayer)) return refuse('only a registered relayer takes a seat');
      if (await c.attestor(r)) return refuse('this relay already holds a seat');
      if (!bk) deposits.push({ account: c.bookAddress.toBase58(), bytes: SIZE.BOOK, lamports: await need(c.bookAddress, SIZE.BOOK), vault: false, own: true, kept: true });
      deposits.push({ account: c.attestorAddress(r).toBase58(), bytes: SIZE.ATTESTOR, lamports: await need(c.attestorAddress(r), SIZE.ATTESTOR), vault: false, own: true });
      deposits.push({ account: c.attestorAddress(r).toBase58(), bytes: 0, lamports: L.bond(rolled(c, cfg, now), bk?.active ?? 0, bk?.potAvg ?? 0), vault: false, own: true, bond: true });
      const q = quote({ reason: 'seat management is never refunded', fee, deposits });
      return { ...q, returned: seatReturned(deposits) };
    }
    case 'join': {
      if (cfg.mint === NO_KEY) return refuse('snapshot rewards start once the mint is set');
      if (!registered) return refuse('only a registered relayer takes a seat');
      const w = registered.work[0];
      if (!(w?.units > 0 && w.epoch + L.SNAPSHOT.CREDIT_EVERY >= cfg.workKey)) return refuse('a seat needs relay work credited in the last 48 epochs');
      const seat = await c.attestor(payerKey);
      // A seat not active is topped up, a leaving one too: it may return within UNBOND (owner, 29 September).
      if (seat?.state === 'active') return refuse('the seat is active: only a seat not active is topped up');
      const own = !funder || pk(funder.publicKey ?? funder).toBase58() === payerKey;
      if (!bk) deposits.push({ account: c.bookAddress.toBase58(), bytes: SIZE.BOOK, lamports: await need(c.bookAddress, SIZE.BOOK), vault: false, own, kept: true });
      if (!seat) deposits.push({ account: c.attestorAddress(payerKey).toBase58(), bytes: SIZE.ATTESTOR, lamports: await need(c.attestorAddress(payerKey), SIZE.ATTESTOR), vault: false, own });
      // The bond follows the reserve target of the last completed weeks: Join rolls the week first.
      const bond = Math.max(0, L.bond(rolled(c, cfg, now), bk?.active ?? 0, bk?.potAvg ?? 0) - (seat?.bond ?? 0));
      if (bond) deposits.push({ account: c.attestorAddress(payerKey).toBase58(), bytes: 0, lamports: bond, vault: false, own, bond: true });
      const q = quote({ reason: 'seat management is never refunded', fee, deposits: deposits.filter(d => d.own) });
      return { ...q, deposits, returned: seatReturned(deposits) };
    }
    case 'activate': case 'leave': case 'withdraw': {
      if (!own) return refuse('this relay holds no seat');
      // A seat leaves once the round of its own reveal is over, its stance settled (snapshots.rs `leave`).
      if (op === 'leave' && st?.epoch1 && st.epoch1 - 1 === cfg.distributing)
        return refuse('the seat revealed in the round still being distributed: it leaves once that round is paid or expires, and a paid reveal\'s unit is credited then');
      return quote({ reason: 'seat management is never refunded', fee, work: settles });
    }
    case 'prune': case 'close': {
      // Housekeeping: refunded from the reserve, no work unit (snapshots.rs).
      if (!registered) return refuse('this relay is not a registered relayer: the program refuses housekeeping it cannot refund');
      const amount = Math.floor(cfg.g.REFUND / 2), refund = amount <= cfg.reserve ? amount : 0;
      return quote({ reason: refund ? null : 'the reserve cannot refund it: housekeeping runs unrefunded', fee, refund });
    }
    case 'fix': case 'expire': case 'commit': case 'veto': case 'reveal': {
      const f = potFee();
      if (f.refused) return refuse(f.refused);
      if (op === 'reveal' && candidate && !await c.maybe(candidate, decodeCandidate))
        deposits.push({ account: pk(candidate).toBase58(), bytes: SIZE.CANDIDATE, lamports: await need(pk(candidate), SIZE.CANDIDATE), vault: false });
      return quote({ ...f, fee, deposits, work: ['commit', 'reveal', 'veto'].includes(op) ? settles : 0 });
    }
    case 'pay': {
      // The fee comes out of the pot for every payment; a work unit per BATCH leaves paid.
      if (!bk?.armed || !e) return refuse('no armed result to pay');
      if (!registered) return refuse('this relay is not a registered relayer: the program refuses a distribution fee it cannot refund');
      if (now < bk.ready) return refuse('the checking delay has not passed');
      const cand = await c.maybe(c.candidateAddress(e.n, bk.armed), decodeCandidate);
      const index = e.leavesPaid, last = Math.min(index + leaves, cand?.count ?? index + leaves);
      const done = cand && last === cand.count, B = L.SNAPSHOT.BATCH;
      const work = Math.floor(last / B) - Math.floor(index / B) + (done && last % B !== 0 ? 1 : 0);
      return quote({ reason: bk.fee < fee ? 'the frozen fee does not cover this transaction\'s fee' : null, fee, refund: bk.fee, work });
    }
    default: return refuse(`unknown snapshot instruction ${op}`);
  }
}
