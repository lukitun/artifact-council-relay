// Words for the program's refusals, which it answers with one bare error whatever the rule.
//
// `exactRefusal` names only rules that, once broken, stay broken until the action executes: what the
// signed bytes say (a title too long, a kick of oneself), what the agent's own record says that only
// its own nonce-bound actions change (its recovery key, its open slots), and what never reverts (a
// proposal's proposer and frozen roster, a ballot cast, a window closed, an upload's owner and its
// expiry, set once at `begin`, a council's third decline of an applicant, a ban, the meta-council never
// claimed). A relay may refuse on these before anything is signed or sent. Everything that other
// agents' actions or time can change (membership, open slots, allowances, the deposit room) is
// `explainRefusal`'s alone:
// it only explains a refusal the program has already made, and never refuses in advance.
//
// The words follow the program's rules as of 29 September: one founder, a one-member artifact may
// only admit, a kick's or ban's target is not on its roster, a set recovery key consents to its
// change, a recovery has its own allowance, each agent has a weekly share of the deposit room, a
// banned agent signs nothing, every application is answered (seconded, declined, withdrawn, or
// expired by the crank), and an artifact left with no members is claimed, not applied to. Since 30
// September an agent without a seat founds on its own funds, and the one member of an artifact
// founded alone seconds its second member's membership with its own seat there. Self-pay mode (owner,
// 30 September): an action signed `selfPaid` draws on no allowance, share or pool and is never
// refused by an empty reserve; only the limits that are not about vault money hold for it.
import * as L from './layout.mjs';
import { signatureRule, seatRule, founderSeat, BANNED, SELF_FOUNDING, SELF_PAID_HINT, HOSTED_JOIN } from './funding.mjs';
export { SELF_PAID_HINT };

const ZERO = '11111111111111111111111111111111';
const META = L.META_KINDS;
const { MAX_OPEN, MAX_COUNCIL, MAX_LINKS, MAX_THREAD, APPLICATION_TTL_DAYS, REAPPLY_DAYS, MAX_DECLINES } = L;
const MAX_FRAME = L.MAX_TEXT + 12, FREE_PAGES = 3;
// (minimum, maximum) of each council and global setting: layout.mjs holds the one JS copy of
// state.rs COUNCIL_BOUNDS and GLOBAL_BOUNDS, so these words cannot drift from what the program takes.
const councilBounds = Object.fromEntries(L.C.map((k, i) => [k, L.COUNCIL_BOUNDS[i]]));
const globalBounds = day => Object.fromEntries(L.G.map((k, i) => [k, L.globalBounds(day)[i]]));
/** The first setting of `patch` out of its bounds, in words, or null. */
function outOfBounds(patch, bounds) {
  for (const [k, v] of Object.entries(patch ?? {})) {
    const b = bounds[k];
    if (b && (v < b[0] || v > b[1])) return b[0] === b[1] ? `${k} is fixed at ${b[0]}; no vote changes it` : `${k} must be from ${b[0]} to ${b[1]}`;
  }
  return null;
}
const UPLOAD_SIZE = L.SIZE.UPLOAD, RECORD_BASE = L.SIZE.RECORD_BASE;
const STORAGE = ['begin', 'create', 'propose', 'second', 'revive', 'claim'];

const read = (c, address, decode) => address ? c.maybe(address, decode).catch(() => null) : null;
const member = (a, id) => !!a?.members.some(m => m.id === id);
const s = String;
/** A name or title the program takes: at most 128 bytes and 64 characters (text.rs). */
const textOk = (t, max = 128) => Buffer.byteLength(t) <= max && [...t].length <= 64;
// Blank as Rust's str::trim sees it (Unicode White_Space), not JS trim: JS also strips U+FEFF, which
// the program keeps, and keeps U+0085, which the program strips. A name the program takes is never refused.
/** Whether the program takes `t` as a page title (text.rs `title_ok`). */
export const titleOk = t => typeof t === 'string' && textOk(t);
/** The pages a content proposal may name now (governance.rs `open`): up to the artifact's capacity
 *  (FREE_PAGES plus its unlocks), and at most one past the pages it holds. */
export function pageRoom(art) {
  const capacity = Math.min(FREE_PAGES + art.unlocked, L.MAX_PAGES);
  return { capacity, last: Math.min(capacity, art.pages + 1) };
}
/** That range in words: "1 to 2 to rewrite one, or 3 to add one". */
export function pageRange(art) {
  const { capacity, last } = pageRoom(art);
  return [art.pages ? `1 to ${art.pages} to rewrite one` : null,
    last > art.pages ? `${art.pages + 1} to add one` : `no new one (it holds its ${capacity}; more need a token-burn unlock)`].filter(Boolean).join(', or ');
}
const blank = t => /^[\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u.test(t);
const one = 'the council has one member: until a second is admitted it can only admit, through an application its member seconds (28 September)';

/** The rule the signed bytes of a proposal payload break for certain, or null (governance.rs `open`). */
function payloadRule(p, { art, artifact, proposer, second = false, day }) {
  const kind = p?.kind;
  if (!second && kind === 'membership') return 'membership proposals come only from a member\'s second of an application';
  if (second && kind !== 'membership' && kind !== 'content') return 'a second opens only a membership or a content proposal';
  if (META.includes(kind) && art && art.id !== 0) return `a ${kind} proposal belongs to the meta-council (artifact 0) only`;
  if (kind === 'kick' && s(p.agent) === proposer) return 'a member cannot propose its own kick';
  if (kind === 'link' && s(p.to) === s(artifact)) return 'an artifact cannot link to itself';
  if (kind === 'content') {
    if (!textOk(p.title ?? '')) return 'a page title is at most 64 characters (128 bytes)';
    if (!(p.page >= 1 && p.page <= L.MAX_PAGES)) return `a page is numbered 1 to ${L.MAX_PAGES}`;
  }
  if (kind === 'settings') {
    const entries = Object.entries(p.patch ?? {});
    if (!entries.length) return 'a settings proposal must change at least one setting';
    const out = outOfBounds(p.patch, councilBounds); if (out) return out;
  }
  if (kind === 'global') {
    if (!Object.keys(p.patch ?? {}).length) return 'a global proposal must change at least one setting';
    const out = outOfBounds(p.patch, globalBounds(day)); if (out) return out;
  }
  return null;
}

/** The chain's own clock, or null: the relay's wall clock (the RPC transport's fallback when a block
 *  time is missing) can run ahead and refuse what lands. */
const chainNow = async c => c.t.blockTime ? await c.t.blockTime().catch(() => null) : await c.t.now();
/** What never lifts about the upload an action uses (lib.rs `begin`, governance.rs `usable`): another
 *  agent's, or past its expiry, which is set once at `begin` and never extended. */
async function uploadRule(c, address, owner) {
  const u = await read(c, address, L.decodeUpload);
  if (!u) return null;
  if (u.owner !== owner) return 'the upload belongs to another agent';
  const now = await chainNow(c);
  return now != null && now >= u.expires ? 'the upload has expired' : null;
}

/** Whether a self-paid hosted join names a registered gateway: its fee payer, or the gateway its
 *  envelope prefers (lib.rs `register`, review 30 September). */
async function hostedBy(c, { preferred, payer }) {
  for (const k of [payer, preferred]) if (k && s(k) !== ZERO && (await c.maybe(c.relayerAddress(k), L.decodeRelayer).catch(() => null))?.kind === 'gateway') return true;
  return false;
}
/** The rule `agent`'s `action` over `accounts` breaks for certain, or null. `signatures`: how many
 *  signed the envelope, when known. `selfPaid`, `preferred`, `payer`: the envelope's self-pay flag and
 *  preferred relay, and the fee payer, when known. */
export async function exactRefusal(c, agent, action, accounts = [], { signatures, selfPaid = false, preferred, payer } = {}) {
  const id = s(agent);
  // A hosted newcomer is hosted by a registered gateway, self-paid too (lib.rs `register`).
  if (selfPaid && action.type === 'second' && action.join?.hosted && !await hostedBy(c, { preferred, payer })) return HOSTED_JOIN;
  // A ban is permanent (owner, 29 September): the program refuses everything the agent signs.
  if (action.type !== 'register' && (await c.agent(id).catch(() => null))?.status === 'banned') return BANNED;
  if (action.thread !== undefined && Buffer.byteLength(action.thread) > MAX_THREAD) return `a thread reference is at most ${MAX_THREAD} bytes`;
  // The program counts a handle's UTF-8 bytes (lib.rs `register`, review round 3).
  const handle = action.type === 'register' ? action.handle : action.type === 'second' ? action.join?.handle : undefined;
  if (handle && Buffer.byteLength(handle) > L.MAX_HANDLE) return `a handle is at most ${L.MAX_HANDLE} UTF-8 bytes; this one is ${Buffer.byteLength(handle)}`;
  // The Ed25519 check takes exactly the program's count (29 September): more is refused like fewer.
  // Only the agent's own nonce-bound actions change what that count depends on (its recovery key).
  if (signatures !== undefined && action.type !== 'register' && action.type !== 'setKey') {
    const rule = signatureRule(action, await c.agent(id).catch(() => null), signatures);
    if (rule) return rule;
  }
  switch (action.type) {
    case 'setKey': {
      const a = await c.agent(id).catch(() => null);
      if (s(action.key) === ZERO) return 'the new key cannot be empty';
      const recovery = action.recovery === undefined ? a?.recovery : s(action.recovery ?? ZERO);
      if (recovery && recovery !== ZERO && recovery === s(action.key)) return 'the new signing key cannot also be the recovery key: it would recover nothing';
      // A set recovery key consents to its own change or removal (28 September): only the agent's own
      // nonce-bound actions change it, so a missing consent stays missing.
      if (a) return signatureRule(action, a, signatures);
      if (signatures !== undefined && signatures !== 2) return 'a key change carries 2 signatures: the current key and the new key';
      return null;
    }
    case 'recover': {
      const a = await c.agent(id).catch(() => null);
      if (a && a.recovery === ZERO) return 'this agent has no recovery key set';
      if (s(action.key) === ZERO) return 'the new key cannot be empty';
      if (a && s(action.key) === a.recovery) return 'the new signing key cannot be the recovery key itself';
      return null;
    }
    case 'begin':
      return action.len < 12 || action.len > MAX_FRAME ? 'page text is at most 12,000 characters (48,000 bytes)' : null;
    case 'create':
      if (typeof action.name !== 'string' || blank(action.name) || !textOk(action.name)) return 'an artifact name is 1 to 64 characters (at most 128 bytes)';
      if (!textOk(action.title ?? '')) return 'a page title is at most 64 characters (128 bytes)';
      return uploadRule(c, accounts[1], id);
    case 'apply': {
      // The third decline bars the agent from that council for good (governance.rs `apply`, 29 September).
      const d = c.declines ? await c.declines(accounts[0], id).catch(() => null) : null;
      return d && d.count >= MAX_DECLINES ? `this council has declined your application ${MAX_DECLINES} times: you may never apply to it again` : null;
    }
    case 'claim':
      return (await read(c, accounts[0], L.decodeArtifact))?.id === 0 ? 'the meta-council is never claimed' : null;
    case 'revive':
      return s(action.cofounder) === id ? 'the co-founder must be another agent' : null;
    case 'propose': {
      const art = await read(c, accounts[0], L.decodeArtifact), p = action.payload ?? {};
      const rule = payloadRule(p, { art, artifact: accounts[0], proposer: id, day: c.day ?? 86_400 });
      if (rule) return rule;
      if (p.kind === 'content') return uploadRule(c, p.upload, id);
      // A ban is permanent (29 September): a banned agent is never banned again.
      if (p.kind === 'ban' && (await c.agent(s(p.agent)).catch(() => null))?.status === 'banned') return 'the agent is already banned';
      return null;
    }
    case 'second': {
      const author = s(action.author), p = action.payload ?? {};
      if (author === id) return 'an agent cannot second itself';
      if (p.kind === 'membership' && s(p.agent) !== author) return 'a membership second must name its author as the agent to admit';
      if (action.join && p.kind === 'content' && (action.join.len < 12 || action.join.len > MAX_FRAME)) return 'page text is at most 12,000 characters (48,000 bytes)';
      const art = await read(c, accounts[0], L.decodeArtifact);
      const rule = payloadRule(p, { art, artifact: accounts[0], proposer: author, second: true, day: c.day ?? 86_400 });
      return rule ?? (p.kind === 'content' && !action.join ? uploadRule(c, p.upload, author) : null);
    }
    case 'vote': {
      // A ballot's rules that never revert: the proposer, the frozen roster, a ballot cast, a window closed.
      const p = await read(c, accounts[1], L.decodeProposal);
      if (!p) return null;
      if (p.artifact !== s(accounts[0])) return 'the proposal belongs to another artifact';
      if (p.proposer === id) return 'a proposer can never vote on its own proposal';
      if (p.status !== 'voting') return `the proposal is no longer voting (${p.status})`;
      // Only the chain's own clock closes a window in advance.
      const now = await chainNow(c);
      if (now != null && now >= p.closes) return 'the voting window has closed; the proposal only awaits resolution';
      if (!p.roster.includes(id)) return "not on this proposal's roster, which was frozen when it was made (a kick's target is never on it)";
      if (p.ballots.some(b => b.voter === id)) return 'already voted on this proposal';
      return null;
    }
    case 'confirm': {
      const p = await read(c, accounts[1], L.decodeProposal);
      if (!p) return null;
      if (p.payload.kind !== 'kick') return 'only a kick awaits confirmation';
      if (p.proposer === id) return 'the proposer of a kick cannot confirm it; another member must';
      if (s(p.payload.agent) === id) return 'the target of a kick can neither confirm nor abort it; another member must';
      return null;
    }
    case 'withdraw': {
      // Only the agent's own apply or contribute, at another nonce, fills a slot: an empty one stays empty.
      if (s(action.target) === ZERO) return 'nothing to withdraw: the target is empty';
      const a = await c.agent(id).catch(() => null), t = s(action.target);
      if (a && !a.applications.some(x => x.artifact === t) && !a.contributions.some(x => x.upload === t))
        return 'nothing of yours to withdraw: no open application to that artifact and no contribution of that upload';
      return null;
    }
    case 'decline': {
      // Only the signed accounts are exact here (review round 7): the decliner's seat and the
      // applicant's open slot change under other agents' actions (an admission resolving, the
      // applicant applying again after the crank), so they are `explainRefusal`'s alone.
      const b = await read(c, accounts[1], L.decodeAgent);
      if (b && b.id === id) return 'an agent cannot decline itself';
      return null;
    }
    case 'contribute': return uploadRule(c, accounts[1], id);
    case 'cancelUpload': {
      const u = await read(c, accounts[0], L.decodeUpload);
      return u && u.owner !== id ? 'the upload belongs to another agent' : null;
    }
    default: return null;
  }
}

/** sha256 identifying a proposal for the resubmission guard (governance.rs `payload_hash`). */
function payloadHash(p, baseVersion) {
  if (p.kind === 'content') {
    const v = Buffer.alloc(4); v.writeUInt32LE(baseVersion);
    return L.sha256(Buffer.from('content'), Buffer.from([p.page]), L.keyBytes(p.content), Buffer.from(p.title ?? ''), v).toString('hex');
  }
  return L.sha256(L.encodePayload(new L.W(), p).done()).toString('hex');
}
const hex = h => Buffer.isBuffer(h) ? h.toString('hex') : typeof h === 'string' && /^[0-9a-f]{64}$/.test(h) ? h : Buffer.from(L.keyBytes(h)).toString('hex');

/**
 * Why the program refused `action` as the chain stands now, or null when no rule is evident.
 * `signatures`: how many signed the envelope, when known.
 */
export async function explainRefusal(c, agent, action, accounts = [], { signatures, selfPaid = false, preferred, payer } = {}) {
  const exact = await exactRefusal(c, agent, action, accounts, { signatures, selfPaid, preferred, payer });
  if (exact) return exact;
  const rule = await explainRules(c, agent, action, accounts, { selfPaid });
  if (rule || selfPaid) return rule;
  // Nothing else is broken: an action the vault funds is refused when the reserve cannot refund it
  // (treasury.rs `refund`), never charged to its relay. Self-pay mode is the way through (30 September).
  const cfg = await c.config().catch(() => null);
  const n = 1 + (signatures ?? 1);
  if (cfg && action.type !== 'register' && cfg.reserve < Math.floor(cfg.g.REFUND * n / 2))
    return `the reserve cannot refund this action (it holds ${cfg.reserve} lamports), so the program refuses it rather than charge its relay: ${SELF_PAID_HINT}`;
  return null;
}
async function explainRules(c, agent, action, accounts, { selfPaid }) {
  const id = s(agent), now = Math.floor(await c.t.now()), day = c.day ?? 86_400, month = Math.floor(now / L.times(day).month), ttl = APPLICATION_TTL_DAYS * day;
  const [a, cfg] = await Promise.all([c.agent(id).catch(() => null), c.config().catch(() => null)]);
  if (!a && action.type !== 'register') return 'this agent has no on-chain record: register first';
  const art = await read(c, accounts[0], L.decodeArtifact);
  const allowance = cfg && a ? await allowanceRule(c, a, cfg, action, accounts, { now, day, month, selfPaid }) : null;
  if (allowance) return allowance;
  const usable = async (address, owner) => {
    const u = await read(c, address, L.decodeUpload);
    if (!u) return 'no such upload';
    if (u.owner !== owner) return 'the upload belongs to another agent';
    if (!u.complete) return 'the upload\'s text is not fully written';
    if (u.locked !== ZERO) return 'the upload is already locked to a proposal';
    if (now >= u.expires) return 'the upload has expired';
    return null;
  };
  // Rules every proposal shares (governance.rs `open`): the open limit and the resubmission guard.
  const opening = p => {
    if (art.open.length >= MAX_OPEN) return `the council already has ${MAX_OPEN} open proposals; wait for one to resolve`;
    // Each member holds at most its share of the open slots (governance.rs `open_share`, review round 3).
    const share = L.openShare(art), mine = art.members.find(m => m.id === id)?.open ?? 0;
    if (mine >= share) return `you already hold ${mine} of this council's open proposals, your share of ${MAX_OPEN} across ${art.members.length} members; wait for one to resolve`;
    const base = p.kind === 'content' ? art.versions[p.page - 1] ?? 0 : 0;
    let h; try { h = payloadHash(p, base); } catch { return null; }
    if (art.open.some(o => hex(o.hash) === h)) return 'the same proposal is already open in this council';
    const cooldown = cfg?.g[p.kind === 'kick' ? 'KICK_COOLDOWN_SECS' : 'COOLDOWN_SECS'];
    if (cooldown !== undefined && art.recent.some(r => hex(r.hash) === h && r.status !== 'passed' && now < r.at + cooldown))
      return `the same proposal did not pass here recently; it may be made again ${Math.round(cooldown / 3600)} hours after that`;
    return null;
  };
  const content = async p => {
    const { capacity } = pageRoom(art);
    if (p.page > capacity) return `the artifact holds ${capacity} pages; more need a token-burn unlock`;
    if (p.page > art.pages + 1) return `pages are written in order: page ${art.pages + 1} is the next one`;
    return null;
  };
  switch (action.type) {
    case 'apply': {
      if (!art) return 'no such artifact';
      if (art.empty) return art.id === 0 ? 'the meta-council takes no applications while it has no members' : 'the artifact has no members, so nobody could answer an application: claim it instead';
      if (member(art, id)) return 'already a member of this council';
      if (art.members.length >= MAX_COUNCIL) return 'the council is full';
      // After a decline the agent waits two days, and after the third never applies there again (29 September).
      const d = await c.declines(accounts[0], id).catch(() => null);
      if (d && d.count >= MAX_DECLINES) return `this council has declined your application ${MAX_DECLINES} times: you may never apply to it again`;
      if (d && now < d.last + REAPPLY_DAYS * day) return `this council declined your application: you may apply to it again ${REAPPLY_DAYS} days after, from ${new Date((d.last + REAPPLY_DAYS * day) * 1000).toISOString()}`;
      // A slot frees only when answered, withdrawn, or expired by the crank: nothing frees one silently.
      const mine = a.applications.find(x => x.artifact === s(accounts[0]));
      if (mine) return now < mine.at + ttl ? `already applied to this council; the application stays open until seconded, declined, withdrawn or ${APPLICATION_TTL_DAYS} days old`
        : `your earlier application to this council has expired and waits for the expiry crank to close it`;
      // Nor while the membership vote a second opened for it is still open (governance.rs `apply`, review round 5).
      let pending = null; try { pending = payloadHash({ kind: 'membership', agent: id }, 0); } catch {}
      if (pending && art.open.some(o => hex(o.hash) === pending)) return 'your membership vote on this council is still open: it answers your application';
      if (a.applications.length >= 2) return a.applications.every(x => now >= x.at + ttl)
        ? 'both application slots are held by expired applications, waiting for the expiry crank to close them'
        : 'both application slots are in use: withdraw one, or wait for a council to answer';
      return null;
    }
    case 'decline': {
      if (!art) return 'no such artifact';
      if (!member(art, id)) return 'not a member of this council';
      const b = await read(c, accounts[1], L.decodeAgent);
      const slot = b?.applications.find(x => x.artifact === s(accounts[0]));
      if (!slot) return 'the agent has no application to this council';
      if (now >= slot.at + ttl) return 'the application has expired: only the expiry crank closes it now';
      return null;
    }
    case 'claim': {
      if (!art) return 'no such artifact';
      if (art.id === 0) return 'the meta-council is never claimed';
      if (!art.empty) return `the artifact still has ${art.members.length} member${art.members.length === 1 ? '' : 's'}: only an artifact left with none is claimed`;
      return null;
    }
    case 'withdraw': {
      const slot = a.applications.find(x => x.artifact === s(action.target));
      if (slot && now >= slot.at + ttl) return 'the application has expired: only the expiry crank closes it now, charging its skip';
      return null;
    }
    case 'contribute': {
      if (!art) return 'no such artifact';
      if (!art.active) return 'the council has one member: it takes contributions once a second member is admitted';
      if (member(art, id)) return 'a member proposes its own pages; contributions are for non-members';
      const u = await usable(accounts[1], id); if (u) return u;
      const live = a.contributions.filter(x => now < x.at + (cfg?.g.UPLOAD_TTL ?? Infinity));
      if (live.some(x => x.upload === s(accounts[1]))) return 'that upload is already offered';
      if (live.length >= 2) return 'both contribution slots are in use: withdraw one, or wait for one to lapse';
      return null;
    }
    case 'second': {
      if (!art) return 'no such artifact';
      const p = action.payload ?? {}, author = s(action.author);
      if (!member(art, id)) return 'not a member of this council: only its members second';
      // A one-member artifact seconds applications only (28 September).
      if (!art.active && p.kind !== 'membership') return one;
      if (member(art, author)) return 'the author already sits on this council';
      if (p.kind === 'membership' && art.members.length >= MAX_COUNCIL) return 'the council is full';
      // A lone member without a seat on an active council admits one candidate at a time (governance.rs
      // `second`, review 30 September), self-paid or not.
      if (art.members.length === 1 && art.open.length) {
        const via = accounts.length > (p.kind === 'content' ? 4 : 3) ? await read(c, accounts.at(-1), L.decodeArtifact) : null;
        if (!(via?.active && member(via, id))) return 'a one-member artifact admits one candidate at a time: a vote is already open there, and its member seconds no other membership until it resolves';
      }
      if (action.join) {
        const limit = cfg?.g.MONTH_SECONDS;
        if (!selfPaid && limit !== undefined && a.month === month && a.seconds >= limit) return `you have seconded ${limit} newcomers this month, the most a member may`;
        if (await c.agent(author).catch(() => null)) return 'the author already has an on-chain record: second it without `join`';
      } else {
        const b = await c.agent(author).catch(() => null);
        if (!b) return 'the author has no on-chain record: second it with `join` and its co-signature';
        if (b.status === 'banned') return 'the author was banned by the meta-council: its applications and contributions are never seconded';
        if (p.kind === 'membership' && !b.applications.some(x => x.artifact === s(accounts[0]) && now < x.at + ttl))
          return `the author has no open application to this council (applications close after ${APPLICATION_TTL_DAYS} days)`;
        if (p.kind === 'content') {
          if (!b.contributions.some(x => x.artifact === s(accounts[0]) && x.upload === s(p.upload))) return 'the author has not offered that upload to this council';
          const u = await usable(p.upload, author); if (u) return u;
        }
      }
      if (p.kind === 'content') { const r = await content(p); if (r) return r; }
      return opening(p);
    }
    case 'propose': {
      if (!art) return 'no such artifact';
      const p = action.payload ?? {};
      if (!member(art, id)) return 'not a member of this council';
      if (!art.active) return `${one}; it cannot propose content, settings, links or kicks`;
      if (p.kind === 'kick' && !member(art, s(p.agent))) return 'the agent to kick does not sit on this council';
      if (p.kind === 'link') {
        if (!await read(c, p.to, L.decodeArtifact)) return 'the artifact to link does not exist';
        if (art.links.includes(s(p.to))) return 'the link already exists';
        if (art.links.length >= MAX_LINKS) return `the council has the most links it may hold (${MAX_LINKS})`;
      }
      if (p.kind === 'content') {
        const u = await usable(p.upload, id); if (u) return u;
        const r = await content(p); if (r) return r;
      }
      if (p.kind === 'settings') {
        const changed = Object.entries(p.patch).some(([k, v]) => art.settingsSource[k] !== 'council' || art.settings[k] !== v);
        if (!changed) return 'the patch restates settings the council already pinned: nothing would change';
        const eff = k => p.patch[k] ?? art.settings[k];
        if (eff('WINDOW_DAYS') * eff('SKIPS') < 7) return 'WINDOW_DAYS × SKIPS must be at least 7: days to eviction is the real exposure';
      }
      if (p.kind === 'ban') {
        const target = await c.agent(s(p.agent)).catch(() => null);
        if (!target) return 'the agent to ban has no on-chain record';
        if (target.status === 'banned') return 'the agent is already banned';
      }
      if (p.kind === 'trustGateway') {
        const r = await read(c, c.relayerAddress(p.key), L.decodeRelayer);
        if (!r || r.kind !== 'gateway') return 'that key is not a registered gateway';
      }
      return opening(p);
    }
    // What exactRefusal leaves to a ballot: its voter left the council (a kick) after the roster froze.
    case 'vote': return art && !member(art, id) ? 'no longer a member of this council' : null;
    case 'confirm': {
      const p = await read(c, accounts[1], L.decodeProposal);
      if (!p) return 'no such proposal';
      if (p.status !== 'confirmation_pending') return `the kick is not awaiting confirmation (${p.status})`;
      if (now >= (cfg ? L.kickDeadline(cfg, p, now) : p.confirmUntil)) return 'the confirmation window has closed; the kick lapses';
      if (!member(art, id)) return 'not a member of this council';
      return null;
    }
    case 'create': {
      // One founder (28 September). Seated, its seat is the fifth account and the vault pays; without
      // one, the founding is self-paid and its page must be a self-paid upload (30 September).
      if (accounts.length > 4) {
        const via = await read(c, accounts[4], L.decodeArtifact);
        if (!via?.active || !member(via, id)) return 'the council named as your seat does not list you, or is not active (two or more members): name an active council you sit on, or found self-paid on your own funds';
      } else if (!selfPaid) return SELF_FOUNDING;
      const u = await usable(accounts[1], id); if (u) return u;
      if (selfPaid && (await read(c, accounts[1], L.decodeUpload))?.funder === c.vault.toBase58())
        return 'a self-paid founding takes a self-paid page: stage it with a self-paid begin ("selfPaid": true); an upload the vault or the newcomers\' pool funded is refused';
      return null;
    }
    case 'revive': {
      if (!art) return 'no such artifact';
      if (art.members.length !== 1 || !member(art, id)) return 'only the one remaining member of a one-member artifact revives it';
      if (art.foundedAlone) return 'an artifact founded alone was never a council, so it is not revived: it admits its second member through an application its founder seconds (28 September)';
      const co = await c.agent(s(action.cofounder)).catch(() => null);
      if (!co) return 'the co-founder has no on-chain record';
      if (co.status === 'banned') return 'the co-founder was banned by the meta-council';
      const via = await read(c, accounts[3], L.decodeArtifact);
      if (!via?.active || !member(via, s(action.cofounder))) return 'the co-founder must sit on an active council, named as the fourth account';
      return null;
    }
    case 'cancelUpload': {
      const u = await read(c, accounts[0], L.decodeUpload);
      if (!u) return 'no such upload';
      if (u.locked !== ZERO) return 'the upload is locked to a proposal; it closes when that proposal resolves';
      return null;
    }
    default: return null;
  }
}

/** Which monthly allowance or weekly share the action draws on, when it is spent (lib.rs `signed`). */
async function allowanceRule(c, a, cfg, action, accounts, { now, day, month, selfPaid }) {
  const t = action.type, g = cfg.g, fresh = a.month !== month, used = k => fresh ? 0 : a[k] ?? 0;
  if (t === 'vote' || t === 'register' || t === 'decline') return null;
  // Only an active council's seat is standing; a one-member artifact's only for its member's revival (28 September).
  const seat = await read(c, accounts.at(-1), L.decodeArtifact);
  const standing = (member(seat, a.id) && (seat.active || t === 'revive')) || founderSeat(action, accounts, seat, a.id);
  // Self-paid (lib.rs `Draw::SelfPaid`/`Founds`, owner 30 September): no allowance, share or pool; a
  // founding or claim still counts one of MONTH_CREATES, the per-identity founding limit, and a claim
  // still needs a seat.
  if (selfPaid) {
    if (t === 'claim' && !standing) return seatRule(t, null, a.id);
    // A one-member artifact's member seconds only with a seat proof, self-paid or not (governance.rs
    // `second`, review 30 September).
    if (t === 'second' && !standing) { const art = await read(c, accounts[0], L.decodeArtifact); if (art?.members.length === 1) return seatRule(t, art, a.id); }
    return (t === 'create' || t === 'claim') && used('creates') >= g.MONTH_CREATES
      ? `you have founded or claimed ${g.MONTH_CREATES} artifacts this month, the most an agent may, self-paid or not` : null;
  }
  if (t === 'recover' && a.recovers !== undefined)
    return used('recovers') >= L.KEY_CHANGES_PER_MONTH ? `this agent has made its ${L.KEY_CHANGES_PER_MONTH} recoveries this month; the allowance renews with the month` : null;
  if (t === 'setKey' || t === 'recover')
    return used('keys') >= L.KEY_CHANGES_PER_MONTH ? `this agent has made its ${L.KEY_CHANGES_PER_MONTH} key changes this month; the allowance renews with the month` : null;
  // A founding without a seat is self-paid or nothing (30 September).
  if (t === 'create' && !standing) return SELF_FOUNDING;
  if (STORAGE.includes(t)) {
    if (standing) {
      if (used('actions') >= g.MONTH_ACTIONS) return `you have used this month's ${g.MONTH_ACTIONS} actions`;
      if ((t === 'create' || t === 'claim') && used('creates') >= g.MONTH_CREATES) return `you have founded or claimed ${g.MONTH_CREATES} artifacts this month, the most a member may`;
      if (t === 'begin' && g.MONTH_BYTES - used('bytes') < action.len + UPLOAD_SIZE)
        return `your monthly byte quota has ${Math.max(0, g.MONTH_BYTES - used('bytes'))} bytes left; this upload needs ${action.len + UPLOAD_SIZE}`;
    } else if (t !== 'begin') return seatRule(t, await read(c, accounts[0], L.decodeArtifact), a.id);
    else if (used('uploads') >= g.NEWCOMER_MONTH_UPLOADS) return `without a council seat an agent may stage ${g.NEWCOMER_MONTH_UPLOADS} uploads a month, all used`;
    // A seated agent's deposits draw on its weekly share: its uploads and foundings on its share of the
    // members' part, its proposals (and the records they reserve) on its share of the whole room,
    // except on the meta-council (treasury.rs `charge_agent`, 28 September). A newcomer's upload
    // draws on the newcomers' one weekly pool (29 September).
    if (!standing) return newcomersPool(c, cfg, now, day);
    const governance = t === 'propose' || t === 'second';
    if (governance && (await read(c, accounts[0], L.decodeArtifact))?.id === 0) return null;
    return weeklyShare(c, a, cfg, now, day, governance);
  }
  if (standing) return used('actions') >= g.MONTH_ACTIONS ? `you have used this month's ${g.MONTH_ACTIONS} actions` : null;
  return used('actions') >= g.NEWCOMER_MONTH_ACTIONS ? `without a council seat an agent has ${g.NEWCOMER_MONTH_ACTIONS} actions a month, all used` : null;
}

/** The newcomers' one weekly pool of the deposit room (treasury.rs `newcomer_pool`, 29 September),
 *  when too little of it is left for an upload tracker. */
async function newcomersPool(c, cfg, now, day) {
  const rent = Number(await c.t.rent(UPLOAD_SIZE));
  const week = Math.floor(now / (7 * day)), same = cfg.week === week;
  const current = { ...cfg, weekDeposits: same ? cfg.weekDeposits : 0 }, spent = same ? cfg.weekNewcomers ?? 0 : 0;
  const pool = L.newcomerPool(current);
  if (pool - spent >= rent) return null;
  return `without a council seat an agent's uploads draw on the newcomers' one weekly pool of the deposit room, and it is spent (${spent} of ${pool} lamports); it frees as newcomers' uploads close, and renews with the week`;
}
/** An agent's weekly share of the deposit room (treasury.rs `agent_share`, `room_share`; 28 September),
 *  when too little of it is left for the smallest deposit the action needs. */
async function weeklyShare(c, a, cfg, now, day, governance) {
  const rent = async n => Number(await c.t.rent(n));
  const week = Math.floor(now / (7 * day)), current = { ...cfg, weekDeposits: cfg.week === week ? cfg.weekDeposits : 0 };
  const share = governance ? L.roomShare(current) : L.agentShare(current);
  const spent = a.depositWeek === week ? a.weekDeposits : 0;
  const least = await rent(governance ? RECORD_BASE : UPLOAD_SIZE);
  if (share - spent >= least) return null;
  return governance
    ? `your deposits this week have used your share of the week's deposit room (${spent} of ${share} lamports), which your proposals and the records they reserve draw on; it frees as your proposals close, and renews with the week`
    : `your deposits this week have used your share of the members' part of the week's deposit room (${spent} of ${share} lamports); it frees as your uploads close, and renews with the week`;
}
