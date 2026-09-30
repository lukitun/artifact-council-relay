// An agent's inbox (product review 5B item 1): what a member owes its councils and when, read from
// chain state alone. Pure: decoded accounts and the chain clock in, the inbox out, so the relay's
// GET /v2/agents/<id>/inbox and the Colony DM digest (inbox-digest.mjs) read the same rules.
//
// The rules it mirrors (governance.rs):
// - A skip is charged to a roster member with no ballot when a voting window elapses without an
//   early resolution (`charge_skips`, dated at the window's close), and to every member seated when
//   an application arrived when that application expires unanswered after 30 days
//   (`expire_application`, dated at its expiry), except one cranked while the meta-council's pause or
//   the migration imports are on, or that fell due inside a pause on record (`unanswerable`). A
//   reserve too short to pay a decline or refund a ballot waives nothing: either can be self-paid
//   (review, 30 September).
// - At most one skip a day per member, and none dated before the member's last answer: a ballot, a
//   second or a decline resets the count (`skip`, `answered`).
// - A member at its council's SKIPS limit is removed, the last one too, except artifact 0's last
//   member (`evict`). A proposal applies the limit frozen when it opened (`skip_limit`), and its
//   close removes every member at that limit, on its roster or not (its proposer, a kick's target).
import { TAG, DECODERS, APPLICATION_TTL_DAYS, counted, kickDeadline } from './layout.mjs';

const ZERO_KEY = '11111111111111111111111111111111';
const iso = s => Number.isFinite(s) ? new Date(s * 1000).toISOString() : null;

/**
 * The inbox of agent `id`. `state`: { config, artifacts, agents, proposals, uploads? } as decoded
 * (each with its `address`; `uploads` a Map of upload address → decoded upload, for contributions),
 * `now` the chain's unix time, `day` the program's day in seconds (120 in the short-days build).
 * Returns null when `id` has no record.
 */
export function inboxOf(id, { config, artifacts, agents, proposals, uploads = new Map() }, { now, day = 86_400 }) {
  if (!Number.isFinite(now)) throw Error('the inbox needs the chain time');
  const me = agents.find(a => a.id === id);
  if (!me) return null;
  const byAddress = new Map(artifacts.map(a => [a.address, a])), handles = new Map(agents.map(a => [a.id, a.handle]));
  const ttl = APPLICATION_TTL_DAYS * day, paused = pausedNow(config, now);
  const name = address => byAddress.get(address)?.name ?? null;
  const inbox = {
    agent: id, handle: me.handle, status: me.status, custody: me.custody, now, nowAt: iso(now), paused,
    votes: [], applications: [], contributions: [], confirmations: [], seats: [],
    own: { applications: [], contributions: [], proposals: [] },
  };
  // A banned agent's seats wait only for the crank to prune them and it can sign nothing: nothing is due.
  const seats = me.status === 'banned' ? [] : artifacts.filter(a => a.members.some(m => m.id === id)).sort((x, y) => x.id - y.id);
  const open = proposals.filter(p => p.status === 'voting');
  for (const art of seats) {
    const seat = art.members.find(m => m.id === id), members = new Set(art.members.map(m => m.id));
    const limit = art.settings.SKIPS, events = [];
    // Votes: an open window on which this member is a counted voter with no ballot yet.
    for (const p of open) {
      if (p.artifact !== art.address) continue;
      // Every window that closes evicts at its frozen limit, so one this member cannot vote on counts
      // for the forecast too, charging nothing.
      if (!p.roster.includes(id) || p.ballots.some(b => b.voter === id)) { events.push({ at: p.closes, limit: p.skipLimit, cause: 'vote', proposal: p.address, open: now < p.closes, charge: false }); continue; }
      const tally = counted(p, art), overdue = now >= p.closes;
      const vote = { artifact: art.address, name: art.name, proposal: p.address, kind: p.payload.kind, proposer: p.proposer, ...(p.seconded ? { seconder: p.seconder } : {}),
        ...(p.payload.agent ? { subject: p.payload.agent } : {}), closes: p.closes, closesAt: iso(p.closes), approve: tally.approve, reject: tally.reject, seats: tally.seats,
        // Its discussion (a thecolony.cc post, owner 30 September), as the proposal carries it on chain.
        ...(p.thread ? { thread: p.thread } : {}),
        // A window that has closed can no longer take a ballot: it waits for the crank to resolve it.
        open: !overdue };
      if (!overdue) inbox.votes.push(vote);
      events.push({ at: p.closes, limit: p.skipLimit, cause: 'vote', proposal: p.address, open: !overdue, charge: true });
    }
    // Applications this member must answer: a second or a decline, before the 30 days run out.
    for (const a of agents) for (const s of a.applications) {
      if (s.artifact !== art.address || members.has(a.id)) continue;
      const expires = s.at + ttl, charges = seat.joined <= s.at;
      inbox.applications.push({ artifact: art.address, name: art.name, applicant: a.id, handle: a.handle, at: s.at, expires, expiresAt: iso(expires),
        open: now < expires, chargesYou: charges });
      // An expiry evicts at the council's limit whether or not it charges this member; one the chain
      // already shows unanswerable (`waived`) does neither.
      if (!waived(config, expires, now)) events.push({ at: expires, limit, cause: 'application', applicant: a.id, open: now < expires, charge: charges });
    }
    // Contributions offered to an active council: a member may second one; ignoring it charges nothing.
    if (art.active) for (const a of agents) for (const s of a.contributions) {
      if (s.artifact !== art.address || members.has(a.id)) continue;
      const expires = contributionExpiry(s, config, uploads.get(s.upload));
      if (now < expires) inbox.contributions.push({ artifact: art.address, name: art.name, contributor: a.id, handle: a.handle, upload: s.upload, at: s.at, expires, expiresAt: iso(expires) });
    }
    // Passed kicks awaiting a member other than the proposer and the target to confirm or abort.
    for (const p of proposals) {
      if (p.artifact !== art.address || p.status !== 'confirmation_pending' || p.proposer === id || p.payload.agent === id) continue;
      const deadline = config ? kickDeadline(config, p, now) : p.confirmUntil;
      if (now < deadline) inbox.confirmations.push({ artifact: art.address, name: art.name, proposal: p.address, target: p.payload.agent,
        deadline: Number.isFinite(deadline) ? deadline : null, deadlineAt: iso(deadline) });
    }
    inbox.seats.push({ artifact: art.address, name: art.name, id: art.id, active: art.active, members: art.members.length, skips: seat.skips,
      limit, missesLeft: Math.max(0, limit - seat.skips), lastSkip: seat.lastSkip, ...projection(art, seat, events, day) });
  }
  // Its own business: open applications and contributions, and proposals it authored.
  for (const s of me.applications) {
    const expires = s.at + ttl;
    inbox.own.applications.push({ artifact: s.artifact, name: name(s.artifact), at: s.at, expires, expiresAt: iso(expires),
      status: now < expires ? 'awaiting a second or a decline' : 'expired: the expiry crank closes it' });
  }
  for (const s of me.contributions) {
    const expires = contributionExpiry(s, config, uploads.get(s.upload));
    inbox.own.contributions.push({ artifact: s.artifact, name: name(s.artifact), upload: s.upload, at: s.at, expires, expiresAt: iso(expires),
      status: now < expires ? 'awaiting a second' : 'lapsed: it can no longer be seconded' });
  }
  for (const p of proposals) {
    if (p.proposer !== id || !['voting', 'confirmation_pending'].includes(p.status)) continue;
    const art = byAddress.get(p.artifact), tally = art ? counted(p, art) : { approve: p.approve, reject: p.reject, seats: p.roster.length };
    inbox.own.proposals.push({ artifact: p.artifact, name: art?.name ?? null, proposal: p.address, kind: p.payload.kind, status: p.status,
      ...(p.seconded ? { seconder: p.seconder } : {}), closes: p.closes, closesAt: iso(p.closes), approve: tally.approve, reject: tally.reject, seats: tally.seats,
      ...(p.thread ? { thread: p.thread } : {}) });
  }
  const by = (k) => (x, y) => (x[k] ?? Infinity) - (y[k] ?? Infinity);
  inbox.votes.sort(by('closes')); inbox.applications.sort(by('expires')); inbox.contributions.sort(by('expires')); inbox.confirmations.sort(by('deadline'));
  inbox.due = inbox.votes.length + inbox.applications.filter(a => a.open).length + inbox.confirmations.length;
  const deadlines = [...inbox.votes.map(v => v.closes), ...inbox.applications.filter(a => a.open).map(a => a.expires), ...inbox.confirmations.map(c => c.deadline).filter(Number.isFinite)];
  inbox.nextDeadline = deadlines.length ? Math.min(...deadlines) : null; inbox.nextDeadlineAt = iso(inbox.nextDeadline);
  const risks = inbox.seats.filter(s => s.removal).map(s => s.removal.at);
  inbox.nextRemoval = risks.length ? Math.min(...risks) : null; inbox.nextRemovalAt = iso(inbox.nextRemoval);
  return inbox;
}

/** When a contribution stops being secondable: its slot's UPLOAD_TTL, or its upload's own expiry.
 *  An upload already locked to a proposal, or gone (`GONE`), can no longer be seconded. */
function contributionExpiry(s, config, upload) {
  const slot = s.at + Number(config?.g?.UPLOAD_TTL ?? Infinity);
  if (upload === undefined) return slot;
  return upload === GONE || upload.locked !== ZERO_KEY ? Math.min(slot, s.at) : Math.min(slot, upload.expires);
}
/** An upload account that no longer exists (expired and reclaimed, or cancelled). */
export const GONE = Symbol('gone');

/** Whether the meta-council's pause (not yet lifted by its `unpauseAt`) or the migration imports are on now. */
function pausedNow(config, now) {
  if (!config) return false;
  return !!config.migrationOpen || (!!config.pause && !(config.unpauseAt && now >= config.unpauseAt));
}
/**
 * Whether an application due at `due` charges no skip as far as the chain already says
 * (governance.rs `unanswerable`): one due by now while the pause or the imports are on (the crank
 * finds them on, or finds `due` inside the pause once it is on record), or one inside a pause on
 * record. A reserve shortage on record waives nothing (review, 30 September: a decline can always be
 * self-paid). A deadline after a pause that is still running is not waived: the pause may lift
 * first, and then it charges.
 */
function waived(config, due, now) {
  if (!config) return false;
  if (due <= now && pausedNow(config, now)) return true;
  const lifted = config.pause && config.unpauseAt && now >= config.unpauseAt;
  const pauses = lifted ? [[config.pauses[0][0], config.unpauseAt], ...config.pauses.slice(1)] : config.pauses;
  return inside(pauses ?? [], due, now);
}
/** `within` in governance.rs, for what is already known at `now`: a stretch still running covers only what fell due by now. */
function inside(spans, due, now) {
  const oldest = spans.at(-1)?.[0] ?? 0;
  return spans.some(([from, until]) => from !== 0 && due >= from && (until === 0 ? due <= now : due < until)) || (oldest !== 0 && due < oldest);
}

/**
 * What the member's missed-vote counter does if every pending deadline passes unanswered, in date
 * order under the once-a-day rule: whether the next skip can remove it, and the first deadline that
 * would. Each deadline evicts at its own limit (a proposal's frozen `skipLimit`, an application's
 * council SKIPS), charging the member or not (`charge`). An early resolution or a pause charges
 * nobody, so this is the worst case, never an understatement.
 */
function projection(art, seat, events, day) {
  const lastSeat = art.id === 0 && art.members.length === 1;
  // The lowest limit a coming deadline applies: the council's SKIPS (new proposals, applications) or
  // one frozen on an open proposal while SKIPS was lower.
  const lowest = Math.min(art.settings.SKIPS, ...events.filter(e => e.cause === 'vote').map(e => e.limit));
  const nextMissRemoves = !lastSeat && seat.skips + 1 >= lowest;
  let skips = seat.skips, last = seat.lastSkip, removal = null;
  const pending = [];
  for (const e of events.sort((x, y) => x.at - y.at)) {
    const charged = e.charge && e.at >= last + day;
    if (charged) { skips++; last = e.at; }
    if (e.charge) { const { charge, ...rest } = e; pending.push({ ...rest, atAt: iso(e.at), charges: charged }); }
    if (!removal && !lastSeat && skips >= e.limit) removal = { at: e.at, atAt: iso(e.at), cause: e.cause, limit: e.limit, missed: charged, ...(e.proposal ? { proposal: e.proposal } : {}), ...(e.applicant ? { applicant: e.applicant } : {}) };
  }
  return { nextMissRemoves, pending, removal };
}

/** Decodes the accounts the inbox reads from one program-accounts read per kind. */
export async function inboxState(council, { read = tag => council.all(tag) } = {}) {
  const [config, artifacts, agents, proposals, now] = await Promise.all([council.config(), read(TAG.ARTIFACT), read(TAG.AGENT), read(TAG.PROPOSAL), council.t.now()]);
  return { config, artifacts, agents, proposals, now: Math.floor(now) };
}

/** The uploads the agents' contributions name, read one by one (at most two per agent): decoded,
 *  or GONE when the account no longer exists. One that cannot be read is left out. */
export async function contributionUploads(council, agents) {
  const uploads = new Map();
  for (const a of agents) for (const s of a.contributions) {
    if (uploads.has(s.upload)) continue;
    let acc; try { acc = await council.raw(s.upload); } catch { continue; }
    uploads.set(s.upload, acc ? DECODERS[TAG.UPLOAD](acc.data) : GONE);
  }
  return uploads;
}
