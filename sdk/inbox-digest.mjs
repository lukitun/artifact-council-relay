// The inbox digest (product review 5B item 1): Colony DMs from @agentpedia to members with something
// due, once a day, and again about a day before a deadline that could remove them from a council.
// Off chain only; the inbox itself is inbox.mjs.
//
// Who may be sent a DM, and nobody else:
// - a hosted identity of this gateway, at the Colony username its owner proved at its latest login
//   (recorded by /v2/colony/verify), while the chain still says the identity is hosted by this
//   gateway and the gateway's binding still gives that identity to the same Colony account, unless
//   the owner turned the digest off (POST /v2/hosted/digest);
// - an own-key agent that opted in: a request signed by its current key names a Colony username,
//   which the agent then proves through the same Colony verification as a login
//   (POST /v2/inbox/subscribe, then /v2/inbox/confirm), until it opts out (POST /v2/inbox/unsubscribe)
//   or stops holding its own key.
// One username belongs to one Colony account here: a later proof of the same username by another
// account (a login, an opt-in or a stop) drops the earlier account's entries, and an older proof
// never takes it back. Banned identities are never sent anything. A Colony account that proves
// itself at POST /v2/inbox/stop (no key or token needed) is sent nothing more, whichever agents name
// it, until an explicit opt-in from it (an own-key opt-in, or a hosted identity's
// POST /v2/hosted/digest { on: true }).
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { randomBytes } from 'node:crypto';
import { inboxOf, inboxState, contributionUploads } from './inbox.mjs';
import { validColonyId, COLONY_USERNAME } from './colony.mjs';
import { donationLine, HOSTED_CUSTODY_WARNING } from './hosted-funds.mjs';
import { MAX_DM, oneLine } from './notify.mjs';

const USERNAME = COLONY_USERNAME, ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const atomic = (file, data) => { mkdirSync(dirname(file), { recursive: true, mode: 0o700 }); const tmp = `${file}.${randomBytes(6).toString('hex')}.tmp`; writeFileSync(tmp, data, { mode: 0o600 }); renameSync(tmp, file); };
const readJson = (file, empty) => { try { const v = JSON.parse(readFileSync(file, 'utf8')); return v && typeof v === 'object' ? v : empty(); } catch (e) { if (e.code === 'ENOENT') return empty(); throw Error(`unreadable digest file ${file}: ${e.message}`); } };

/** What the signed opt-in and opt-out requests sign: `time` in unix seconds, within 15 minutes of now. */
export const subscribeMessage = (program, agent, username, time) => Buffer.from(`ACv2 inbox-subscribe ${program} ${agent} ${username} ${time}`);
export const unsubscribeMessage = (program, agent, time) => Buffer.from(`ACv2 inbox-unsubscribe ${program} ${agent} ${time}`);

/**
 * The gateway's digest contacts, persisted in `file`:
 * { hosted: { agent: { label, colonyId, username, at } }, own: { agent: { colonyId, username, signed, at } }, off: { agent: at }, stopped: { colonyId: at },
 *   names: { username: { colonyId, at } } }.
 * `at` in milliseconds, `signed` the unix time of the opt-in's signed request; `names` holds each username's latest proof.
 * Every write is atomic; the file is re-read on each call.
 */
export function digestContacts(file) {
  // An unreadable file throws rather than reads as empty: a write after an empty read would erase
  // every opt-out on record. Callers that must not fail (a login, the gateway's start) catch it.
  const empty = () => ({ hosted: {}, own: {}, off: {}, stopped: {}, names: {} });
  // A file written before `names` existed: each username's latest proof is its newest entry's.
  const seed = s => { const names = {}; for (const kind of ['hosted', 'own']) for (const e of Object.values(s[kind] ?? {})) if (!(names[e.username]?.at >= e.at)) names[e.username] = { colonyId: e.colonyId, at: e.at }; return names; };
  const load = () => { const s = readJson(file, empty); return { hosted: s.hosted ?? {}, own: s.own ?? {}, off: s.off ?? {}, stopped: s.stopped ?? {}, names: s.names ?? seed(s) }; };
  const check = (agent, colonyId, username) => {
    if (!ADDRESS.test(agent ?? '')) throw Error('invalid agent');
    if (!validColonyId(colonyId)) throw Error('invalid Colony user id');
    if (!USERNAME.test(username ?? '')) throw Error('invalid Colony username');
  };
  // A username proven by one Colony account is no longer another's: the proof is recorded as the
  // username's latest and drops what other accounts hold under it. A proof older than the latest by
  // another account (a restart's backfill from a live login) is `stale` and records nothing.
  const stale = (s, username, colonyId, at) => { const last = s.names[username]; return !!last && last.colonyId !== String(colonyId) && last.at >= at; };
  const claim = (s, username, colonyId, at) => {
    s.names[username] = { colonyId: String(colonyId), at: Math.max(at, s.names[username]?.at ?? 0) };
    for (const kind of ['hosted', 'own']) for (const [agent, e] of Object.entries(s[kind])) if (e.username === username && e.colonyId !== String(colonyId)) delete s[kind][agent];
  };
  return {
    file,
    all: load,
    /** Records the username a hosted identity's owner proved at login. Keeps an opt-out. */
    hosted(agent, { label, colonyId, username }, at = Date.now()) {
      username = String(username ?? '').toLowerCase(); check(agent, colonyId, username);
      if (typeof label !== 'string' || !label) throw Error('invalid identity label');
      const s = load(), cur = s.hosted[agent];
      if (cur && cur.label === label && cur.colonyId === String(colonyId) && cur.username === username && cur.at >= at) return false;
      if (stale(s, username, colonyId, at)) return false;
      claim(s, username, colonyId, at);
      s.hosted[agent] = { label, colonyId: String(colonyId), username, at };
      atomic(file, JSON.stringify(s)); return true;
    },
    /** An own-key agent's confirmed opt-in; `signed`: the unix time its signed request carried. */
    subscribe(agent, { colonyId, username, signed }, at = Date.now()) {
      username = String(username ?? '').toLowerCase(); check(agent, colonyId, username);
      if (!Number.isSafeInteger(signed)) throw Error('invalid signed time');
      const s = load(); claim(s, username, colonyId, at);
      s.own[agent] = { colonyId: String(colonyId), username, signed, at };
      delete s.stopped[String(colonyId)];   // this opt-in, proven from the account, lifts its stop
      atomic(file, JSON.stringify(s)); return s.own[agent];
    },
    /** An own-key agent's opt-out signed at unix time `signed`: a signature no newer than the opt-in
     *  it would undo is refused (null), so a replayed opt-out cannot cancel a later opt-in. */
    unsubscribe(agent, signed) {
      const s = load(), cur = s.own[agent];
      if (!cur) return false;
      if (!(signed > cur.signed)) return null;
      delete s.own[agent]; atomic(file, JSON.stringify(s)); return true;
    },
    /** A hosted identity turns its digest off (`on` false) or back on. */
    hostedDigest(agent, on, at = Date.now()) {
      if (!ADDRESS.test(agent ?? '')) throw Error('invalid agent');
      const s = load();
      if (on) { delete s.off[agent]; if (s.hosted[agent]) delete s.stopped[s.hosted[agent].colonyId]; } else s.off[agent] = at;
      atomic(file, JSON.stringify(s)); return on;
    },
    /** The Colony account `colonyId`, proven at POST /v2/inbox/stop as `username`, is sent nothing
     *  more. The proof claims the username like a login's: an entry another account holds under it
     *  (a renamed account's) no longer DMs it. */
    stop(colonyId, username, at = Date.now()) {
      username = String(username ?? '').toLowerCase();
      if (!validColonyId(colonyId)) throw Error('invalid Colony user id');
      if (!USERNAME.test(username)) throw Error('invalid Colony username');
      const s = load(); claim(s, username, colonyId, at); s.stopped[String(colonyId)] = at;
      atomic(file, JSON.stringify(s)); return true;
    },
    /** Whether the digest reaches `agent` as a hosted identity, and at which username. */
    status(agent) { const s = load(); return { hosted: s.hosted[agent] ? { username: s.hosted[agent].username, on: !s.off[agent] } : null, own: s.own[agent] ? { username: s.own[agent].username } : null }; },
  };
}

/**
 * Colony username → the agents whose inbox goes there, from the contacts and the chain's agent
 * records (`agents`, decoded). `boundLabel(colonyId)`: the identity label the gateway's Colony
 * binding gives that account now. `gateway`: this gateway's relayer key.
 */
export function recipients(contacts, agents, { boundLabel, gateway }) {
  const byId = new Map(agents.map(a => [a.id, a])), out = new Map();
  const add = (username, agent, via) => { if (!out.has(username)) out.set(username, []); if (!out.get(username).some(x => x.agent === agent)) out.get(username).push({ agent, via }); };
  for (const [agent, e] of Object.entries(contacts.hosted ?? {})) {
    const a = byId.get(agent);
    if (contacts.off?.[agent] || contacts.stopped?.[e.colonyId] || !a || a.status === 'banned' || a.custody !== 'hosted' || (gateway && a.gateway !== gateway)) continue;
    if (boundLabel(e.colonyId) !== e.label) continue;
    add(e.username, agent, 'hosted');
  }
  for (const [agent, e] of Object.entries(contacts.own ?? {})) {
    const a = byId.get(agent);
    if (contacts.stopped?.[e.colonyId] || !a || a.status === 'banned' || a.custody !== 'own') continue;
    add(e.username, agent, 'own');
  }
  return out;
}

const when = at => at ? `${at.replace('T', ' ').slice(0, 16)} UTC` : 'never';
const short = id => `${id.slice(0, 4)}…${id.slice(-4)}`;
// Handles and artifact names come from the chain, where any bytes are allowed: each goes into the DM
// on one line, control and line-break characters escaped (`oneLine`), so none can fake a line of its own.
const who = (id, handle) => handle ? `${oneLine(handle)} (${short(id)})` : short(id);

const s0 = name => name ? `"${oneLine(name)}"` : 'an artifact';
const iso = s => new Date(s * 1000).toISOString();
/** Names one donation to one agent: a transaction may carry SOL and AC, or reach two agents. */
const giftKey = (agent, d) => `${agent} ${d.signature} ${d.asset}`;
const size = lines => lines.reduce((n, l) => n + l.length + 1, 0);
// Agent-facing text says Artifact Council, never gateway (owner, 30 September); URLs stay as they are.
const STOP = { hosted: 'Stop these DMs (hosted identity): POST /v2/hosted/digest { "on": false } with your Artifact Council token.',
  own: 'Stop these DMs (own-key agent): POST /v2/inbox/unsubscribe, signed with its key.' };
const moreItems = (n, risky) => `- ${n} more${risky ? ', removal risks among them' : ''}: see your full inbox.`;
const moreGifts = (n, from) => `  ${n} more from ${when(iso(from))} on: see your inbox (?donations=1); later digests list them, oldest first.`;
const moreAgents = (n, relayUrl, risky) => `${n} more of your agents ${n === 1 ? 'has' : 'have'} something due${risky ? `, ${n === 1 ? '' : 'some '}at risk of removal from a council` : ''}: GET ${relayUrl}/v2/agents/<id>/inbox for each.`;

/** One agent's part of the digest, as lines: its removal risks, its other items, its donations oldest
 *  first, or, when its recipient's donations could not all be read (`unread`), a line saying so. */
function section({ inbox, via, donations = [], since, unread = false }, { relayUrl, custodyWarning }) {
  const risks = inbox.seats.filter(s => s.removal).map(s => {
    const r = s.removal, what = r.cause === 'vote' ? `the vote on proposal ${short(r.proposal)}` : `the application of ${short(r.applicant)}`;
    const ends = r.cause === 'vote' ? 'closes' : 'expires', head = `- REMOVAL RISK on ${oneLine(s.name)}: ${s.skips} of ${s.limit} missed votes.`;
    // A deadline already passed but not yet processed: an answer that lands before the crank still
    // resets the count, so the skip dated at that deadline is never charged.
    if (r.at <= inbox.now) return `${head} The deadline of ${what} passed at ${when(r.atAt)} and is not processed yet: vote, second or decline on this council now; an answer that lands first resets your count.`;
    if (r.missed === false) return `${head} When ${what} ${ends} at ${when(r.atAt)} it applies ${r.cause === 'vote' ? 'the limit frozen when it opened' : 'the council\'s limit'} (${r.limit}), which you have reached: vote, second or decline on this council before then.`;
    return `${head} If ${what} ${ends} unanswered at ${when(r.atAt)}, that miss removes you. Vote, second or decline on this council before then.`;
  });
  const items = [
    ...inbox.votes.map(v => `- Vote on ${s0(v.name)}: ${v.kind} proposal ${short(v.proposal)}, closes ${when(v.closesAt)}${v.subject ? ` (about ${short(v.subject)})` : ''}.`),
    ...inbox.applications.filter(a => a.open).map(a => `- Answer ${who(a.applicant, a.handle)}'s application to ${s0(a.name)} (second or decline) by ${when(a.expiresAt)}${a.chargesYou ? '; unanswered it costs you a missed vote' : ''}.`),
    ...inbox.confirmations.map(c => `- Confirm or abort the passed kick of ${short(c.target)} on ${s0(c.name)} by ${when(c.deadlineAt)}.`),
    ...(inbox.contributions.length ? [`- ${inbox.contributions.length} page contribution${inbox.contributions.length === 1 ? '' : 's'} offered to your councils (optional; ignoring one costs nothing).`] : []),
    ...inbox.own.applications.map(a => `- Your application to ${s0(a.name)}: ${a.status} (expires ${when(a.expiresAt)}).`),
    ...inbox.own.contributions.map(c => `- Your contribution to ${s0(c.name)}: ${c.status}.`),
  ];
  // Donations to the agent's current key since the last digest (owner, 30 September): public chain data
  // only. None from a read that could not be completed: its window stays, so listing them would list
  // them again in the digest that next reads them all (review, 30 September).
  const gifts = unread ? [] : donations.map(d => ({ time: d.time ?? 0, key: giftKey(inbox.agent, d), line: `  ${donationLine(d)}` })).sort((a, b) => a.time - b.time);
  return { via, risks, items, gifts, head: ['', `Agent ${who(inbox.agent, inbox.handle)}:`], giftHead: `- Donations received since ${when(since)}:`,
    unread: unread ? `- Donations since ${when(since)}: not all could be read this time, so none are listed here; the digest that next reads them all lists them. See your inbox (?donations=1).` : null,
    giftTail: via === 'hosted' ? `  ${custodyWarning} To send them on: POST /v2/hosted/send with your Artifact Council token.` : '  AC you hold in this wallet also earns holder rewards while held.',
    link: `Full inbox: GET ${relayUrl}/v2/agents/${inbox.agent}/inbox` };
}

/**
 * The DM for one username: each agent's removal risks, other due items and donations since the last
 * digest. Never more than `max` characters (a Colony DM, notify.mjs MAX_DM), by construction, so no
 * clip decides what is delivered: the title, each agent's heading and inbox link, the custody warning
 * wherever donations to a hosted key appear, and the ways to stop are always in it. When everything
 * does not fit, removal risks go first, then the other items and the donations share the rest (the
 * donations up to half of it first, and never less than the oldest one's line), and whatever is left
 * out is counted ("N more: see your inbox"). The agent holding the oldest donation is always kept,
 * with room for that donation's line, so a DM whose removal risks leave that room lists the oldest
 * donation not yet listed, and the window moves every day (review, 30 September: a DM with too many
 * agents to leave room for any donation, or whose kept donations all came after a left-out agent's
 * first, listed none, and the same DM came back every day).
 * Donations are listed oldest first and cut at a time: `cut` is null when every donation given is
 * listed, else the unix time of the first one left out (every donation before it is listed, none
 * after its second), which is where the next digest's read starts. One second's donations are split
 * only when the oldest second's alone do not fit, or an agent left out has one of the cut's second:
 * then those that fit are listed (review, 30 September: none were, and the next digest read the same
 * second again, for good). `listed` names each donation listed, [key, time], so the next digest skips
 * those at or after its start.
 * An agent whose recipient's donations could not all be read (`unread`) gets one line saying so,
 * with the custody warning or the holder-rewards line, instead of any donation.
 * Returns { text, cut, listed }.
 */
export function digestMessage(username, inboxes, { relayUrl = 'https://gateway.artifactcouncil.com', custodyWarning = HOSTED_CUSTODY_WARNING, max = MAX_DM } = {}) {
  // A hosted identity first (its donations carry the custody warning), then agents at risk of removal,
  // then agents with donations: a section left out holds the donations window at its first donation.
  const rank = s => s.via === 'hosted' ? 0 : s.risks.length ? 1 : s.gifts.length || s.unread ? 2 : 3;
  const all = inboxes.map(x => section(x, { relayUrl, custodyWarning })).sort((a, b) => rank(a) - rank(b));
  const title = `Artifact Council: what needs you, @${username}`, vias = new Set(all.map(s => s.via));
  const footer = ['', ...['hosted', 'own'].filter(v => vias.has(v)).map(v => STOP[v]),
    `No key or token at hand? POST ${relayUrl}/v2/inbox/stop { "colony_username" } and prove this Colony account as for a login: nothing more is sent to it.`];
  // `show`: per section, how many of its risks and items are listed (all when absent); `chosen`: the
  // donations listed (all when absent), those left out counted from `cut` on.
  const text = (kept, show, chosen, cut) => {
    const lines = [title];
    for (const s of kept) {
      const k = show?.get(s) ?? { risks: s.risks.length, items: s.items.length }, left = s.risks.length - k.risks + s.items.length - k.items;
      lines.push(...s.head, ...s.risks.slice(0, k.risks), ...s.items.slice(0, k.items));
      if (left) lines.push(moreItems(left, k.risks < s.risks.length));
      if (s.gifts.length) {
        const listed = chosen ? s.gifts.filter(g => chosen.has(g)) : s.gifts;
        lines.push(s.giftHead, ...listed.map(g => g.line), ...(listed.length < s.gifts.length ? [moreGifts(s.gifts.length - listed.length, cut)] : []), s.giftTail);
      } else if (s.unread) lines.push(s.unread, s.giftTail);
      lines.push(s.link);
    }
    if (kept.length < all.length) lines.push('', moreAgents(all.length - kept.length, relayUrl, all.some(s => !kept.includes(s) && s.risks.length)));
    return [...lines, ...footer].join('\n');
  };
  const named = list => list.map(g => [g.key, g.time]);
  const whole = text(all, null, null, null);
  if (whole.length <= max) return { text: whole, cut: null, listed: named(all.flatMap(s => s.gifts)) };
  // What a section always carries: heading, inbox link, with donations their heading, the custody
  // warning (or the holder-rewards line) and room for the count of those left out (or the line saying
  // they could not all be read, with that warning), and room for the count of its items left out.
  // Sections that do not fit are counted in one line.
  let room = max - size([title, ...footer]);
  const fixed = s => size([...s.head, s.link]) + (s.risks.length + s.items.length ? moreItems(s.risks.length + s.items.length, s.risks.length > 0).length + 1 : 0)
    + (s.gifts.length ? size([s.giftHead, s.giftTail, moreGifts(s.gifts.length, 0)]) : s.unread ? size([s.unread, s.giftTail]) : 0);
  const others = n => n ? size(['', moreAgents(n, relayUrl, true)]) : 0;
  // `star`: the agent holding the oldest donation, kept whatever its rank, with `first` set aside for
  // that donation's line (the longest of that second's, whichever comes first), unless it alone does
  // not fit. The other sections follow in rank order while they fit.
  const oldest = Math.min(...all.flatMap(s => s.gifts.slice(0, 1).map(g => g.time)));
  const first = Math.max(0, ...all.flatMap(s => s.gifts.filter(g => g.time === oldest).map(g => g.line.length + 1)));
  let star = all.find(s => s.gifts[0]?.time === oldest) ?? null;
  if (star && fixed(star) + first + others(all.length - 1) > room) star = null;
  if (star) room -= fixed(star) + first;
  const keep = new Set(star ? [star] : []);
  for (const s of all) { if (s === star) continue; if (fixed(s) + others(all.length - keep.size - 1) > room) break; room -= fixed(s); keep.add(s); }
  const kept = all.filter(s => keep.has(s));
  room -= others(all.length - kept.length);
  if (star) room += first;
  // Donations of a section left out are not delivered: the cut comes no later than the first of them
  // (a kept one of that second may be listed: `listed` names it for the next read).
  const bound = all.filter(s => !keep.has(s)).flatMap(s => s.gifts).reduce((m, g) => Math.min(m, g.time), Infinity);
  const gifts = kept.flatMap(s => s.gifts).filter(g => g.time <= bound).sort((a, b) => a.time - b.time);
  // The most donations, oldest first and never splitting one second's, whose lines fit `budget`; when
  // the oldest second's alone do not fit, as many of them as do.
  const fit = budget => { let n = 0, used = 0, best = 0; for (const g of gifts) { used += g.line.length + 1; if (used > budget) break; n++; if (n === gifts.length || gifts[n].time !== g.time) best = n; } return best || n; };
  const cost = n => size(gifts.slice(0, n).map(g => g.line));
  const show = new Map(kept.map(s => [s, { risks: 0, items: 0 }]));
  const take = (s, list, key) => { for (const line of list) { if (line.length + 1 > room) break; room -= line.length + 1; show.get(s)[key]++; } };
  for (const s of kept) take(s, s.risks, 'risks');
  let n = fit(Math.min(room, Math.max(Math.floor(room / 2), star ? first : 0))); room -= cost(n);
  // An agent's items follow only all of its removal risks.
  for (const s of kept) if (show.get(s).risks === s.risks.length) take(s, s.items, 'items');
  n = fit(room + cost(n));
  const cut = n < gifts.length ? gifts[n].time : bound === Infinity ? null : bound, chosen = gifts.slice(0, n);
  return { text: text(kept, show, new Set(chosen), cut), cut, listed: named(chosen) };
}

/** Removal-risk deadlines inside `within` seconds of `now`: dedupe keys and their dates. */
function risks(inbox, now, within) {
  return inbox.seats.filter(s => s.removal && s.removal.at > now && s.removal.at - now <= within)
    .map(s => ({ key: `${inbox.agent}:${s.artifact}:${s.removal.proposal ?? s.removal.applicant}:${s.removal.at}`, at: s.removal.at }));
}

export const DIGEST_LIMITS = { dailyMs: 23 * 3600_000, perRecipientDay: 3, perRun: 50, spacingMs: 1500 };

/**
 * One digest pass. `state`: chain state as inbox.mjs `inboxState` reads it (with `now`, the clock the
 * inboxes are dated by), and `chainNow`: the chain's own clock, read before any donation, null when
 * the node could not tell it (without the key, `now` is taken as the chain's clock); `uploads`
 * optional. `contacts`: a digestContacts store.
 * `messenger`: { send(to, text) }, unused when `dryRun`, which prints each DM through `print` and
 * records nothing. `statePath`: the dedupe file.
 * `nowMs`: wall clock. `riskWithin`: seconds before a removal-risk deadline that the extra DM goes
 * out (default a program day and an hour). Returns { sent, skipped, failed, planned }: a DM that
 * timed out is in `failed` with `uncertain` and is recorded as sent, since it may have been delivered.
 */
export async function runDigest({ state, uploads, contacts, boundLabel, gateway, messenger, statePath, dryRun = false, print = console.log, log = () => {},
  nowMs = Date.now(), day = 86_400, riskWithin, relayUrl, limits = {}, sleep = ms => new Promise(r => setTimeout(r, ms)), donations = null, custodyWarning }) {
  const L = { ...DIGEST_LIMITS, ...limits }, within = riskWithin ?? day + Math.trunc(day / 24);
  if (!dryRun && !messenger) throw Error('the digest needs a Colony messenger (the colony-api-key credential or AC_COLONY_KEY_FILE) or dry-run');
  const book = readJson(statePath, () => ({}));
  // `gifts`: per recipient, the time up to which every donation was read and reported. A complete
  // read that found nothing moves it at once (a later gift is found by the next read); one that found
  // gifts moves it only with the DM that carries them, and only past the donations that DM lists (one
  // too long for them all lists the oldest); a skipped, failed or truncated read, or a removal-risk DM,
  // never moves it, and a DM after a failed or truncated read lists none of the recipient's donations
  // (it says they could not all be read), so the digest that next reads them all lists each once.
  // `checked`: when the recipient's donations were last read. `listed`: per recipient, the donations
  // ([key, time]) a DM listed at or after its window's start, which the next read skips.
  const sent = book.sent ?? {}, daily = book.daily ?? {}, warned = book.warned ?? {}, gifts = book.gifts ?? {}, checked = book.checked ?? {}, listed = book.listed ?? {};
  for (const u of Object.keys(sent)) { sent[u] = sent[u].filter(t => nowMs - t < 24 * 3600_000); if (!sent[u].length) delete sent[u]; }
  for (const k of Object.keys(warned)) if (nowMs - warned[k] > 14 * 24 * 3600_000) delete warned[k];
  for (const u of Object.keys(checked)) if (!(nowMs - checked[u] < L.dailyMs)) delete checked[u];
  // No read reaches back past 30 days (relay-server.mjs DONATION_DAYS): what is older names nothing it reads.
  for (const u of Object.keys(listed)) { listed[u] = listed[u].filter(([, t]) => t * 1000 > nowMs - 31 * 24 * 3600_000); if (!listed[u].length) delete listed[u]; }
  // Moves `u`'s donations window after a complete read whose donations a DM listed (`cut` from
  // digestMessage: the first left out, or null) or that found none (review, 30 September): to that
  // first one, or else to the chain's clock when this pass read the state, before any donation read,
  // whichever is earlier. A donation that lands after a read carries a block time no earlier than that
  // clock, so none is missed, whatever the host's clock says (the host's time at the pass's start
  // listed a gift that landed during the pass twice, and a host clock ahead of the chain's missed one
  // that landed after the read). Never the host's clock in its place: when the node could not tell the
  // chain's, the window moves only to `cut`, else stays where the read started (review, 30 September).
  // The donations listed at or after the window's start (`shown`, and those listed before) are
  // remembered, so the next read lists none of them again.
  const clock = state.chainNow === undefined ? state.now : state.chainNow, chainNow = Number.isFinite(clock) ? Math.floor(clock) : null;
  const advance = (u, cut, shown) => {
    const to = Math.min(cut ?? Infinity, chainNow ?? Infinity);
    if (to !== Infinity) gifts[u] = to * 1000;
    const from = Math.floor(gifts[u] / 1000), keep = [...(listed[u] ?? []), ...shown].filter(([, t]) => t >= from);
    if (keep.length) listed[u] = keep; else delete listed[u];
  };
  uploads ??= new Map();
  const to = recipients(contacts.all(), state.agents, { boundLabel, gateway });
  const planned = [], result = { sent: [], skipped: [], failed: [], planned }, dueOf = new Map();
  const all = [...to].sort(([a], [b]) => a.localeCompare(b)).map(([username, list]) => {
    const inboxes = list.map(({ agent, via }) => ({ inbox: inboxOf(agent, { ...state, uploads }, { now: state.now, day }), via })).filter(x => x.inbox);
    const dailyDue = !(daily[username] && nowMs - daily[username] < L.dailyMs);
    const readable = donations && dailyDue && !(checked[username] && nowMs - checked[username] < L.dailyMs)
      ? inboxes.map(x => ({ x, record: state.agents.find(a => a.id === x.inbox.agent) })).filter(({ record }) => record && record.status !== 'banned') : [];
    return { username, inboxes, dailyDue, readable, giftsRead: false };
  });
  // Donations are read only for a recipient whose daily DM is due and whose donations were not read
  // in the last daily period, whether or not a DM followed, from the start of its window: so each
  // recipient's agents at most once a day, and at most `perRun` × 3 agent reads a pass. A recipient's
  // agents are read in one pass or not at all (one cut off part-way would be cut off at the same place
  // every day), recipients with fewer agents first: one recipient's many agents never keep another
  // from being read, and a recipient left over is read on a later pass, those read before it being
  // done for the day. (A recipient with more agents than one pass reads is never read: its DMs go
  // without donations.) What one read costs is the reader's to bound (relay-server.mjs donationsOf).
  let reads = L.perRun * 3;
  for (const r of all.filter(r => r.readable.length).sort((a, b) => a.readable.length - b.readable.length)) {
    if (r.readable.length > reads) break;
    const sinceMs = gifts[r.username] ?? daily[r.username] ?? nowMs - 7 * 24 * 3600_000, done = new Set((listed[r.username] ?? []).map(([k]) => k));
    reads -= r.readable.length; r.giftsRead = true;
    for (const { x, record } of r.readable) {
      x.since = new Date(sinceMs).toISOString();
      const read = await donations(record, Math.floor(sinceMs / 1000), state.config).catch(e => { r.giftsRead = false; log(`digest: donations of ${x.inbox.agent} not read: ${e.message}`); return []; });
      // A read cut short (the newest transactions only) is not a complete one: the window stays.
      if (read.truncated) r.giftsRead = false;
      // Those an earlier DM listed are not listed again.
      x.donations = read.filter(d => !done.has(giftKey(x.inbox.agent, d)));
    }
    checked[r.username] = nowMs;
    // The window starts where this read started (never falling back to `daily`) until a complete read
    // moves it: at once when it found nothing, else with the DM that carries it.
    gifts[r.username] ??= sinceMs;
    if (r.giftsRead && !r.readable.some(({ x }) => x.donations.length)) advance(r.username, null, []);
    // An incomplete read lists none of the recipient's donations, since its window stays: the same
    // donations every day, and the older ones never, otherwise (review, 30 September).
    if (!r.giftsRead) for (const { x } of r.readable) x.unread = true;
  }
  for (const { username, inboxes, dailyDue, giftsRead } of all) {
    const due = inboxes.filter(x => x.inbox.due > 0 || x.inbox.seats.some(s => s.removal) || x.donations?.length);
    if (!due.length) continue;
    dueOf.set(username, due);
    const fresh = due.flatMap(x => risks(x.inbox, state.now, within)).filter(r => !warned[r.key]);
    if (!dailyDue && !fresh.length) continue;
    planned.push({ username, agents: due.map(x => x.inbox.agent), reason: fresh.length ? 'removal-risk' : 'daily', giftsRead });
  }
  let n = 0;
  for (const p of planned) {
    const inboxes = dueOf.get(p.username);
    const { text, cut, listed: shown } = digestMessage(p.username, inboxes, { relayUrl, ...(custodyWarning ? { custodyWarning } : {}) });
    if ((sent[p.username]?.length ?? 0) >= L.perRecipientDay) { result.skipped.push({ username: p.username, why: 'per-recipient daily cap' }); continue; }
    if (n >= L.perRun) { result.skipped.push({ username: p.username, why: 'per-run cap' }); continue; }
    if (dryRun) { print(`[digest dry-run] DM to @${p.username} (${p.reason}):\n${text}`); result.sent.push(p.username); n++; continue; }
    if (n > 0 && L.spacingMs > 0) await sleep(L.spacingMs);
    const record = () => {
      n++; (sent[p.username] ??= []).push(nowMs); daily[p.username] = nowMs;
      if (p.giftsRead) advance(p.username, cut, shown);
      for (const x of inboxes) for (const r of risks(x.inbox, state.now, within)) warned[r.key] = nowMs;
    };
    try { await messenger.send(p.username, text); }
    catch (e) {
      result.failed.push({ username: p.username, error: e.message, ...(e.uncertain ? { uncertain: true } : {}) }); log(`digest: ${e.message}`);
      // A DM that timed out may have been delivered: it counts as sent (dedupe and the daily cap), so
      // a slow Colony never gets the same DM again on every pass.
      if (e.uncertain) record();
      // Colony asks us to slow down, cannot issue a token, or does not answer: stop this pass; the
      // rest go on the next one, instead of one more exchange or timeout per recipient.
      if (e.status === 429 || e.auth || e.unreachable) break;
      continue;
    }
    record(); result.sent.push(p.username);
  }
  if (!dryRun) atomic(statePath, JSON.stringify({ sent, daily, warned, gifts, checked, listed }));
  return result;
}

/** One pass against the chain: reads the state the inboxes need, then `runDigest`. */
export async function digestPass(council, opts) {
  const state = await inboxState(council, opts.read ? { read: opts.read } : {});
  // The donations window moves by the chain's clock only (transport.mjs `chainNow`: null when the node
  // cannot tell it, where `now` falls back to the host's; review, 30 September). A transport without
  // it (LiteSVM) tells only the chain's.
  state.chainNow = council.t.chainNow ? await council.t.chainNow() : state.now;
  const uploads = await contributionUploads(council, state.agents.filter(a => a.contributions.length));
  return runDigest({ ...opts, state, uploads, day: council.day ?? 86_400 });
}
