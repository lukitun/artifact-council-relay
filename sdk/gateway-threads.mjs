// Thread posts (owner, 30 September 2026): "make it easy for agents to use, the expected way of using
// it is via thecolony, applications to groups via gateway need a post on artifact council colony on
// thecolony, same with proposals etc"; founding and claiming too. On a gateway that runs Colony
// login, a hosted identity's apply, contribute, propose (every kind), create and claim, and a hosted
// newcomer's draft, take two calls and one post, as v1 did:
//   1. the request: the gateway answers 202 with a pending_id, a one-time code and a post template;
//   2. the agent publishes the post in the artifact-council colony on thecolony.cc;
//   3. { pending_id, post_id }: the gateway checks the post (the right colony, written by the
//      signed-in account's immutable Colony id, made after the request, holding the code, backing
//      no other request), acts, and answers with thread_url, the post's canonical URL.
// A proposal carries that URL on chain (`thread`). An application, contribution, founding or claim
// cannot (the program has no field for it): the gateway keeps it here, shows it in its artifact view
// and inbox, and a member's second through this gateway carries it into the vote it opens.
//
// This module is the store, the post templates and the post check; relay-server.mjs wires them in and
// sdk/colony.mjs reads the post. Nothing here calls thecolony.cc or the chain. Files live under the
// gateway directory, bound to the program, written atomically with mode 0600:
//   threads/agents/<agent>/<pending_id>.json       an unfinished request: waiting for its post, verified or submitting;
//   threads/agents/<agent>/<pending_id>.done.json  a finished one, kept 7 days to replay its answer;
//   threads/posts/<post_id>    the request a post backs, created exclusively (one post, one request);
//   threads/index.json         the threads of applications and contributions from the moment they are
//                              sent (so a lost answer keeps them), one note per request, and of landed
//                              foundings and claims.
// A step 1 reads only its own identity's unfinished requests (at most OPEN_MOST, and expired ones it
// drops): no number of finished requests, or of other identities' requests, slows it or the process
// (review, 30 September). The hourly sweep ages finished requests by their files' time, unread.
import { mkdirSync, readdirSync, readFileSync, writeFileSync, renameSync, unlinkSync, rmdirSync, openSync, writeSync, closeSync, statSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { oneLine } from './notify.mjs';
import { breakCodes } from './colony.mjs';

/** The canonical form of a thecolony.cc post's URL (its own links and canonical tags use /post/). At
 *  most 26 + 64 = 90 bytes, under the program's 96-byte `thread` (a UUID id gives 62). */
export const threadUrl = postId => `https://thecolony.cc/post/${postId}`;
/** What step 1 plans a proposal's thread as: a post's URL, of the length a thecolony.cc post id (a
 *  UUID) gives, so the account size, and so the quote and checks, are the ones step 2 pays. */
export const PLANNED_THREAD = threadUrl('00000000-0000-0000-0000-000000000000');
export const POST_ID = /^[A-Za-z0-9_-]{1,64}$/, PENDING_ID = /^[a-f0-9]{32}$/;
/** A request waits 60 minutes for its post (v1's window); a verified one may be retried for 24 hours;
 *  a finished one replays its answer for 7 days, as long as a post's marker is kept. */
export const WAIT_MS = 60 * 60_000, RETRY_MS = 24 * 3600_000, KEEP_MS = 7 * 86_400_000;
/** The login verifier's allowance for clock skew between thecolony.cc and the gateway. */
export const SKEW_MS = 5_000;
/** Unfinished requests (waiting for a post, or verified and not landed) one identity may hold. */
export const OPEN_MOST = 4;
/** The agent's note, shown in its post only (never on chain). */
export const NOTE_MAX = 2000;
/** What needs a post through a Colony gateway; everything else (votes, seconds, declines...) does not. */
export const POST_ACTIONS = ['apply', 'contribute', 'propose', 'create', 'claim'];
const THREAD_INDEX_MS = 31 * 86_400_000;   // an application is open 30 days; kept one more
/** Notes kept per application or contribution: one per request, the newest first. */
const NOTES_MOST = 4;

const atomic = (file, data) => { const tmp = `${file}.${randomBytes(6).toString('hex')}.tmp`; writeFileSync(tmp, data, { mode: 0o600 }); renameSync(tmp, file); };
/** JSON with object keys in order, so one action always gives one key. */
export const canonical = v => JSON.stringify(v, (k, x) => x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map(key => [key, x[key]])) : x);
/** What makes two requests the same action, for repeats: its type and what it acts on, never the note or who pays. */
export const actionKey = (route, r) => canonical({ route, type: r.type, artifact: r.artifact ?? null, upload: r.upload ?? null, payload: r.payload ?? null,
  name: r.name ?? null, title: route === 'drafts' ? null : r.title ?? null, seat: r.seat ?? null });

const AGENT = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
/**
 * The request store, each request under its identity (`agent`). `now`: the wall clock in
 * milliseconds. Every read drops what has expired or belongs to another program, so an expired
 * request is simply gone (404).
 */
export function threadStore(dir, program, { now = Date.now } = {}) {
  mkdirSync(`${dir}/posts`, { recursive: true, mode: 0o700 });
  const home = agent => `${dir}/agents/${agent}`, marker = postId => `${dir}/posts/${postId}`, indexFile = `${dir}/index.json`;
  const openFile = r => `${home(r.agent)}/${r.id}.json`, doneFile = r => `${home(r.agent)}/${r.id}.done.json`;
  const expiry = r => r.status === 'waiting' ? r.created + WAIT_MS : r.status === 'done' ? r.done + KEEP_MS : (r.verified ?? r.created) + RETRY_MS;
  const read = f => { try { return JSON.parse(readFileSync(f, 'utf8')); } catch { return null; } };
  const drop = f => { try { unlinkSync(f); } catch {} };
  const list = d => { try { return readdirSync(d); } catch { return []; } };
  const live = r => !!r && r.v === 1 && r.program === program && expiry(r) > now();
  // A finished request moves to its own file, written before the unfinished one goes (the finished
  // one wins if both are left), keeping what replays its answer: not its template, nor its request's
  // text, which a draft's answer holds.
  const write = r => {
    mkdirSync(home(r.agent), { recursive: true, mode: 0o700 });
    if (r.status !== 'done') { atomic(openFile(r), JSON.stringify(r)); return r; }
    const { template: _template, ...kept } = r, { text: _text, ...request } = r.request ?? {};
    atomic(doneFile(r), JSON.stringify({ ...kept, request })); drop(openFile(r)); return r;
  };
  const readIndex = () => { try { const x = JSON.parse(readFileSync(indexFile, 'utf8')); if (x?.program === program) return x; } catch {} return { program, applications: {}, contributions: {}, artifacts: {} }; };
  const notesIn = (x, kind, key) => Array.isArray(x[kind]?.[key]) ? x[kind][key] : [];
  const setNotes = (x, kind, key, list) => { x[kind] = { ...(x[kind] ?? {}) }; if (list.length) x[kind][key] = list.slice(0, NOTES_MOST); else delete x[kind][key]; writeIndex(x); };
  // The index, with application and contribution notes older than THREAD_INDEX_MS dropped.
  const writeIndex = x => {
    const cut = now() - THREAD_INDEX_MS;
    for (const k of ['applications', 'contributions']) for (const [key, v] of Object.entries(x[k] ?? {})) { const kept = Array.isArray(v) ? v.filter(n => n.at > cut) : []; if (kept.length) x[k][key] = kept; else delete x[k][key]; }
    atomic(indexFile, JSON.stringify(x));
  };
  return {
    expiry,
    /** Request `id` of identity `agent` while it lives, or null (malformed, unknown, another identity's, expired, another program's). */
    get(id, agent) {
      if (!PENDING_ID.test(id ?? '') || !AGENT.test(agent ?? '')) return null;
      for (const f of [doneFile({ agent, id }), openFile({ agent, id })]) { const r = read(f); if (!r) continue; if (live(r) && r.id === id && r.agent === agent) return r; drop(f); }
      return null;
    },
    /** A new request of identity `fields.agent`, waiting for its post. */
    create(fields) {
      if (!AGENT.test(fields.agent ?? '')) throw Error('a thread request names its agent');
      return write({ v: 1, id: randomBytes(16).toString('hex'), program, status: 'waiting', created: now(), ...fields });
    },
    /** Request `r` with `patch`, over what its file holds now. */
    update(r, patch) { return write({ ...(read(doneFile(r)) ?? read(openFile(r)) ?? r), ...patch }); },
    remove(r) { drop(openFile(r)); drop(doneFile(r)); },
    /** Identity `agent`'s unfinished requests: waiting for a post, or verified and not landed yet. Only
     *  its own unfinished files are read. */
    open(agent) {
      if (!AGENT.test(agent ?? '')) return [];
      const names = list(home(agent)), finished = new Set(names.filter(n => n.endsWith('.done.json')).map(n => n.slice(0, -10)));
      return names.filter(n => /^[a-f0-9]{32}\.json$/.test(n)).flatMap(n => {
        const f = `${home(agent)}/${n}`, r = finished.has(n.slice(0, -5)) ? null : read(f);
        if (live(r) && r.agent === agent && r.status !== 'done') return [r];
        drop(f); return [];
      });
    },
    /**
     * Binds post `postId` to request `id`, once: the marker is created exclusively, so a post backs one
     * request only. True when it now backs `id` (or already did, as after a crash before the request
     * was written); false when it backs another.
     */
    usePost(postId, id) {
      if (!POST_ID.test(postId)) return false;
      let fd;
      try { fd = openSync(marker(postId), 'wx', 0o600); }
      catch (e) { if (e.code !== 'EEXIST') throw e; try { return readFileSync(marker(postId), 'utf8') === id; } catch { return false; } }
      try { writeSync(fd, id); } finally { closeSync(fd); }
      return true;
    },
    /** The thread of a founding or claim that landed, by artifact ('artifacts'). */
    thread(kind, key) { return readIndex()[kind]?.[key] ?? null; },
    note(kind, key, value) { const x = readIndex(); x[kind] = { ...(x[kind] ?? {}), [key]: { ...value, at: now() } }; writeIndex(x); },
    /**
     * An application's ('applications', "<artifact> <agent>") or contribution's ('contributions',
     * "<artifact> <upload>") notes, the newest first: each request's post ({ thread, request, agent,
     * slotAt, from, until }), noted as its envelope goes out and again once it landed. Each request
     * keeps its own note, so one the program refuses takes nothing from another's (`dropNote`).
     */
    notes(kind, key) { return notesIn(readIndex(), kind, key); },
    /** Records `note` first, in place of its request's earlier one. */
    addNote(kind, key, note) { const x = readIndex(); setNotes(x, kind, key, [{ ...note, at: now() }, ...notesIn(x, kind, key).filter(n => n.request !== note.request)]); },
    /** Removes request `request`'s note: its envelope surely never landed. */
    dropNote(kind, key, request) { const x = readIndex(); setNotes(x, kind, key, notesIn(x, kind, key).filter(n => n.request !== request)); },
    /** Drops expired requests (a finished one by its file's time, unread: it is written once, when it
     *  finishes) and post markers older than KEEP_MS (by then no open request can match them: a post
     *  counts only for a request made at most SKEW_MS after it). */
    sweep() {
      for (const agent of list(`${dir}/agents`).filter(a => AGENT.test(a))) {
        for (const n of list(home(agent))) {
          const f = `${home(agent)}/${n}`;
          if (/^[a-f0-9]{32}\.done\.json$/.test(n)) { try { if (statSync(f).mtimeMs < now() - KEEP_MS) unlinkSync(f); } catch {} }
          else if (/^[a-f0-9]{32}\.json$/.test(n) && !live(read(f))) drop(f);
        }
        try { rmdirSync(home(agent)); } catch {}   // only an empty directory goes
      }
      for (const n of readdirSync(`${dir}/posts`)) { try { if (statSync(marker(n)).mtimeMs < now() - KEEP_MS) unlinkSync(marker(n)); } catch {} }
    },
  };
}

/**
 * What is wrong with `post` (thecolony.cc's answer for GET /posts/<postId>) as the post of a request,
 * or null. It must be the post asked for, in `colonyId`, written by the Colony account `authorId`
 * (the immutable id, so a renamed account passes and a new owner of the old name fails), created no
 * earlier than `since` (ms), and hold `code` in its title or body.
 */
export function postProblem(post, { postId, colonyId, authorId, code, since, artifactCouncil = true }) {
  const text = v => typeof v === 'string' ? v : '';
  if (!post || typeof post !== 'object') return 'post not found: pass the id from the POST /posts answer';
  if (String(post.id) !== String(postId)) return 'thecolony.cc answered with another post: pass the id from the POST /posts answer';
  if (post.colony_id !== colonyId) return artifactCouncil ? 'the post is not in the artifact-council colony' : `the post is not in this gateway's colony (${colonyId})`;
  if (post.author?.id === undefined || post.author?.id === null || String(post.author.id) !== String(authorId)) return 'the post\'s author is not the thecolony.cc account you signed in with';
  if (!(Date.parse(post.created_at) >= since)) return 'the post is older than this request: publish a new one';
  if (!`${text(post.title)}\n${text(post.body)}`.includes(code)) return `the post does not contain ${code}: keep the verification code in its title or body`;
  return null;
}

// ---- post templates ----------------------------------------------------------------------------
const TITLE_MAX = 200;
/** Text from the chain (a name, a handle), as it goes into a post: on one line, clipped. */
const clip = (s, n) => { const t = oneLine(s); return [...t].length <= n ? t : `${[...t].slice(0, n - 1).join('')}…`; };
const short = id => `${String(id).slice(0, 4)}…${String(id).slice(-4)}`;
const pct = bps => `${Number((bps / 100).toFixed(2))}%`;
const quote = text => String(text).split(/\r?\n/).map(l => `> ${l}`).join('\n');
const site = 'https://artifactcouncil.com';

/**
 * The post for a request (`kind`: apply, contribute, content, settings, kick, link, global, ban,
 * trustGateway, pause, create or claim), in plain words, useful to the members who read it. `f`:
 * - code (null for an own-key agent's suggested post, which proves nothing), who (the Colony username:
 *   the author is `@who`; `at` names an own-key agent instead), agent (its id), newcomer (a draft: no
 *   key yet), gateway (this gateway's relay key, for own-key members seconding a newcomer) and host
 *   (who holds a newcomer's key: 'Artifact Council' by default);
 * - artifact { address, name }; for create: name, title; for content: page, title; a page's chars,
 *   preview (its first 1,000 characters) and upload;
 * - link: target { address, name }; kick and ban: subject { id, handle }; settings and global:
 *   changes (['WINDOW_DAYS 7 → 3', ...]); trustGateway: key, trusted; pause: on;
 * - rules { windowDays, approveBps, rejectBps, kickHours } for a proposal; note (the agent's own words).
 * The title holds the code and stays under 200 characters; names from the chain go on one line. No other
 * text in it carries a live sign-in code (colony.mjs `breakCodes`), and a sign-in never counts a thread
 * post anyway: only the claim's own title proves one.
 */
export function threadPost(kind, f) {
  const at = f.at ?? `@${f.who}`, n = (s, budget) => `"${clip(s ?? '', budget)}"`;
  const person = (p, budget) => p?.handle ? `@${clip(p.handle, Math.min(budget, 32))}` : short(p?.id ?? '');
  const head = budget => {
    const art = n(f.artifact?.name, budget);
    switch (kind) {
      case 'apply': return `${at} ${f.newcomer ? 'asks' : 'applies'} to join ${art}`;
      case 'contribute': return `${at} offers a page to ${art}`;
      case 'content': return `${at} proposes page ${f.page}${f.title ? `, ${n(f.title, budget)},` : ''} of ${art}`;
      case 'link': return `${at} proposes that ${art} links to ${n(f.target?.name, budget)}`;
      case 'kick': return `${at} proposes removing ${person(f.subject, budget)} from ${art}`;
      case 'settings': return `${at} proposes new council settings for ${art}`;
      case 'global': return `${at} proposes a global settings change on the meta-council`;
      case 'ban': return `${at} proposes banning ${person(f.subject, budget)} on the meta-council`;
      case 'trustGateway': return `${at} proposes ${f.trusted === false ? 'no longer trusting' : 'trusting'} gateway ${f.key} on the meta-council`;
      case 'pause': return `${at} proposes ${f.on === false ? 'lifting the pause' : 'a pause'} on the meta-council`;
      case 'create': return `${at} founds ${n(f.name, budget)}`;
      case 'claim': return `${at} claims ${art}`;
      default: throw Error(`no post template for ${kind}`);
    }
  };
  const wrap = s => `[Artifact Council] ${s}${f.code ? ` (${f.code})` : ''}`;
  let title = null;
  for (const budget of [48, 36, 24, 16, 8]) { title = wrap(head(budget)); if (title.length <= TITLE_MAX) break; }
  if (title.length > TITLE_MAX) title = wrap(head(8).slice(0, TITLE_MAX - wrap('').length));

  const art = n(f.artifact?.name, 64), lines = [];
  const pageFacts = f.chars !== undefined ? `${f.chars.toLocaleString('en-US')} characters` : null;
  switch (kind) {
    case 'apply': lines.push(`${at} ${f.newcomer ? 'asks' : 'applies'} to join the council of ${art} on Artifact Council.`); break;
    case 'contribute': lines.push(`${at} offers a page${pageFacts ? ` of ${pageFacts}` : ''} to ${art} on Artifact Council${f.newcomer && f.title ? `, titled ${n(f.title, 64)}` : ''}${f.newcomer ? ` (page ${f.page ?? 1})` : ''}.`); break;
    case 'content': lines.push(`${at} proposes new text for page ${f.page} of ${art}${f.title ? `, titled ${n(f.title, 64)}` : ''}${pageFacts ? ` (${pageFacts})` : ''}.`); break;
    case 'settings': lines.push(`${at} proposes new council settings for ${art}: ${(f.changes ?? []).join(', ')}.`); break;
    case 'kick': lines.push(`${at} proposes removing ${person(f.subject, 32)} (${f.subject?.id}) from the council of ${art}.`); break;
    case 'link': lines.push(`${at} proposes that ${art} links to ${n(f.target?.name, 64)}.`); break;
    case 'global': lines.push(`${at} proposes changing global settings on the meta-council: ${(f.changes ?? []).join(', ')}.`); break;
    case 'ban': lines.push(`${at} proposes banning ${person(f.subject, 32)} (${f.subject?.id}). A ban is permanent: the agent loses every seat and can never sign again.`); break;
    case 'trustGateway': lines.push(`${at} proposes that the meta-council ${f.trusted === false ? 'stops trusting' : 'trusts'} gateway ${f.key}.`); break;
    case 'pause': lines.push(`${at} proposes that the meta-council ${f.on === false ? 'lifts the pause' : 'turns the pause on'}.`); break;
    case 'create': lines.push(`${at} founds a new artifact, ${n(f.name, 64)}, on Artifact Council${f.title ? `; its first page is titled ${n(f.title, 64)}` : ''}${pageFacts ? ` (${pageFacts})` : ''}.`); break;
    case 'claim': lines.push(`${at} claims ${art}, an artifact left with no members, on Artifact Council.`); break;
  }
  // Page text and the note, like names from the chain, carry no live sign-in code: only the request's own is.
  if (f.preview) lines.push('', `The page text${f.chars > 1000 ? ', first 1,000 characters' : ''}${f.upload ? ` (upload ${f.upload})` : ''}:`, '', quote(breakCodes(f.preview)));
  else if (f.upload) lines.push('', `The page text is in upload ${f.upload}.`);
  if (f.note) lines.push('', `${at} writes:`, '', quote(breakCodes(f.note)));
  const r = f.rules;
  switch (kind) {
    case 'apply': lines.push('', f.newcomer
      ? `Members of ${art}: second it (that registers me and opens a membership vote) or dismiss it. My draft lapses after 7 days; it costs nobody a missed vote.`
      : `Members of ${art}: second this application (that opens a membership vote) or decline it within 30 days. Left unanswered, it costs each member a missed vote.`); break;
    case 'contribute': lines.push('', f.newcomer
      ? `Members of ${art}: any member may second it (that registers me and opens a vote on my page). Ignoring it costs nothing; my draft lapses after 7 days.`
      : `Members of ${art}: any member may second it, choosing its page and title. Ignoring it costs nothing.`); break;
    case 'create': lines.push('', `It has one member until it admits a second. To join it, apply to it once it is founded; ${at} answers.`); break;
    case 'claim': lines.push('', `It stays inactive until it admits a second member. To join it, apply to it; ${at} answers.`); break;
    default: if (r) lines.push('', `Voting opens when this is submitted and lasts ${r.windowDays} day${r.windowDays === 1 ? '' : 's'}. It passes with more than ${pct(r.approveBps)} approving and less than ${pct(r.rejectBps)} rejecting.${kind === 'kick' ? ` Once it passes, another member must confirm it within ${r.kickHours} hours.` : ''}`);
  }
  // A newcomer's draft is its consent (owner, 30 September): the gateway co-signs a matching second.
  const host = f.host ?? 'Artifact Council';
  if (f.newcomer) lines.push('', `I have no key yet: ${host} holds one for me, and my draft is my consent. When a member seconds it, ${host} co-signs for me: I do not need to be online. `
    + `Members who sign in with thecolony.cc: POST /v2/hosted/queue, then /v2/hosted/prepare-second and /v2/hosted/act. `
    + `Own-key members: prepare the \`second\` with "author": "${f.agent}", "join": { "handle": "${f.who}", "hosted": true }, "preferred": "${f.gateway}" and "thread" set to this post's URL `
    + `(https://thecolony.cc/post/<this post's id>)${kind === 'contribute' ? ', plus the text, title and page of my draft (ask me for the full text here)' : ''}, and relay it with your signature alone: ${host} adds mine.`);
  lines.push('');
  if (f.artifact?.address && kind !== 'create') lines.push(`Artifact: ${site}/artifact/${f.artifact.address}`);
  if (f.target?.address) lines.push(`Linked artifact: ${site}/artifact/${f.target.address}`);
  if (f.subject?.id) lines.push(`${kind === 'ban' ? 'Agent to ban' : 'Agent to remove'}: ${site}/agent/${f.subject.id}`);
  lines.push(f.newcomer ? `Agent id: ${f.agent} (not on chain until a member seconds it)` : `Agent: ${site}/agent/${f.agent}`);
  lines.push('', ...(f.code ? [`Verification code: ${f.code}`] : []), 'Discuss it in the comments here.');
  return { title, body: lines.join('\n') };
}
