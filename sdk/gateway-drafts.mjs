// Authenticated, program-bound newcomer drafts. Bounded per identity and globally; expire after
// seven days. Only the owner can mutate a draft; the gateway checks council membership on reads.
// A member may dismiss a draft: like a decline on chain (owner, 29 September), the same identity
// drafts for that artifact again only after `wait`, and never after `most` dismissals, counted per
// (identity, artifact) in dismissals.json. Drafts are off chain, so they charge nobody a skip. A
// draft also carries its seconding handshake (`note`): the member's prepared message and the
// newcomer's approval, each side reading the other's from the gateway. Its `thread` goes into that
// second on chain, so it is at most MAX_THREAD bytes; on a gateway that runs Colony login the gateway
// sets it from the draft's verified post (gateway-threads.mjs) and records that post's id (`post`), and
// `check` is the dry run it makes before asking for that post. There, a draft without `post` (saved
// before posts were checked, with a thread of the client's choosing) keeps working without a thread.
// A draft is its owner's consent (owner, 30 September: "draft = consent"): when a member seconds it
// exactly, the gateway co-signs for its hosted newcomer, until the newcomer removes the draft or it
// lapses. Once its owner is registered (a member seconded another of its drafts) a draft no longer
// stands for consent: the gateway sends a remaining application on chain as the agent's own, and marks
// what it cannot send (`registered`: { next }, the step the agent takes itself).
// `consent` records who gave it ({ label | legacyKey, colony }: how the gateway derives the
// newcomer's key, and the Colony account signed in when it was saved); it is never shown to members.
import { mkdirSync, readdirSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { clipHandle, MAX_THREAD } from './layout.mjs';
export function gatewayDrafts(dir, program, { now = Date.now, ttl = 7 * 86400000, maximum = 4096, bytes = 100000, wait = 2 * 86400000, most = 3 } = {}) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const ledger = `${dir}/dismissals.json`;
  const dismissals = () => { try { const d = JSON.parse(readFileSync(ledger, 'utf8')); return d.program === program ? d.rows : {}; } catch (e) { if (e.code === 'ENOENT') return {}; throw e; } };
  const atomic = (file, json) => { const temp = `${file}.${randomBytes(8).toString('hex')}.tmp`; writeFileSync(temp, json, { mode: 0o600 }); renameSync(temp, file); };
  const fail = (s, status = 400) => Object.assign(Error(s), { status });
  const path = id => { if (!/^[a-f0-9]{32}$/.test(id ?? '')) throw fail('invalid draft id'); return `${dir}/${id}.json`; };
  const remove = id => { try { unlinkSync(path(id)); } catch(e) { if(e.code !== 'ENOENT') throw e; } };
  const all = () => readdirSync(dir).filter(n => /^[a-f0-9]{32}\.json$/.test(n)).flatMap(n => {
    const d = JSON.parse(readFileSync(`${dir}/${n}`, 'utf8'));
    if (d.expires <= now() || d.program !== program) { remove(n.slice(0,-5)); return []; }
    return [d];
  });
  const draft = (owner, { artifact, type, text, title = '', page = 1, thread = '', post = null, handle = '', consent = null }) => {
    if (!['apply','contribute'].includes(type)) throw fail('draft type must be apply or contribute');
    const no = dismissalsOf(owner, artifact);
    if (no.count >= most) throw fail(`dismissed ${no.count} times by this council: this identity never drafts for it again`, 409);
    if (no.count && now() < no.last + wait) throw fail(`dismissed by this council: draft for it again after ${new Date(no.last + wait).toISOString()}`, 409);
    if (type === 'contribute' && typeof text !== 'string') throw fail('contribution text is required');
    if (!Number.isSafeInteger(page) || page < 1 || typeof title !== 'string' || typeof thread !== 'string' || typeof handle !== 'string'
      || (post !== null && !(typeof post === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(post)))) throw fail('invalid draft fields');
    // The second that carries it would be refused on chain, and the draft could never be seconded.
    if (Buffer.byteLength(thread) > MAX_THREAD) throw fail(`a thread reference is at most ${MAX_THREAD} bytes`);
    const rows = all(), mine = rows.filter(d => d.owner === owner), existing = mine.find(d => d.artifact === artifact && d.type === type);
    if (!existing && mine.filter(d => d.type === type).length >= 2) throw fail(`at most two pending drafts of each type: you have two ${type === 'apply' ? 'applications' : 'pages'} waiting. Remove one ({ "remove": "<draft id>" }; POST /v2/hosted/drafts {} lists them) to draft another now. Once a member seconds one you are registered, and you apply to further councils yourself with POST /v2/hosted/act instead`, 429);
    if (!existing && rows.length >= maximum) throw fail('draft queue full', 503);
    if (consent !== null && (typeof consent !== 'object' || !(typeof consent.label === 'string' || consent.legacyKey === true) || !(consent.colony === null || typeof consent.colony === 'string'))) throw fail('invalid draft consent');
    const d = { id: existing?.id ?? randomBytes(16).toString('hex'), program, owner, artifact, type, ...(type === 'contribute' ? { text } : {}), title, page, thread, ...(post ? { post } : {}), handle: clipHandle(handle),
      ...(consent ? { consent: consent.legacyKey ? { legacyKey: true, colony: consent.colony } : { label: consent.label, colony: consent.colony } } : {}), expires: now() + ttl };
    if (Buffer.byteLength(JSON.stringify(d)) + mine.filter(x => x.id !== d.id).reduce((n,x) => n + Buffer.byteLength(JSON.stringify(x)),0) > bytes) throw fail('identity draft quota exceeded', 413);
    return d;
  };
  const dismissalsOf = (owner, artifact) => dismissals()[`${owner} ${artifact}`] ?? { count: 0, last: 0 };
  return {
    list: artifact => all().filter(d => d.artifact === artifact),
    own: owner => all().filter(d => d.owner === owner),
    get(id) { return all().find(d => d.id === id) ?? null; },
    remove(owner, id) { const d = this.get(id); if (!d || d.owner !== owner) throw fail('draft not found', 404); remove(id); },
    /** Deletes every draft of `owner` (a banned identity). */
    removeOwner(owner) { const mine = this.own(owner); for (const d of mine) remove(d.id); return mine.length; },
    /** A member's no to draft `id`: it goes, and its owner's dismissals by that artifact count one more. */
    dismiss(id) {
      const d = this.get(id); if (!d) throw fail('draft not found or expired', 404);
      const rows = dismissals(), key = `${d.owner} ${d.artifact}`, row = { count: (rows[key]?.count ?? 0) + 1, last: now() };
      atomic(ledger, JSON.stringify({ program, rows: { ...rows, [key]: row } })); remove(id);
      return { draft: d, ...row };
    },
    dismissals: dismissalsOf,
    /**
     * The seconding handshake, kept on the draft so neither side needs another channel: a hosted
     * member's prepared `second` ({ by, message, expires }, shown to the newcomer in its own drafts),
     * then the newcomer's approval `cosigned` ({ message, cosignature }, shown to members in the
     * queue). A newer prepared second replaces both; editing the draft (`put`) drops them. `registered`
     * ({ next, at }): its owner was registered and the gateway could not send it on chain for it.
     */
    note(id, field, value) {
      if (!['second', 'cosigned', 'registered'].includes(field)) throw fail('invalid draft note');
      const d = this.get(id); if (!d) throw fail('draft not found or expired', 404);
      const next = { ...d, [field]: value };
      if (field === 'second') delete next.cosigned;
      atomic(path(id), JSON.stringify(next)); return next;
    },
    /** The draft `put` would save, after every check it makes, without saving it: the dry run before
     *  a newcomer is asked for its post. */
    check(owner, fields) { return draft(owner, fields); },
    put(owner, fields) {
      const d = draft(owner, fields), target = path(d.id), temp = `${target}.${randomBytes(8).toString('hex')}.tmp`;
      writeFileSync(temp, JSON.stringify(d), { mode: 0o600 }); renameSync(temp, target); return d;
    }
  };
}
