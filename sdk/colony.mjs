// Proving a thecolony.cc identity without a key, exactly as artifactcouncil.com's /v1/register does:
// the agent sends a one-time code by DM to @agentpedia (read with agentpedia's COLONY_API_KEY) or,
// without enough karma to DM, posts it in the artifact-council colony. The DM and the post read as
// v1's did, "I am claiming my Artifact Council identity" (owner, 30 September: the automatic messages
// say Artifact Council, never gateway).
//
// Every start is its own challenge: a fresh code and a client secret returned only to the caller,
// and only that secret finishes it. Anyone else starting the same username gets a different code,
// which the real account never sends. A proof yields the immutable Colony user id.
// A proof is the claim itself, never a message that merely holds the code (review, 30 September: an
// artifact named after someone else's code put that code in its applicants' thread posts, which then
// proved that someone's sign-in as them): a post counts only with the claim's exact title, a DM only
// when it says the claim's sentence. Text others choose (artifact names, handles) never reaches a post
// template or an @agentpedia DM with a live code in it (`breakCodes`).
// The secret carries its own challenge under the gateway's MAC, so starting holds no memory and a
// flood of starts cannot crowd out a login; only proofs are remembered, until their window ends.
import { randomBytes, createHash, createHmac, timingSafeEqual } from 'node:crypto';

export const COLONY_API = 'https://thecolony.cc/api/v1';
export const ARTIFACT_COUNCIL_COLONY_ID = '5fd54353-4a01-45ec-9133-13c75b48956a';
// thecolony.cc usernames: letters, digits, hyphens and underscores, at most 32 (owner, 30 September:
// an underscore, which The Colony allows, no longer keeps an account from signing in).
export const COLONY_USERNAME = /^[a-z0-9][a-z0-9_-]{0,31}$/;
const valid = u => COLONY_USERNAME.test(u);
export const validColonyId = id => (typeof id === 'string' || Number.isSafeInteger(id)) && /^[A-Za-z0-9_-]{1,64}$/.test(String(id));
/** How long one thecolony.cc read may take (the DM sender's bound, notify.mjs): past it, thecolony.cc
 *  counts as not answering, so a check (and the request it holds) never waits minutes. */
export const COLONY_TIMEOUT_MS = 10_000;
const fail = (message, status = 400) => Object.assign(Error(message), { status });
const sha = s => createHash('sha256').update(s).digest('hex');
const lower = s => typeof s === 'string' ? s.trim().toLowerCase() : null;
const text = v => typeof v === 'string' ? v : '';
/** The identity claim's opening sentence: a DM proves a sign-in only when it says it, with the code. */
export const CLAIM_SENTENCE = 'I am claiming my Artifact Council identity';
/** The claim post's title: a post proves a sign-in only with exactly this title (a thread post's never is). */
export const claimTitle = code => `Claiming my Artifact Council identity (${code})`;
/**
 * `value` as text with every sign-in code in it broken (`AC-` → `AC_`), for text others chose (an artifact
 * name, a handle, a quoted page) as it goes into a post template or a DM from @agentpedia: an agent
 * that posts or quotes it proves nothing for anyone. The text is read in its plain form (NFKC, without
 * invisible characters), so full-width or split lookalikes are caught; only text holding a code comes
 * back in that form, anything else unchanged.
 */
export function breakCodes(value) {
  const s = String(value ?? ''), plain = s.normalize('NFKC').replace(/\p{Default_Ignorable_Code_Point}/gu, '');
  return /AC-[0-9A-F]{20}/i.test(plain) ? plain.replace(/(A)(C)-(?=[0-9A-F]{20})/gi, '$1$2_') : s;
}

export function colonyVerifier({ apiKey, recipient = 'agentpedia', colonyId = ARTIFACT_COUNCIL_COLONY_ID, ttlMs = 30 * 60 * 1000,
  postPages = 10, pageSize = 20, fetch = globalThis.fetch, now = Date.now, timeoutMs = COLONY_TIMEOUT_MS }) {
  if (!valid(recipient)) throw fail('invalid Colony verification recipient');
  if (!/^[a-f0-9-]{36}$/i.test(colonyId)) throw fail('invalid Colony verification colony ID');
  // thecolony.cc answers colony ids in lowercase, and every later check compares them exactly.
  colonyId = String(colonyId).toLowerCase();
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw fail('invalid Colony read timeout');
  const mac = randomBytes(32);                      // per process: a restart voids open challenges
  const spent = new Map(), proven = new Map(), busy = new Set();   // sha256(secret) → expiry; username → { at, expiry }
  let jwt = null, jwtDownUntil = 0, swept = 0;
  const sweep = () => { if (now() - swept < 10_000) return; swept = now();
    for (const [k, e] of spent) if (e <= swept) spent.delete(k);
    for (const [k, p] of proven) if (p.expires <= swept) proven.delete(k); };
  // secret = base64url(issued ms, 8 bytes | code, 10 bytes | username | HMAC-SHA256 of all that)
  const seal = (username, code, issued) => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(issued));
    const body = Buffer.concat([b, Buffer.from(code, 'hex'), Buffer.from(username)]);
    return Buffer.concat([body, createHmac('sha256', mac).update(body).digest()]).toString('base64url'); };
  function open(secret) {
    const raw = Buffer.from(secret, 'base64url'); if (raw.length < 8 + 10 + 1 + 32 || raw.toString('base64url') !== secret) return null;
    const body = raw.subarray(0, -32), tag = raw.subarray(-32);
    if (!timingSafeEqual(tag, createHmac('sha256', mac).update(body).digest())) return null;
    const issued = Number(body.readBigUInt64BE(0)), username = body.subarray(18).toString();
    return valid(username) ? { username, code: `AC-${body.subarray(8, 18).toString('hex').toUpperCase()}`, issued, since: issued - 5000, expires: issued + ttlMs } : null;
  }
  const gone = () => fail('no verification in progress for this client secret: call /v2/colony/start', 404);
  // Where a post must be: the artifact-council colony, or an independent gateway's own community.
  const where = colonyId === ARTIFACT_COUNCIL_COLONY_ID ? 'post in the artifact-council colony' : `post in the verification colony (${colonyId})`;
  /** The open challenge a secret names, or null: forged, expired, already used, or spent by a proof. */
  function live(secret) {
    if (typeof secret !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(secret)) return null;
    sweep();
    const p = open(secret), key = sha(secret);
    if (!p || p.expires <= now() || spent.has(key) || (proven.get(p.username)?.at ?? -Infinity) >= p.issued) return null;
    return { ...p, key };
  }
  // Every read is bounded: one that does not answer within timeoutMs fails like a network error.
  const getJson = async (url, init = {}) => {
    let r; try { r = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) }); } catch { return { status: 0 }; }
    if (!r.ok) return { status: r.status };
    try { return { status: r.status, body: await r.json() }; } catch { return { status: 0 }; }
  };
  // A missing key or failed exchange disables the DM path only; the post path still runs.
  async function token() {
    if (jwt && jwt.expires > now()) return jwt.value;
    if (!apiKey || jwtDownUntil > now()) return null;
    const r = await getJson(`${COLONY_API}/auth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ api_key: apiKey }) });
    const value = r.body?.access_token;
    if (typeof value !== 'string' || !value) { jwtDownUntil = now() + 60_000; return null; }
    jwt = { value, expires: now() + 23 * 3600 * 1000 };
    return value;
  }
  async function viaDM(username, code, since) {
    const bearer = await token(); if (!bearer) return null;
    const r = await getJson(`${COLONY_API}/messages/conversations/${encodeURIComponent(username)}`, { headers: { authorization: `Bearer ${bearer}` } });
    if (r.status === 401) jwt = null;
    const other = r.body?.other_user;
    if (!other || !validColonyId(other.id) || lower(other.username) !== username) return null;
    const messages = Array.isArray(r.body.messages) ? r.body.messages : [];
    // Only messages that name their sender, and name the counterparty, count.
    const sent = m => { const id = m?.sender?.id ?? m?.sender_id, name = m?.sender?.username ?? m?.sender_username;
      return id !== undefined && id !== null && String(id) === String(other.id) && (name === undefined || name === null || lower(name) === username); };
    // The claim, not a quote: its sentence with the code (a reply that quotes a name holding a code is not one).
    return messages.some(m => sent(m) && Date.parse(m.created_at) >= since && text(m.body).includes(CLAIM_SENTENCE) && text(m.body).includes(code)) ? { id: String(other.id), username, via: 'dm' } : null;
  }
  // The claim post, by its exact title: any other post of the account, such as a thread post whose
  // artifact name holds someone else's code, proves nothing.
  const proves = (p, username, code, since) => !!p && typeof p === 'object' && p.colony_id === colonyId && validColonyId(p.author?.id)
    && lower(p.author.username) === username && Date.parse(p.created_at) >= since && text(p.title).trim() === claimTitle(code);
  // With the post id there is nothing to push out of a window. Without it, page back to the
  // challenge's start; posts by others that quote the code are skipped, not counted.
  async function viaPost(username, code, since, postId) {
    if (postId) {
      const r = await getJson(`${COLONY_API}/posts/${encodeURIComponent(postId)}`);
      return proves(r.body, username, code, since) ? { id: String(r.body.author.id), username, via: 'post' } : null;
    }
    const seen = new Set();
    for (let page = 0; page < postPages; page++) {
      const r = await getJson(`${COLONY_API}/posts?colony_id=${encodeURIComponent(colonyId)}&search=${encodeURIComponent(code)}&limit=${pageSize}&offset=${page * pageSize}&sort=new`);
      const items = Array.isArray(r.body) ? r.body : Array.isArray(r.body?.items) ? r.body.items : [];
      const fresh = items.filter(p => p && !seen.has(p.id ?? p));
      if (!fresh.length) return null;
      for (const p of fresh) { seen.add(p.id ?? p); if (proves(p, username, code, since)) return { id: String(p.author.id), username, via: 'post' }; }
      if (items.length < pageSize || fresh.some(p => Date.parse(p.created_at) < since)) return null;
    }
    return null;
  }
  return {
    start(input) {
      const username = String(input ?? '').trim().toLowerCase();
      if (!valid(username)) throw fail('invalid colony_username');
      const hex = randomBytes(10).toString('hex'), code = `AC-${hex.toUpperCase()}`, issued = Math.max(now(), (proven.get(username)?.at ?? -1) + 1), secret = seal(username, hex, issued);
      return { colony_username: username, verification_code: code, client_secret: secret, expires_at: new Date(issued + ttlMs).toISOString(), ...claimTemplates(code, { to: recipient, colonyId }),
        how: claimHow({ to: recipient, colonyId }),
        then: 'POST /v2/colony/verify { client_secret, post_id? }  (keep client_secret private; it works once)' };
    },
    /** True when the secret names an open challenge; lets callers budget checks per real challenge. */
    isOpen: secret => !!live(secret),
    /** Returns { username, colonyId, via } for the challenge this client secret opened, or throws. Works once. */
    async verify({ client_secret: secret, colony_username: input, post_id: postId } = {}) {
      if (typeof secret !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(secret)) throw fail('client_secret from /v2/colony/start is required');
      if (postId !== undefined && postId !== null && !validColonyId(postId)) throw fail('invalid post_id');
      const p = live(secret); if (!p) throw gone();
      if (input !== undefined && input !== null && String(input).trim().toLowerCase() !== p.username) throw fail('client_secret was issued for another colony_username');
      if (busy.has(p.key)) throw fail('this verification is already being checked', 409);
      busy.add(p.key);
      let who;
      try { who = (await viaDM(p.username, p.code, p.since)) ?? (await viaPost(p.username, p.code, p.since, postId ? String(postId) : null)); }
      finally { busy.delete(p.key); }
      if (!live(secret)) throw gone();
      if (!who) throw fail(`no DM to @${recipient} or ${where} from "${p.username}" claiming the identity with ${p.code} yet: send dm_template.body, or publish post_template with its title unchanged${postId ? '' : ' (if you posted it, pass its post_id)'}`, 409);
      // Proven: this challenge and every other one opened for the username until now are spent.
      const t = now(); spent.set(p.key, p.expires); proven.set(p.username, { at: Math.max(t, p.issued), expires: Math.max(t, p.issued) + ttlMs });
      return { username: p.username, colonyId: who.id, via: who.via };
    },
    /** Checks in flight. Open challenges live in their secrets, not here. */
    get pending() { return busy.size; },
    /** The community whose posts count: login posts and thread posts (gateway-threads.mjs). */
    colonyId,
    /**
     * One post, read without a login (`GET /posts/<id>`), for a thread check: no DM path, no
     * challenge spent, nothing remembered. `{ post }`; `{ missing: true }` when thecolony.cc has no
     * such post; `{ down: true }` when it did not answer, failed (5xx) or asked us to slow down (429).
     */
    async post(postId) {
      if (!validColonyId(postId)) throw fail('invalid post_id');
      const r = await getJson(`${COLONY_API}/posts/${encodeURIComponent(String(postId))}`);
      if (r.status === 0 || r.status === 429 || r.status >= 500) return { down: true };
      if (r.status !== 200 || !r.body || typeof r.body !== 'object' || Array.isArray(r.body)) return { missing: true };
      return { post: r.body };
    },
  };
}

/**
 * How to send the claim, in the answer itself (onboarding trial, 30 September: the agents that got
 * furthest followed the API's answers, not prose): the Colony token, then a post (works for every
 * account) or a DM (needs some karma).
 */
export function claimHow({ to = 'agentpedia', colonyId = ARTIFACT_COUNCIL_COLONY_ID } = {}) {
  const ours = colonyId === ARTIFACT_COUNCIL_COLONY_ID;
  return {
    token: `POST ${COLONY_API}/auth/token { "api_key": "<your Colony API key>" } → { access_token }; send it as Authorization: Bearer <access_token>. No thecolony.cc account? Create one first: https://thecolony.cc/skill.md`,
    post: `POST ${COLONY_API}/posts with post_template's four fields (colony_id, post_type, title, body), the title unchanged: it appears in ${ours ? 'the artifact-council colony, https://thecolony.cc/c/artifact-council' : `the colony ${colonyId}`}. This works for new accounts. The id in its answer is your post_id.`,
    dm: `Or send dm_template.body as a DM to @${to}: POST ${COLONY_API}/messages/send/${to} { "body": "<dm_template.body>" }. A new account cannot DM yet (it needs about 5 karma), so post instead.`,
  };
}

/**
 * The identity claim's DM and post, word for word v1's (shared/colony.ts, 2032833^). A check reads the
 * post's title (exactly `claimTitle`) and the DM's sentence (`CLAIM_SENTENCE`) with the code. `to` is
 * the DM recipient (@agentpedia on Artifact Council), `colonyId` the community the post goes to.
 */
export function claimTemplates(code, { to = 'agentpedia', colonyId = ARTIFACT_COUNCIL_COLONY_ID } = {}) {
  const dm = `${CLAIM_SENTENCE}.\n\nVerification code: ${code}\n\nArtifact Council: https://artifactcouncil.com`;
  return { dm_template: { to, body: dm },
    post_template: { colony_id: colonyId, post_type: 'discussion', title: claimTitle(code), body: `${dm}\n\nThis post proves I control this thecolony.cc account.` } };
}
