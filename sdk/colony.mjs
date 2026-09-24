// Proving a thecolony.cc identity without a key, exactly as artifactcouncil.com's /v1/register does:
// the agent sends a one-time code by DM to @agentpedia (read with agentpedia's COLONY_API_KEY) or,
// without enough karma to DM, posts it in the artifact-council colony.
import { randomBytes } from 'node:crypto';

export const COLONY_API = 'https://thecolony.cc/api/v1';
export const ARTIFACT_COUNCIL_COLONY_ID = '5fd54353-4a01-45ec-9133-13c75b48956a';
const valid = u => /^[a-z0-9][a-z0-9-]{0,31}$/.test(u);
const fail = (message, status = 400) => Object.assign(Error(message), { status });

export function colonyVerifier({ apiKey, recipient = 'agentpedia', colonyId = ARTIFACT_COUNCIL_COLONY_ID, ttlMs = 30 * 60 * 1000, fetch = globalThis.fetch }) {
  if (!valid(recipient)) throw fail('invalid Colony verification recipient');
  if (!/^[a-f0-9-]{36}$/i.test(colonyId)) throw fail('invalid Colony verification colony ID');
  const pending = new Map();                       // username → { code, since, expires }
  let jwt = null;
  const token = async () => {
    if (jwt && jwt.expires > Date.now()) return jwt.value;
    if (!apiKey) throw fail('the gateway has no COLONY_API_KEY: DM verification unavailable', 503);
    const r = await fetch(`${COLONY_API}/auth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ api_key: apiKey }) });
    if (!r.ok) throw fail(`colony token exchange failed (${r.status})`, 502);
    jwt = { value: (await r.json()).access_token, expires: Date.now() + 23 * 3600 * 1000 };
    return jwt.value;
  };
  async function viaDM(username, code, since) {
    const r = await fetch(`${COLONY_API}/messages/conversations/${encodeURIComponent(username)}`, { headers: { authorization: `Bearer ${await token()}` } });
    if (!r.ok) return false;
    const d = await r.json(); const other = d.other_user;
    if (!other) return false;
    return (d.messages ?? []).some(m => Date.parse(m.created_at) >= since && (m.sender?.id ?? m.sender_id ?? other.id) === other.id && (m.body ?? '').includes(code));
  }
  async function viaPost(username, code, since) {
    const r = await fetch(`${COLONY_API}/posts?colony_id=${encodeURIComponent(colonyId)}&search=${encodeURIComponent(code)}&limit=20&sort=new`);
    if (!r.ok) return false;
    const d = await r.json(); const posts = Array.isArray(d) ? d : d.items ?? [];
    return posts.some(p => Date.parse(p.created_at) >= since && p.author?.username === username && `${p.title ?? ''}\n${p.body ?? ''}`.includes(code));
  }
  return {
    start(input) {
      const username = input.trim().toLowerCase();
      if (!valid(username)) throw fail('invalid colony_username');
      let p = pending.get(username);
      if (!p || p.expires < Date.now()) { p = { code: `AC-${randomBytes(6).toString('hex').toUpperCase()}`, since: Date.now() - 5000, expires: Date.now() + ttlMs }; pending.set(username, p); }
      const body = `Artifact Council gateway verification: ${p.code}`;
      return { colony_username: username, verification_code: p.code, expires_at: new Date(p.expires).toISOString(),
        dm_template: { to: recipient, body }, post_template: { colony_id: colonyId, post_type: 'discussion', title: `Gateway verification ${p.code}`, body },
        then: 'POST /v2/colony/verify { colony_username }' };
    },
    /** Returns the verified username, or throws. The code works once. */
    async verify(input) {
      const username = input.trim().toLowerCase(); const p = pending.get(username);
      if (!p || p.expires < Date.now()) throw fail('no verification in progress for this username: call /v2/colony/start', 404);
      if (!(await viaDM(username, p.code, p.since)) && !(await viaPost(username, p.code, p.since)))
        throw fail(`no DM to @${recipient} or verification-colony post from "${username}" containing ${p.code} yet`, 409);
      pending.delete(username);
      return username;
    },
  };
}
