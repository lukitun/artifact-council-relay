// Snapshots of the live artifactcouncil.com state, and the one manifest builder they feed:
// `liveDb` reads the database (read-only, service key, includes ballot voters); `liveApi` reads the
// public API, which anyone can use but which omits who cast each ballot.
import { createHash } from 'node:crypto';

const sha = s => createHash('sha256').update(s).digest('hex');
const time = iso => Math.floor(Date.parse(iso) / 1000);
const at = p => p.applied_at ?? p.resolved_at ?? p.closes_at ?? p.created_at;

export function liveDb({ url = process.env.SUPABASE_URL, key = process.env.SUPABASE_SERVICE_ROLE_KEY } = {}) {
  if (!url || !key) throw Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required');
  const get = async (table, query = 'select=*') => {
    const out = []; const size = 1000;
    for (let from = 0; ; from += size) {
      const r = await fetch(`${url}/rest/v1/${table}?${query}&order=id`, { headers: { apikey: key, authorization: `Bearer ${key}`, range: `${from}-${from + size - 1}` } });
      if (!r.ok) throw Error(`${table}: ${r.status} ${await r.text()}`);
      const rows = await r.json(); out.push(...rows); if (rows.length < size) return out;
    }
  };
  return {
    async agentByColony(username) {
      const rows = await get('agents', `select=id,handle,colony_username&colony_username=eq.${encodeURIComponent(username)}`);
      return rows[0] ?? null;
    },
    async snapshot() {
      const [agents, groups, memberships, pages, proposals, votes, links] = await Promise.all([
        get('agents', 'select=id,handle,colony_username,created_at'), get('groups', 'select=id,name,created_at,settings'), get('memberships'),
        get('artifacts', 'select=id,group_id,page,version,title,content,updated_at'), get('proposals'), get('votes', 'select=id,proposal_id,voter_id,vote,created_at'), get('artifact_links')]);
      return { agents, groups, memberships, pages, proposals, votes, links, at: new Date().toISOString() };
    },
  };
}

const fetchJson = async (url, tries = 4) => {
  for (let i = 0; ; i++) {
    const r = await fetch(url).catch(e => ({ ok: false, statusText: e.message }));
    if (r.ok) return r.json();
    if (i >= tries) throw Error(`${url}: ${r.status ?? ''} ${r.statusText}`);
    await new Promise(res => setTimeout(res, 1000 * 2 ** i));
  }
};
/** The public API, reshaped into the database's rows so `manifestFrom` treats both alike. */
export function liveApi(base = 'https://artifactcouncil.com/v1') {
  return {
    async snapshot() {
      const s = { agents: new Map(), groups: [], memberships: [], pages: [], proposals: [], votes: [], links: [], at: new Date().toISOString() };
      const agent = (id, a) => { if (id && !s.agents.has(id)) s.agents.set(id, { id, handle: a?.handle ?? null, colony_username: a?.colony_username ?? null, created_at: null }); };
      for (const g of await fetchJson(`${base}/groups`)) {
        const d = await fetchJson(`${base}/groups?id=${g.id}`);
        const props = await fetchJson(`${base}/proposals?group_id=${g.id}&status=all&include_votes=1`);
        const settings = {};
        for (const k of ['voting_period_days', 'kick_after_skips']) if (d.settings_source?.[k] === 'council') settings[k] = d.settings[k];
        s.groups.push({ id: g.id, name: g.name, created_at: g.created_at, settings });
        for (const m of d.members ?? []) { agent(m.agent_id, m.agent); s.memberships.push({ agent_id: m.agent_id, group_id: g.id, joined_at: m.joined_at }); }
        for (const p of d.pages ?? []) s.pages.push({ group_id: g.id, page: p.page, version: p.version, title: p.title, content: p.content, updated_at: p.updated_at });
        for (const l of d.links ?? []) { const to = l.to_group_id ?? l.id; if (typeof to === 'string') s.links.push({ from_group_id: g.id, to_group_id: to, approved_at: l.approved_at ?? true }); }
        for (const p of Array.isArray(props) ? props : props.proposals ?? []) {
          agent(p.proposer_id, p.proposer);
          s.proposals.push(p);
          (p.votes ?? []).forEach((v, i) => {
            const voter = typeof v.voter === 'object' ? v.voter?.id : v.voter;   // { id, handle } in current API responses
            agent(voter, typeof v.voter === 'object' ? v.voter : null);
            s.votes.push({ id: `${p.id}:${i}`, proposal_id: p.id, voter_id: voter ?? null, vote: v.vote, created_at: v.created_at ?? p.created_at });
          });
        }
      }
      return { ...s, agents: [...s.agents.values()] };
    },
  };
}

/** The migration manifest, from either snapshot source. */
export function manifestFrom(s, source = 'artifactcouncil.com database') {
  const byGroup = (rows, id) => rows.filter(r => r.group_id === id);
  const groups = [...s.groups].sort((a, b) => (b.name === 'Artifact Council') - (a.name === 'Artifact Council') || a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id));
  const gaps = [];
  const artifacts = groups.map(g => {
    const props = byGroup(s.proposals, g.id);
    const members = byGroup(s.memberships, g.id).sort((a, b) => a.joined_at.localeCompare(b.joined_at)).map(m => ({ agent: m.agent_id, joined: time(m.joined_at) }));
    const settings = {};
    if (g.settings?.voting_period_days) settings.WINDOW_DAYS = g.settings.voting_period_days;
    if (g.settings?.kick_after_skips) settings.SKIPS = g.settings.kick_after_skips;
    const pages = byGroup(s.pages, g.id).sort((a, b) => a.page - b.page).map(p => {
      const applied = props.filter(x => x.type === 'content' && x.status === 'passed' && (x.payload?.page ?? 1) === p.page && typeof x.payload?.new_content === 'string')
        .sort((a, b) => at(a).localeCompare(at(b)));
      const versions = applied.map(x => ({ text: x.payload.new_content, title: x.payload.title ?? null, time: time(at(x)), source: x.id }));
      if (versions.at(-1)?.text !== p.content) versions.push({ text: p.content, title: p.title ?? null, time: time(p.updated_at ?? g.created_at), source: `${g.id}:page${p.page}:v${p.version}` });
      if (versions.length < p.version) gaps.push({ artifact: g.id, page: p.page, liveVersion: p.version, recoverable: versions.length, note: 'earlier versions (at least the genesis text) are not stored anywhere recoverable' });
      if (versions.length > p.version) gaps.push({ artifact: g.id, page: p.page, liveVersion: p.version, recoverable: versions.length, note: 'more passed content proposals than live versions: a passed proposal was not applied' });
      return { page: p.page, title: p.title ?? '', version: p.version, sha256: sha(p.content), versions };
    });
    const open = props.filter(p => p.status === 'voting' || p.status === 'confirmation_pending').sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id))
      .map(p => ({ id: p.id, type: p.type, proposer: p.proposer_id, payload: p.payload, created: time(p.created_at), closes: time(p.closes_at), status: p.status,
        confirmUntil: p.confirm_closes_at ? time(p.confirm_closes_at) : 0, thread: p.colony_post_id ? `https://thecolony.cc/p/${p.colony_post_id}` : '',
        ballots: s.votes.filter(v => v.proposal_id === p.id).sort((a, b) => a.created_at.localeCompare(b.created_at)).map(v => ({ agent: v.voter_id, approve: v.vote === 'approve', vote: v.id })) }));
    for (const p of open) if (p.ballots.some(b => !b.agent)) gaps.push({ artifact: g.id, proposal: p.id, ballots: p.ballots.length, note: 'the source does not say who cast these ballots' });
    return { id: g.id, name: g.name, created: time(g.created_at), members, settings, pages, open,
      links: s.links.filter(l => l.from_group_id === g.id && l.approved_at).map(l => l.to_group_id) };
  });
  const agents = s.agents.map(a => ({ id: a.id, handle: a.handle ?? null, colony: a.colony_username ?? null })).sort((a, b) => a.id.localeCompare(b.id));
  const manifest = { source, exportedAt: s.at, agents, artifacts, gaps };
  return { ...manifest, digest: sha(JSON.stringify({ ...manifest, exportedAt: undefined })) };
}
