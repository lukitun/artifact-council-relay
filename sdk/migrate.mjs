// Migration from artifactcouncil.com to the chain: export a deterministic manifest (from the
// public API or, with the service key, the database), import it (resumable), and verify the chain
// against it. Both sources go through one builder, `manifestFrom` in livedb.mjs.
import { createHash } from 'node:crypto';
import { Keypair, PublicKey } from '@solana/web3.js';
import { liveApi, manifestFrom } from './livedb.mjs';
import { decodeProposal } from './layout.mjs';

const sha = s => createHash('sha256').update(s).digest('hex');

/** The public-API manifest: anyone can reproduce it. The API omits who cast each ballot, so
 *  open-proposal ballots appear as gaps (the database export has them). */
export async function exportManifest(base = 'https://artifactcouncil.com/v1') {
  return manifestFrom(await liveApi(base).snapshot(), base);
}

/** Deterministic hosted key for an imported agent, held by the founder's gateway. */
export function hostedKey(gatewaySeed, agentId) {
  return Keypair.fromSeed(createHash('sha256').update(gatewaySeed).update('agent:').update(agentId).digest());
}

/**
 * Imports a manifest through the setup key. Resumable: each step checks chain state first.
 * `gateway` is the founder's registered gateway wallet; `seed` derives the hosted keys it holds.
 */
export async function importManifest(c, manifest, { setup, gateway, seed, limit = Infinity, log = () => {} }) {
  if (!(await c.agent(setup.publicKey))) { await c.register(setup, setup, { handle: 'migration' }); }
  const ids = new Map(manifest.agents.map(a => [a.id, hostedKey(seed, a.id).publicKey]));
  // Preserve registered identities even if they hold no current council seat.
  for (const a of manifest.agents) {
    const id = ids.get(a.id);
    if (await c.agent(id)) continue;
    await c.setup({ type: 'importAgent', id, signer: id, gateway: gateway.publicKey, handle: (a.handle ?? '').slice(0, 32), eligible: true, created: 0 }, [c.agentAddress(id)], setup);
    log(`agent ${a.handle} → ${id.toBase58()}`);
  }
  const addresses = [];
  for (const [n, a] of manifest.artifacts.slice(0, limit).entries()) {
    const address = c.artifactAddress(n); addresses.push(address);
    if ((await c.config()).artifacts <= n) {
      if ((await c.config()).artifacts !== n) throw Error('artifacts out of order');
      await c.setup({ type: 'importArtifact', name: a.name, members: a.members.map(m => [ids.get(m.agent), m.joined]), patch: a.settings, created: a.created }, [address], setup);
      log(`artifact ${n}: ${a.name}`);
    }
    let art = await c.artifact(address);
    const all = a.pages.flatMap(p => p.versions.map(v => ({ ...v, page: p.page, pageTitle: p.title })));
    all.sort((x, y) => x.time - y.time || x.page - y.page);
    for (const [i, v] of all.entries()) {
      if (i < art.history) continue;
      const up = await c.upload(setup, v.text, setup);
      const source = createHash('sha256').update(v.source).digest();
      const u = await c.read(up.address, (await import('./layout.mjs')).decodeUpload);
      await c.setup({ type: 'importVersion', page: v.page, title: (v.title ?? v.pageTitle ?? '').slice(0, 64), time: v.time, source },
        [address, up.address, u.funder, c.recordAddress(address, art.history + 1)], setup);
      art = await c.artifact(address);
    }
    // Open proposals are numbered in manifest order, so the artifact's proposal counter says how
    // many were already imported.
    const representable = a.open.filter(p => representableKind(p, ids, manifest));
    for (const [j, p] of representable.entries()) {
      if (j < (await c.artifact(address)).proposals) continue;
      const payload = await mapPayload(c, p, ids, manifest, setup);
      const extra = [address, c.proposalAddress(address, j)];
      if (payload.kind === 'content') extra.push(payload.upload);
      const roster = (await c.artifact(address)).members.map(m => new PublicKey(m.id));
      await c.setup({ type: 'importProposal', payload, proposer: ids.get(p.proposer), roster, ballots: p.ballots.filter(b => ids.has(b.agent)).map(b => [ids.get(b.agent), b.approve]),
        created: p.created, closes: p.closes, status: p.status, confirmUntil: p.confirmUntil, thread: p.thread.slice(0, 96) }, extra, setup);
      log(`  open ${p.type} ${p.id}`);
    }
    for (const p of a.open.filter(p => !representable.includes(p))) log(`  not importable: open ${p.type} ${p.id}`);
  }
  // Targets must exist first, including forward references in the manifest ordering.
  for (const [n, a] of manifest.artifacts.slice(0, limit).entries()) {
    const address = c.artifactAddress(n);
    for (const target of a.links ?? []) {
      const i = manifest.artifacts.findIndex(x => x.id === target);
      if (i < 0 || i >= limit) throw Error(`${a.name}: linked artifact ${target} is outside this import`);
      const to = c.artifactAddress(i), art = await c.artifact(address);
      if (art.links.includes(to.toBase58())) continue;
      const source = createHash('sha256').update(`legacy-link:${a.id}:${target}`).digest();
      await c.setup({ type: 'importLink', source }, [address, to, c.recordAddress(address, art.history + 1)], setup);
      log(`  imported approved link ${a.name} → ${manifest.artifacts[i].name}`);
    }
  }
  return addresses;
}
function representableKind(p, ids, manifest) {
  switch (p.type) {
    case 'membership': case 'kick': return ids.has(p.payload.agent_id);
    case 'settings': case 'content': return true;
    case 'link': return manifest.artifacts.some(a => a.id === p.payload.to_group_id);
    default: return false;
  }
}
async function mapPayload(c, p, ids, manifest, setup) {
  switch (p.type) {
    case 'membership': return ids.has(p.payload.agent_id) ? { kind: 'membership', agent: ids.get(p.payload.agent_id) } : null;
    case 'kick': return ids.has(p.payload.agent_id) ? { kind: 'kick', agent: ids.get(p.payload.agent_id) } : null;
    case 'settings': { const patch = {}; if (p.payload.voting_period_days) patch.WINDOW_DAYS = p.payload.voting_period_days; if (p.payload.kick_after_skips) patch.SKIPS = p.payload.kick_after_skips; return { kind: 'settings', patch }; }
    case 'link': { const i = manifest.artifacts.findIndex(a => a.id === p.payload.to_group_id); return i < 0 ? null : { kind: 'link', to: c.artifactAddress(i) }; }
    case 'content': {
      const up = await c.upload(setup, p.payload.new_content, setup);
      return { kind: 'content', page: p.payload.page ?? 1, upload: up.address, content: up.content, title: (p.payload.title ?? '').slice(0, 64) };
    }
    default: return null;
  }
}

/** Compares chain state with a manifest (and, optionally, the live site). Returns discrepancies. */
export async function verifyMigration(c, manifest, { limit = Infinity, agentIds, proposalAddresses } = {}) {
  if (!agentIds) throw Error('migration verification requires the legacy-to-chain agent identity map');
  const identity = id => {
    const value = agentIds.get(id);
    return value?.toBase58 ? value.toBase58() : value;
  };
  const problems = []; const report = [];
  for (const [n, a] of manifest.artifacts.slice(0, limit).entries()) {
    const address = c.artifactAddress(n);
    const v = await c.verify(address);
    problems.push(...v.problems.map(p => `${a.name}: ${p}`));
    const art = v.artifact;
    if (art.name !== a.name) problems.push(`${a.name}: name differs on chain (${art.name})`);
    if (art.members.length !== a.members.length) problems.push(`${a.name}: ${art.members.length} members on chain, ${a.members.length} live`);
    const expectedMembers = a.members.map(m => identity(m.agent));
    if (expectedMembers.some(id => !id) || JSON.stringify(art.members.map(m => m.id).sort()) !== JSON.stringify(expectedMembers.sort())) problems.push(`${a.name}: council identities differ`);
    for (const [setting, value] of Object.entries(a.settings ?? {})) {
      if (art.settings[setting] !== value || art.settingsSource[setting] !== 'council') problems.push(`${a.name}: setting ${setting} differs`);
    }
    const links = (a.links ?? []).map(id => {
      const index = manifest.artifacts.findIndex(x => x.id === id);
      return index < 0 ? `missing:${id}` : c.artifactAddress(index).toBase58();
    });
    if (JSON.stringify([...art.links].sort()) !== JSON.stringify(links.sort())) problems.push(`${a.name}: approved links differ`);
    for (const p of a.pages) {
      const onChain = v.versions.filter(x => x.page === p.page);
      const texts = onChain.map(x => x.bytes?.toString('utf8'));
      const expected = p.versions.map(x => x.text);
      if (JSON.stringify(texts) !== JSON.stringify(expected)) problems.push(`${a.name} page ${p.page}: version texts differ`);
      const current = onChain.at(-1);
      if (!current?.bytes || sha(current.bytes) !== p.sha256) problems.push(`${a.name} page ${p.page}: current text differs from the live site`);
    }
    if (art.open.length !== a.open.length) problems.push(`${a.name}: ${art.open.length} open proposals on chain, ${a.open.length} live`);
    for (const [j, expected] of a.open.entries()) {
      const proposalAddress = proposalAddresses ? proposalAddresses.get(expected.id) : c.proposalAddress(address, j);
      const proposal = proposalAddress ? await c.maybe(proposalAddress, decodeProposal) : null;
      if (!proposal) { problems.push(`${a.name}: open proposal ${expected.id} is missing`); continue; }
      if (proposal.proposer !== identity(expected.proposer) || proposal.created !== expected.created || proposal.closes !== expected.closes || proposal.status !== expected.status || proposal.confirmUntil !== expected.confirmUntil) problems.push(`${a.name}: proposal ${expected.id} identity, timing or status differs`);
      const ballots = expected.ballots.map(b => [identity(b.agent), b.approve]).sort();
      if (JSON.stringify(proposal.ballots.map(b => [b.voter, b.approve]).sort()) !== JSON.stringify(ballots)) problems.push(`${a.name}: proposal ${expected.id} ballots differ`);
    }
    report.push({ n, address: address.toBase58(), name: a.name, members: art.members.length, versions: v.versions.length, open: art.open.length });
  }
  return { ok: problems.length === 0, problems, report, gaps: manifest.gaps };
}
