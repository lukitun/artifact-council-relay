// Gateway sessions, bans and identity bindings. A bearer token is stored only as its SHA-256 and
// names a derivation label, never a key: the hosted key is derived from the gateway seed in
// memory per request. Tokens expire and can be revoked. An identity with no Colony login to fall
// back on (anonymous hosting) keeps a recovery secret, stored hashed, that renews its token. An
// identity whose key file predates derived keys (`legacyKey`) keeps it until mainnet.
// The denylist is a text file the operator edits (`colony:<user id>`, `ip:<address or CIDR>`,
// `agent:<address>`); it is re-read on change. The gateway keeps its own `bans.txt` of the Colony
// ids behind identities the meta-council banned, so a new login cannot mint another (29 September).
import { readFileSync, writeFileSync, renameSync, readdirSync, unlinkSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { BlockList, isIP } from 'node:net';
import { Keypair } from '@solana/web3.js';
import { hostedKey } from './identities.mjs';
import { validColonyId } from './colony.mjs';

const sha = s => createHash('sha256').update(s).digest('hex');
const fail = (message, status) => Object.assign(Error(message), { status });
const atomic = (file, data) => { const tmp = `${file}.${randomBytes(6).toString('hex')}.tmp`; writeFileSync(tmp, data, { mode: 0o600 }); renameSync(tmp, file); };
const TOKEN_FILE = /^[0-9a-f]{64}\.json$/, ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

export function gatewaySessions({ dir, seed, ttlMs = 30 * 24 * 3600 * 1000, now = Date.now, log = () => {} }) {
  if (!dir) throw Error('gateway sessions need a directory');
  if (!seed || seed.length < 16) throw Error('the gateway needs its seed (at least 16 bytes) to derive hosted keys');
  if (!(Number.isFinite(ttlMs) && ttlMs > 0)) throw Error('token lifetime must be a positive number of milliseconds');
  mkdirSync(`${dir}/keys`, { recursive: true, mode: 0o700 }); mkdirSync(`${dir}/anon`, { recursive: true, mode: 0o700 });
  const file = hash => `${dir}/${hash}.json`;
  const read = f => { try { return JSON.parse(readFileSync(f, 'utf8')); } catch { return null; } };
  const remove = f => { try { unlinkSync(f); } catch {} };
  // Anonymous identities: agent → { label | legacyKey, recovery: [SHA-256 of each recovery secret] }.
  const anonFile = agent => `${dir}/anon/${agent}.json`;
  const addRecovery = (agent, how, hash) => {
    const cur = read(anonFile(agent)), hashes = Array.isArray(cur?.recovery) ? cur.recovery : [];
    if (!hashes.includes(hash)) atomic(anonFile(agent), JSON.stringify({ agent, ...how, recovery: [...hashes, hash] }));
  };
  const revokeRecoveryHash = (agent, hash) => {
    if (!ADDRESS.test(agent ?? '')) return;
    const rec = read(anonFile(agent));
    if (Array.isArray(rec?.recovery) && rec.recovery.includes(hash)) atomic(anonFile(agent), JSON.stringify({ ...rec, recovery: rec.recovery.filter(h => h !== hash) }));
  };
  const records = () => readdirSync(dir).filter(n => TOKEN_FILE.test(n)).map(n => `${dir}/${n}`);
  function sweep() {
    let revoked = 0;
    for (const f of records()) { const rec = read(f); if (rec?.v !== 2 || rec.expires <= now()) { remove(f); revoked++; } }
    if (revoked) log(`gateway: removed ${revoked} expired or unreadable token(s)`);
    return revoked;
  }
  const keyFor = rec => {
    if (rec.legacyKey) { const s = read(`${dir}/keys/${rec.agent}.json`); return Array.isArray(s) ? Keypair.fromSecretKey(Uint8Array.from(s)) : null; }
    return typeof rec.label === 'string' ? hostedKey(seed, rec.label) : null;
  };
  const store = rec => {
    const token = randomBytes(32).toString('base64url');
    atomic(file(sha(token)), JSON.stringify({ v: 2, ...rec, created: now(), expires: now() + ttlMs }));
    return { token, expires: now() + ttlMs };
  };
  sweep();
  return {
    sweep,
    /** Issues a token for a seed-derived identity; returns the token, which is never stored. */
    issue({ label, colony = null }) {
      const key = hostedKey(seed, label);
      return { ...store({ agent: key.publicKey.toBase58(), label, ...(colony ? { colony } : {}) }), key };
    },
    /** An anonymous identity's recovery secret (returned once, stored hashed); it renews expired or revoked tokens. */
    recoverable({ label }) {
      const agent = hostedKey(seed, label).publicKey.toBase58(), recovery = randomBytes(32).toString('base64url');
      addRecovery(agent, { label }, sha(recovery));
      return recovery;
    },
    /** Checks an anonymous identity's recovery secret (or throws 401); `issue()` then makes its new token. */
    recover(agent, recovery) {
      const refused = () => fail('unknown agent or wrong recovery secret', 401);
      if (typeof agent !== 'string' || !ADDRESS.test(agent) || typeof recovery !== 'string' || !/^[A-Za-z0-9_-]{20,128}$/.test(recovery)) throw refused();
      const rec = read(anonFile(agent));
      if (!rec || rec.agent !== agent || !Array.isArray(rec.recovery) || !rec.recovery.includes(sha(recovery))) throw refused();
      const key = keyFor(rec.legacyKey ? { legacyKey: true, agent } : { label: rec.label });
      if (!key || key.publicKey.toBase58() !== agent) throw refused();
      return { key, issue: () => store(rec.legacyKey ? { agent, legacyKey: true } : { agent, label: rec.label }) };
    },
    /** The key of a recorded identity ({ label } or { legacyKey: true, agent }), for a sweep after its
     *  tokens are gone; null when this gateway cannot derive or read it. */
    keyOf(rec) { try { return keyFor(rec); } catch { return null; } },
    /** How this gateway derives `agent`'s key ({ label } | { legacyKey: true }), from its anonymous
     *  record, legacy key file or live tokens; null when none of them names it. */
    recordOf(agent) {
      if (!ADDRESS.test(agent ?? '')) return null;
      const anon = read(anonFile(agent));
      if (anon?.legacyKey) return { legacyKey: true };
      if (typeof anon?.label === 'string') return { label: anon.label };
      if (existsSync(`${dir}/keys/${agent}.json`)) return { legacyKey: true };
      for (const f of records()) { const r = read(f); if (r?.agent === agent) return r.legacyKey ? { legacyKey: true } : typeof r.label === 'string' ? { label: r.label } : null; }
      return null;
    },
    /** Drops an identity's recovery secrets (the gateway no longer holds custody). */
    forget(agent) { if (ADDRESS.test(agent ?? '')) remove(anonFile(agent)); },
    /** Resolves a bearer token to its identity and in-memory key, or throws 401. */
    lookup(token) {
      if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{20,128}$/.test(token)) throw fail('missing or malformed bearer token', 401);
      const hash = sha(token), f = file(hash);
      if (!existsSync(f)) throw fail('unknown or revoked bearer token', 401);
      const rec = read(f);
      if (rec?.v !== 2) throw fail('unknown or revoked bearer token', 401);
      if (!(rec.expires > now())) { remove(f); throw fail('bearer token expired: sign in again (or renew it with your recovery secret)', 401); }
      const key = keyFor(rec);
      if (!key || key.publicKey.toBase58() !== rec.agent) throw fail('bearer token does not match the keys held here: sign in again', 401);
      return { hash, agent: rec.agent, label: rec.label ?? null, key, colony: rec.colony ?? null, expires: rec.expires };
    },
    /** Live Colony logins, oldest first: { agent, label, colony: { id, username }, created }. */
    logins() {
      return records().map(read).filter(r => r?.v === 2 && r.expires > now() && r.colony && typeof r.label === 'string')
        .map(r => ({ agent: r.agent, label: r.label, colony: r.colony, created: r.created })).sort((x, y) => x.created - y.created);
    },
    revoke(hash) { const f = file(hash); const had = existsSync(f); revokeRecoveryHash(read(f)?.agent, hash); remove(f); return had ? 1 : 0; },
    /** Revokes every token for an agent (by address). */
    revokeWhere({ agent }) {
      let n = 0;
      for (const f of records()) { const rec = read(f); if (agent && rec?.agent === agent) { revokeRecoveryHash(agent, f.slice(-69,-5)); remove(f); n++; } }
      const anon = ADDRESS.test(agent ?? '') ? read(anonFile(agent)) : null;
      if (anon?.legacyKey) remove(anonFile(agent));
      return n;
    },
  };
}

// Colony user id ↔ identity label, first come first bound, persisted. A label once bound to a
// Colony id is never handed to another id, so a renamed account's old username leads nowhere.
// The one exception: a username-keyed identity bound by username alone (`unverified`, a first
// login with no attestation) yields to the id the operator later attests.
export function colonyBindings(file) {
  let state = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : { byId: {}, byLabel: {} };
  if (!state || typeof state.byId !== 'object' || typeof state.byLabel !== 'object' || (state.unverified !== undefined && typeof state.unverified !== 'object')) throw Error(`invalid Colony bindings file ${file}`);
  const marks = () => state.unverified ?? {};
  return {
    labelFor: id => Object.hasOwn(state.byId, String(id)) ? state.byId[String(id)] : null,
    ownerOf: label => Object.hasOwn(state.byLabel, label) ? state.byLabel[label] : null,
    labels: () => Object.keys(state.byLabel),
    unverified: label => Object.hasOwn(marks(), label),
    /**
     * Binds label to id unless either is already bound elsewhere (or id is bound to `replacing`,
     * which is released if it was unverified). `displace` takes a label from an unverified owner;
     * `unverified` marks the binding as made by username alone. Synchronous.
     */
    claim(label, id, { replacing = null, displace = false, unverified = false } = {}) {
      id = String(id);
      if (!validColonyId(id)) throw Error('invalid Colony user id');
      const owner = this.ownerOf(label), current = this.labelFor(id);
      if (owner === id && current === label && this.unverified(label) === unverified) return true;
      if ((owner !== null && owner !== id && !(displace && this.unverified(label))) || (current !== null && current !== label && current !== replacing)) return false;
      const byId = { ...state.byId, [id]: label }, byLabel = { ...state.byLabel, [label]: id }, next = { ...marks() };
      if (owner !== null && owner !== id && byId[owner] === label) delete byId[owner];
      if (current !== null && current !== label && this.unverified(current)) { delete byLabel[current]; delete next[current]; }
      delete next[label]; if (unverified) next[label] = id;
      const written = { byId, byLabel, unverified: next };
      atomic(file, JSON.stringify(written)); state = written;
      return true;
    },
  };
}

// Operator attestations: identity label → the Colony user id that owns it. Migrated identities
// (manifest agent id) and pre-hardening `colony:<username>` identities were keyed by a username that
// can change hands, so the gateway gives them only to the attested id. Sources: `colony_id` pins in
// the frozen manifest, and a JSON file the operator edits ({ "<label>": "<colony user id>" }),
// re-read on change. Conflicts fail startup; a broken edit keeps the previous attestations.
export function colonyAttestations({ file = null, pins = {} } = {}) {
  let stamp = null, byLabel = new Map(), byId = new Map();
  function build(extra) {
    const nextLabel = new Map(), nextId = new Map();
    const add = (label, id, where) => {
      if (typeof label !== 'string' || !label || label.length > 128 || !validColonyId(id)) throw Error(`${where}: expected { "<identity label>": "<colony user id>" }`);
      id = String(id);
      if (nextLabel.has(label) && nextLabel.get(label) !== id) throw Error(`${where}: ${label} is attested to two Colony ids`);
      if (nextId.has(id) && nextId.get(id) !== label) throw Error(`${where}: Colony id ${id} is attested to two identities`);
      nextLabel.set(label, id); nextId.set(id, label);
    };
    for (const [label, id] of Object.entries(pins)) add(label, id, 'migration manifest');
    if (extra !== null && (typeof extra !== 'object' || Array.isArray(extra))) throw Error(`attestations ${file}: expected a JSON object`);
    for (const [label, id] of Object.entries(extra ?? {})) add(label, id, `attestations ${file}`);
    byLabel = nextLabel; byId = nextId;
  }
  function refresh(strict) {
    let st = null; if (file) try { st = statSync(file); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    const next = st ? `${st.mtimeMs}:${st.ctimeMs}:${st.size}:${st.ino}` : 'absent';
    if (next === stamp) return;
    try { build(st ? JSON.parse(readFileSync(file, 'utf8')) : null); stamp = next; }
    catch (e) { if (strict) throw e; console.error(`${e.message}; keeping the previous attestations`); stamp = next; }
  }
  refresh(true);
  return {
    labelFor: id => { refresh(false); return byId.get(String(id)) ?? null; },
    ownerOf: label => { refresh(false); return byLabel.get(label) ?? null; },
  };
}

export const normalizeIp = ip => { const s = String(ip ?? '').trim().toLowerCase().replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/, ''); return isIP(s) ? s : null; };
const loopback = ip => ip === '::1' || /^127\./.test(ip ?? '');
// A CDN in front of the local proxy (Netlify's signed proxy rewrites) proves itself with an
// HS256 JWS in `x-nf-sign` under a secret shared with this gateway. Unsigned or forged: not trusted.
export function proxySigned(jws, secret, now = Date.now) {
  const [head, claims, sig, extra] = typeof jws === 'string' ? jws.split('.') : [];
  if (!secret || !head || !claims || !sig || extra !== undefined) return false;
  let h, c; try { h = JSON.parse(Buffer.from(head, 'base64url')); c = JSON.parse(Buffer.from(claims, 'base64url')); } catch { return false; }
  if (h?.alg !== 'HS256' || c?.iss !== 'netlify' || (c.exp !== undefined && !(c.exp * 1000 > now()))) return false;
  const want = createHmac('sha256', secret).update(`${head}.${claims}`).digest(), got = Buffer.from(sig, 'base64url');
  return got.length === want.length && timingSafeEqual(got, want);
}
/**
 * Client address: the socket peer; behind the loopback proxy, the last X-Forwarded-For entry (the
 * address that reached the proxy). When that hop is a CDN that signed the request, the client is
 * the entry the CDN appended before it, the address the CDN saw. Nothing further left is trusted.
 */
export function clientIp(req, { proxySecret } = {}) {
  const peer = normalizeIp(req.socket?.remoteAddress), headers = req.headers ?? {};
  const hops = String(headers['x-forwarded-for'] ?? '').split(',').map(normalizeIp);
  if (!peer || !loopback(peer) || !hops.at(-1)) return peer ?? 'unknown';
  const edge = hops.pop();
  if (!proxySecret || !proxySigned(headers['x-nf-sign'], proxySecret)) return edge;
  return hops.at(-1) ?? edge;
}
/** Rate-limit bucket: an IPv4 address, or the /64 an IPv6 address sits in (one subscriber's block). */
export function ipBucket(ip) {
  if (isIP(ip ?? '') !== 6) return ip;
  const groups = part => part ? part.split(':').flatMap(g => g.includes('.') ? ['0', '0'] : [g]) : [];
  const [head, tail] = ip.split('::'), h = groups(head), t = tail === undefined ? [] : groups(tail);
  const full = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
  return `${full.slice(0, 4).map(g => parseInt(g, 16).toString(16)).join(':')}::/64`;
}

/** `by`: who keeps the list, as agents are told when it refuses them (Artifact Council on its own
 *  deployment; this gateway's operator otherwise). */
export function denylist(file, { by = null } = {}) {
  let stamp = null, ids = new Set(), agents = new Set(), ips = new BlockList();
  function parse(raw) {
    const nextIds = new Set(), nextAgents = new Set(), nextIps = new BlockList();
    raw.split('\n').forEach((line, i) => {
      const entry = line.replace(/#.*/, '').trim(); if (!entry) return;
      const m = entry.match(/^(colony|ip|agent):(.+)$/); const value = m?.[2].trim();
      if (m?.[1] === 'colony' && validColonyId(value)) return void nextIds.add(value);
      if (m?.[1] === 'agent' && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) return void nextAgents.add(value);
      if (m?.[1] === 'ip') {
        const [addr, bits] = value.split('/'), ip = normalizeIp(addr), type = ip && (isIP(ip) === 6 ? 'ipv6' : 'ipv4');
        if (ip && bits === undefined) return void nextIps.addAddress(ip, type);
        const n = Number(bits);
        if (ip && /^\d{1,3}$/.test(bits) && n <= (type === 'ipv6' ? 128 : 32)) return void nextIps.addSubnet(ip, n, type);
      }
      throw Error(`denylist ${file} line ${i + 1}: expected colony:<id>, ip:<address[/bits]> or agent:<address>`);
    });
    ids = nextIds; agents = nextAgents; ips = nextIps;
  }
  function refresh(strict) {
    let st; try { st = statSync(file); } catch (e) { if (e.code !== 'ENOENT') throw e; st = null; }
    const next = st ? `${st.mtimeMs}:${st.ctimeMs}:${st.size}:${st.ino}` : 'absent';
    if (next === stamp) return;
    try { parse(st ? readFileSync(file, 'utf8') : ''); stamp = next; }
    catch (e) { if (strict) throw e; console.error(`${e.message}; keeping the previous denylist`); stamp = next; }
  }
  refresh(true);
  return {
    banned({ ip, colony, agent } = {}) {
      refresh(false);
      const addr = normalizeIp(ip);
      return (addr && ips.check(addr, isIP(addr) === 6 ? 'ipv6' : 'ipv4')) || (colony != null && ids.has(String(colony))) || (agent != null && agents.has(agent));
    },
    check(who) { if (this.banned(who)) throw fail(`banned by ${by ?? 'this gateway\'s operator'} (its own ban list, not a meta-council ban)`, 403); },
  };
}

/**
 * Colony ids whose hosted identity the meta-council banned (cleanup-spec §2.11, owner 29 September):
 * one `<colony id> <agent address>` line each, appended by the gateway, never by the operator's
 * denylist. A ban is permanent, so nothing is ever removed.
 */
export function bans(file) {
  const read = () => { try { return readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return ''; throw e; } };
  const ids = () => new Set(read().split('\n').map(l => l.replace(/#.*/, '').trim().split(/\s+/)[0]).filter(Boolean));
  return {
    has: colony => colony != null && ids().has(String(colony)),
    add(colony, agent) {
      colony = String(colony);
      if (!validColonyId(colony)) throw Error('invalid Colony user id');
      if (this.has(colony)) return false;
      const raw = read(); atomic(file, `${raw}${raw && !raw.endsWith('\n') ? '\n' : ''}${colony} ${agent}\n`);
      return true;
    },
  };
}

/**
 * Fixed one-minute window per key, in memory. A call returns false when the request may go ahead,
 * else the whole seconds until the key's window resets (at least 1), for a `Retry-After` header.
 * `grace` extra reads (`{ read: true }`) are allowed in a key's first window only, so a newcomer's
 * first look around is not throttled; every later window has the plain budget.
 */
export function rateLimiter(perMinute, now = Date.now, { grace = 0 } = {}) {
  if (!(Number.isSafeInteger(grace) && grace >= 0)) throw Error('grace must be a non-negative integer');
  const hits = new Map();
  return (key, { read = false } = {}) => {
    if (perMinute === Infinity) return false;
    const t = now(), h = hits.get(key) ?? { n: 0, since: t, first: true };
    if (t - h.since > 60_000) { h.n = 0; h.since = t; h.first = false; }
    h.n++; hits.set(key, h);
    if (hits.size > 10_000) for (const [k, v] of hits) if (t - v.since > 60_000) hits.delete(k);
    return h.n > perMinute + (h.first && read ? grace : 0) && Math.max(1, Math.ceil((h.since + 60_000 - t) / 1000));
  };
}
