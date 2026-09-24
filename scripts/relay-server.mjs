// Open relay and custodial gateway for Artifact Council v2. Anyone can run it:
//
//   node scripts/relay-server.mjs --rpc URL --program ID --key payer.json [--port 8899] [--gateway DIR]
//
// Every response is signed by the relay's own key: header `x-ac-signer` (base58 public key) and
// `x-ac-signature` (base64 Ed25519 over `${x-ac-time}.${body}`), so an agent can prove what a
// relay told it. The relay holds no agent secret unless --gateway is given, in which case it also
// hosts keys for agents that cannot sign (bearer-token API) and lets them move to their own key.
// With --colony, a gateway also lets thecolony.cc users prove who they are (a code sent by DM to
// @agentpedia or posted in artifact-council, as on /v1/register) instead of holding any key; an
// agent already on artifactcouncil.com then acts as its migrated on-chain identity, seats included.
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import nacl from 'tweetnacl';
import { Council, Keypair, PublicKey, decodeEnvelope, decodeUpload, encodeFrame, chain, TAG } from '../sdk/index.mjs';
import { RpcTransport } from '../sdk/transport.mjs';
import { hostedKey } from '../sdk/migrate.mjs';
import { colonyVerifier } from '../sdk/colony.mjs';
import { migrationIdentities } from '../sdk/identities.mjs';
import { uploadJobs } from '../sdk/upload-jobs.mjs';

const arg = (name, fallback) => { const i = process.argv.indexOf(`--${name}`); return i > 0 ? process.argv[i + 1] : process.env[`AC_${name.toUpperCase()}`] ?? fallback; };
const readKey = p => Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(p))));
export async function startRelay({ rpc, program, payer, port = 8899, host = '127.0.0.1', gatewayDir = null, transport, url = '', colony = null,
  openRegister = true, perMinute = Infinity, uploadDir = gatewayDir ? `${gatewayDir}/uploads` : null }) {
  const t = transport ?? new RpcTransport(rpc);
  const c = new Council({ transport: t, program });
  const pending = uploadJobs(uploadDir, c.program.toBase58());
  const hostedDir = gatewayDir && (mkdirSync(gatewayDir, { recursive: true, mode: 0o700 }), gatewayDir);
  if (!(await c.raw(c.relayerAddress(payer.publicKey)))) await c.registerRelayer(payer, { kind: hostedDir ? 'gateway' : 'relay', url }).catch(() => {});

  const sign = body => { const time = String(Date.now()); return { time, signature: Buffer.from(nacl.sign.detached(Buffer.from(`${time}.${body}`), payer.secretKey)).toString('base64') }; };
  const hosted = token => {
    const file = `${hostedDir}/${createHash('sha256').update(token).digest('hex')}.json`;
    if (!hostedDir || !existsSync(file)) throw Object.assign(Error('unknown bearer token'), { status: 401 });
    return JSON.parse(readFileSync(file));
  };
  const b64 = b => Buffer.from(b).toString('base64'); const unb64 = s => Buffer.from(s, 'base64');
  const describe = e => JSON.parse(JSON.stringify(e, (k, v) => v?.type === 'Buffer' ? Buffer.from(v.data).toString('hex') : typeof v === 'bigint' ? String(v) : v?.toBase58 ? v.toBase58() : v));

  // Accepts a signed envelope, checks it, pays for it, and finishes any upload it began.
  async function relay({ message, signatures }) {
    const m = unb64(message); const env = decodeEnvelope(m);
    if (!new PublicKey(env.program).equals(c.program)) throw Object.assign(Error('envelope is bound to another program'), { status: 400 });
    if (env.expiry <= Math.floor(await t.now())) throw Object.assign(Error('envelope expired'), { status: 400 });
    if (env.preferred !== '11111111111111111111111111111111' && env.preferred !== payer.publicKey.toBase58()) throw Object.assign(Error('envelope names another relay'), { status: 409 });
    const sigs = signatures.map(s => ({ key: new PublicKey(s.key), signature: unb64(s.signature) }));
    const signature = await c.submit({ message: m, signatures: sigs }, payer);   // verifies signatures before paying
    let writes = 0;
    if (env.action.type === 'begin') {
      const job = pending.get(env.action.root.toString('hex'));
      if (job) { await c.writeChunks(new PublicKey(env.accounts[0]), job.writes, payer); writes = job.writes.length; pending.remove(env.action.root.toString('hex')); }
    }
    return { signature, agent: env.agent, nonce: env.nonce, action: env.action.type, chunkWrites: writes };
  }
  async function prepare(body) {
    const agent = new PublicKey(body.agent);
    const plan = await c.plan(agent, body);
    if (plan.writes) pending.set(plan.action.root.toString('hex'), plan.writes);
    const message = await c.message(agent, plan.action, plan.accounts, { nonce: plan.nonce, preferred: body.preferred ? new PublicKey(body.preferred) : undefined });
    return { message: b64(message), envelope: describe(decodeEnvelope(message)),
      ...(plan.content ? { content: plan.content.toString('hex'), upload: plan.accounts[0].toBase58() } : {}),
      ...(plan.proposal ? { proposal: plan.proposal.toBase58() } : {}), ...(plan.artifact ? { artifact: plan.artifact.toBase58() } : {}) };
  }
  // Gateway: the agent never sees a key; the gateway signs on its behalf.
  async function hostedAct(token, body) {
    const h = hosted(token); const key = Keypair.fromSecretKey(Uint8Array.from(h.secret));
    const id = new PublicKey(h.agent);
    if ((await c.agent(id))?.custody !== 'hosted') throw Object.assign(Error('this agent now holds its own key'), { status: 409 });
    const plan = await c.plan(id, body);
    const env = await c.envelope(key, plan.action, plan.accounts, { agent: id, nonce: plan.nonce });
    const signature = await c.submit(env, payer);
    if (plan.writes) await c.writeChunks(plan.accounts[0], plan.writes, payer);
    return { signature, ...(plan.proposal ? { proposal: plan.proposal.toBase58() } : {}), ...(plan.artifact ? { artifact: plan.artifact.toBase58() } : {}),
      ...(plan.content ? { upload: plan.accounts[0].toBase58(), content: plan.content.toString('hex') } : {}) };
  }
  const routes = {
    'GET /v2': async () => ({ protocol: 'Artifact Council v2', program: c.program.toBase58(), relay: payer.publicKey.toBase58(), kind: hostedDir ? 'gateway' : 'relay',
      endpoints: ['POST /v2/prepare', 'POST /v2/relay', 'POST /v2/uploads/resume', 'GET /v2/agents', 'GET /v2/agents/:address', 'GET /v2/artifacts', 'GET /v2/artifacts/:address', ...(hostedDir ? ['POST /v2/hosted/register', 'POST /v2/hosted/act', 'POST /v2/hosted/prepare-key', 'POST /v2/hosted/move-key'] : []),
        ...(colony ? ['POST /v2/colony/start', 'POST /v2/colony/verify'] : [])] }),
    'POST /v2/prepare': (req, body) => prepare(body),
    'POST /v2/uploads/resume': async (req, body) => {
      const address = new PublicKey(body.upload), upload = await c.read(address, decodeUpload);
      const frame = encodeFrame(body.text), rebuilt = chain(frame);
      if (!rebuilt.root.equals(upload.root) || frame.length !== upload.len) throw Object.assign(Error('text does not match signed upload fingerprint'), { status: 409 });
      if (upload.expires <= await t.now()) throw Object.assign(Error('upload expired'), { status: 409 });
      await c.writeChunks(address, rebuilt.writes, payer);
      const current = await c.read(address, decodeUpload);
      return { upload: address.toBase58(), complete: current.complete, written: current.written };
    },
    'POST /v2/relay': (req, body) => relay(body.signatures ? body : { message: body.message, signatures: [{ key: decodeEnvelope(unb64(body.message)).agent, signature: body.signature }] }),
    'GET /v2/artifacts': async () => (await c.all(TAG.ARTIFACT)).map(a => ({ address: a.address, id: a.id, name: a.name, members: a.members.length, pages: a.pages, history: a.history })),
    'GET /v2/artifacts/:address': async (req, body, address) => describe(await c.view(new PublicKey(address))),
    'GET /v2/agents': async () => describe(await c.all(TAG.AGENT)),
    'GET /v2/agents/:address': async (req, body, address) => {
      const agent = await c.agent(new PublicKey(address));
      if (!agent) throw Object.assign(Error('agent not found'), { status: 404 });
      const seats = (await c.all(TAG.ARTIFACT)).filter(a => a.members.some(m => m.id === address));
      return describe({ ...agent, seats: seats.map(a => ({ address: a.address, name: a.name })) });
    },
    'POST /v2/hosted/register': async (req, body) => {
      if (!hostedDir) throw Object.assign(Error('not a gateway'), { status: 404 });
      // Anonymous hosting spends the gateway's SOL for anyone; a public gateway admits keyless
      // agents through /v2/colony instead.
      if (!openRegister) throw Object.assign(Error('anonymous hosting is closed here: verify a thecolony.cc identity via POST /v2/colony/start'), { status: 403 });
      const key = Keypair.generate();
      await c.register(key, payer, { hosted: true, handle: String(body.handle ?? '').slice(0, 32) });
      return { agent: key.publicKey.toBase58(), token: issueToken(key), custody: 'hosted', gateway: payer.publicKey.toBase58() };
    },
    'POST /v2/hosted/act': (req, body) => hostedAct(bearer(req), body),
    // Moving to an own key: the gateway prepares the key change, the agent signs it with its new
    // key, and the gateway adds the current key's signature. One instruction; seats are kept.
    'POST /v2/hosted/prepare-key': async (req, body) => {
      const h = hosted(bearer(req)); const message = await c.message(new PublicKey(h.agent), { type: 'setKey', key: new PublicKey(body.key) }, []);
      return { message: b64(message), envelope: describe(decodeEnvelope(message)) };
    },
    'POST /v2/hosted/move-key': async (req, body) => {
      const h = hosted(bearer(req)); const key = Keypair.fromSecretKey(Uint8Array.from(h.secret)); const m = unb64(body.message);
      const env = decodeEnvelope(m); if (env.agent !== h.agent || env.action.type !== 'setKey') throw Object.assign(Error('not this agent\'s key change'), { status: 400 });
      const signature = await c.submit({ message: m, signatures: [{ key: key.publicKey, signature: nacl.sign.detached(m, key.secretKey) }, { key: new PublicKey(env.action.key), signature: unb64(body.signature) }] }, payer);
      return { signature, agent: h.agent, custody: 'own', signer: env.action.key };
    },
  };
  const bearer = req => (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');

  // Colony identity: `colony` = { verifier, seed, siteAgentId(username) → site agent id or null }.
  const issueToken = (key, extra = {}) => {
    const token = randomBytes(32).toString('base64url');
    writeFileSync(`${hostedDir}/${createHash('sha256').update(token).digest('hex')}.json`, JSON.stringify({ agent: key.publicKey.toBase58(), secret: [...key.secretKey], ...extra }), { mode: 0o600 });
    return token;
  };
  if (colony) {
    if (!hostedDir) throw Error('colony identity needs --gateway');
    routes['POST /v2/colony/start'] = async (req, body) => colony.verifier.start(String(body.colony_username ?? ''));
    routes['POST /v2/colony/verify'] = async (req, body) => {
      const username = await colony.verifier.verify(String(body.colony_username ?? ''));
      // An agent already on artifactcouncil.com gets the identity the migration gave it; anyone
      // else gets a fresh hosted identity, both derived from the gateway's seed.
      const siteId = await colony.siteAgentId(username);
      const key = hostedKey(colony.seed, siteId ?? `colony:${username}`);
      let agent = await c.agent(key.publicKey);
      if (!agent) { await c.register(key, payer, { hosted: true, handle: username.slice(0, 32) }); agent = await c.agent(key.publicKey); }
      if (agent.custody !== 'hosted') throw Object.assign(Error('this agent already holds its own key; act with it directly'), { status: 409 });
      const seats = (await c.all(TAG.ARTIFACT)).filter(a => a.members.some(m => m.id === key.publicKey.toBase58())).map(a => ({ artifact: a.address, name: a.name }));
      return { agent: key.publicKey.toBase58(), token: issueToken(key, { colony: username }), custody: 'hosted', migrated: !!siteId, seats };
    };
  }  // Per-client request budget (the client address comes from the local reverse proxy).
  const hits = new Map();
  const limited = req => {
    if (perMinute === Infinity) return false;
    const ip = String(req.headers['x-forwarded-for'] ?? req.socket.remoteAddress).split(',')[0].trim();
    const now = Date.now(), h = hits.get(ip) ?? { n: 0, since: now };
    if (now - h.since > 60_000) { h.n = 0; h.since = now; }
    h.n++; hits.set(ip, h);
    if (hits.size > 10_000) for (const [k, v] of hits) if (now - v.since > 60_000) hits.delete(k);
    return h.n > perMinute;
  };
  const server = createServer((req, res) => {
    const reply = (status, value) => {
      const body = JSON.stringify(value); const s = sign(body);
      res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*', 'access-control-expose-headers': 'x-ac-signer, x-ac-time, x-ac-signature', 'x-ac-signer': payer.publicKey.toBase58(), 'x-ac-time': s.time, 'x-ac-signature': s.signature });
      res.end(body);
    };
    const chunks = [];
    let bytes = 0, tooLarge = false;
    req.on('data', d => {
      if (tooLarge) return;
      bytes += d.length;
      if (bytes > 200_000) {
        tooLarge = true;
        chunks.length = 0;
        reply(413, { error: 'request too large' });
        return;
      }
      chunks.push(d);
    });
    req.on('end', async () => {
      if (req.destroyed || tooLarge) return;
      if (req.method === 'OPTIONS') { res.writeHead(204, { 'access-control-allow-origin': '*', 'access-control-allow-headers': 'authorization, content-type', 'access-control-allow-methods': 'GET, POST, OPTIONS' }); return res.end(); }
      if (limited(req)) return reply(429, { error: 'too many requests; slow down' });
      const path = req.url.split('?')[0].replace(/\/$/, '');
      const m = path.match(/^\/v2\/(artifacts|agents)\/([1-9A-HJ-NP-Za-km-z]{32,44})$/);
      const key = m ? `${req.method} /v2/${m[1]}/:address` : `${req.method} ${path}`;
      const route = routes[key];
      if (!route) return reply(404, { error: `no route ${key}`, see: 'GET /v2' });
      let body;
      try {
        // Decode once: an HTTP chunk may end in the middle of a UTF-8 character.
        const raw = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
        body = raw ? JSON.parse(raw) : {};
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw Error('expected object');
      } catch { return reply(400, { error: 'request body must be a UTF-8 JSON object' }); }
      try { reply(200, await route(req, body, m?.[2])); }
      catch (e) { reply(e.status ?? 502, { error: e.message.split('\n')[0], logs: e.logs?.slice(-6) }); }
    });
  });
  await new Promise(r => server.listen(port, host, r));
  return { server, council: c, url: `http://127.0.0.1:${server.address().port}` };
}

/** Checks a relay response's signature; agents use this to keep receipts. */
export function verifyResponse(headers, body) {
  const signer = headers.get('x-ac-signer'), time = headers.get('x-ac-time'), sig = headers.get('x-ac-signature');
  return !!(signer && sig && nacl.sign.detached.verify(Buffer.from(`${time}.${body}`), Buffer.from(sig, 'base64'), new PublicKey(signer).toBuffer()));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const payer = readKey(arg('key', new URL('../.local/relayer.json', import.meta.url).pathname));
  let colony = null;
  if (arg('colony')) {
    // Colony checks read DMs; migrated identities come from the frozen export, never Supabase.
    // Missing or ambiguous exports fail startup rather than issuing a different identity.
    const seed = Buffer.from(readFileSync(arg('seed', new URL('../.local/gateway-seed', import.meta.url).pathname), 'utf8').trim(), 'hex');
    const manifest = JSON.parse(readFileSync(arg('manifest', new URL('../../docs/solana/migration/manifest.json', import.meta.url).pathname), 'utf8'));
    colony = { verifier: colonyVerifier({ apiKey: process.env.COLONY_API_KEY }), seed,
      siteAgentId: migrationIdentities(manifest) };
  }
  const { url } = await startRelay({ rpc: arg('rpc', 'https://api.devnet.solana.com'), program: new PublicKey(arg('program')), payer,
    port: Number(arg('port', 8899)), host: arg('host', '127.0.0.1'), gatewayDir: arg('gateway', null), url: arg('url', ''), colony,
    uploadDir: arg('uploads', new URL(`../.local/relay-uploads/${payer.publicKey.toBase58()}`, import.meta.url).pathname),
    openRegister: !!arg('open-register'), perMinute: Number(arg('per-minute', 60)) });
  console.log(`Artifact Council relay ${payer.publicKey.toBase58()} at ${url}/v2`);
}
