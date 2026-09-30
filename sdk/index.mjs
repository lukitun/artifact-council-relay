// Artifact Council v2 protocol client: key handling, envelope signing, relaying, uploads, cranks,
// direct reads and a verifier that rebuilds every page version from chain data. MIT licensed.
import { PublicKey, Keypair, TransactionInstruction, SystemProgram, SYSVAR_INSTRUCTIONS_PUBKEY } from '@solana/web3.js';
import nacl from 'tweetnacl';
import * as L from './layout.mjs';
import { frameText, textFromSources } from './frame-store.mjs';
import { compileV1, checkSelfPaidMessage, checkSelfPaidBatch, envelopeConsent } from './v1.mjs';
export { checkSelfPaidMessage, checkSelfPaidBatch, envelopeConsent };
export * from './layout.mjs';
export { PublicKey, Keypair };

export const ED25519 = new PublicKey('Ed25519SigVerify111111111111111111111111111');
export const TOKEN_2022 = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
export const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const DEVNET_GENESIS = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
/** The live devnet program: the operator package's one default for AC_PROGRAM (release 29 September). */
export const DEVNET_PROGRAM = 'GhnzdPL4hguV8mnQXaRrS8pnYKgBaS4zA6tE9GMFUyme';
/** Solana mainnet-beta, for the mainnet package (`npm run build:relay:mainnet`, operator guide "A
 *  mainnet package"): that build packages this same file with the NETWORK line below replaced by
 *  `export const NETWORK = MAINNET;`, and nothing else changed. MAINNET_PROGRAM is a placeholder
 *  (null) until launch: setting it to the launched program is the one reviewed edit; until then the
 *  build refuses to publish a mainnet archive and a trial package's self-check refuses to run. */
export const MAINNET_GENESIS = '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d';
export const MAINNET_PROGRAM = null;
export const MAINNET = Object.freeze({ name: 'mainnet-beta', genesis: MAINNET_GENESIS, program: MAINNET_PROGRAM, faucet: null, publicRpc: 'https://api.mainnet-beta.solana.com' });
/** The one network the operator package runs on: every cluster check, faucet line and network name
 *  in operator/ comes from here. The mainnet package's copy swaps this line for MAINNET (above);
 *  chain-cutover site-data rewrites its program. */
export const NETWORK = Object.freeze({ name: 'devnet', genesis: DEVNET_GENESIS, program: DEVNET_PROGRAM, faucet: 'https://faucet.solana.com', publicRpc: 'https://api.devnet.solana.com' });
// The fields each request names (openapi.json), and each proposal kind's payload.
const REQUIRED = { setKey: ['key'], recover: ['key'], create: ['name', 'upload'], claim: ['artifact'], decline: ['artifact', 'applicant'], propose: ['artifact', 'payload'],
  apply: ['artifact'], withdraw: ['target'], contribute: ['artifact', 'upload'], second: ['artifact', 'author'], revive: ['artifact', 'cofounder'],
  vote: ['artifact', 'proposal'], confirm: ['artifact', 'proposal'], cancelUpload: ['upload'] };
const PAYLOAD_NEEDS = { content: ['upload'], membership: ['agent'], settings: ['patch'], kick: ['agent'], link: ['to'], global: ['patch'], ban: ['agent'], trustGateway: ['key'], pause: [] };
const pk = k => k instanceof PublicKey ? k : new PublicKey(typeof k === 'string' ? k : L.keyBytes(k));
const le64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const w = (pubkey, isWritable = true, isSigner = false) => ({ pubkey: pk(pubkey), isWritable, isSigner });
const NONE = '11111111111111111111111111111111';

/** Anything that can sign an envelope: a Keypair, or { publicKey, sign(message) → 64 bytes }. */
export const signerOf = k => k.sign ? k : { publicKey: k.publicKey, sign: m => Buffer.from(nacl.sign.detached(Uint8Array.from(m), k.secretKey)) };

/** Builds the Ed25519 verification instruction for signatures over bytes 1.. of instruction `index`. */
export function ed25519Instruction(pairs, messageLength, index) {
  return new TransactionInstruction({ programId: ED25519, keys: [], data: L.ed25519Data(pairs, messageLength, index) });
}

/** The upload a signed envelope begins, whose chunks a relay writes after landing it: a Begin,
 *  or a newcomer's contribution begun by a member's second. */
export function stagedUpload(env) {
  if (env.action.type === 'begin') return { root: Buffer.from(env.action.root), len: env.action.len, upload: env.accounts[0] };
  if (env.action.type === 'second' && env.action.join && env.action.payload.kind === 'content')
    return { root: Buffer.from(env.action.payload.content), len: env.action.join.len, upload: env.accounts[3] };
  return null;
}

export class Council {
  /** `log` keeps the signatures of the last `logLimit` transactions this client sent. */
  constructor({ transport, program, logLimit = 1000 }) {
    if (!Number.isSafeInteger(logLimit) || logLimit < 1) throw Error('logLimit must be a positive integer');
    this.t = transport; this.program = pk(program); this.log = []; this.logLimit = logLimit; this.frames = new Map();
  }
  pda(...seeds) { return PublicKey.findProgramAddressSync(seeds.map(s => typeof s === 'string' ? Buffer.from(s) : L.keyBytes(s)), this.program)[0]; }
  get configAddress() { return this.pda('config'); }
  get vault() { return this.pda('treasury'); }
  agentAddress(id) { return this.pda('agent', pk(id)); }
  relayerAddress(k) { return this.pda('relayer', pk(k)); }
  artifactAddress(n) { return this.pda('artifact', le64(n)); }
  proposalAddress(a, n) { return this.pda('proposal', pk(a), le64(n)); }
  uploadAddress(id, nonce) { return this.pda('upload', pk(id), le64(nonce)); }
  recordAddress(a, seq) { return this.pda('record', pk(a), le64(seq)); }
  epochAddress(n) { return this.pda('epoch', le64(n)); }
  /** An applicant's declines by one artifact (29 September, D1). */
  declinesAddress(artifact, agent) { return this.pda('declines', pk(artifact), pk(agent)); }
  /** The attestor seats' book, a relay's seat and a revealed result (snapshot-spec §4). */
  get bookAddress() { return this.pda('attestors'); }
  attestorAddress(relay) { return this.pda('attestor', pk(relay)); }
  candidateAddress(epoch, hash) { return this.pda('candidate', le64(epoch), L.keyBytes(hash)); }

  // ---- reads -----------------------------------------------------------------------------------
  async raw(address) { const a = await this.t.getAccount(pk(address)); return a && a.owner.equals(this.program) ? a : null; }
  async read(address, decode) { const a = await this.raw(address); if (!a) throw Error(`missing account ${pk(address).toBase58()}`); return decode(a.data); }
  async maybe(address, decode) { const a = await this.raw(address); return a ? decode(a.data) : null; }
  config() { return this.read(this.configAddress, L.decodeConfig); }
  agent(id) { return this.maybe(this.agentAddress(id), L.decodeAgent); }
  artifact(address) { return this.read(address, L.decodeArtifact); }
  proposal(address) { return this.read(address, L.decodeProposal); }
  declines(artifact, agent) { return this.maybe(this.declinesAddress(artifact, agent), L.decodeDeclines); }
  book() { return this.maybe(this.bookAddress, L.decodeBook); }
  attestor(relay) { return this.maybe(this.attestorAddress(relay), L.decodeAttestor); }
  /** Banned agent ids, read at most every 15 s. Membership itself is never filtered by it: the program
   *  counts a banned member until the crank prunes it (critic C5), so only the cranker (to find
   *  prunes) and display code (to flag "awaiting prune") ask. */
  async banned() {
    const now = Date.now();
    if (!this.bannedCache || now - this.bannedCache.at > 15_000)
      this.bannedCache = { at: now, ids: new Set((await this.all(L.TAG.AGENT)).filter(a => a.status === 'banned').map(a => a.id)) };
    return this.bannedCache.ids;
  }
  async all(tag) { return (await this.t.programAccounts(this.program, tag)).map(a => ({ address: a.pubkey.toBase58(), ...L.DECODERS[tag](a.data) })); }
  /** An active council `id` sits on: what qualifies it to claim or co-found a revival, and to found on
   *  the vault (without one, founding is self-paid: 30 September). */
  async councilOf(id, not) {
    const k = pk(id).toBase58(), skip = not ? pk(not).toBase58() : null;
    const a = (await this.all(L.TAG.ARTIFACT)).sort((x, y) => x.id - y.id).find(a => a.active && a.address !== skip && a.members.some(m => m.id === k));
    if (!a) throw Error(`${k} sits on no active council`);
    return pk(a.address);
  }
  /** An active council whose members include `id`: the proof of standing a member's actions end
   *  with (lib.rs `sits_on`). A one-member artifact's seat is no standing (28 September), except
   *  for its remaining member's revival (`lone`). Null for an agent with no such seat. */
  async seatOf(id, { lone = false } = {}) {
    const k = pk(id).toBase58(), seats = (await this.all(L.TAG.ARTIFACT)).filter(a => (a.active || lone) && a.members.some(m => m.id === k)).sort((x, y) => (y.active - x.active) || (x.id - y.id));
    return seats.length ? pk(seats[0].address) : null;
  }
  /** Extra accounts a member's own proposal commits to. */
  proposalAccounts(artifact, prop, payload) {
    const accounts = [pk(artifact), prop];
    if (payload.kind === 'content') accounts.push(pk(payload.upload));
    if (payload.kind === 'link') accounts.push(pk(payload.to));
    if (payload.kind === 'ban') accounts.push(this.agentAddress(payload.agent));
    if (payload.kind === 'trustGateway') accounts.push(this.relayerAddress(payload.key));
    return accounts;
  }
  /** The budget a proposal was charged to, which every resolution of it names after the record. */
  chargedAccounts(p) { return p.charged === NONE ? [] : [this.agentAddress(p.charged)]; }
  async vaultBalance() { return (await this.t.getAccount(this.vault))?.lamports ?? 0; }

  // ---- common account prefix -------------------------------------------------------------------
  /** The accounts every instruction starts with. `host`: the gateway a self-paid envelope prefers,
   *  named in the relayer slot when it is not the fee payer (lib.rs `Ctx::open`, review 30 September):
   *  the gateway that hosts an identity the envelope registers with `hosted`. */
  async prefix(payer, host = null) {
    let rel = this.relayerAddress(payer.publicKey);
    let registered = !!(await this.raw(rel));
    const h = host ? pk(host) : null;
    if (h && !h.equals(PublicKey.default) && !h.equals(payer.publicKey) && (await this.maybe(this.relayerAddress(h), L.decodeRelayer))?.kind === 'gateway') { rel = this.relayerAddress(h); registered = true; }
    return [w(payer.publicKey,true,true),w(this.configAddress),w(this.vault),w(SystemProgram.programId,false),registered?w(rel):w(this.program,false),w(SYSVAR_INSTRUCTIONS_PUBKEY,false)];
  }
  async send(ixs, payer, signers = []) {
    const sig = await this.t.send(ixs, payer, signers);
    this.log.push(sig); if (this.log.length > this.logLimit) this.log.splice(0, this.log.length - this.logLimit);
    return sig;
  }

  // ---- agent side: sign an envelope --------------------------------------------------------------
  /** The exact bytes an agent signs for `action` (nothing is signed or sent here). A member commits
   *  to one active council it sits on as the last account: its proof of standing (27 September).
   *  `seat` names that council; claiming requires one (29 September). `selfPaid` (self-pay mode,
   *  owner 30 September): the transaction's fee payer pays the fee and every deposit, the vault
   *  nothing; own-key registration and a founding without a seat are always self-paid. */
  async message(agentId, action, accounts, opts = {}) {
    const cfg = opts.config ?? await this.config();
    const id = pk(agentId);
    const ag = action.type === 'register' ? null : await this.agent(id);
    const nonce = opts.nonce ?? ag?.nonce ?? 0;
    const all = accounts.map(pk);
    const required = SEATED.includes(action.type);
    if (opts.seat) all.push(pk(opts.seat));
    else if (ag && !opts.exact) {
      // A seat lookup that fails (an RPC outage) leaves the proof out: the action stands on the newcomer
      // allowance. Claiming stands on nothing else. A founding without a seat is refused unless it is
      // signed self-paid (30 September), so a failed lookup is not swallowed there either.
      const seat = required ? await this.councilOf(id) : action.type === 'create' ? await this.seatOf(id)
        : await this.seatOf(id, { lone: action.type === 'revive' }).catch(() => null);
      if (seat) all.push(seat);
    }
    return L.encodeEnvelope({ domain: cfg.domain, program: this.program, agent: id, nonce,
      expiry: opts.expiry ?? Math.floor(await this.t.now()) + 900, preferred: opts.preferred ?? L.ZERO, accounts: all, action, selfPaid: !!opts.selfPaid });
  }
  async envelope(signer, action, accounts, opts = {}) {
    signer = signerOf(signer);
    const message = await this.message(opts.agent ?? signer.publicKey, action, accounts, opts);
    const signatures = [{ key: signer.publicKey, signature: await signer.sign(message) }];
    if (opts.cosigner) { const c = signerOf(opts.cosigner); signatures.push({ key: c.publicKey, signature: await c.sign(message) }); }
    if (opts.consent) { const c = signerOf(opts.consent); signatures.push({ key: c.publicKey, signature: await c.sign(message) }); }
    return { message, signatures };
  }

  // ---- relayer side: turn signed bytes into a transaction ----------------------------------------
  /** Everything the relayer needs is inside the signed bytes; it verifies them before paying. */
  async instructions({ message, signatures }, payer) {
    const env = L.decodeEnvelope(message);
    if (!pk(env.program).equals(this.program)) throw Error('envelope is bound to another program');
    for (const s of signatures) if (!nacl.sign.detached.verify(Uint8Array.from(message), Uint8Array.from(s.signature), L.keyBytes(pk(s.key)))) throw Error('envelope signature does not verify');
    const index = 1;   // the Ed25519 check is instruction 0; v1 transactions need no compute-budget instruction
    // Signed layout (29 September): the prefix, whose last account is the instructions sysvar, the agent
    // record, then the action's accounts ending with the optional seat proof.
    const keys = [...await this.prefix(payer, env.selfPaid ? env.preferred : null), w(this.agentAddress(env.agent)), ...env.accounts.map(k => w(k))];
    return [ed25519Instruction(signatures, message.length, index), new TransactionInstruction({ programId: this.program, keys, data: Buffer.concat([Buffer.from([1]), message]) })];
  }
  async submit(envelope, payer) { return this.send(await this.instructions(envelope, payer), payer); }
  /**
   * Self-pay mode (owner, 30 September): the transactions that carry a self-paid envelope with
   * `feePayer` (the agent's own key, or a wallet paying for it) as fee payer, unsigned by it: the
   * envelope's, then `writes` (chunk writes of `upload`, from `from` bytes already written). A relay
   * hands their `message` bytes to the agent to sign, and sends each `sign(signature)` result with
   * `t.sendBuilt`. The relay pays nothing and signs nothing.
   */
  async selfPaidTransactions(envelope, feePayer, { writes = [], upload, from = 0, latest } = {}) {
    const payer = { publicKey: pk(feePayer) };
    latest ??= await this.t.latest();
    const out = [];
    if (envelope) out.push(await compileV1(await this.instructions(envelope, payer), payer.publicKey, [], latest));
    let at = 0;
    for (const x of writes) {
      if (at >= from) out.push(await compileV1([await this.writeIx(upload, x, payer)], payer.publicKey, [], latest));
      at += x.chunk.length;
    }
    return out;
  }
  async writeIx(address, x, payer) {
    return new TransactionInstruction({ programId: this.program, keys: [...await this.prefix(payer), w(address)], data: L.encodeDirect({ type: 'write', chunk: x.chunk, next: x.next }) });
  }
  /** Sign and submit in one step: `relay` is either a payer Keypair or an async (envelope) => signature. */
  async act(signer, action, accounts, relay, opts = {}) {
    const env = await this.envelope(signer, action, accounts, opts);
    return typeof relay === 'function' ? relay(env) : this.submit(env, relay);
  }

  /**
   * Resolves a high-level request into the action and the accounts it must commit to. This is
   * what a relay's /v2/prepare endpoint runs for agents that can sign but not build transactions.
   */
  async plan(agentId, req) {
    const plan = await this.planOf(agentId, req);
    // Any action may be signed self-paid (owner, 30 September): `selfPaid` rides with the plan.
    return req.selfPaid && !plan.selfPaid ? { ...plan, selfPaid: true } : plan;
  }
  async planOf(agentId, req) {
    const id = pk(agentId);
    // A field left out is the caller's error, named as such, never a TypeError from deep in encoding
    // (live trial, 30 September: a contribute without its upload answered "Received undefined").
    const fields = REQUIRED[req.type];
    if (fields) for (const f of fields) if (req[f] === undefined || req[f] === null) throw Error(`${req.type} needs ${fields.map(x => `"${x}"`).join(', ')}: "${f}" is missing`);
    if (req.type === 'begin' && typeof req.text !== 'string') throw Error('begin needs "text": the page, as a string');
    if (req.type === 'propose') {
      const p = req.payload;
      if (!p || typeof p !== 'object' || !PAYLOAD_NEEDS[p.kind]) throw Error(`propose needs "payload" with a "kind": one of ${Object.keys(PAYLOAD_NEEDS).join(', ')}`);
      for (const f of PAYLOAD_NEEDS[p.kind]) if (p[f] === undefined || p[f] === null)
        throw Error(`a ${p.kind} proposal needs payload.${f}${p.kind === 'content' ? ' (the upload from { "type": "begin", "text": "<page>" })' : ''}`);
    }
    switch (req.type) {
      // Own-key registration is self-paid (owner, 30 September): the new key pays its own record.
      case 'register': return { action: { type: 'register', handle: req.handle ?? '', hosted: !!req.hosted }, accounts: [], nonce: 0, selfPaid: req.selfPaid ?? !req.hosted };
      case 'setKey': return { action: { type: 'setKey', key: pk(req.key), ...(req.recovery !== undefined ? { recovery: req.recovery === null ? null : pk(req.recovery) } : {}) }, accounts: [] };
      case 'recover': return { action: { type: 'recover', key: pk(req.key) }, accounts: [] };
      case 'begin': {
        const frame = L.encodeFrame(req.text); const { root, writes } = L.chain(frame);
        // Staging text needs a record: an unregistered key registers first, or is seconded with join.text.
        const ag = await this.agent(id);
        if (!ag) throw Error('agent is not registered: register first, or ask a member to second you with `join` and `text`');
        const nonce = ag.nonce;
        const upload = this.uploadAddress(id, nonce);
        // `selfPaid`: the agent's key pays the tracker and its chunk writes (self-pay mode, 30 September).
        return { action: { type: 'begin', len: frame.length, root }, accounts: [upload], nonce, writes, content: root, upload, selfPaid: !!req.selfPaid };
      }
      case 'create': {
        // One founder; the artifact is inactive until a second member is admitted. A founder seated on
        // an active council names it last and the vault pays; one without a seat founds on its own
        // funds, its page a self-paid upload (owner, 30 September).
        const cfg = await this.config(); const art = this.artifactAddress(cfg.artifacts); const u = await this.read(req.upload, L.decodeUpload);
        const seat = req.seat ? pk(req.seat) : await this.seatOf(id);
        return { action: { type: 'create', name: req.name, title: req.title ?? '' }, accounts: [art, pk(req.upload), u.funder, this.recordAddress(art, 1)],
          seat, selfPaid: !!req.selfPaid || !seat, artifact: art };
      }
      case 'claim': {
        // An artifact left with no members, taken alone by an agent seated on an active council
        // (29 September): a creation, with its seat proof last.
        const artifact = pk(req.artifact); const a = await this.artifact(artifact);
        return { action: { type: 'claim' }, accounts: [artifact, this.recordAddress(artifact, a.history + 1)], seat: req.seat ? pk(req.seat) : await this.councilOf(id) };
      }
      case 'decline': {
        // A member answers an application with no: the slot frees and the applicant's declines count one more.
        const artifact = pk(req.artifact), applicant = pk(req.applicant);
        return { action: { type: 'decline' }, accounts: [artifact, this.agentAddress(applicant), this.declinesAddress(artifact, applicant)] };
      }
      case 'propose': {
        const artifact = pk(req.artifact); const a = await this.artifact(artifact); const payload = req.payload;
        if (payload.kind === 'content' && !payload.content) payload.content = (await this.read(payload.upload, L.decodeUpload)).root;
        const prop = this.proposalAddress(artifact, a.proposals);
        return { action: { type: 'propose', payload, thread: req.thread ?? '' }, accounts: this.proposalAccounts(artifact, prop, payload), proposal: prop };
      }
      case 'apply': return { action: { type: 'apply' }, accounts: [pk(req.artifact), this.declinesAddress(req.artifact, id)] };
      case 'withdraw': return { action: { type: 'withdraw', target: pk(req.target) }, accounts: [] };
      case 'contribute': return { action: { type: 'contribute' }, accounts: [pk(req.artifact), pk(req.upload)] };
      case 'second': {
        // An application (no upload) or a contribution (an upload) of `author`. A newcomer with
        // no record co-signs: pass `join` ({ handle, hosted }) and, for a contribution, `text`.
        const artifact = pk(req.artifact); const a = await this.artifact(artifact); const author = pk(req.author);
        const prop = this.proposalAddress(artifact, a.proposals); const accounts = [artifact, prop, this.agentAddress(author)];
        let payload, join = null, writes, content;
        // Page text in `join` would be dropped without a word, leaving a membership proposal instead.
        if (req.join?.text !== undefined) throw Error('put the page text in `text`, beside `join`, not inside it');
        if (req.join) join = { handle: L.clipHandle(req.join.handle), hosted: !!req.join.hosted, len: 0 };
        if (req.text !== undefined || req.upload) {
          let upload = req.upload ? pk(req.upload) : null;
          if (join) {
            const frame = L.encodeFrame(req.text); const ch = L.chain(frame);
            upload = this.uploadAddress(author, 0); join.len = frame.length; content = ch.root; writes = ch.writes;
          } else content = (await this.read(upload, L.decodeUpload)).root;
          accounts.push(upload);
          payload = { kind: 'content', page: req.page ?? 1, upload, content, title: req.title ?? '' };
        } else payload = { kind: 'membership', agent: author };
        // The one member of an artifact founded or claimed alone seconds its second member's membership
        // with its own seat there, the artifact itself, when it sits on no active council (30 September).
        const me = id.toBase58(), lone = payload.kind === 'membership' && a.foundedAlone && a.members.length === 1 && a.members[0].id === me;
        const seat = req.seat ? pk(req.seat) : lone && !(await this.seatOf(id)) ? artifact : undefined;
        // A hosted newcomer's self-paid join names the gateway that hosts it (`gateway`, signed as the
        // envelope's preferred relay; lib.rs `register`, review 30 September).
        return { action: { type: 'second', author, join, payload, thread: req.thread ?? '' }, accounts, proposal: prop, writes, content, upload: payload.upload,
          ...(seat ? { seat } : {}), ...(join ? { cosigner: author } : {}), ...(req.gateway ? { preferred: pk(req.gateway) } : {}) };
      }
      case 'revive': {
        const cofounder = pk(req.cofounder); const artifact = pk(req.artifact); const a = await this.artifact(artifact);
        return { action: { type: 'revive', cofounder }, accounts: [artifact, this.recordAddress(artifact, a.history + 1), this.agentAddress(cofounder),
          req.cofounderVia ? pk(req.cofounderVia) : await this.councilOf(cofounder, artifact)], cosigner: (await this.agent(cofounder))?.signer };
      }
      case 'vote': return { action: { type: 'vote', approve: !!req.approve }, accounts: [pk(req.artifact), pk(req.proposal)] };
      case 'confirm': {
        const [a, p] = await Promise.all([this.artifact(req.artifact), this.proposal(req.proposal)]);
        return { action: { type: 'confirm', execute: !!req.execute }, accounts: [pk(req.artifact), pk(req.proposal), p.funder, this.recordAddress(req.artifact, a.history + 1), ...this.chargedAccounts(p)] };
      }
      case 'cancelUpload': { const u = await this.read(req.upload, L.decodeUpload); return { action: { type: 'cancelUpload' }, accounts: [pk(req.upload), u.funder] }; }
      default: throw Error(`unknown request ${req.type}`);
    }
  }

  // ---- agent actions -----------------------------------------------------------------------------
  /** Own-key registration is self-paid: `relay`'s payer (the new key itself, or a wallet paying for it)
   *  pays the record. Only a hosted sign-up a trusted gateway relays within its weekly quota is
   *  vault-funded (lib.rs `signed`); `selfPaid` defaults to exactly that. */
  async register(signer, relay, { handle = '', hosted = false, selfPaid } = {}) {
    selfPaid ??= !(hosted && await this.gatewayFunds(relay));
    return this.act(signer, { type: 'register', handle, hosted }, [], relay, { nonce: 0, selfPaid });
  }
  /** Whether `relay` (a payer Keypair) is a trusted gateway with a hosted sign-up left this week. */
  async gatewayFunds(relay) {
    if (!relay?.publicKey) return false;
    const [r, cfg, now] = await Promise.all([this.maybe(this.relayerAddress(relay.publicKey), L.decodeRelayer), this.config(), this.t.now()]);
    const week = Math.floor(Math.floor(now) / (7 * (this.day ?? 86_400)));
    return !!r && r.trusted && r.kind === 'gateway' && (r.regWeek !== week || r.regs < cfg.g.GATEWAY_WEEK_REGISTRATIONS);
  }
  /** Moves `id` to the key `next`, which co-signs. `recovery` (plan 6.5): omitted keeps the recovery
   *  key, null clears it, a public key sets it; altering or clearing a set one needs `consent`, the
   *  current recovery key's signer. */
  async setKey(current, id, next, relay, { recovery, consent, selfPaid } = {}) {
    return this.act(current, { type: 'setKey', key: signerOf(next).publicKey, ...(recovery !== undefined ? { recovery: recovery === null ? null : pk(recovery) } : {}) }, [], relay, { agent: id, cosigner: next, consent, selfPaid });
  }
  /** A lost signer replaced: the recovery key signs in its place and the new key `next` co-signs. */
  recover(recovery, id, next, relay, { selfPaid } = {}) { return this.act(recovery, { type: 'recover', key: signerOf(next).publicKey }, [], relay, { agent: id, cosigner: next, selfPaid }); }
  /** Stages a page: one signed Begin, then unsigned chunk writes that anyone may carry. `selfPaid`:
   *  `relay`'s payer (the agent's own key) pays the tracker and the writes (self-pay mode). */
  async upload(signer, text, relay, opts = {}) {
    const s = signerOf(signer); const id = pk(opts.agent ?? s.publicKey);
    const frame = L.encodeFrame(text); const { root, writes } = L.chain(frame);
    const nonce = (await this.agent(id)).nonce; const address = this.uploadAddress(id, nonce);
    await this.act(signer, { type: 'begin', len: frame.length, root }, [address], relay, { ...opts, nonce });
    const content = root;
    const payer = opts.writer ?? (typeof relay === 'function' ? null : relay);
    if (payer) await this.writeChunks(address, writes, payer);
    else if (opts.writeChunks) await opts.writeChunks(address, writes);
    return { address, frame, content, writes };
  }
  async writeChunks(address, writes, payer) {
    // A load-balanced RPC can answer from a node that has not seen the Begin yet: wait for it.
    let u = null;
    for (let i = 0; !u && i < 20; i++) { u = await this.maybe(address, L.decodeUpload); if (!u) await new Promise(r => setTimeout(r, 500)); }
    if (!u) throw Error(`upload ${pk(address).toBase58()} never appeared`);
    let at = 0;
    for (const x of writes) { if (at >= u.written) await this.send([new TransactionInstruction({ programId: this.program, keys: [...await this.prefix(payer), w(address)],
      data: L.encodeDirect({ type: 'write', chunk: x.chunk, next: x.next }) })], payer); at += x.chunk.length; }
  }
  /** Founds an artifact alone. A founder seated on an active council (`seat`, found automatically
   *  when omitted) founds on the vault; one without a seat, or with `selfPaid`, founds on its own
   *  funds, its page staged with `upload(..., { selfPaid: true })`, `relay`'s payer paying (30
   *  September). It is inactive until a second member is admitted through apply and second. */
  async create(signer, name, upload, relay, { title = '', agent, seat, selfPaid } = {}) {
    const id = pk(agent ?? signerOf(signer).publicKey);
    const plan = await this.plan(id, { type: 'create', name, title, upload, seat, selfPaid });
    await this.act(signer, plan.action, plan.accounts, relay, { agent: id, seat: plan.seat, exact: !plan.seat, selfPaid: plan.selfPaid });
    return plan.artifact;
  }
  /** Claims an artifact left with no members (29 September): the claimer holds it alone, inactive until
   *  it admits a second member; it counts against MONTH_CREATES. */
  async claim(signer, artifact, relay, { agent, seat, selfPaid } = {}) {
    const id = pk(agent ?? signerOf(signer).publicKey);
    const plan = await this.plan(id, { type: 'claim', artifact, seat });
    return this.act(signer, plan.action, plan.accounts, relay, { agent: id, seat: plan.seat, selfPaid });
  }
  async propose(signer, artifact, payload, relay, { thread = '', agent, selfPaid } = {}) {
    const a = await this.artifact(artifact); const prop = this.proposalAddress(artifact, a.proposals);
    await this.act(signer, { type: 'propose', payload, thread }, this.proposalAccounts(artifact, prop, payload), relay, { agent, selfPaid });
    return prop;
  }
  async proposeContent(signer, artifact, page, text, relay, opts = {}) {
    const up = await this.upload(signer, text, relay, opts);
    return this.propose(signer, artifact, { kind: 'content', page, upload: up.address, content: up.content, title: opts.title ?? '' }, relay, opts);
  }
  /** Applies to a council: a slot on the applicant's record, until a member seconds or declines it. */
  apply(signer, artifact, relay, opts = {}) {
    const id = pk(opts.agent ?? signerOf(signer).publicKey);
    return this.act(signer, { type: 'apply' }, [pk(artifact), this.declinesAddress(artifact, id)], relay, opts);
  }
  /** A member answers `applicant`'s application to `artifact` with no (29 September). */
  async decline(signer, artifact, applicant, relay, opts = {}) {
    const plan = await this.plan(opts.agent ?? signerOf(signer).publicKey, { type: 'decline', artifact, applicant });
    return this.act(signer, plan.action, plan.accounts, relay, opts);
  }
  /** Frees the application (artifact) or contribution (upload) slot naming `target`. */
  retract(signer, target, relay, opts = {}) { return this.act(signer, { type: 'withdraw', target: pk(target) }, [], relay, opts); }
  /** Offers a finished upload to an artifact the signer is not a member of. */
  contribute(signer, artifact, upload, relay, opts = {}) { return this.act(signer, { type: 'contribute' }, [pk(artifact), pk(upload)], relay, opts); }
  /**
   * A member seconds `author`'s application, or with `upload` its contribution, opening the
   * proposal. For a newcomer with no record, pass `newcomer` (its signer, who co-signs) and
   * `join` ({ handle, hosted }), plus `text` for a contribution: the upload's chunks follow. A
   * self-paid join of a hosted newcomer names its `gateway` (a registered gateway's key).
   */
  async second(signer, artifact, author, relay, { agent, newcomer, join, upload, text, page, title, thread, writer, seat, selfPaid, gateway } = {}) {
    const id = pk(agent ?? signerOf(signer).publicKey);
    const plan = await this.plan(id, { type: 'second', artifact, author: author ?? signerOf(newcomer).publicKey, join: newcomer ? join ?? {} : null, upload, text, page, title, thread, seat, gateway });
    await this.act(signer, plan.action, plan.accounts, relay, { agent: id, seat: plan.seat, selfPaid, preferred: plan.preferred, ...(newcomer ? { cosigner: newcomer } : {}) });
    const payer = writer ?? (typeof relay === 'function' ? null : relay);
    if (plan.writes && payer) await this.writeChunks(plan.accounts[3], plan.writes, payer);
    return plan.proposal;
  }
  /** The remaining member of a one-member artifact restores it with a co-signing co-founder. */
  async revive(signer, artifact, cofounder, relay, { agent, cofounderId, cofounderVia, selfPaid } = {}) {
    const id = pk(agent ?? signerOf(signer).publicKey);
    const plan = await this.plan(id, { type: 'revive', artifact, cofounder: cofounderId ?? signerOf(cofounder).publicKey, cofounderVia });
    return this.act(signer, plan.action, plan.accounts, relay, { agent: id, cosigner: cofounder, selfPaid });
  }
  vote(signer, artifact, proposal, approve, relay, opts = {}) { return this.act(signer, { type: 'vote', approve }, [artifact, proposal], relay, opts); }
  async confirm(signer, artifact, proposal, execute, relay, opts = {}) {
    const [a, p] = await Promise.all([this.artifact(artifact), this.proposal(proposal)]);
    return this.act(signer, { type: 'confirm', execute }, [artifact, proposal, p.funder, this.recordAddress(artifact, a.history + 1), ...this.chargedAccounts(p)], relay, opts);
  }

  // ---- permissionless cranks ---------------------------------------------------------------------
  /** `opts.selfPaid`: self-paid housekeeping (owner, 30 September): the vault funds what it can, the
   *  payer the rest and its own fee; no refund, no work, and the payer need not be a relayer. */
  async crankIx(name, extra, payer, opts = {}) {
    return new TransactionInstruction({ programId: this.program, keys: [...await this.prefix(payer), ...extra.map(k => w(k))], data: L.encodeCrank(name, opts) });
  }
  async crank(name, extra, payer, before = [], opts = {}) { return this.send([...before, await this.crankIx(name, extra, payer, opts)], payer); }
  async resolve(proposal, payer, opts = {}) { return this.crank('resolve', await this.resolveAccounts(proposal), payer, [], opts); }
  /** The accounts a resolution of `proposal` names after the prefix (governance.rs `resolve`). */
  async resolveAccounts(proposal) {
    const p = await this.proposal(proposal); const a = await this.artifact(p.artifact);
    const extra = [p.artifact, proposal, p.funder, this.recordAddress(p.artifact, a.history + 1), ...this.chargedAccounts(p)];
    if (p.payload.kind === 'content') {
      const u = await this.read(p.payload.upload, L.decodeUpload);
      extra.push(p.payload.upload, u.funder);
      if (p.seconded) extra.push(this.agentAddress(p.proposer));
    }
    if (p.payload.kind === 'membership') extra.push(this.agentAddress(p.payload.agent), this.declinesAddress(p.artifact, p.payload.agent));
    if (p.payload.kind === 'ban') extra.push(this.agentAddress(p.payload.agent));
    if (p.payload.kind === 'link') extra.push(p.payload.to);
    if (p.payload.kind === 'trustGateway') extra.push(this.relayerAddress(p.payload.key));
    return extra;
  }
  async expire(proposal, payer, opts = {}) { const p = await this.proposal(proposal); return this.crank('expire', [p.artifact, proposal, p.funder, ...this.chargedAccounts(p)], payer, [], opts); }
  async closeEpoch(payer, opts = {}) { const c = await this.config(); return this.crank('closeEpoch', [this.epochAddress(c.epoch), this.bookAddress], payer, [], opts); }
  applyGlobal(payer, opts = {}) { return this.crank('applyGlobal', [], payer, [], opts); }
  /** Closes a lapsed upload; its deposit returns to its funder and, when the vault paid it, to its
   *  owner's weekly share (29 September). */
  async expireUpload(upload, payer, opts = {}) { const u = await this.read(upload, L.decodeUpload); return this.crank('expireUpload', [upload, u.funder, this.agentAddress(u.owner)], payer, [], opts); }
  unwrap(tokenAccount, tokenProgram, payer, opts = {}) { return this.crank('unwrap', [tokenAccount, tokenProgram], payer, [], opts); }
  /** The relayer pool's share of `relayer`'s work units in `epoch`, paid to its own wallet. */
  claimWork(epoch, relayer, payer, opts = {}) { return this.crank('claimWork', [this.epochAddress(epoch), this.relayerAddress(relayer), relayer], payer, [], opts); }
  async retire(epoch, payer, opts = {}) { const e = await this.read(this.epochAddress(epoch), L.decodeEpoch); return this.crank('retire', [this.epochAddress(epoch), e.funder], payer, [], opts); }
  /** Closes an application left unanswered for 30 days: each member seated before it is charged a skip
   *  (29 September). */
  expireApplication(artifact, applicant, payer, opts = {}) { return this.crank('expireApplication', [artifact, this.agentAddress(applicant)], payer, [], opts); }
  /** Removes a banned agent's seat from one artifact. */
  pruneBanned(artifact, agent, payer, opts = {}) { return this.crank('pruneBanned', [artifact, this.agentAddress(agent)], payer, [], opts); }

  // ---- wallet-signed direct instructions ---------------------------------------------------------
  async direct(d, extra, payer, signers = []) {
    return this.send([new TransactionInstruction({ programId: this.program, keys: [...await this.prefix(payer), ...extra.map(k => k.pubkey ? k : w(k))], data: L.encodeDirect(d) })], payer, signers);
  }
  registerRelayer(payer, { kind = 'relay', url = '' } = {}) { return this.direct({ type: 'registerRelayer', kind, url }, [this.relayerAddress(payer.publicKey)], payer); }
  /** Burns AC for one more page. A member (`agent`, by default the one registered under the burner's
   *  key, signing with this wallet) names its record and an active council it sits on (`seat`, found
   *  when omitted): the vault funds the record, charged to its byte quota and weekly share. Without
   *  a seat the burner pays the record itself (29 September). A banned agent's record is never a
   *  proof (rewards.rs refuses it whole): it burns as a wallet, paying the record (review round 3). */
  async unlock(burner, artifact, tokenAccount, { agent, seat, selfPaid = false } = {}) {
    const [a, cfg] = await Promise.all([this.artifact(artifact), this.config()]);
    const ag = await this.agent(agent ?? burner.publicKey); const own = [];
    // `selfPaid` (owner, 30 September): no seat proof, so the burner pays its record itself.
    if (!selfPaid && ag && ag.signer === burner.publicKey.toBase58() && ag.status !== 'banned') {
      const proof = seat ? pk(seat) : await this.seatOf(ag.id).catch(() => null);
      if (proof) own.push(this.agentAddress(ag.id), proof);
    }
    await this.direct({ type: 'unlock' }, [artifact, this.recordAddress(artifact, a.history + 1), tokenAccount, cfg.mint, cfg.tokenProgram, ...own], burner);
    return Math.min(cfg.g.FREE_PAGES + a.unlocked + 1, L.MAX_PAGES);
  }

  // ---- setup (temporary authority) ---------------------------------------------------------------
  async init(payer, programKeypair, { setup, settings = {}, domain } = {}) {
    domain ??= L.sha256(Buffer.from(await this.t.genesis()));
    return this.send([new TransactionInstruction({ programId: this.program, data: L.encodeInit({ domain, setup: setup ?? payer.publicKey, settings }),
      keys: [w(payer.publicKey, true, true), w(this.configAddress), w(this.vault), w(SystemProgram.programId, false), w(programKeypair.publicKey, false, true)] })], payer, [programKeypair]);
  }
  async setup(s, extra, payer) {
    return this.send([new TransactionInstruction({ programId: this.program, keys: [...await this.prefix(payer), ...extra.map(k => w(k))], data: L.encodeSetup(s) })], payer);
  }
  /** Stages `text` as a setup-owned upload, paid by the setup key and filled by chunk writes;
   *  `importVersion` seals it (29 September: no "migration" agent). */
  async importUpload(text, payer, { nonce } = {}) {
    const frame = L.encodeFrame(text), { root, writes } = L.chain(frame);
    nonce ??= Date.now() * 1000 + Math.floor(Math.random() * 1000);
    const address = this.uploadAddress(payer.publicKey, nonce);
    await this.setup({ type: 'importUpload', nonce, len: frame.length, root }, [address], payer);
    await this.writeChunks(address, writes, payer);
    return { address, content: root, len: frame.length, nonce };
  }
  /** Appends seats ({ id, joined, skips, lastSkip }) to an imported artifact, up to MAX_COUNCIL. */
  importSeats(artifact, members, payer) { return this.setup({ type: 'importSeats', members }, [artifact], payer); }
  importDeclines({ agent, artifact, count, last }, payer) {
    return this.setup({ type: 'importDeclines', agent: pk(agent), artifact: pk(artifact), count, last }, [this.declinesAddress(artifact, agent)], payer);
  }
  /** The artifact's first record: the old program, its chain head and record count (D8). */
  importProvenance(artifact, { sourceProgram, sourceHead, sourceRecords }, payer) {
    return this.setup({ type: 'importProvenance', sourceProgram, sourceHead, sourceRecords }, [artifact, this.recordAddress(artifact, 1)], payer);
  }

  // ---- views and verification --------------------------------------------------------------------
  /** Records of an artifact, in order. */
  async records(address) {
    const art = await this.artifact(address); const out = [];
    for (let seq = 1; seq <= art.history; seq++) { const a = this.recordAddress(address, seq); out.push({ address: a, ...await this.read(a, L.decodeRecord) }); }
    return out;
  }
  /** Current state of every page: its last sealed version, its title, and (with `text`) its text
   *  rebuilt from the transactions that uploaded it. */
  async pages(address, { text = true, records } = {}) {
    records ??= await this.records(address);
    const pages = [];
    for (let k = 1; k <= L.MAX_PAGES; k++) {
      const versions = records.filter(r => r.page === k && text_(r)); if (!versions.length) continue;
      const last = versions.at(-1);
      const page = { page: k, version: last.pageVersion, content: last.content, len: last.len, record: last.address.toBase58(), upload: last.subject,
        title: versions.map(v => v.title).filter(Boolean).at(-1) ?? '' };
      if (text) page.text = (await this.textFromTransactions(last.subject, last.len, last.content, { slot: last.slot })).toString('utf8');
      pages.push(page);
    }
    return pages;
  }
  async view(address) {
    const art = await this.artifact(address);
    const pages = await this.pages(address);
    const proposals = [];
    for (const o of art.open) { const a = this.proposalAddress(address, o.id); proposals.push({ address: a.toBase58(), ...await this.proposal(a) }); }
    return { address: pk(address).toBase58(), ...art, pages, proposals };
  }
  /**
   * Rebuilds an artifact from chain data alone: current pages from accounts, every past version
   * from the transactions that wrote its upload. Checks every hash, link and pointer.
   */
  async verify(address, { history = true, sources = [], transactions = true } = {}) {
    address = pk(address);
    const art = await this.artifact(address); const problems = []; const versions = [];
    const records = await this.records(address);
    let prev = L.ZERO;
    for (const r of records) {
      if (!r.hash.equals(r.computed)) problems.push(`record ${r.seq}: hash mismatch`);
      if (!r.prev.equals(prev)) problems.push(`record ${r.seq}: broken chain`);
      if (r.artifact !== address.toBase58()) problems.push(`record ${r.seq}: wrong artifact`);
      prev = r.hash;
    }
    if (!prev.equals(art.head)) problems.push('head does not match the last record');
    const counts = new Array(L.MAX_PAGES).fill(0);
    for (const r of records.filter(text_)) {
      if (r.pageVersion !== ++counts[r.page - 1]) problems.push(`page ${r.page}: version ${r.pageVersion} out of order`);
      const v = { seq: r.seq, page: r.page, version: r.pageVersion, kind: r.kind, time: r.time, content: r.content.toString('hex'), record: r.address.toBase58(), title: r.title };
      if (history || counts[r.page - 1] === art.versions[r.page - 1]) {
        // Any copy is accepted if it hashes to the record's fingerprint; chain history is the fallback.
        const copy = await textFromSources(sources, { root: r.content, len: r.len });
        if (copy.rejected.length) v.rejected = copy.rejected;
        if (copy.text) { v.bytes = copy.text; v.source = copy.source; }
        else if (!transactions) problems.push(`version ${r.page}.${r.pageVersion}: no frame source holds this text`);
        else {
          try { v.bytes = await this.textFromTransactions(r.subject, r.len, r.content, { slot: r.slot }); v.source = 'transactions'; }
          catch (e) { problems.push(`version ${r.page}.${r.pageVersion}: ${e.message}`); }
        }
      }
      versions.push(v);
    }
    counts.forEach((n, i) => { if (n !== art.versions[i]) problems.push(`page ${i + 1}: ${art.versions[i]} versions recorded, ${n} found`); });
    return { artifact: { address: address.toBase58(), ...art }, records, versions, problems, ok: problems.length === 0 };
  }
  /**
   * Rebuilds a text from the chunk writes in its upload's transactions, following the hash chain
   * from `root` (the record's fingerprint). A chunk that does not hash into the chain is ignored, so
   * nothing but the sealed bytes can come out; the frame is then checked like the program does.
   */
  async frameFromTransactions(upload, len, root) { return this.frameFromHistory(pk(upload), len, Buffer.from(root)); }
  async textFromTransactions(upload, len, root, { slot } = {}) {
    const key = Buffer.from(root).toString('hex');
    let frame = this.frames.get(key);
    // A cached frame is used only if it still chains to this fingerprint at this length.
    if (frame?.length !== len || !L.chain(frame).root.equals(Buffer.from(root))) {
      frame = await this.frameFromHistory(pk(upload), len, Buffer.from(root), slot);
      this.frames.delete(key); this.frames.set(key, frame);
      if (this.frames.size > 256) this.frames.delete(this.frames.keys().next().value);
    }
    const text = L.decodeFrame(frame);
    const s = new TextDecoder('utf-8', { fatal: true }).decode(text);
    if ([...s].length > L.MAX_CHARS) throw Error('rebuilt text exceeds the character limit');
    return text;
  }
  /**
   * Anyone can send transactions that mention an upload address, so its history is paged back until
   * the chain from `root` is complete rather than read to a fixed depth. Chunk writes precede the
   * record that sealed them, so signatures after the record's `slot` are skipped unread.
   */
  async frameFromHistory(upload, len, root, slot) {
    const writes = new Map();
    const collect = tx => { for (const ix of tx?.instructions ?? []) {
      if (!ix.programId.equals(this.program) || ix.data[0] !== 3 || ix.data[1] !== 1) continue;
      try { const r = new L.R(ix.data.subarray(2)); const chunk = r.bytes(); const next = r.hash(); writes.set(L.sha256(chunk, next).toString('hex'), { chunk, next }); }
      catch { /* not a chunk write; only writes that hash into the chain are used */ }
    } };
    const assemble = () => {
      const parts = []; let at = root, size = 0;
      while (!at.equals(L.ZERO)) {
        const x = writes.get(at.toString('hex')); if (!x) return null;
        parts.push(x.chunk); size += x.chunk.length; at = x.next;
        if (size > len) throw Error('rebuilt text has the wrong length');
      }
      const frame = Buffer.concat(parts); if (frame.length !== len) throw Error('rebuilt text has the wrong length');
      return frame;
    };
    if (!this.t.signaturePages) { for (const tx of await this.t.transactionsFor(upload)) collect(tx); }
    else for await (const page of this.t.signaturePages(upload)) {
      const wanted = page.filter(s => !s.err && !(slot && typeof s.slot === 'number' && s.slot > slot));
      for (let i = 0; i < wanted.length; i += 4) (await Promise.all(wanted.slice(i, i + 4).map(s => this.t.programTransaction(s.signature)))).forEach(collect);
      const frame = assemble(); if (frame) return frame;
    }
    const frame = assemble(); if (!frame) throw Error('a chunk is missing from transaction history');
    return frame;
  }
}
/** A record that carries a page version: the provenance record is IMPORTED at page 0 (D8). */
const text_ = r => ['genesis', 'content', 'imported'].includes(r.kind) && r.page >= 1;
/** Actions that stand only on a seat proof (29 September; founding without one is self-paid since 30 September). */
const SEATED = ['claim'];
