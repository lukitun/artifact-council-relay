// Artifact Council v2 client: key handling, envelope signing, relaying, uploads, cranks, direct
// reads and a verifier that rebuilds every page version from chain data. MIT licensed.
import { PublicKey, Keypair, TransactionInstruction, SystemProgram, SYSVAR_INSTRUCTIONS_PUBKEY } from '@solana/web3.js';
import nacl from 'tweetnacl';
import * as L from './layout.mjs';
export * from './layout.mjs';
export { PublicKey, Keypair };

export const ED25519 = new PublicKey('Ed25519SigVerify111111111111111111111111111');
export const TOKEN_2022 = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
export const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const DEVNET_GENESIS = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
const pk = k => k instanceof PublicKey ? k : new PublicKey(typeof k === 'string' ? k : L.keyBytes(k));
const le64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
const w = (pubkey, isWritable = true, isSigner = false) => ({ pubkey: pk(pubkey), isWritable, isSigner });

/** Anything that can sign an envelope: a Keypair, or { publicKey, sign(message) → 64 bytes }. */
export const signerOf = k => k.sign ? k : { publicKey: k.publicKey, sign: m => Buffer.from(nacl.sign.detached(Uint8Array.from(m), k.secretKey)) };

/** Builds the Ed25519 verification instruction for signatures over bytes 1.. of instruction `index`. */
export function ed25519Instruction(pairs, messageLength, index) {
  const off = 2 + 14 * pairs.length; const data = Buffer.alloc(off + 96 * pairs.length);
  data[0] = pairs.length;
  pairs.forEach(({ key, signature }, i) => {
    const o = 2 + 14 * i, at = off + 96 * i;
    data.writeUInt16LE(at + 32, o); data.writeUInt16LE(0xffff, o + 2); data.writeUInt16LE(at, o + 4); data.writeUInt16LE(0xffff, o + 6);
    data.writeUInt16LE(1, o + 8); data.writeUInt16LE(messageLength, o + 10); data.writeUInt16LE(index, o + 12);
    L.keyBytes(key).copy(data, at); Buffer.from(signature).copy(data, at + 32);
  });
  return new TransactionInstruction({ programId: ED25519, keys: [], data });
}

export class Council {
  constructor({ transport, program }) {
    this.t = transport; this.program = pk(program); this.log = [];
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
  holderAddress(owner) { return this.pda('holder', pk(owner)); }

  // ---- reads -----------------------------------------------------------------------------------
  async raw(address) { const a = await this.t.getAccount(pk(address)); return a && a.owner.equals(this.program) ? a : null; }
  async read(address, decode) { const a = await this.raw(address); if (!a) throw Error(`missing account ${pk(address).toBase58()}`); return decode(a.data); }
  async maybe(address, decode) { const a = await this.raw(address); return a ? decode(a.data) : null; }
  config() { return this.read(this.configAddress, L.decodeConfig); }
  agent(id) { return this.maybe(this.agentAddress(id), L.decodeAgent); }
  artifact(address) { return this.read(address, L.decodeArtifact); }
  proposal(address) { return this.read(address, L.decodeProposal); }
  async all(tag) { return (await this.t.programAccounts(this.program, tag)).map(a => ({ address: a.pubkey.toBase58(), ...L.DECODERS[tag](a.data) })); }
  async vaultBalance() { return (await this.t.getAccount(this.vault))?.lamports ?? 0; }

  // ---- common account prefix -------------------------------------------------------------------
  async prefix(payer) {
    const rel = this.relayerAddress(payer.publicKey);
    const registered = !!(await this.raw(rel));
    return [w(payer.publicKey, true, true), w(this.configAddress), w(this.vault), w(SystemProgram.programId, false), registered ? w(rel) : w(this.program, false)];
  }
  async send(ixs, payer, signers = []) {
    const sig = await this.t.send(ixs, payer, signers);
    this.log.push(sig); return sig;
  }

  // ---- agent side: sign an envelope --------------------------------------------------------------
  /** The exact bytes an agent signs for `action` (nothing is signed or sent here). */
  async message(agentId, action, accounts, opts = {}) {
    const cfg = opts.config ?? await this.config();
    const id = pk(agentId);
    const nonce = opts.nonce ?? (await this.agent(id))?.nonce ?? 0;
    return L.encodeEnvelope({ domain: cfg.domain, program: this.program, agent: id, nonce,
      expiry: opts.expiry ?? Math.floor(await this.t.now()) + 900, preferred: opts.preferred ?? L.ZERO, accounts: accounts.map(pk), action });
  }
  async envelope(signer, action, accounts, opts = {}) {
    signer = signerOf(signer);
    const message = await this.message(opts.agent ?? signer.publicKey, action, accounts, opts);
    const signatures = [{ key: signer.publicKey, signature: await signer.sign(message) }];
    if (opts.cosigner) { const c = signerOf(opts.cosigner); signatures.push({ key: c.publicKey, signature: await c.sign(message) }); }
    return { message, signatures };
  }

  // ---- relayer side: turn signed bytes into a transaction ----------------------------------------
  /** Everything the relayer needs is inside the signed bytes; it verifies them before paying. */
  async instructions({ message, signatures }, payer) {
    const env = L.decodeEnvelope(message);
    if (!pk(env.program).equals(this.program)) throw Error('envelope is bound to another program');
    for (const s of signatures) if (!nacl.sign.detached.verify(Uint8Array.from(message), Uint8Array.from(s.signature), L.keyBytes(pk(s.key)))) throw Error('envelope signature does not verify');
    const index = 1;   // the Ed25519 check is instruction 0; v1 transactions need no compute-budget instruction
    const keys = [...await this.prefix(payer), w(this.agentAddress(env.agent)), w(SYSVAR_INSTRUCTIONS_PUBKEY, false), ...env.accounts.map(k => w(k))];
    return [ed25519Instruction(signatures, message.length, index), new TransactionInstruction({ programId: this.program, keys, data: Buffer.concat([Buffer.from([1]), message]) })];
  }
  async submit(envelope, payer) { return this.send(await this.instructions(envelope, payer), payer); }
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
    const id = pk(agentId);
    switch (req.type) {
      case 'register': return { action: { type: 'register', handle: req.handle ?? '', hosted: !!req.hosted }, accounts: [], nonce: 0 };
      case 'setKey': return { action: { type: 'setKey', key: pk(req.key) }, accounts: [] };
      case 'begin': {
        const frame = L.encodeFrame(req.text); const { root, writes } = L.chain(frame);
        const nonce = (await this.agent(id)).nonce;
        return { action: { type: 'begin', len: frame.length, root }, accounts: [this.uploadAddress(id, nonce)], nonce, writes, content: root };
      }
      case 'create': {
        const cfg = await this.config(); const art = this.artifactAddress(cfg.artifacts); const u = await this.read(req.upload, L.decodeUpload);
        return { action: { type: 'create', name: req.name, title: req.title ?? '' }, accounts: [art, pk(req.upload), u.funder, this.recordAddress(art, 1)], artifact: art };
      }
      case 'propose': case 'apply': {
        const artifact = pk(req.artifact); const a = await this.artifact(artifact);
        const payload = req.type === 'apply' ? { kind: 'membership', agent: id } : req.payload;
        if (payload.kind === 'content' && !payload.content) payload.content = (await this.read(payload.upload, L.decodeUpload)).root;
        const prop = this.proposalAddress(artifact, a.proposals); const accounts = [artifact, prop];
        if (payload.kind === 'content') accounts.push(pk(payload.upload));
        return { action: { type: 'propose', payload, thread: req.thread ?? '' }, accounts, proposal: prop };
      }
      case 'vote': return { action: { type: 'vote', approve: !!req.approve }, accounts: [pk(req.artifact), pk(req.proposal)] };
      case 'confirm': {
        const [a, p] = await Promise.all([this.artifact(req.artifact), this.proposal(req.proposal)]);
        return { action: { type: 'confirm', execute: !!req.execute }, accounts: [pk(req.artifact), pk(req.proposal), p.funder, this.recordAddress(req.artifact, a.history + 1)] };
      }
      case 'vouch': return { action: { type: 'vouch' }, accounts: [this.agentAddress(req.target)] };
      case 'cancelUpload': { const u = await this.read(req.upload, L.decodeUpload); return { action: { type: 'cancelUpload' }, accounts: [pk(req.upload), u.funder] }; }
      default: throw Error(`unknown request ${req.type}`);
    }
  }

  // ---- agent actions -----------------------------------------------------------------------------
  register(signer, relay, { handle = '', hosted = false } = {}) { return this.act(signer, { type: 'register', handle, hosted }, [], relay, { nonce: 0 }); }
  async setKey(current, id, next, relay) { return this.act(current, { type: 'setKey', key: signerOf(next).publicKey }, [], relay, { agent: id, cosigner: next }); }
  /** Stages a page: one signed Begin, then unsigned chunk writes that anyone may carry. */
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
  async create(signer, name, upload, relay, { title = '', agent } = {}) {
    const cfg = await this.config(); const id = pk(agent ?? signerOf(signer).publicKey);
    const art = this.artifactAddress(cfg.artifacts); const u = await this.read(upload, L.decodeUpload);
    await this.act(signer, { type: 'create', name, title }, [art, upload, u.funder, this.recordAddress(art, 1)], relay, { agent: id, config: cfg });
    return art;
  }
  async propose(signer, artifact, payload, relay, { thread = '', agent } = {}) {
    const a = await this.artifact(artifact); const prop = this.proposalAddress(artifact, a.proposals);
    const accounts = [artifact, prop]; if (payload.kind === 'content') accounts.push(payload.upload);
    await this.act(signer, { type: 'propose', payload, thread }, accounts, relay, { agent });
    return prop;
  }
  async proposeContent(signer, artifact, page, text, relay, opts = {}) {
    const up = await this.upload(signer, text, relay, opts);
    return this.propose(signer, artifact, { kind: 'content', page, upload: up.address, content: up.content, title: opts.title ?? '' }, relay, opts);
  }
  apply(signer, artifact, relay, opts = {}) { return this.propose(signer, artifact, { kind: 'membership', agent: pk(opts.agent ?? signerOf(signer).publicKey) }, relay, opts); }
  vote(signer, artifact, proposal, approve, relay, opts = {}) { return this.act(signer, { type: 'vote', approve }, [artifact, proposal], relay, opts); }
  async confirm(signer, artifact, proposal, execute, relay, opts = {}) {
    const [a, p] = await Promise.all([this.artifact(artifact), this.proposal(proposal)]);
    return this.act(signer, { type: 'confirm', execute }, [artifact, proposal, p.funder, this.recordAddress(artifact, a.history + 1)], relay, opts);
  }
  vouch(signer, target, relay, opts = {}) { return this.act(signer, { type: 'vouch' }, [this.agentAddress(target)], relay, opts); }

  // ---- permissionless cranks ---------------------------------------------------------------------
  async crankIx(name, extra, payer) {
    return new TransactionInstruction({ programId: this.program, keys: [...await this.prefix(payer), ...extra.map(k => w(k))], data: L.encodeCrank(name) });
  }
  async crank(name, extra, payer, before = []) { return this.send([...before, await this.crankIx(name, extra, payer)], payer); }
  async resolve(proposal, payer) {
    const p = await this.proposal(proposal); const a = await this.artifact(p.artifact);
    const extra = [p.artifact, proposal, p.funder, this.recordAddress(p.artifact, a.history + 1)]; const before = [];
    if (p.payload.kind === 'content') {
      const u = await this.read(p.payload.upload, L.decodeUpload);
      extra.push(p.payload.upload, u.funder);
    }
    if (p.payload.kind === 'grant') extra.push(this.agentAddress(p.payload.agent));
    if (p.payload.kind === 'link') extra.push(p.payload.to);
    return this.crank('resolve', extra, payer, before);
  }
  async expire(proposal, payer) { const p = await this.proposal(proposal); return this.crank('expire', [p.artifact, proposal, p.funder], payer); }
  async closeEpoch(payer) { const c = await this.config(); return this.crank('closeEpoch', [this.epochAddress(c.epoch)], payer); }
  applyGlobal(payer) { return this.crank('applyGlobal', [], payer); }
  async expireUpload(upload, payer) { const u = await this.read(upload, L.decodeUpload); return this.crank('expireUpload', [upload, u.funder], payer); }
  unwrap(tokenAccount, tokenProgram, payer) { return this.crank('unwrap', [tokenAccount, tokenProgram], payer); }
  async claim(epoch, relayer, payer) { return this.crank('claim', [this.epochAddress(epoch), this.relayerAddress(relayer), relayer], payer); }
  async retire(epoch, payer) { const e = await this.read(this.epochAddress(epoch), L.decodeEpoch); return this.crank('retire', [this.epochAddress(epoch), e.funder], payer); }
  /** Runs a whole holder distribution for the epoch being distributed, in batches. */
  async distribute(payer, batch = 8) {
    const cfg = await this.config(); if (cfg.distributing === null) return { epoch: null };
    const n = cfg.distributing; const ep = this.epochAddress(n);
    const holders = (await this.all(L.TAG.HOLDER)).filter(h => h.registered <= n);
    const todo = holders.filter(h => h.tallied <= n);
    for (let i = 0; i < todo.length; i += batch) await this.crank('tally', [ep, ...todo.slice(i, i + batch).flatMap(h => [h.address, h.token])], payer);
    const e = await this.read(ep, L.decodeEpoch);
    if (e.weight > 0n) {
      const fresh = (await this.all(L.TAG.HOLDER)).filter(h => h.tallied === n + 1 && h.paid <= n && h.weight > 0);
      for (let i = 0; i < fresh.length; i += batch) await this.crank('pay', [ep, ...fresh.slice(i, i + batch).flatMap(h => [h.address, h.owner])], payer);
    }
    return { epoch: n, ...(await this.read(ep, L.decodeEpoch)) };
  }

  // ---- wallet-signed direct instructions ---------------------------------------------------------
  async direct(d, extra, payer, signers = []) {
    return this.send([new TransactionInstruction({ programId: this.program, keys: [...await this.prefix(payer), ...extra.map(k => k.pubkey ? k : w(k))], data: L.encodeDirect(d) })], payer, signers);
  }
  registerRelayer(payer, { kind = 'relay', url = '' } = {}) { return this.direct({ type: 'registerRelayer', kind, url }, [this.relayerAddress(payer.publicKey)], payer); }
  registerHolder(owner, tokenAccount) { return this.direct({ type: 'registerHolder' }, [this.holderAddress(owner.publicKey), tokenAccount], owner); }
  async closeHolder(owner) { const h = await this.read(this.holderAddress(owner.publicKey), L.decodeHolder); return this.direct({ type: 'closeHolder' }, [this.holderAddress(owner.publicKey), h.funder], owner); }
  withdraw(owner) { return this.direct({ type: 'withdraw' }, [this.holderAddress(owner.publicKey)], owner); }
  async sponsor(sponsor, artifact, tokenAccount) {
    const [a, cfg] = await Promise.all([this.artifact(artifact), this.config()]);
    await this.direct({ type: 'sponsor' }, [artifact, this.recordAddress(artifact, a.history + 1), tokenAccount, cfg.mint, cfg.tokenProgram], sponsor);
    return Math.min(cfg.g.FREE_PAGES + a.sponsored + 1, L.MAX_PAGES);
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
      const versions = records.filter(r => r.page === k && TEXT_KINDS.includes(r.kind)); if (!versions.length) continue;
      const last = versions.at(-1);
      const page = { page: k, version: last.pageVersion, content: last.content, len: last.len, record: last.address.toBase58(), upload: last.subject,
        title: versions.map(v => v.title).filter(Boolean).at(-1) ?? '' };
      if (text) page.text = (await this.textFromTransactions(last.subject, last.len, last.content)).toString('utf8');
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
  async verify(address, { history = true } = {}) {
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
    for (const r of records.filter(r => TEXT_KINDS.includes(r.kind))) {
      if (r.pageVersion !== ++counts[r.page - 1]) problems.push(`page ${r.page}: version ${r.pageVersion} out of order`);
      const v = { seq: r.seq, page: r.page, version: r.pageVersion, kind: r.kind, time: r.time, content: r.content.toString('hex'), record: r.address.toBase58(), title: r.title };
      if (history || counts[r.page - 1] === art.versions[r.page - 1]) {
        try { v.bytes = await this.textFromTransactions(r.subject, r.len, r.content); }
        catch (e) { problems.push(`version ${r.page}.${r.pageVersion}: ${e.message}`); }
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
  async textFromTransactions(upload, len, root) {
    const txs = await this.t.transactionsFor(pk(upload));
    const writes = new Map();
    for (const tx of txs) for (const ix of tx.instructions) {
      if (!ix.programId.equals(this.program) || ix.data[0] !== 3 || ix.data[1] !== 1) continue;
      const r = new L.R(ix.data.subarray(2)); const chunk = r.bytes(); const next = r.hash();
      writes.set(L.sha256(chunk, next).toString('hex'), { chunk, next });
    }
    const parts = []; let at = Buffer.from(root);
    while (!at.equals(L.ZERO)) { const x = writes.get(at.toString('hex')); if (!x) throw Error('a chunk is missing from transaction history'); parts.push(x.chunk); at = x.next; }
    const frame = Buffer.concat(parts); if (frame.length !== len) throw Error('rebuilt text has the wrong length');
    const text = L.decodeFrame(frame);
    const s = new TextDecoder('utf-8', { fatal: true }).decode(text);
    if ([...s].length > L.MAX_CHARS) throw Error('rebuilt text exceeds the character limit');
    return text;
  }
}
const TEXT_KINDS = ['genesis', 'content', 'imported'];
