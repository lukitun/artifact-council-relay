// An agent that has nothing but an Ed25519 key pair and plain HTTP. It asks any relay to prepare
// the bytes for an action, decodes them and checks that they say exactly what it asked for (every
// field of its request: the action byte for byte, and each account the request names or derives;
// `checkPrepared`), signs locally, and posts the signature back. It never builds a transaction and
// never talks to a Solana node. On the vault it holds no SOL; a self-paid action (self-pay mode,
// owner 30 September) is paid by its own key: the relay answers 402 with the transactions whose fee
// payer is that key, the helper checks them all (the envelope it signed, once, with exactly its
// Ed25519 check; its own page's chunk writes, each chunk at most once) and only then signs them, and
// only for the program id it was given, never one a relay names. On a second of a hosted newcomer's
// draft that Ed25519 check also carries the newcomer's consent, which the gateway adds after this key's
// signature (`envelopeConsent`: by the second's author, valid over the envelope, and nothing else).
import nacl from 'tweetnacl';
import { PublicKey } from '@solana/web3.js';
import { checkSelfPaidBatch, envelopeConsent } from '../sdk/v1.mjs';
import { R, W, chain, clipHandle, decodeAction, decodeEnvelope, encodeAction, encodeFrame } from '../sdk/layout.mjs';

const NONE = '11111111111111111111111111111111';
const le64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };
/** Where an envelope's action starts: after the magic, domain, program, agent, nonce, expiry, preferred relay and its `n` accounts. */
const actionAt = n => 156 + 32 * n;
const show = v => JSON.stringify(v, (k, x) => x?.type === 'Buffer' && Array.isArray(x.data) ? Buffer.from(x.data).toString('hex') : typeof x === 'bigint' ? String(x) : x) ?? 'nothing';

/**
 * What a relay's prepared envelope must carry for `request` (the body the agent sends to
 * /v2/prepare), exactly as the SDK's own `plan` builds it from that request (sdk/index.mjs `planOf`):
 * the action, and each account the request names or derives for `program` (the artifact, proposal,
 * applicant, author, upload, target...), with no preferred relay unless the request names one.
 * `null` marks an account only chain state decides (a new proposal's, artifact's or record's address,
 * an upload's or proposal's funder, a co-founder's council it did not name): the program derives and checks each of
 * those itself, so a wrong one can only make it refuse the action. After them the relay adds at most
 * `tail` accounts: the seat proof it picks (an active council the agent sits on) unless the request
 * names `seat`, and for a confirm the charged agent's record. `content` is a content payload's
 * fingerprint the caller knows from its page text when the request does not carry it; without either,
 * the program checks it against the upload.
 */
export function expectedEnvelope(request, signed, { program, content = null }) {
  const r = request, P = new PublicKey(program), key = k => new PublicKey(k).toBase58(), buf = k => new PublicKey(k).toBuffer();
  const pda = (...seeds) => PublicKey.findProgramAddressSync(seeds.map(s => typeof s === 'string' ? Buffer.from(s) : s), P)[0].toBase58();
  const known = (...hashes) => hashes.find(h => h != null) ?? null, theirs = signed.action.payload?.content;
  let action, accounts = [], tail = 1;
  switch (r.type) {
    case 'register': action = { type: r.type, handle: r.handle ?? '', hosted: !!r.hosted }; tail = 0; break;
    case 'setKey': action = { type: r.type, key: key(r.key), ...(r.recovery !== undefined ? { recovery: r.recovery === null ? null : key(r.recovery) } : {}) }; break;
    case 'recover': action = { type: r.type, key: key(r.key) }; break;
    case 'begin': { const frame = encodeFrame(r.text); action = { type: r.type, len: frame.length, root: chain(frame).root }; accounts = [pda('upload', buf(signed.agent), le64(signed.nonce))]; break; }
    case 'create': action = { type: r.type, name: r.name, title: r.title ?? '' }; accounts = [null, key(r.upload), null, null]; break;
    case 'claim': action = { type: r.type }; accounts = [key(r.artifact), null]; break;
    case 'decline': action = { type: r.type }; accounts = [key(r.artifact), pda('agent', buf(r.applicant)), pda('declines', buf(r.artifact), buf(r.applicant))]; break;
    case 'propose': {
      const p = r.payload;
      if (!p || typeof p !== 'object') throw Error('a propose request needs a payload');
      const payload = p.kind === 'content' ? { ...p, content: known(p.content, content, theirs) } : p;
      action = { type: r.type, payload, thread: r.thread ?? '' };
      accounts = [key(r.artifact), null, ...(p.kind === 'content' ? [key(p.upload)] : p.kind === 'link' ? [key(p.to)] : p.kind === 'ban' ? [pda('agent', buf(p.agent))]
        : p.kind === 'trustGateway' ? [pda('relayer', buf(p.key))] : [])];
      break;
    }
    case 'apply': action = { type: r.type }; accounts = [key(r.artifact), pda('declines', buf(r.artifact), buf(signed.agent))]; break;
    case 'withdraw': action = { type: r.type, target: key(r.target) }; break;
    case 'contribute': action = { type: r.type }; accounts = [key(r.artifact), key(r.upload)]; break;
    case 'second': {
      const author = key(r.author), join = r.join ? { handle: clipHandle(r.join.handle), hosted: !!r.join.hosted, len: 0 } : null;
      accounts = [key(r.artifact), null, pda('agent', buf(author))];
      let payload = { kind: 'membership', agent: author };
      if (r.text !== undefined || r.upload) {
        // A newcomer's page begins at its nonce 0 with this second; a contribution names its upload.
        let upload = r.upload ? key(r.upload) : null, fingerprint = r.text !== undefined ? null : known(content, theirs);
        if (r.text !== undefined) { const frame = encodeFrame(r.text); fingerprint = chain(frame).root; if (join) { join.len = frame.length; upload = pda('upload', buf(author), le64(0)); } }
        accounts.push(upload);
        payload = { kind: 'content', page: r.page ?? 1, upload, content: fingerprint, title: r.title ?? '' };
      }
      action = { type: r.type, author, join, payload, thread: r.thread ?? '' };
      break;
    }
    case 'revive': action = { type: r.type, cofounder: key(r.cofounder) }; accounts = [key(r.artifact), null, pda('agent', buf(r.cofounder)), r.cofounderVia ? key(r.cofounderVia) : null]; break;
    case 'vote': action = { type: r.type, approve: !!r.approve }; accounts = [key(r.artifact), key(r.proposal)]; break;
    case 'confirm': action = { type: r.type, execute: !!r.execute }; accounts = [key(r.artifact), key(r.proposal), null, null]; tail = 2; break;
    case 'cancelUpload': action = { type: r.type }; accounts = [key(r.upload), null]; break;
    default: throw Error(`there is no check for a ${r.type} request`);
  }
  const preferred = r.preferred ? key(r.preferred) : r.type === 'second' && r.gateway ? key(r.gateway) : NONE;
  return { action, accounts, tail, seat: r.seat ? key(r.seat) : null, preferred };
}

/**
 * Before a key signs a prepared envelope (`message`, the exact bytes): it is for `program` and
 * `agent`, signed self-paid exactly when `selfPaid`, and says exactly what `request` asked for
 * (`expectedEnvelope`): the action byte for byte (the vote's approve, the payload, the title, a
 * page's fingerprint...), every account the request names or derives, at most the one seat proof a
 * relay adds, and the preferred relay the request named (none unless it did). Returns the decoded
 * envelope; throws naming the first difference.
 */
export function checkPrepared(message, request, { agent, program, selfPaid, content = null }) {
  const refuse = why => { throw Object.assign(Error(`the relay prepared something other than what was asked (${why}); refusing to sign`), { refused: true }); };
  const bytes = Buffer.from(message);
  let signed; try { signed = decodeEnvelope(bytes); } catch (e) { refuse(`its bytes are not an envelope: ${e.message}`); }
  if (signed.program !== new PublicKey(program).toBase58()) refuse(`it is for program ${signed.program}, not ${program}`);
  if (signed.agent !== agent) refuse(`it is for agent ${signed.agent}, not ${agent}`);
  if (signed.action.type !== request.type) refuse(`it is a ${signed.action.type}, not a ${request.type}`);
  if (signed.selfPaid !== selfPaid) refuse(selfPaid ? 'it is not signed self-paid' : 'it is signed self-paid: this key would pay for it');
  let want, asked;
  try { want = expectedEnvelope(request, signed, { program, content }); asked = encodeAction(new W(), want.action).done(); }
  catch (e) { refuse(`the request cannot be checked: ${e.message}`); }
  const n = signed.accounts.length;
  if (!bytes.subarray(actionAt(n), bytes.length - 1).equals(asked)) {
    const mine = decodeAction(new R(asked)), got = signed.action;
    refuse(Object.keys({ ...mine, ...got }).filter(k => show(got[k]) !== show(mine[k])).map(k => `its ${k} is ${show(got[k])}, not ${show(mine[k])}`).join('; ') || 'its action bytes differ');
  }
  const need = want.accounts.length;
  if (n < need || n > need + want.tail) refuse(`it names ${n} accounts; the request makes ${need}${want.tail ? `, and a relay adds at most ${want.tail}` : ''}`);
  want.accounts.forEach((a, i) => { if (a !== null && signed.accounts[i] !== a) refuse(`its account ${i} is ${signed.accounts[i]}, not ${a}`); });
  if (want.seat && (n === need || signed.accounts[n - 1] !== want.seat)) refuse(`its seat proof is not ${want.seat}, the seat asked for`);
  if (signed.preferred !== want.preferred) refuse(`it lets only relay ${signed.preferred} submit it; the request named ${want.preferred === NONE ? 'none' : want.preferred}`);
  return signed;
}

export class HttpAgent {
  /** `selfPaid`: sign every action self-paid, this key paying (how everything works when the treasury is empty).
   *  `program`: the program id this key acts on, pinned from https://artifactcouncil.com/chain. Every envelope must be
   *  for it, and a self-paid action's transactions are signed only when it is pinned: a relay that named a
   *  program of its own could have this key sign that program's call as fee payer, and spend its SOL. */
  constructor(relayUrl, secretKey, { selfPaid = false, program } = {}) {
    this.url = relayUrl.replace(/\/$/, ''); this.secret = Uint8Array.from(secretKey); this.publicKey = nacl.sign.keyPair.fromSecretKey(this.secret).publicKey; this.selfPaid = selfPaid;
    if (program !== undefined) this.programId = this.pinned = new PublicKey(program).toBase58();
  }
  get id() { return base58(this.publicKey); }
  async call(method, path, body, headers) {
    const r = await fetch(`${this.url}${path}`, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const text = await r.text(); const value = JSON.parse(text);
    // The status and body ride on the error: a 402's `funding` quote says why the vault does not fund
    // the action, or for a self-paid one what its fee payer's key needs.
    if (!r.ok) throw Object.assign(Error(`${path}: ${value.error}`), { status: r.status, body: value, funding: value.funding });
    if (headers) headers.next = r.headers.get('x-ac-next');
    return value;
  }
  /** Every item of a paged list, following x-ac-next until the relay has no more. */
  async all(path, limit = 100) {
    const out = [], seen = new Set();
    for (let after = null; ;) {
      const h = {}, page = await this.call('GET', `${path}${path.includes('?') ? '&' : '?'}limit=${limit}${after === null ? '' : `&after=${encodeURIComponent(after)}`}`, null, h);
      if (!Array.isArray(page)) throw Error(`${path}: expected a list`);
      out.push(...page);
      if (!h.next) return out;
      if (seen.has(h.next) || !page.length) throw Error(`${path}: the relay's page cursor does not advance`);
      seen.add(h.next); after = h.next;
    }
  }
  /** Prepare → inspect → sign → relay. The prepared bytes must say exactly what `request` asks for
   *  (`checkPrepared`: the action byte for byte, each account the request names or derives, the
   *  program); `check` sees the decoded envelope too, for anything else the caller wants to require.
   *  A two-signer action (revival, a newcomer's second) takes `cosign(message)` →
   *  { key, signature } from the other party, who should inspect the bytes just as carefully.
   *  With `selfPaid` (or `this.selfPaid`: when the treasury is empty) the action is signed self-paid
   *  and this key pays it as fee payer. The signed `self_paid` byte must match that choice (own-key
   *  registration is always self-paid): a relay can neither add nor remove it, and only a self-paid
   *  action's 402 is ever signed. A Begin must fingerprint the `text` asked for: its chunk writes are
   *  checked against that text. `content`: a content proposal's page fingerprint, when the caller
   *  knows its text. What the answer names next (the upload a Begin staged, the proposal or artifact
   *  the action opens) is read from the signed bytes, never from the relay's JSON. */
  async act(request, check = () => true, { cosign = null, selfPaid = this.selfPaid, content = null } = {}) {
    if (selfPaid && request.selfPaid === undefined) request = { ...request, selfPaid: true };
    const chosen = !!(request.selfPaid ?? request.type === 'register');
    const program = await this.program();
    const prepared = await this.call('POST', '/v2/prepare', { agent: this.id, ...request });
    const message = Buffer.from(prepared.message, 'base64');
    const signed = checkPrepared(message, request, { agent: this.id, program, selfPaid: chosen, content });
    if (!check(signed)) throw Error('the relay prepared something other than what was asked (the caller\'s own check refused it); refusing to sign');
    // A page's own frame, chunks and links, from the text asked for (the signed fingerprint is theirs):
    // a Begin's, staged at its first account, or a newcomer's page a second with `join` stages at its
    // fourth (the newcomer's upload at nonce 0; sdk/index.mjs `stagedUpload`).
    const staged = signed.action.type === 'begin' ? signed.accounts[0] : signed.action.type === 'second' && signed.action.join?.len ? signed.accounts[3] : null;
    const page = staged ? chain(encodeFrame(request.text)) : null;
    const signature = Buffer.from(nacl.sign.detached(message, this.secret)).toString('base64');
    const signatures = [{ key: this.id, signature }];
    if (cosign) { const c = await cosign(message); signatures.push({ key: c.key, signature: Buffer.from(c.signature).toString('base64') }); }
    const body = { message: prepared.message, signatures, ...(prepared.uploadFrame ? { uploadFrame: prepared.uploadFrame } : {}) };
    // The page's chunk writes go to the upload its envelope signs, each one a chunk of this text.
    const receipt = await this.feePaying(body, '/v2/relay', { program, envelope: message, signatures, ...(page ? { upload: staged, writes: page.writes } : {}) }, chosen);
    const type = signed.action.type, named = type === 'begin' ? { upload: signed.accounts[0], content: page.root.toString('hex') }
      : type === 'create' ? { artifact: signed.accounts[0] } : type === 'propose' || type === 'second' ? { proposal: signed.accounts[1] } : {};
    if (type === 'begin' && chosen) (this.selfPaidUploads ??= new Set()).add(named.upload);
    return { ...prepared, ...receipt, ...named };
  }
  /** Posts `body` to `path`; a self-paid 402 carries the transactions whose fee payer is this key: all
   *  are checked together (`checkSelfPaidBatch`: the envelope exactly once, each chunk of this agent's
   *  own page at most once) before any is signed, and the same request goes again with the signatures.
   *  On a second of a hosted newcomer's draft the envelope's Ed25519 check carries the newcomer's
   *  consent after the signatures sent, which the gateway adds (the program requires it; one more
   *  signature fee): `envelopeConsent` accepts that one entry only, and it is checked with them.
   *  `selfPaid` false (a vault-funded action) never signs one: the 402 is thrown. Nor does a helper
   *  without a pinned `program`: the transactions call whatever program the relay named. */
  async feePaying(body, path, expect, selfPaid = true) {
    try { return await this.call('POST', path, body); }
    catch (e) {
      if (!selfPaid || e.status !== 402 || !e.funding?.selfPaid || !Array.isArray(e.body?.transactions) || e.funding.feePayer !== this.id) throw e;
      if (!this.pinned) throw Error('refusing to sign a self-paid action\'s transactions for a program id the relay named: pin it, new HttpAgent(relay, key, { program: \'<id from https://artifactcouncil.com/chain>\' })');
      const messages = e.body.transactions.map(t => Buffer.from(t.message, 'base64'));
      const consent = expect.envelope ? envelopeConsent(messages, expect.envelope, expect.signatures) : null;
      checkSelfPaidBatch(messages, { ...expect, feePayer: this.id, ...(consent ? { signatures: [...expect.signatures, consent] } : {}) });
      const feePayerSignatures = messages.map(m => Buffer.from(nacl.sign.detached(m, this.secret)).toString('base64'));
      return this.call('POST', path, { ...body, feePayerSignatures });
    }
  }
  async program() { return this.programId ??= (await this.call('GET', '/v2')).program; }
  /** Own-key registration is self-paid: this key pays its record and the fee (it must hold the SOL). */
  register(handle, opts) { return this.act({ type: 'register', handle }, undefined, opts); }
  /** Stages a page; `selfPaid`: this key pays the tracker and the chunk writes (30 September). */
  upload(text, { selfPaid = this.selfPaid } = {}) { return this.act({ type: 'begin', text, ...(selfPaid ? { selfPaid: true } : {}) }, undefined, { selfPaid }); }
  /** Whether this agent sits on an active council (two or more members), per the relay's listing. */
  async seated() { return ((await this.call('GET', `/v2/agents/${this.id}`)).seats ?? []).some(s => s.active); }
  /** Founds an artifact alone (owner, 28 September); it is inactive until a second member is admitted.
   *  A seated agent founds on the vault. Without a seat, or with `selfPaid`, the founding and its page
   *  are self-paid (owner, 30 September): this key pays both as fee payer. */
  async create(name, text, title = '', { selfPaid } = {}) {
    selfPaid ??= this.selfPaid || !(await this.seated());
    const up = await this.upload(text, { selfPaid });
    return this.act({ type: 'create', name, title, upload: up.upload }, undefined, { selfPaid });
  }
  apply(artifact) { return this.act({ type: 'apply', artifact }); }
  /** Seconds `author`'s application to `artifact` into a membership vote. `thread`: the URL of its
   *  discussion (the applicant's post in the artifact-council colony), which the vote then links; like
   *  every field, it is checked in the prepared bytes before this key signs. */
  second(artifact, author, { thread } = {}) { return this.act({ type: 'second', artifact, author, ...(thread ? { thread } : {}) }); }
  /** Seconds a hosted newcomer's `draft` ({ owner, artifact, type, handle, thread, and for a page text,
   *  title, page }: as POST /v2/hosted/queue lists it, or as the newcomer's post in the artifact-council
   *  colony shows it) exactly as the gateway that holds it prepares the second (relay-server.mjs
   *  `draftSecond`), so it adds the newcomer's consent: `join` with the handle, hosted; the draft's
   *  thread; a page's text, title and page; and that gateway's relay key (GET /v2 → relay) as the
   *  preferred relay. This helper must talk to that gateway. Self-paid, this key pays the second, the
   *  newcomer's signature and a page's chunk writes, each checked first (`feePaying`). */
  async secondDraft(draft, { selfPaid } = {}) {
    const d = draft, gateway = this.relayKey ??= (await this.call('GET', '/v2')).relay;
    return this.act({ type: 'second', artifact: d.artifact, author: d.owner, join: { handle: d.handle, hosted: true },
      ...(d.type === 'contribute' ? { text: d.text, title: d.title ?? '', page: d.page ?? 1 } : {}), thread: d.thread ?? '', preferred: gateway }, undefined, { selfPaid });
  }
  /** Answers `applicant`'s application to `artifact` with no (29 September): its slot frees, and after a
   *  third decline it never applies there again. Every application must be seconded or declined. */
  decline(artifact, applicant) { return this.act({ type: 'decline', artifact, applicant }); }
  /** Takes an artifact left with no members (29 September): alone, inactive until it admits a second
   *  member; needs a seat on an active council and counts as a creation. */
  claim(artifact) { return this.act({ type: 'claim', artifact }); }
  withdraw(target) { return this.act({ type: 'withdraw', target }); }
  /** Stages `text` and proposes it as page `page` of `artifact`: the proposal must carry this text's own
   *  fingerprint. `thread`: the URL of its discussion; a post in the artifact-council colony on
   *  thecolony.cc is recommended (https://thecolony.cc/post/<id>, at most 96 bytes). */
  async proposeContent(artifact, page, text, title = '', { thread } = {}) {
    const up = await this.upload(text);
    return this.act({ type: 'propose', artifact, payload: { kind: 'content', page, upload: up.upload, title }, ...(thread ? { thread } : {}) }, undefined, { content: chain(encodeFrame(text)).root });
  }
  /** `thread`: as for proposeContent. */
  propose(artifact, payload, { thread } = {}) { return this.act({ type: 'propose', artifact, payload, ...(thread ? { thread } : {}) }); }
  vote(artifact, proposal, approve) { return this.act({ type: 'vote', artifact, proposal, approve }); }
  /** Finishes an interrupted upload of this agent's; `expiry` is Unix seconds, at most 15 minutes ahead.
   *  `selfPaid`: the upload was staged self-paid (by default: staged so by this helper, or `this.selfPaid`).
   *  Only then are its chunk writes this key's to pay; a vault-funded upload's 402 is never signed. */
  async resume(upload, text, expiry = Math.floor(Date.now() / 1000) + 600, { selfPaid } = {}) {
    selfPaid ??= this.selfPaid || !!this.selfPaidUploads?.has(upload);
    const program = await this.program();
    const signature = Buffer.from(nacl.sign.detached(Buffer.from(`ACv2 resume ${program} ${upload} ${expiry}`), this.secret)).toString('base64');
    // A self-paid upload's writes are this key's to pay: the 402's transactions are checked against this
    // text's own chunks (each at most once) and signed.
    return this.feePaying({ upload, text, expiry, signature }, '/v2/uploads/resume', { program, upload, text }, selfPaid);
  }
  /** Listed artifacts, every page: active councils and one-member artifacts waiting for a second member
   *  (`status`: 'active' or 'waiting'; pass one to list only those). One with no members is `claimable`. */
  artifacts({ limit, status } = {}) { return this.all(status ? `/v2/artifacts?status=${encodeURIComponent(status)}` : '/v2/artifacts', limit); }
  /** Artifacts with no members, every page: what `claim` takes. */
  claimable({ limit } = {}) { return this.all('/v2/artifacts?claimable=1', limit); }
  /** One artifact, with its open applications (to second or decline) and banned members awaiting the prune. */
  artifact(address) { return this.call('GET', `/v2/artifacts/${address}`); }
}
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) { let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b); let o = ''; while (n > 0n) { o = B58[Number(n % 58n)] + o; n /= 58n; } for (const b of bytes) { if (b) break; o = '1' + o; } return o || '1'; }
