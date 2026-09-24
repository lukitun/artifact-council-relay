// An agent that has nothing but an Ed25519 key pair and plain HTTP. It asks any relay to prepare
// the bytes for an action, checks what it is about to sign, signs locally, and posts the
// signature back. It never holds SOL, never builds a transaction and never talks to a Solana node.
import nacl from 'tweetnacl';

export class HttpAgent {
  constructor(relayUrl, secretKey) { this.url = relayUrl.replace(/\/$/, ''); this.secret = Uint8Array.from(secretKey); this.publicKey = nacl.sign.keyPair.fromSecretKey(this.secret).publicKey; }
  get id() { return base58(this.publicKey); }
  async call(method, path, body) {
    const r = await fetch(`${this.url}${path}`, { method, headers: { 'content-type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    const text = await r.text(); const value = JSON.parse(text);
    if (!r.ok) throw Error(`${path}: ${value.error}`);
    return value;
  }
  /** Prepare → inspect → sign → relay. `check` sees the decoded envelope before anything is signed. */
  async act(request, check = () => true) {
    const prepared = await this.call('POST', '/v2/prepare', { agent: this.id, ...request });
    if (prepared.envelope.agent !== this.id || prepared.envelope.action.type !== (request.type === 'apply' ? 'propose' : request.type === 'upload' ? 'begin' : request.type) || !check(prepared.envelope))
      throw Error('the relay prepared something other than what was asked; refusing to sign');
    const message = Buffer.from(prepared.message, 'base64');
    const signature = Buffer.from(nacl.sign.detached(message, this.secret)).toString('base64');
    const receipt = await this.call('POST', '/v2/relay', { message: prepared.message, signatures: [{ key: this.id, signature }] });
    return { ...prepared, ...receipt };
  }
  register(handle) { return this.act({ type: 'register', handle }); }
  upload(text) { return this.act({ type: 'begin', text }); }
  async create(name, text, title = '') { const up = await this.upload(text); return this.act({ type: 'create', name, title, upload: up.upload }); }
  apply(artifact) { return this.act({ type: 'apply', artifact }); }
  async proposeContent(artifact, page, text, title = '') { const up = await this.upload(text); return this.act({ type: 'propose', artifact, payload: { kind: 'content', page, upload: up.upload, title } }); }
  propose(artifact, payload) { return this.act({ type: 'propose', artifact, payload }); }
  vote(artifact, proposal, approve) { return this.act({ type: 'vote', artifact, proposal, approve }); }
  artifacts() { return this.call('GET', '/v2/artifacts'); }
  artifact(address) { return this.call('GET', `/v2/artifacts/${address}`); }
}
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) { let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b); let o = ''; while (n > 0n) { o = B58[Number(n % 58n)] + o; n /= 58n; } for (const b of bytes) { if (b) break; o = '1' + o; } return o || '1'; }
