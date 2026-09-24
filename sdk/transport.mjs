// Transports: how the client reaches a chain. RpcTransport speaks plain JSON-RPC over HTTP to any
// standard Solana endpoint (no websocket, no indexer, no privileged provider). Every transaction
// read passes maxSupportedTransactionVersion: 1.
import { Connection, PublicKey } from '@solana/web3.js';
import { buildV1 } from './v1.mjs';
import { base58, fromBase58 } from './layout.mjs';

export class RpcTransport {
  constructor(url, { commitment = 'confirmed' } = {}) {
    this.rpc = new Connection(url, commitment); this.url = url; this.commitment = commitment;
  }
  async call(method, params) {
    for (let i = 0; ; i++) {
      try { return await this.rpc._rpcRequest(method, params).then(r => { if (r.error) throw Object.assign(Error(r.error.message), { rpc: r.error }); return r.result; }); }
      catch (e) { if (i >= 5 || e.rpc?.code === -32602) throw e; await new Promise(r => setTimeout(r, 500 * 2 ** i)); }
    }
  }
  async getAccount(k) {
    const r = await this.call('getAccountInfo', [k.toBase58(), { encoding: 'base64', commitment: this.commitment }]);
    return r.value ? { data: Buffer.from(r.value.data[0], 'base64'), owner: new PublicKey(r.value.owner), lamports: r.value.lamports } : null;
  }
  async programAccounts(program, tag) {
    const r = await this.call('getProgramAccounts', [program.toBase58(), { encoding: 'base64', commitment: this.commitment, filters: [{ memcmp: { offset: 0, bytes: base58([tag]) } }] }]);
    return r.map(a => ({ pubkey: new PublicKey(a.pubkey), data: Buffer.from(a.account.data[0], 'base64'), lamports: a.account.lamports }));
  }
  async now() { const slot = await this.call('getSlot', [{ commitment: this.commitment }]); return (await this.call('getBlockTime', [slot]).catch(() => null)) ?? Date.now() / 1000; }
  genesis() { return this.call('getGenesisHash', []); }
  async send(ixs, payer, signers = []) {
    // A node can hand out a blockhash its simulator has not seen yet; that is not a refusal, so
    // rebuild with a fresh blockhash rather than fail.
    for (let i = 0; ; i++) {
      try { return await this.sendOnce(ixs, payer, signers); }
      catch (e) { if (i >= 3 || !/Blockhash not found/i.test(e.message)) throw e; await new Promise(r => setTimeout(r, 2000)); }
    }
  }
  async sendOnce(ixs, payer, signers) {
    const latest = (await this.call('getLatestBlockhash', [{ commitment: this.commitment }])).value;
    const { raw, signature } = await buildV1(ixs, payer, signers, latest);
    // The signature is known before submission, so a dropped response never turns one action into
    // two transactions: every resend is byte-identical and deduplicated by the cluster.
    const landed = async () => {
      const s = (await this.call('getSignatureStatuses', [[signature], { searchTransactionHistory: true }])).value[0];
      if (s?.err) throw Object.assign(Error(`${signature} failed: ${JSON.stringify(s.err)}`), { signature, err: s.err });
      return s && (s.confirmationStatus === 'confirmed' || s.confirmationStatus === 'finalized');
    };
    let simulated = false;
    for (let attempt = 0; attempt < 8; attempt++) {
      try { await this.call('sendTransaction', [raw.toString('base64'), { encoding: 'base64', skipPreflight: simulated, maxRetries: 3 }]); }
      catch (e) {
        if (/already been processed/i.test(e.message)) { if (await landed()) return signature; }
        // A failed simulation is a real refusal; rate limits and network errors are retried.
        else if (e.rpc?.code === -32002 || /simulation failed/i.test(e.message)) { const logs = e.rpc?.data?.logs; throw Object.assign(Error(`${e.message}${logs ? '\n' + logs.join('\n') : ''}`), { logs }); }
        else { await new Promise(r => setTimeout(r, 1500 * (attempt + 1))); continue; }
      }
      simulated = true;
      for (let i = 0; i < 10; i++) { if (await landed()) return signature; await new Promise(r => setTimeout(r, 800)); }
    }
    throw Error(`unconfirmed transaction ${signature}`);
  }
  /** Successful transactions that touched `address`, oldest first, as program instructions. */
  async transactionsFor(address) {
    const sigs = []; let before;
    for (;;) {
      const page = await this.call('getSignaturesForAddress', [address.toBase58(), { limit: 1000, before, commitment: this.commitment }]);
      sigs.push(...page); if (page.length < 1000) break; before = page.at(-1).signature;
    }
    const out = [];
    for (const s of sigs.reverse()) {
      if (s.err) continue;
      const tx = await this.call('getTransaction', [s.signature, { encoding: 'json', commitment: this.commitment, maxSupportedTransactionVersion: 1 }]);
      if (!tx || tx.meta?.err) continue;
      const m = tx.transaction.message; const keys = m.accountKeys.map(k => typeof k === 'string' ? k : k.pubkey);
      out.push({ signature: s.signature, slot: tx.slot, instructions: m.instructions.map(ix => ({ programId: new PublicKey(keys[ix.programIdIndex]),
        accounts: ix.accounts.map(i => keys[i]), data: Buffer.from(fromBase58(ix.data)) })) });
    }
    return out;
  }
}

/** In-process chain for tests: the same client code against LiteSVM, with a controllable clock. */
export class SvmTransport {
  constructor(svm) { this.svm = svm; this.history = []; }
  async getAccount(k) {
    const a = this.svm.getAccount(k.toBase58());
    return a.exists ? { data: Buffer.from(a.data), owner: new PublicKey(a.programAddress), lamports: Number(a.lamports) } : null;
  }
  async programAccounts(program, tag) {
    return this.svm.getProgramAccounts(program.toBase58()).filter(a => a.data[0] === tag)
      .map(a => ({ pubkey: new PublicKey(a.address), data: Buffer.from(a.data), lamports: Number(a.lamports) }));
  }
  async now() { return Number(this.svm.getClock().unixTimestamp); }
  genesis() { return 'LiteSVM11111111111111111111111111111111111'; }
  warp(seconds) {
    const c = this.svm.getClock(); c.unixTimestamp += BigInt(seconds); c.slot += BigInt(Math.max(1, Math.round(seconds * 2.5))); this.svm.setClock(c); this.svm.expireBlockhash();
  }
  async send(ixs, payer, signers = []) {
    const { transaction, signature } = await buildV1(ixs, payer, signers, { blockhash: this.svm.latestBlockhash(), lastValidBlockHeight: 1000000n });
    const r = this.svm.sendTransaction(transaction);
    if (typeof r.err === 'function') {
      const logs = r.meta().logs();
      throw Object.assign(Error(`transaction failed: ${r.toString?.() ?? r.err()}\n${logs.slice(-12).join('\n')}`), { logs });
    }
    this.last = { cu: Number(r.computeUnitsConsumed()), logs: r.logs() };
    this.history.push({ signature, instructions: ixs.map(ix => ({ programId: ix.programId, accounts: ix.keys.map(k => k.pubkey.toBase58()), data: Buffer.from(ix.data) })) });
    this.svm.expireBlockhash();
    return signature;
  }
  async transactionsFor(address) {
    const a = address.toBase58();
    return this.history.filter(t => t.instructions.some(ix => ix.accounts.includes(a)));
  }
}
