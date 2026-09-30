// Transports: how the client reaches a chain. RpcTransport speaks plain JSON-RPC over HTTP to any
// standard Solana endpoint (no websocket, no indexer, no privileged provider). Every transaction
// read passes maxSupportedTransactionVersion: 1.
import { Connection, PublicKey } from '@solana/web3.js';
import { buildV1 } from './v1.mjs';
import { base58, fromBase58 } from './layout.mjs';

// A JSON-RPC error is the node's answer, not a fault on the way to it: only node unhealthy, block
// status not yet available, minimum context slot not reached, internal error and rate limits are
// worth asking again. Preflight refusals, block-not-available and every other answer fail at once,
// as does an HTTP 4xx other than 408 and 429. Network faults and 5xx are retried.
const TRANSIENT = new Set([-32005, -32014, -32016, -32603, 429]);
export const transient = e => e.rpc ? TRANSIENT.has(e.rpc.code) || /rate limit|too many requests/i.test(e.rpc.message ?? '')
  : !/^4(?!08|29)\d\d\b/.test(e.message ?? '');
const refused = e => e.rpc?.code === -32002 || /simulation failed/i.test(e.message);
/** How many of an address's newest signatures recentTransactions reads by default. */
export const RECENT_SIGNATURES = 12;
/** One transaction's public balance changes, from getTransaction (json): its signers, the programs it
 *  ran (inner ones too), each account's lamport change and each (owner, mint)'s token change. */
export function balanceRecord(signature, tx) {
  const m = tx.transaction.message, meta = tx.meta ?? {}, loaded = meta.loadedAddresses;
  const keys = [...m.accountKeys.map(k => typeof k === 'string' ? k : k.pubkey), ...(loaded?.writable ?? []), ...(loaded?.readonly ?? [])];
  const n = m.header?.numRequiredSignatures ?? m.accountKeys.filter(k => k?.signer).length;
  const programs = new Set(m.instructions.map(ix => keys[ix.programIdIndex]));
  for (const g of meta.innerInstructions ?? []) for (const ix of g.instructions ?? []) programs.add(keys[ix.programIdIndex]);
  const sol = {};
  keys.forEach((k, i) => { const d = (meta.postBalances?.[i] ?? 0) - (meta.preBalances?.[i] ?? 0); if (d) sol[k] = (sol[k] ?? 0) + d; });
  const tok = new Map();
  for (const [list, sign] of [[meta.preTokenBalances, -1n], [meta.postTokenBalances, 1n]]) for (const b of list ?? []) {
    const k = `${b.owner}:${b.mint}`; tok.set(k, (tok.get(k) ?? 0n) + sign * BigInt(b.uiTokenAmount?.amount ?? 0));
  }
  return { signature, time: tx.blockTime ?? null, signers: keys.slice(0, n), programs: [...programs].filter(Boolean), sol,
    tokens: [...tok].filter(([, d]) => d !== 0n).map(([k, d]) => { const [owner, mint] = k.split(':'); return { owner, mint, delta: String(d) }; }) };
}

export class RpcTransport {
  constructor(url, { commitment = 'confirmed', request, sleep = ms => new Promise(r => setTimeout(r, ms)), builds = 3, poll = 1000, resend = 4, polls = 180 } = {}) {
    this.rpc = new Connection(url, commitment); this.url = url; this.commitment = commitment;
    this.request = request ?? ((method, params) => this.rpc._rpcRequest(method, params));
    Object.assign(this, { sleep, builds, poll, resend, polls });
  }
  async call1(method, params) {
    const r = await this.request(method, params);
    if (r.error) throw Object.assign(Error(r.error.message), { rpc: r.error });
    return r.result;
  }
  async call(method, params) {
    for (let i = 0; ; i++) {
      try { return await this.call1(method, params); }
      catch (e) { if (i >= 5 || !transient(e)) throw e; await this.sleep(500 * 2 ** i); }
    }
  }
  async getAccounts(keys) {
    const out = [];
    for (let i = 0; i < keys.length; i += 100) {
      const chunk = keys.slice(i, i + 100);
      const r = await this.call('getMultipleAccounts', [chunk.map(k => k.toBase58()), { encoding: 'base64', commitment: this.commitment }]);
      if (r.value?.length !== chunk.length) throw Error(`getMultipleAccounts returned ${r.value?.length} of ${chunk.length} accounts`);
      out.push(...r.value.map(v => v ? { data: Buffer.from(v.data[0], 'base64'), owner: new PublicKey(v.owner), lamports: v.lamports, executable: v.executable } : null));
    }
    return out;
  }
  async getAccount(k) {
    const r = await this.call('getAccountInfo', [k.toBase58(), { encoding: 'base64', commitment: this.commitment }]);
    return r.value ? { data: Buffer.from(r.value.data[0], 'base64'), owner: new PublicKey(r.value.owner), lamports: r.value.lamports, executable: r.value.executable } : null;
  }
  async programAccounts(program, tag) {
    const r = await this.call('getProgramAccounts', [program.toBase58(), { encoding: 'base64', commitment: this.commitment, filters: [{ memcmp: { offset: 0, bytes: base58([tag]) } }] }]);
    return r.map(a => ({ pubkey: new PublicKey(a.pubkey), data: Buffer.from(a.account.data[0], 'base64'), lamports: a.account.lamports }));
  }
  /** Every account `program` owns, whatever its layout. */
  async allProgramAccounts(program) {
    const r = await this.call('getProgramAccounts', [program.toBase58(), { encoding: 'base64', commitment: this.commitment }]);
    return r.map(a => ({ pubkey: new PublicKey(a.pubkey), data: Buffer.from(a.account.data[0], 'base64'), lamports: a.account.lamports }));
  }
  async transaction(signature, commitment = this.commitment) {
    const tx=await this.call('getTransaction',[signature,{encoding:'json',commitment,maxSupportedTransactionVersion:1}]);
    if(!tx)return null;
    const message=tx.transaction.message, keys=message.accountKeys.map(k=>typeof k==='string'?k:k.pubkey), meta=tx.meta;
    return {signature,error:meta?.err,payer:keys[0],time:tx.blockTime??null,payerDelta:meta?meta.postBalances[0]-meta.preBalances[0]:null,
      instructions:message.instructions.map(ix=>({program:keys[ix.programIdIndex],accounts:ix.accounts.map(i=>keys[i]),data:Buffer.from(fromBase58(ix.data))}))};
  }
  rent(size) { return this.call('getMinimumBalanceForRentExemption', [size]); }
  /** The successful transactions among the newest `limit` signatures that touched `address`, newest
   *  first. A failed signature, or one the node returns no transaction for, is left out of the list, so
   *  its length says nothing of the history's: the array says how far back it is whole, from the
   *  signatures themselves. `complete`: every transaction the address ever had is in it (fewer
   *  signatures than asked for, each read). `after`: every successful transaction later than this unix
   *  time is in it, null when unknown. An unread transaction might be any: the list is whole only after it. */
  async recentTransactions(address, limit = RECENT_SIGNATURES) {
    const signatures = await this.call('getSignaturesForAddress', [address.toBase58(), { limit, commitment: this.commitment }]);
    const read = await Promise.all(signatures.map(s => s.err ? null : this.transaction(s.signature)));
    const gap = signatures.findIndex((s, i) => !s.err && !read[i]), edge = gap >= 0 ? signatures[gap] : signatures.length >= limit ? signatures.at(-1) : null;
    return Object.assign(read.filter(Boolean), { complete: !edge, after: edge?.blockTime ?? null });
  }
  // The chain's clock at the latest slot, or null when the node has no block time for it.
  async blockTime() { const slot = await this.call('getSlot', [{ commitment: this.commitment }]); return this.call('getBlockTime', [slot]).catch(() => null); }
  async now() { return (await this.blockTime()) ?? Date.now() / 1000; }
  /** The chain's clock only, never the host's: null when the node cannot tell it (review round 3). */
  async chainNow() { try { return await this.blockTime(); } catch { return null; } }
  genesis() { return this.call('getGenesisHash', []); }
  /** `config` travels in the v1 transaction (v1.mjs): a veto passes `priorityFeeLamports`. */
  async send(ixs, payer, signers = [], config = {}) {
    // A new build (fresh blockhash, new signature) is made only when the last one can no longer
    // land: its blockhash expired with no status anywhere, or the node refused it unseen before
    // any copy left. So one action never becomes two transactions.
    for (let build = 1; ; build++) {
      const { signature, rebuild } = await this.sendOnce(ixs, payer, signers, config);
      if (!rebuild) return signature;
      if (build >= this.builds) throw Object.assign(Error(`transaction ${signature} did not land within ${build} blockhashes`), { signature });
      if (rebuild === 'unseen') await this.sleep(2000);
    }
  }
  /** The blockhash a transaction built now lives on. */
  async latest() { return (await this.call('getLatestBlockhash', [{ commitment: this.commitment }])).value; }
  /** Whether a transaction built on `latest` can still land: its blockhash has not expired. */
  async blockhashValid(latest) { return await this.call('getBlockHeight', [{ commitment: this.commitment }]) <= Number(latest.lastValidBlockHeight); }
  /** Sends a transaction built and signed elsewhere (self-pay mode: the agent's key is its fee payer).
   *  It cannot be rebuilt: past its blockhash it fails, and the agent signs a fresh one. */
  async sendBuilt({ raw, signature, latest }) {
    const r = await this.sendWire(raw, signature, latest);
    if (r.rebuild) throw Object.assign(Error(`transaction ${signature} did not land before its blockhash expired: sign a fresh one`), { signature, expired: true });
    return r.signature;
  }
  async sendOnce(ixs, payer, signers, config = {}) {
    const latest0 = (await this.call('getLatestBlockhash', [{ commitment: this.commitment }])).value;
    const built = { ...await buildV1(ixs, payer, signers, latest0, config), latest: latest0 };
    return this.sendWire(built.raw, built.signature, built.latest);
  }
  async sendWire(raw, signature, latest) {
    const wire = raw.toString('base64');
    const status = async () => {
      const s = (await this.call('getSignatureStatuses', [[signature], { searchTransactionHistory: true }])).value[0];
      if (s?.err) { const logs = await this.failureLogs(signature); throw Object.assign(Error(`${signature} failed: ${JSON.stringify(s.err)}${logs ? '\n' + logs.join('\n') : ''}`), { signature, err: s.err, logs, ...(logs && { refused: true }) }); }
      return s;
    };
    const expired = async () => await this.call('getBlockHeight', [{ commitment: this.commitment }]) > latest.lastValidBlockHeight;
    // Every copy is byte-identical and simulated first. `out` turns true once a copy may have
    // reached a leader; from then on a refusal is final only if the cluster has no status for it.
    let out = false;
    for (let tick = 0; tick < this.polls; tick++) {
      if (tick % this.resend === 0) {
        try { await this.call1('sendTransaction', [wire, { encoding: 'base64', preflightCommitment: this.commitment, maxRetries: 3 }]); out = true; }
        catch (e) {
          if (/already been processed/i.test(e.message)) out = true;
          else if (/blockhash not found/i.test(e.message)) { if (!out) return { signature, rebuild: 'unseen' }; }
          else if (refused(e)) {
            // `unsent`: preflight refused the first copy, so nothing reached a leader and no fee was paid.
            if (!out || !await status()) { const logs = e.rpc?.data?.logs; throw Object.assign(Error(`${e.message}${logs ? '\n' + logs.join('\n') : ''}`), { logs, refused: true, signature, unsent: !out }); }
          }
          // Any other fault might have followed acceptance: never rebuild early after it.
          else if (!out && !transient(e)) throw e;
          else out = true;
        }
      }
      const s = await status();
      if (s?.confirmationStatus === 'confirmed' || s?.confirmationStatus === 'finalized') return { signature };
      if (!s && (tick + 1) % this.resend === 0 && await expired() && !await status()) return { signature, rebuild: 'expired' };
      await this.sleep(this.poll);
    }
    throw Object.assign(Error(`unconfirmed transaction ${signature}`), { signature });
  }
  // A copy that landed and failed was refused by the program at execution, as final as a preflight
  // refusal. It is marked refused only with its logs, so a payer shortfall stays told apart.
  async failureLogs(signature) {
    for (let i = 0; i < 3; i++) {
      const tx = await this.call1('getTransaction', [signature, { encoding: 'json', commitment: this.commitment, maxSupportedTransactionVersion: 1 }]).catch(() => null);
      if (Array.isArray(tx?.meta?.logMessages)) return tx.meta.logMessages;
      if (i < 2) await this.sleep(this.poll);
    }
  }
  /** A recent blockhash, for a transaction someone else signs (a Solana Pay transaction request). */
  async blockhash() { return (await this.call('getLatestBlockhash', [{ commitment: this.commitment }])).value.blockhash; }
  /** Successful transactions that touched `address` at or after unix time `since`, newest first, at
   *  most `limit`, each as `balanceRecord` reads it (donations, hosted-funds.mjs). The array is marked
   *  `truncated` when a transaction since `since` may be left unread (the limit or the page ran out),
   *  with `completeAfter` when known: every unread one is at or before that time, so the read is
   *  complete for any window starting after it. Transactions signed by a key in `skip` (the owner's
   *  own, never a donation) or that ran a program in `skipPrograms` (the council program's holder
   *  payouts, deposit returns and refunds, never a donation either) are left out and do not count
   *  toward `limit`, so a burst of them does not hide an older transfer; the read pages back through
   *  at most `signatures` signatures (`limit` × 4 by default), each one a getTransaction call, the
   *  skipped ones too. */
  async balanceHistory(address, { since = 0, limit = 25, skip = [], skipPrograms = [], signatures = Math.max(1, limit) * 4 } = {}) {
    const budget = Math.max(1, signatures), mine = new Set(skip.map(String)), ran = new Set(skipPrograms.map(String)), out = [];
    const cut = at => Object.assign(out, { truncated: true }, at != null ? { completeAfter: at } : {});
    let read = 0, before;
    for (;;) {
      const ask = Math.min(1000, budget - read);
      const sigs = await this.call('getSignaturesForAddress', [address.toBase58(), { limit: ask, ...(before ? { before } : {}), commitment: this.commitment }]);
      read += sigs.length;
      for (const s of sigs) {
        if (s.blockTime != null && s.blockTime < since) return out;
        if (s.err) continue;
        if (out.length >= limit) return cut(s.blockTime);
        const tx = await this.call('getTransaction', [s.signature, { encoding: 'json', commitment: this.commitment, maxSupportedTransactionVersion: 1 }]);
        if (tx && !tx.meta?.err) { const r = balanceRecord(s.signature, tx); if (!r.signers.some(k => mine.has(k)) && !r.programs.some(p => ran.has(p))) out.push(r); }
      }
      // The history ran out, or the budget did: every unread one is older than the last read.
      if (sigs.length < ask) return out;
      if (read >= budget) return cut(sigs.at(-1).blockTime);
      before = sigs.at(-1).signature;
    }
  }
  /** Signatures that touched `address`, newest first, one page of up to 1,000 at a time (`before`). */
  async *signaturePages(address) {
    const seen = new Set(); let before;
    for (;;) {
      const page = await this.call('getSignaturesForAddress', [address.toBase58(), { limit: 1000, before, commitment: this.commitment }]);
      const fresh = page.filter(s => !seen.has(s.signature)); for (const s of fresh) seen.add(s.signature);
      yield fresh;
      if (page.length < 1000 || !fresh.length) return;
      before = page.at(-1).signature;
    }
  }
  /** One successful transaction as program instructions, or null. Instructions another program made
   *  by CPI follow the top-level ones, marked `inner`. */
  async programTransaction(signature) {
    const tx = await this.call('getTransaction', [signature, { encoding: 'json', commitment: this.commitment, maxSupportedTransactionVersion: 1 }]);
    if (!tx || tx.meta?.err) return null;
    const m = tx.transaction.message, loaded = tx.meta?.loadedAddresses;
    const keys = [...m.accountKeys.map(k => typeof k === 'string' ? k : k.pubkey), ...(loaded?.writable ?? []), ...(loaded?.readonly ?? [])];
    const instructions = [];
    for (const ix of [...m.instructions, ...(tx.meta?.innerInstructions ?? []).flatMap(g => (g?.instructions ?? []).map(i => ({ ...i, inner: true })))]) {
      try { instructions.push({ programId: new PublicKey(keys[ix.programIdIndex]), accounts: ix.accounts.map(i => keys[i]), data: Buffer.from(fromBase58(ix.data)), ...(ix.inner ? { inner: true } : {}) }); }
      catch { /* an instruction this reader cannot resolve (e.g. a lookup-table key) */ }
    }
    return { signature, slot: tx.slot, instructions };
  }
  /** Successful transactions that touched `address`, oldest first, as program instructions. */
  async transactionsFor(address) {
    const sigs = [];
    for await (const page of this.signaturePages(address)) sigs.push(...page);
    const out = [];
    for (const s of sigs.reverse()) { if (s.err) continue; const tx = await this.programTransaction(s.signature); if (tx) out.push(tx); }
    return out;
  }
}

/** In-process chain for tests: the same client code against LiteSVM, with a controllable clock. */
export class SvmTransport {
  constructor(svm) { this.svm = svm; this.history = []; }
  async getAccount(k) {
    const a = this.svm.getAccount(k.toBase58());
    return a.exists ? { data: Buffer.from(a.data), owner: new PublicKey(a.programAddress), lamports: Number(a.lamports), executable: a.executable } : null;
  }
  getAccounts(keys) { return Promise.all(keys.map(k => this.getAccount(k))); }
  async programAccounts(program, tag) {
    return (await this.allProgramAccounts(program)).filter(a => a.data[0] === tag);
  }
  async allProgramAccounts(program) {
    return this.svm.getProgramAccounts(program.toBase58()).map(a => ({ pubkey: new PublicKey(a.address), data: Buffer.from(a.data), lamports: Number(a.lamports) }));
  }
  async transaction(signature) {
    const tx=[...this.history,...(this.failedHistory??[])].find(t=>t.signature===signature);
    return tx?{signature,error:tx.error??null,payer:tx.payer,time:tx.time,payerDelta:tx.payerDelta,instructions:tx.instructions.map(ix=>({program:ix.programId.toBase58(),accounts:ix.accounts,data:ix.data}))}:null;
  }
  rent(size) { return Number(this.svm.minimumBalanceForRentExemption(BigInt(size))); }
  /** As RpcTransport answers it, over the successful transactions this simulator keeps in order. */
  async recentTransactions(address, limit = RECENT_SIGNATURES) {
    const all = await this.transactionsFor(address), newest = all.slice(-limit).reverse();
    return Object.assign(await Promise.all(newest.map(tx => this.transaction(tx.signature))), { complete: all.length < limit, after: all.length < limit ? null : newest.at(-1)?.time ?? null });
  }
  async now() { return Number(this.svm.getClock().unixTimestamp); }
  genesis() { return 'LiteSVM11111111111111111111111111111111111'; }
  warp(seconds) {
    const c = this.svm.getClock(); c.unixTimestamp += BigInt(seconds); c.slot += BigInt(Math.max(1, Math.round(seconds * 2.5))); this.svm.setClock(c); this.svm.expireBlockhash();
  }
  send(ixs, payer, signers = []) {
    // Building signs asynchronously. Serialize simulator submissions so another writer cannot
    // expire the blockhash between building and executing a transaction.
    const next = (this.pendingSend ?? Promise.resolve()).then(() => this.sendSerial(ixs, payer, signers));
    this.pendingSend = next.catch(() => {});
    return next;
  }
  async latest() { return { blockhash: this.svm.latestBlockhash(), lastValidBlockHeight: 1000000n }; }
  /** A transaction built and signed elsewhere (self-pay mode). The simulator expires its blockhash
   *  after every transaction, so a batch signed at once (a Begin and its chunk writes) is checked
   *  against it here, where a cluster would still accept it. */
  sendBuilt({ transaction, signature, ixs, feePayer }) {
    const payer = { publicKey: new PublicKey(feePayer) };
    const next = (this.pendingSend ?? Promise.resolve()).then(() => this.sendSerial(ixs, payer, [], { transaction, signature }));
    this.pendingSend = next.catch(() => {});
    return next;
  }
  async sendSerial(ixs, payer, signers = [], built = null) {
    const { transaction, signature } = built ?? await buildV1(ixs, payer, signers, { blockhash: this.svm.latestBlockhash(), lastValidBlockHeight: 1000000n });
    const paying = payer.publicKey.toBase58(), before = this.svm.getBalance(paying) ?? 0n;
    // With `recordBalances`, every account's lamports and token balance before and after (balanceHistory).
    const touched = this.recordBalances ? [...new Set([paying, ...ixs.flatMap(ix => [ix.programId.toBase58(), ...ix.keys.map(k => k.pubkey.toBase58())])])] : null;
    const pre = touched && touched.map(k => this.balanceOf(k));
    if (built) this.svm.withBlockhashCheck(false);
    let r;
    try { r = this.svm.sendTransaction(transaction); } finally { if (built) this.svm.withBlockhashCheck(true); }
    if (typeof r.err === 'function') {
      // Fees burned so far (tests reconcile every lamport): what a refused transaction still cost.
      this.fees = (this.fees ?? 0) + Number(before - (this.svm.getBalance(paying) ?? 0n));
      const logs = r.meta().logs();
      (this.failedHistory??=[]).push({signature,error:String(r.err()),payer:paying,time:Number(this.svm.getClock().unixTimestamp),
        slot:Number(this.svm.getClock().slot),payerDelta:Number((this.svm.getBalance(paying)??0n)-before),
        instructions:ixs.map(ix=>({programId:ix.programId,accounts:ix.keys.map(k=>k.pubkey.toBase58()),data:Buffer.from(ix.data)}))});
      this.svm.expireBlockhash();
      throw Object.assign(Error(`transaction failed: ${r.toString?.() ?? r.err()}\n${logs.slice(-12).join('\n')}`), { logs, refused: true, signature });
    }
    // 5,000 lamports a signature: the transaction's own and each one an Ed25519 instruction verifies.
    const sigs = new Set([payer, ...signers].map(k => k.publicKey.toBase58())).size
      + ixs.filter(ix => ix.programId.toBase58() === 'Ed25519SigVerify111111111111111111111111111').reduce((n, ix) => n + ix.data[0], 0);
    this.fees = (this.fees ?? 0) + 5000 * sigs;
    this.last = { cu: Number(r.computeUnitsConsumed()), logs: r.logs() };
    const balances = touched && this.balanceChanges(touched, pre, [...new Set([paying, ...signers.map(k => k.publicKey.toBase58())])], ixs);
    this.history.push({ signature, slot: Number(this.svm.getClock().slot), payer: payer.publicKey.toBase58(), time: Number(this.svm.getClock().unixTimestamp),
      payerDelta: Number((this.svm.getBalance(payer.publicKey.toBase58()) ?? 0n) - before), instructions: ixs.map(ix => ({ programId: ix.programId, accounts: ix.keys.map(k => k.pubkey.toBase58()), data: Buffer.from(ix.data) })),
      ...(balances ? { balances } : {}) });
    this.svm.expireBlockhash();
    return signature;
  }
  async transactionsFor(address) {
    const a = address.toBase58();
    return this.history.filter(t => !t.error && t.instructions.some(ix => ix.accounts.includes(a)));
  }
  async blockhash() { return this.svm.latestBlockhash(); }
  /** An account's lamports and, for a token account, its (owner, mint, amount). */
  balanceOf(k) {
    const a = this.svm.getAccount(k);
    if (!a.exists) return { lamports: 0, token: null };
    const d = Buffer.from(a.data), token = ['TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA', 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb'].includes(a.programAddress) && d.length >= 165
      ? { mint: new PublicKey(d.subarray(0, 32)).toBase58(), owner: new PublicKey(d.subarray(32, 64)).toBase58(), amount: d.readBigUInt64LE(64) } : null;
    return { lamports: Number(a.lamports), token };
  }
  balanceChanges(keys, pre, signers, ixs) {
    const post = keys.map(k => this.balanceOf(k)), sol = {}, tok = new Map();
    keys.forEach((k, i) => {
      const d = post[i].lamports - pre[i].lamports; if (d) sol[k] = d;
      for (const [b, sign] of [[pre[i].token, -1n], [post[i].token, 1n]]) if (b) { const x = `${b.owner}:${b.mint}`; tok.set(x, (tok.get(x) ?? 0n) + sign * b.amount); }
    });
    return { signers, programs: [...new Set(ixs.map(ix => ix.programId.toBase58()))], sol,
      tokens: [...tok].filter(([, d]) => d !== 0n).map(([x, d]) => { const [owner, mint] = x.split(':'); return { owner, mint, delta: String(d) }; }) };
  }
  /** balanceHistory as RpcTransport answers it, from transactions sent with `recordBalances` on. */
  async balanceHistory(address, { since = 0, limit = 25, skip = [], skipPrograms = [] } = {}) {
    const a = address.toBase58(), mine = new Set(skip.map(String)), ran = new Set(skipPrograms.map(String));
    const all = this.history.filter(t => t.balances && t.time >= since && (t.payer === a || t.instructions.some(ix => ix.accounts.includes(a)))
      && !t.balances.signers.some(k => mine.has(k)) && !t.balances.programs.some(p => ran.has(p)));
    const out = all.reverse().slice(0, limit).map(t => ({ signature: t.signature, time: t.time, ...t.balances }));
    return all.length > limit ? Object.assign(out, { truncated: true, completeAfter: all[limit].time }) : out;
  }
}
