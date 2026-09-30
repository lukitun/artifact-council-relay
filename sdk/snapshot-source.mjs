// The canonical holder dataset of one distribution (snapshot-spec §5.1): the state of every token
// account of the mint at the END of the snapshot slot S* that `Fix` drew. Every honest seat builds the
// same bytes from any honest RPC, so the same dataset, root and result hash; commit-reveal
// (independent recomputation) and the holder check cover what one RPC could hide.
//
// 1. Wait until the finalized slot is past S*, then read every token account of the mint in one
//    finalized bank S_i (getProgramAccounts withContext).
// 2. Roll back to S*: for each account of the mint touched in (S*, S_i], its (exists, owner, amount)
//    before the first transaction that touched it. Transfers, SetAuthority and close-and-recreate
//    all come back; accounts closed in the window reappear.
// 3. Supply at S* is the mint's supply less the window's net change. The balances must sum to it,
//    or the seat neither commits nor vetoes.
// 4. The committed source (version 3) is { program, mint, epoch, slot: S*, supply, accounts:
//    [[address, owner, amount]] by address, amount > 0 }: nothing specific to the capture. The
//    capture's own evidence (its bank slots, the signatures of the window's transactions that moved
//    the mint) is kept apart, never committed.
import { PublicKey } from '@solana/web3.js';
import { makeSnapshot } from './snapshots.mjs';
import { exclusions } from './exclusions.mjs';
import { sha256, fromBase58, RESERVED_KEYS } from './layout.mjs';
// The runtime's reserved keys can never receive a payment (treasury.rs `RESERVED`, 29 September review).
const excluded = new Set([...exclusions(), ...RESERVED_KEYS]);
const order = (a, b) => Buffer.compare(Buffer.from(fromBase58(a)), Buffer.from(fromBase58(b)));

/** The round's parameters, as the program checks them, all frozen at the close: the pot, holder
 *  minimum and MIN_PAYOUT (the epoch record; a patch applied mid-round changes no seat's leaf set,
 *  29 September), the snapshot slot, fee and fee reserve (the book). */
export const roundOf = (e, book) => ({ epoch: e.n, closeSlot: e.closeSlot, slot: book.snapSlot, pot: e.pot, reserve: book.reserve, fee: book.fee,
  minHolder: e.minHolder, minPayout: e.minPayout });

/** The canonical source: accounts with a balance, by address; supply and amounts as decimal strings. */
export function canonicalSource({ program, mint, epoch, slot, supply, accounts }) {
  const list = accounts.filter(a => BigInt(a.amount) > 0n).map(a => [new PublicKey(a.address).toBase58(), new PublicKey(a.owner).toBase58(), BigInt(a.amount).toString()])
    .sort((a, b) => order(a[0], b[0]));
  for (let i = 1; i < list.length; i++) if (list[i - 1][0] === list[i][0]) throw Error('duplicate token account');
  return { version: 3, program: new PublicKey(program).toBase58(), mint: new PublicKey(mint).toBase58(), epoch, slot, supply: BigInt(supply).toString(), accounts: list };
}
export const sourceBytes = source => Buffer.from(JSON.stringify(source) + '\n');
/** The supply invariant: the balances at S* sum to the supply at S*. It catches omissions, not
 *  reassignments. */
export function checkSupply(source) {
  const sum = source.accounts.reduce((s, a) => s + BigInt(a[2]), 0n);
  if (sum !== BigInt(source.supply)) throw Error(`supply invariant failed: balances ${sum}, supply ${source.supply}`);
}

/**
 * Rolls a bank's view back to the end of slot `slot` (S*). `current` is every token account of `mint`
 * in bank `current.slot` ([{ address, owner, amount }]); `supply` the mint's supply in bank
 * `supply.slot`; `blocks` every block after S* up to the later of the two, each with its
 * transactions in order as { signature, keys, pre, post } (token balances: { index, mint, owner,
 * amount }). Returns the accounts and supply at S*.
 */
export function rollback({ mint, slot, current, supply, blocks }) {
  mint = new PublicKey(mint).toBase58();
  const state = new Map(current.accounts.map(a => [new PublicKey(a.address).toBase58(), { owner: new PublicKey(a.owner).toBase58(), amount: BigInt(a.amount) }]));
  const before = new Map(); let net = 0n;
  for (const block of [...blocks].sort((a, b) => a.slot - b.slot)) {
    if (block.slot <= slot) continue;
    for (const tx of block.transactions) {
      const pre = tx.pre.filter(b => b.mint === mint), post = tx.post.filter(b => b.mint === mint);
      if (block.slot <= supply.slot) net += post.reduce((s, b) => s + BigInt(b.amount), 0n) - pre.reduce((s, b) => s + BigInt(b.amount), 0n);
      if (block.slot > current.slot) continue;
      for (const b of [...pre, ...post]) {
        const address = tx.keys[b.index];
        if (before.has(address)) continue;
        const was = pre.find(p => p.index === b.index);
        before.set(address, was ? { owner: was.owner, amount: BigInt(was.amount) } : null);
      }
    }
  }
  for (const [address, was] of before) { if (was) state.set(address, was); else state.delete(address); }
  return { accounts: [...state].map(([address, a]) => ({ address, ...a })), supply: BigInt(supply.amount) - net };
}

/** Owner totals of a source: ordinary on-curve owners, exclusions and reserved keys left out. */
export function balancesOf(source) {
  const totals = new Map();
  for (const [, owner, amount] of source.accounts) {
    if (!PublicKey.isOnCurve(new PublicKey(owner).toBuffer()) || excluded.has(owner)) continue;
    totals.set(owner, (totals.get(owner) ?? 0n) + BigInt(amount));
  }
  return [...totals].map(([owner, weight]) => ({ owner, weight }));
}
/** The dataset of `round` built from a canonical source: the source must be this round's and pass the
 *  supply invariant. */
export function snapshotFromSource(c, source, { mint, epoch, slot, pot, reserve, fee, minPayout, minHolder }) {
  if (source.version !== 3 || source.program !== c.program.toBase58() || source.mint !== new PublicKey(mint).toBase58() || source.epoch !== epoch || source.slot !== slot)
    throw Error('snapshot source program, mint, epoch or slot mismatch');
  const again = canonicalSource({ ...source, accounts: source.accounts.map(([address, owner, amount]) => ({ address, owner, amount })) });
  if (!sourceBytes(again).equals(sourceBytes(source))) throw Error('snapshot source is not canonical');
  checkSupply(source);
  return makeSnapshot(c, { mint, epoch, slot, pot, reserve, fee, minPayout, minHolder, sourceHash: sha256(sourceBytes(source)).toString('hex'), balances: balancesOf(source) });
}

/** A token account of `mint` in raw data, or null: initialized or frozen, the base layout or an
 *  extended one (account type byte 2). */
export function tokenAccount(address, data, mint) {
  const d = Buffer.from(data);
  if (d.length < 165 || (d.length > 165 && d[165] !== 2) || ![1, 2].includes(d[108])) return null;
  if (new PublicKey(d.subarray(0, 32)).toBase58() !== mint) return null;
  return { address, owner: new PublicKey(d.subarray(32, 64)).toBase58(), amount: d.readBigUInt64LE(64) };
}
/** The most slots a capture walks back from its bank to S* (review round 7): about an hour, far past
 *  the round's commit, reveal and checking windows. A seat whose capture failed retries every
 *  RETRY_SECS for as long as the round is in flight, days while a pause holds Pay: each retry would
 *  otherwise walk a longer window. Past this it fails before any scan or block is read; another
 *  seat's dataset still pays the round. */
export const MAX_WINDOW_SLOTS = 9_000;
/** One block's transactions that touch `mint`, as rollback wants them (only their `mint` balances),
 *  and its parent slot: nothing else of a block is kept, so a long window holds little (review
 *  round 7). Every block fetched is one the chain produced, so any RPC error is an error: -32007 and
 *  -32009 also answer for a real block a node lost to a snapshot jump or never stored (29 September
 *  review). */
async function blockAt(call, slot, mint) {
  const b = await call('getBlock', [slot, { encoding: 'json', transactionDetails: 'full', rewards: false, maxSupportedTransactionVersion: 1, commitment: 'finalized' }]);
  if (!b || !Number.isSafeInteger(b.parentSlot) || b.parentSlot >= slot) throw Error(`RPC returned no block for slot ${slot}`);
  const balances = list => (list ?? []).filter(b => b.mint === mint).map(b => ({ index: b.accountIndex, mint: b.mint, owner: b.owner, amount: b.uiTokenAmount.amount }));
  const transactions = [];
  for (const { transaction: t, meta: m } of b.transactions ?? []) {
    const pre = balances(m?.preTokenBalances), post = balances(m?.postTokenBalances);
    if (!pre.length && !post.length) continue;
    const keys = [...t.message.accountKeys.map(k => typeof k === 'string' ? k : k.pubkey), ...(m?.loadedAddresses?.writable ?? []), ...(m?.loadedAddresses?.readonly ?? [])];
    transactions.push({ signature: t.signatures[0], keys: [...new Set([...pre, ...post].map(x => x.index))].reduce((k, i) => (k[i] = keys[i], k), []), pre, post });
  }
  return { slot, parent: b.parentSlot, transactions };
}
/**
 * Captures the canonical source of the distribution in flight over JSON-RPC (a paid RPC: a
 * token-program scan and about 150 blocks an epoch). Returns null until the finalized slot is past
 * S*; otherwise { source, evidence }, the source checked against the supply invariant. Refused once
 * the finalized slot is more than `maxSlots` past S*. The evidence's signatures are the window's
 * transactions that moved the mint.
 */
export async function captureSource(c, { epoch, slot }, { maxSlots = MAX_WINDOW_SLOTS } = {}) {
  const call = (m, p) => c.t.call(m, p), cfg = await c.config();
  const finalized = await call('getSlot', [{ commitment: 'finalized' }]);
  if (finalized <= slot) return null;
  if (finalized - slot > maxSlots) throw Error(`the window since the snapshot slot is ${finalized - slot} slots, over the ${maxSlots} a capture walks: this seat has no dataset for the round`);
  // Both reads come from a bank past S*: rollback only rolls back, so a lagging node's older bank
  // would pass as S* (a load-balanced RPC answers from any node).
  const scan = await call('getProgramAccounts', [cfg.tokenProgram, { commitment: 'finalized', encoding: 'base64', withContext: true, minContextSlot: slot + 1,
    filters: [{ memcmp: { offset: 0, bytes: cfg.mint } }] }]);
  if (!scan.context || !Array.isArray(scan.value)) throw Error('RPC did not provide a single bank context');
  if (!(scan.context.slot > slot)) throw Error(`RPC scanned a bank at or before the snapshot slot (${scan.context.slot} <= ${slot})`);
  const mintInfo = await call('getAccountInfo', [cfg.mint, { commitment: 'finalized', encoding: 'base64', minContextSlot: slot + 1 }]);
  if (!(mintInfo.context?.slot > slot)) throw Error(`RPC read the mint at or before the snapshot slot (${mintInfo.context?.slot} <= ${slot})`);
  const current = { slot: scan.context.slot, accounts: scan.value.map(a => tokenAccount(a.pubkey, Buffer.from(a.account.data[0], 'base64'), cfg.mint)).filter(Boolean) };
  const supply = { slot: mintInfo.context.slot, amount: Buffer.from(mintInfo.value.data[0], 'base64').readBigUInt64LE(36) };
  // The window's blocks are the chain behind the later bank, parent by parent back past S*: a bank
  // exists only at a produced slot, and every slot the chain skipped between two of its blocks is
  // proven empty by the parent link, not by an RPC error.
  const blocks = [];
  const from = Math.max(current.slot, supply.slot);
  if (from - slot > maxSlots) throw Error(`the window since the snapshot slot is ${from - slot} slots, over the ${maxSlots} a capture walks: this seat has no dataset for the round`);
  for (let s = from; s > slot;) { const b = await blockAt(call, s, cfg.mint); blocks.unshift(b); s = b.parent; }
  if (!blocks.some(b => b.slot === Math.min(current.slot, supply.slot))) throw Error('the scan and the mint read come from different forks');
  const at = rollback({ mint: cfg.mint, slot, current, supply, blocks });
  const source = canonicalSource({ program: c.program, mint: cfg.mint, epoch, slot, supply: at.supply, accounts: at.accounts });
  checkSupply(source);
  return { source, evidence: { captureSlot: current.slot, supplySlot: supply.slot, signatures: blocks.flatMap(b => b.transactions.map(t => t.signature)) } };
}
