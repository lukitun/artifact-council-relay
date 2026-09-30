// Donations to agents and the funds a hosted key holds (owner, 30 September).
//
// Anyone can donate SOL or AC to an agent: the donation address is the agent's CURRENT signing key
// (its own key, or for a hosted agent the key the gateway holds). No program change: these are
// ordinary System and token transfers. A hosted key's funds are in the gateway's custody, so a
// hosted agent can send them to an address it names (planSend) and, when it moves to its own key,
// the gateway sweeps the old key's whole SOL and AC balance to the new key (planSweep).
//
// What an AC transfer needs: the recipient's associated token account (created idempotently by
// whoever pays, when missing) and TransferChecked with the mint's decimals. A SOL transfer must
// leave both ends either empty or rent-exempt, which the runtime enforces; the plans check it first
// so a refused transaction never costs a fee.
import { PublicKey, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import { readFileSync, writeFileSync, renameSync, readdirSync, mkdirSync, appendFileSync, unlinkSync } from 'node:fs';
import { randomBytes } from 'node:crypto';

export const ATA_PROGRAM = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
export const TOKEN = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const TOKEN_2022 = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
/** One signature's base fee. A send, a donation and a hosted-paid sweep have one signer; a
 *  gateway-paid sweep has two (the gateway and the hosted key). */
export const TX_FEE = 5000;
/** An associated token account's size: Token-2022's carries the ImmutableOwner extension. */
export const ataSize = tokenProgram => new PublicKey(tokenProgram).equals(TOKEN_2022) ? 170 : 165;
/** What an agent's current key signs to have a gateway run its sweep again (POST /v2/hosted/sweep). */
export const sweepMessage = (program, agent, time) => Buffer.from(`ACv2 sweep ${program} ${agent} ${time}`);

/** The custody warning, word for word wherever donations to a hosted agent appear (owner, 30 September;
 *  "Artifact Council holds hosted identities' keys", not "the gateway", since the owner's instruction of
 *  the same day). */
export const HOSTED_CUSTODY_WARNING = "We strongly recommend against receiving donations on a hosted key. Artifact Council holds hosted identities' keys to make things easier for agents; that means Artifact Council controls the key and any funds sent to it. Move to your own key (move-key) first, and your balance moves with you.";

/**
 * The custody warning for a hosted agent whose key the gateway `gateway` (base58) holds. The owner's
 * words exactly when that gateway is Artifact Council's (`ours` is this relay's gateway key and
 * `operator` 'Artifact Council'); otherwise the same warning naming who really holds the key: this
 * gateway's operator, or for an agent another gateway hosts, that gateway's operator.
 */
export function custodyWarning({ gateway, ours = null, operator = null }) {
  if (ours && gateway === ours && operator === 'Artifact Council') return HOSTED_CUSTODY_WARNING;
  const head = 'We strongly recommend against receiving donations on a hosted key. A gateway holds hosted keys to make things easier for agents; that means ';
  if (ours && gateway === ours) return `${head}${operator ? `${operator}, the operator of this gateway,` : 'the operator of this gateway'} controls the key and any funds sent to it. Move to your own key (move-key) first, and your balance moves with you.`;
  return `${head}the operator of gateway ${gateway} controls the key and any funds sent to it. Move to your own key (move-key) with that gateway first; how your balance moves is up to its operator.`;
}

const pk = k => k instanceof PublicKey ? k : new PublicKey(k);
const fail = (message, status = 409, detail) => Object.assign(Error(message), { status, ...(detail ? { detail } : {}) });
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; };

/** The associated token account of `owner` (any address, on the curve or not) for `mint`. */
export function ataOf(owner, mint, tokenProgram) {
  return PublicKey.findProgramAddressSync([pk(owner).toBuffer(), pk(tokenProgram).toBuffer(), pk(mint).toBuffer()], ATA_PROGRAM)[0];
}
export function createAtaIdempotent(payer, owner, mint, tokenProgram) {
  return new TransactionInstruction({ programId: ATA_PROGRAM, data: Buffer.from([1]), keys: [
    { pubkey: pk(payer), isSigner: true, isWritable: true }, { pubkey: ataOf(owner, mint, tokenProgram), isSigner: false, isWritable: true },
    { pubkey: pk(owner), isSigner: false, isWritable: false }, { pubkey: pk(mint), isSigner: false, isWritable: false },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, { pubkey: pk(tokenProgram), isSigner: false, isWritable: false }] });
}
export function transferChecked(from, mint, to, authority, amount, decimals, tokenProgram) {
  return new TransactionInstruction({ programId: pk(tokenProgram), data: Buffer.concat([Buffer.from([12]), u64(amount), Buffer.from([decimals])]), keys: [
    { pubkey: pk(from), isSigner: false, isWritable: true }, { pubkey: pk(mint), isSigner: false, isWritable: false },
    { pubkey: pk(to), isSigner: false, isWritable: true }, { pubkey: pk(authority), isSigner: true, isWritable: false }] });
}
export function closeAccount(account, destination, authority, tokenProgram) {
  return new TransactionInstruction({ programId: pk(tokenProgram), data: Buffer.from([9]), keys: [
    { pubkey: pk(account), isSigner: false, isWritable: true }, { pubkey: pk(destination), isSigner: false, isWritable: true },
    { pubkey: pk(authority), isSigner: true, isWritable: false }] });
}
const isTokenProgram = owner => owner && (pk(owner).equals(TOKEN) || pk(owner).equals(TOKEN_2022));
/** The AC settings of a decoded config, or null while the mint is not set. */
export function tokenOf(cfg) {
  if (!cfg?.mint || pk(cfg.mint).equals(PublicKey.default) || !cfg.tokenProgram || pk(cfg.tokenProgram).equals(PublicKey.default)) return null;
  return { mint: pk(cfg.mint), tokenProgram: pk(cfg.tokenProgram), decimals: cfg.decimals };
}
/** Base units of `text` ("1.5") at `decimals`, or throws 400. */
export function toBaseUnits(text, decimals) {
  const s = String(text ?? '').trim(), m = /^(\d{1,20})(?:\.(\d+))?$/.exec(s);
  if (!m || (m[2] ?? '').length > decimals) throw fail(`amount must be a positive decimal number with at most ${decimals} decimals`, 400);
  const v = BigInt(m[1]) * 10n ** BigInt(decimals) + BigInt((m[2] ?? '').padEnd(decimals, '0') || '0');
  if (v <= 0n || v >= 2n ** 64n) throw fail('amount must be positive and fit in 64 bits', 400);
  return v;
}
export const fromBaseUnits = (v, decimals) => { const s = BigInt(v).toString().padStart(decimals + 1, '0'); const i = s.slice(0, s.length - decimals), f = s.slice(s.length - decimals).replace(/0+$/, ''); return f ? `${i}.${f}` : i; };

/** What `owner` holds: SOL (lamports) and, with a token, AC in its associated account. */
export async function holdings(t, owner, token) {
  const o = pk(owner), acct = await t.getAccount(o);
  const out = { address: o.toBase58(), sol: acct?.lamports ?? 0, ac: 0n, ata: null, ataExists: false, ataLamports: 0 };
  if (token) {
    const ata = ataOf(o, token.mint, token.tokenProgram), a = await t.getAccount(ata);
    out.ata = ata.toBase58();
    if (a && isTokenProgram(a.owner) && a.data.length >= 72) { out.ataExists = true; out.ac = a.data.readBigUInt64LE(64); out.ataLamports = a.lamports; }
  }
  return out;
}

/**
 * What creating the associated token account `ata` costs its payer now: nothing when a token
 * account is there; otherwise the rent shortfall, since lamports someone sent to the address count
 * toward it (the ATA program tops the account up to its rent-exempt minimum). An address any other
 * program holds cannot become a token account: refused.
 */
export async function ataCost(t, ata, tokenProgram) {
  const a = await t.getAccount(ata);
  if (a && isTokenProgram(a.owner) && a.data.length >= 165) return { exists: true, create: 0 };
  if (a && (!pk(a.owner).equals(SystemProgram.programId) || a.data.length)) throw fail('the recipient\'s token account address is held by another program', 409);
  return { exists: false, create: Math.max(0, (await t.rent(ataSize(tokenProgram))) - (a?.lamports ?? 0)) };
}

/**
 * A hosted agent's send of `amount` (base units, a bigint; or 'max') of `asset` ('SOL' | 'AC') from
 * the hosted key `from` to the address `to`, the hosted key paying the fee. Never more than the
 * balance less the fee, any recipient token account it must create, and the hosted key's own rent
 * floor. Throws 400 for a bad request and 409 when the balance does not allow it.
 * Returns { ixs, asset, to, amount, fee, createsTokenAccount, solSpent, after }.
 */
export async function planSend(t, { from, to, asset, amount, cfg }) {
  const token = tokenOf(cfg), rentMin = await t.rent(0);
  let dest; try { dest = pk(to); } catch { throw fail('to must be a base58 Solana address', 400); }
  if (dest.equals(pk(from))) throw fail('to is this hosted key itself', 400);
  if (!['SOL', 'AC'].includes(asset)) throw fail('asset must be SOL or AC', 400);
  const mine = await holdings(t, from, token), there = await t.getAccount(dest);
  if (asset === 'SOL') {
    const max = BigInt(Math.max(0, mine.sol - TX_FEE - rentMin));
    const v = amount === 'max' ? max : BigInt(amount);
    if (v <= 0n) throw fail(`nothing to send: this hosted key holds ${mine.sol} lamports; ${TX_FEE} pay the fee and ${rentMin} stay as its rent-exempt minimum`, 409, { balance: mine.sol, max: String(max) });
    if (v > max) throw fail(`at most ${max} lamports can be sent: the balance ${mine.sol} less the fee (${TX_FEE}) and this key's rent-exempt minimum (${rentMin})`, 409, { balance: mine.sol, max: String(max) });
    if ((there?.lamports ?? 0) + Number(v) < rentMin) throw fail(`the recipient holds no SOL yet: send at least ${rentMin - (there?.lamports ?? 0)} lamports so its account is rent-exempt`, 409);
    return { ixs: [SystemProgram.transfer({ fromPubkey: pk(from), toPubkey: dest, lamports: v })], asset, to: dest.toBase58(), amount: v, fee: TX_FEE, createsTokenAccount: false,
      solSpent: Number(v) + TX_FEE, after: { sol: mine.sol - Number(v) - TX_FEE, ac: mine.ac } };
  }
  if (!token) throw fail('the AC mint is not set on this deployment yet', 409);
  // AC goes to a wallet (its associated account), never into a token account named as the wallet.
  if (there && isTokenProgram(there.owner)) throw fail('to is a token account: name the wallet that owns it', 400);
  const v = amount === 'max' ? mine.ac : BigInt(amount);
  if (v <= 0n) throw fail('this hosted key holds no AC', 409, { ac: String(mine.ac) });
  if (v > mine.ac) throw fail(`at most ${mine.ac} AC base units can be sent`, 409, { ac: String(mine.ac) });
  const destAta = ataOf(dest, token.mint, token.tokenProgram), { exists, create } = await ataCost(t, destAta, token.tokenProgram), need = TX_FEE + create;
  // The fee payer must stay rent-exempt after the fee, and the key keeps its floor after the rent.
  if (mine.sol - need < rentMin) throw fail(`this hosted key needs ${need + rentMin} lamports of SOL for the fee${create ? ', the recipient\'s token account' : ''} and its own rent-exempt minimum; it holds ${mine.sol}`, 409,
    { balance: mine.sol, needed: need + rentMin });
  return { ixs: [...(exists ? [] : [createAtaIdempotent(from, dest, token.mint, token.tokenProgram)]), transferChecked(mine.ata, token.mint, destAta, from, v, token.decimals, token.tokenProgram)],
    asset, to: dest.toBase58(), amount: v, fee: TX_FEE, createsTokenAccount: !exists, solSpent: need, after: { sol: mine.sol - need, ac: mine.ac - v } };
}

/**
 * The sweep of the old hosted key `from` to the agent's new key `to`: its whole AC (then its
 * emptied token account is closed) and its whole SOL.
 *
 * The hosted key pays the fee (one signature) when it can, and any new token account's rent, from
 * its own SOL. Otherwise `gateway` is the fee payer (two signatures) and the sweep repays it: the
 * closed token account's rent goes to the gateway, which takes back the fee and any new token
 * account's rent and forwards the rest to the new key; when that is not enough, the hosted key's
 * SOL makes up the difference. So a gateway-paid sweep costs the gateway nothing, except that on an
 * agent's first sweep it may absorb up to `maxLoss` lamports (a hosted key holding AC and no SOL
 * cannot repay the new key's token account and two fees any other way). SOL that cannot move
 * (too little to leave the new key rent-exempt) stays and is reported as dust.
 * Returns { ixs, payer: 'hosted' | 'gateway' | null, sol, ac, dust, closes, create, cost, loss } or
 * null when nothing is held. With no `ixs`, `ac` and `dust` are what stays on the old key. `cost`
 * is the most the gateway spends before it is repaid; `loss` what it keeps paying.
 */
/** What the agent sends the old hosted key so a later sweep moves what is left with the gateway
 *  paying nothing: two fees, plus the rent-exempt minimum when the key holds no SOL (a transfer
 *  cannot leave an empty account under it; the runtime refuses it for rent). */
export const unlockLamports = (oldSol, rentMin) => 2 * TX_FEE + (oldSol > 0 ? 0 : rentMin);
export async function planSweep(t, { from, to, cfg, gateway, maxLoss = 0 }) {
  const token = tokenOf(cfg), rentMin = await t.rent(0), old = await holdings(t, from, token), dest = pk(to), gw = pk(gateway), src = pk(from);
  if (dest.equals(src)) throw fail('the new key is the old key', 400);
  if (old.sol === 0 && !old.ataExists) return null;
  const newSol = (await t.getAccount(dest))?.lamports ?? 0;
  const tokens = old.ataExists, moveAc = tokens && old.ac > 0n;
  const destAta = token ? ataOf(dest, token.mint, token.tokenProgram) : null;
  const create = moveAc ? (await ataCost(t, destAta, token.tokenProgram)).create : 0;
  const lands = d => d === 0 || newSol + d >= rentMin;   // the new key ends empty-handed or rent-exempt
  const acIxs = payer => moveAc ? [createAtaIdempotent(payer, dest, token.mint, token.tokenProgram), transferChecked(old.ata, token.mint, destAta, src, old.ac, token.decimals, token.tokenProgram)] : [];
  const transfer = (a, b, lamports) => lamports > 0 ? [SystemProgram.transfer({ fromPubkey: a, toPubkey: b, lamports })] : [];
  const nothing = { ixs: [], payer: null, sol: 0, ac: old.ac, dust: old.sol, closes: false, create, cost: 0, loss: 0 };
  // The hosted key pays: the runtime takes the fee first and refuses a fee payer it would leave
  // rent-paying; it ends empty, everything it held (less the fee and any new token account) at the new key.
  if (old.sol - TX_FEE >= rentMin || old.sol === TX_FEE) {
    const move = old.sol - TX_FEE - create, credit = move + (tokens ? old.ataLamports : 0);
    if (move >= 0 && lands(credit)) return { ixs: [...acIxs(src), ...(tokens ? [closeAccount(old.ata, dest, src, token.tokenProgram)] : []), ...transfer(src, dest, move)],
      payer: 'hosted', sol: move, ac: old.ac, dust: 0, closes: tokens, create, cost: 0, loss: 0 };
  }
  // The gateway pays two signatures' fees and any new token account, and is repaid from the closed
  // token account's rent (`back`), then from the hosted key's SOL (`take`); the rest goes to the new key.
  const cost = 2 * TX_FEE + create, back = (tokens ? old.ataLamports : 0) - cost;
  for (const take of [back < 0 ? Math.min(old.sol, -back) : 0, 0]) {
    const forward = Math.max(0, back), sol = old.sol - take + forward, loss = Math.max(0, -back - take);
    if (loss > maxLoss || !lands(sol)) continue;
    return { ixs: [...acIxs(gw), ...(tokens ? [closeAccount(old.ata, gw, src, token.tokenProgram)] : []), ...transfer(src, gw, take), ...transfer(src, dest, old.sol - take), ...transfer(gw, dest, forward)],
      payer: 'gateway', sol, ac: old.ac, dust: 0, closes: tokens, create, cost, loss };
  }
  return nothing;
}

/** A donation's instructions, paid and signed by the donor: SOL, or AC with the recipient's token
 *  account created when missing. */
export function donationInstructions({ donor, recipient, asset, amount, cfg }) {
  if (asset === 'SOL') return [SystemProgram.transfer({ fromPubkey: pk(donor), toPubkey: pk(recipient), lamports: BigInt(amount) })];
  const token = tokenOf(cfg);
  if (!token) throw fail('the AC mint is not set on this deployment yet', 409);
  return [createAtaIdempotent(donor, recipient, token.mint, token.tokenProgram),
    transferChecked(ataOf(donor, token.mint, token.tokenProgram), token.mint, ataOf(recipient, token.mint, token.tokenProgram), donor, amount, token.decimals, token.tokenProgram)];
}
/** The unsigned transaction a Solana Pay transaction request answers with (base64, legacy, donor pays). */
export function donationTransaction(ixs, donor, blockhash) {
  const tx = new Transaction({ feePayer: pk(donor), recentBlockhash: blockhash }).add(...ixs);
  return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
}

/**
 * Donations `owner` received since unix time `since`, newest first, from the chain history of the
 * owner and its AC account (public data only: signature, time, sending wallet, asset, amount).
 * A donation is a transfer in that no key of this agent signed (`owner`, and in `own` the keys it
 * used before, such as a hosted agent's old key, whose sweeps are not gifts) and that did not run
 * `program` (holder rewards and protocol refunds are not donations); transactions whose fee payer
 * is in `exclude` (a gateway's own) are left out too. `from` is the wallet the funds left: for
 * SOL the account whose balance fell most, for AC the owner whose AC fell; the fee payer (or null)
 * only when the history shows neither. `t.balanceHistory(address, { since, limit, skip,
 * skipPrograms, signatures })` supplies the transactions (`skip`: the agent's keys, and
 * `skipPrograms`: `program`, whose transactions are never gifts and so do not count toward `limit`;
 * `signatures`: how many signatures a read may page through, the transport's default when left
 * out). The list is marked `truncated` when a read stopped short (more transfers than `limit`, or
 * more transactions than `signatures`), so a donation since `since` may be missing from it;
 * `completeAfter`, when known, bounds what is missing: every unread transfer is at or before it, so
 * the list is complete for any window starting after it (`donationsSince`).
 */
export async function donationsTo(t, { owner, cfg, program, since = 0, limit = 25, signatures, exclude = [], own = [] }) {
  const o = pk(owner).toBase58(), token = tokenOf(cfg), skip = new Set(exclude.map(k => pk(k).toBase58())), mine = new Set([o, ...own.map(k => pk(k).toBase58())]);
  const addresses = [o, ...(token ? [ataOf(o, token.mint, token.tokenProgram).toBase58()] : [])], seen = new Map();
  let truncated = false, completeAfter = -Infinity;
  const cut = at => { truncated = true; completeAfter = Math.max(completeAfter, at ?? Infinity); };
  // The keys' own transactions and the program's (holder payouts list every holder's wallet; deposit
  // returns, refunds) are never gifts: skipped in the read, so they do not fill its limit.
  const skipPrograms = program ? [pk(program).toBase58()] : [];
  for (const a of addresses) { const h = await t.balanceHistory(pk(a), { since, limit, skip: [...mine], skipPrograms, ...(signatures ? { signatures } : {}) }); if (h.truncated) cut(h.completeAfter); for (const r of h) seen.set(r.signature, r); }
  const out = [];
  const most = entries => entries.filter(([k, d]) => d < 0 && !mine.has(k)).sort((x, y) => x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0)[0]?.[0] ?? null;
  for (const r of [...seen.values()].sort((x, y) => (y.time ?? 0) - (x.time ?? 0))) {
    if ((r.time ?? 0) < since || r.signers.some(s => mine.has(s)) || (program && r.programs.includes(pk(program).toBase58()))) continue;
    const payer = r.signers[0] ?? null;
    if (payer && skip.has(payer)) continue;
    const at = r.time ? new Date(r.time * 1000).toISOString() : null;
    const sol = r.sol[o] ?? 0;
    if (sol > 0) out.push({ signature: r.signature, time: r.time, at, from: most(Object.entries(r.sol)) ?? payer, asset: 'SOL', amount: String(sol) });
    if (token) {
      const moves = r.tokens.filter(x => x.mint === token.mint.toBase58()), ac = moves.filter(x => x.owner === o).reduce((s, x) => s + BigInt(x.delta), 0n);
      if (ac > 0n) out.push({ signature: r.signature, time: r.time, at, from: most(moves.map(x => [x.owner, BigInt(x.delta)])) ?? payer, asset: 'AC', amount: String(ac), decimals: token.decimals });
    }
  }
  if (out.length > limit) cut(out[limit].time);
  return truncated ? Object.assign(out.slice(0, limit), { truncated: true }, Number.isFinite(completeAfter) ? { completeAfter } : {}) : out;
}
/** The donations at or after `since` from a `donationsTo` list read from an earlier time, the newest
 *  `limit` of them, marked `truncated` (with `completeAfter`, when known) only when this window may
 *  miss one: the wider read can stop short further back, and a list cut to `limit` leaves out older
 *  ones, all at or before the first one it leaves out. */
export function donationsSince(all, since, limit = Infinity) {
  const list = all.filter(d => (d.time ?? 0) >= since);
  let after = all.truncated && !(all.completeAfter != null && since > all.completeAfter) ? all.completeAfter ?? Infinity : null;
  if (list.length > limit) after = Math.max(after ?? -Infinity, list[limit].time ?? Infinity);
  const out = list.length > limit ? list.slice(0, limit) : list;
  return after === null ? out : Object.assign(out, { truncated: true }, Number.isFinite(after) ? { completeAfter: after } : {});
}
/** One line per donation, for DMs: amounts in SOL and AC, the sender shortened. */
export function donationLine(d) {
  const short = id => id ? `${id.slice(0, 4)}…${id.slice(-4)}` : 'unknown';
  const amount = d.asset === 'SOL' ? `${fromBaseUnits(d.amount, 9)} SOL` : `${fromBaseUnits(d.amount, d.decimals ?? 6)} AC`;
  return `${amount} from ${short(d.from)} (${d.at ? d.at.slice(0, 16).replace('T', ' ') + ' UTC' : 'time unknown'}, tx ${short(d.signature)})`;
}

const ADDRESS = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
/**
 * The gateway's sweep jobs, one file per agent in `dir`: { agent, from (the old hosted key), label |
 * legacyKey, to (the key it moved to), created, status: 'moving' (written before the key change
 * is sent) | 'pending' | 'done', attempts, next,
 * lastError, result }. A job stays after it is done, so the agent can run it again for funds that
 * reach the old key later. No secret is stored: a label only names a key the gateway seed derives.
 */
export function sweepJobs(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const file = agent => { if (!ADDRESS.test(agent ?? '')) throw Error('invalid agent'); return `${dir}/${agent}.json`; };
  const read = agent => { try { return JSON.parse(readFileSync(file(agent), 'utf8')); } catch { return null; } };
  const write = job => { const tmp = `${file(job.agent)}.${randomBytes(6).toString('hex')}.tmp`; writeFileSync(tmp, JSON.stringify(job), { mode: 0o600 }); renameSync(tmp, file(job.agent)); return job; };
  return {
    get: read,
    put: job => write({ status: 'pending', attempts: 0, next: 0, lastError: null, result: null, ...job }),
    update: (agent, patch) => { const cur = read(agent); return cur ? write({ ...cur, ...patch }) : null; },
    remove: agent => { try { unlinkSync(file(agent)); } catch {} },
    all: () => readdirSync(dir).filter(n => /^[1-9A-HJ-NP-Za-km-z]{32,44}\.json$/.test(n)).map(n => read(n.slice(0, -5))).filter(Boolean),
    /** Every old hosted key swept into `agent`'s keys: its transfers are not donations. */
    sources: agent => { const j = agent && ADDRESS.test(agent) ? read(agent) : null; return j ? [j.from] : []; },
  };
}
/** Retry spacing of a failed sweep: 5 minutes, doubling, at most 6 hours. */
export const sweepBackoff = attempts => Math.min(6 * 3600_000, 5 * 60_000 * 2 ** Math.max(0, attempts - 1));
/** Appends one JSON line to `file` (the hosted funds log): never a token, key, label or IP. */
export function logLine(file, entry) {
  const line = JSON.stringify({ at: new Date().toISOString(), ...entry });
  if (file) try { appendFileSync(file, line + '\n', { mode: 0o600 }); } catch (e) { console.error(`hosted funds log ${file}: ${e.message}`); }
  console.log(`hosted-funds ${line}`);
}
