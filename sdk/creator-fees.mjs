// The relays' creator-fee crank (owner, 30 September 2026: built into our relays before the mainnet
// launch; pump plan section 7 step 7). Once an epoch, for the program's configured mint, it moves the
// coin's creator fees into the vault, the PDA ["treasury"] the coin names as its creator:
// - on the bonding curve, collect_creator_fee_v2 (pump): what creator_vault(vault) holds above its
//   rent floor goes to the vault. The vault never signs; any fee payer may crank it.
// - after graduation, PumpSwap's creator fees wait as WSOL in ammCreatorVaultAta(vault):
//   transfer_creator_fees_to_pump (PumpSwap, no signer) moves them into creator_vault(vault) and the
//   same collect follows, in one transaction. When that transaction fails, the WSOL fallback runs:
//   collect_coin_creator_fee into the vault's WSOL account (the payer creates it) and our own
//   Crank::Unwrap, which closes that account into the vault, in one transaction. A WSOL account of
//   the vault left by anyone else's collect_coin_creator_fee is unwrapped the same way.
// Before anything is sent the creator is checked on two read paths over the same bytes: the decoded
// accounts (pump.mjs creatorStatus) and the raw bytes (bonding_curve.creator at offset 49 and, after
// graduation, pool.coin_creator at 211, with their owners and discriminators). A mismatch, a fee
// sharing config or a holder-rewards coin refuses the pass and pages; so do pump 6049/6050 and
// PumpSwap 6047/6048 (the creator moved to a sharing config), a transfer path that failed even when
// the WSOL fallback then carried the fees, and repeated failures in a row, throttled like
// every page (alerts.mjs `page`: Colony DMs to the owner through notify.mjs).
// Fees are collected only when the amount beats the fee: at least `minLamports`, and `feeMultiple`
// times the transaction's worst cost. The fee payer is the relay's own wallet and our program refunds
// no pump instruction (only the Unwrap, its own crank), so every transaction's worst cost is held
// against a bound per epoch (`epochBudget`) and the relay's daily spend ledger. The WSOL fallback's
// rent is never refunded to the relay (the Unwrap closes the account into the vault), so it also runs
// at most `fallbacksPerDay` times a UTC day (0: never; the fees then wait in PumpSwap). Every signature is
// appended in full to <dir>/signatures.jsonl; <dir>/state.json keeps the epoch handled and any
// transaction whose outcome is unknown, so a restart neither collects twice in an epoch nor sends
// while an earlier transaction may still land. Each transaction re-reads what it moves right before
// it is built: a relay beside it (both our seats run this crank) that collected first leaves dust.
import { appendFileSync, readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';
import * as P from './pump.mjs';
import { clusterOfGenesis } from './cluster.mjs';
import { page } from './alerts.mjs';
import { oneLine } from './notify.mjs';

const { PublicKey } = P.web3;
const NONE = '11111111111111111111111111111111';
const PUMP = P.PUMP_PROGRAM_ID.toBase58(), AMM = P.PUMP_AMM_PROGRAM_ID.toBase58();
/** One signature, the fee payer's: what a crank transaction costs before any priority fee. */
export const TX_FEE = 5000;
/** A token account's size: the vault's WSOL account the fallback opens (its rent ends in the vault). */
const TOKEN_ACCOUNT = 165;
/** The creator moved to a fee sharing config, by the program that says so (PumpSwap's own 6049 is
 *  another error: CashbackNotEnabled). */
export const CREATOR_MIGRATED = Object.freeze({ [PUMP]: [6049, 6050], [AMM]: [6047, 6048] });
const ERROR_NAMES = { [PUMP]: { ...P.PUMP_ERRORS, 6050: 'UnableToDistributeCreatorVaultMigratedToSharingConfig' }, [AMM]: P.AMM_ERRORS };
/**
 * `every` ms between checks (the collect itself runs once an epoch), `lead` seconds before the epoch
 * is due to close from which it may run (so that close recognises the fees at once), `minLamports`
 * the smallest collect, `feeMultiple` how many times its worst cost a collect must move, `epochBudget`
 * the lamports this wallet may spend on it in one epoch, `priorityLamports` a v1 priority fee per
 * transaction, `failuresBeforePage` failed passes in a row that page, `repeatMs` how often an open
 * page repeats, `pendingMs` how long a transaction of unknown outcome is waited for, `fallbacksPerDay`
 * how many WSOL fallbacks (each costs the relay a token account's rent, about 0.0015 SOL, that ends
 * in the vault) may be sent in a UTC day: 0 turns the fallback off. What PumpSwap holds carries over,
 * so a fallback or two a day still moves all of it.
 */
export const DEFAULTS = Object.freeze({ every: 60_000, lead: 300, minLamports: 1_000_000, feeMultiple: 10, epochBudget: 2_000_000, priorityLamports: 0,
  failuresBeforePage: 3, repeatMs: 3_600_000, pendingMs: 150_000, fallbacksPerDay: 2 });

/** The crank's settings from the relay's flags (`get(name)`: --name, else AC_NAME), or null when it is
 *  off (the default: only our relays collect, owner 30 September). Bad values refuse to start. */
export function creatorFeeSettings(get) {
  const mode = String(get('creator-fees') ?? 'off');
  if (mode === 'off') return null;
  if (mode !== 'on') throw Error('--creator-fees must be on or off');
  const setting = (name, lo, hi, fallback) => {
    const v = Number(get(name) ?? fallback);
    if (!(Number.isSafeInteger(v) && v >= lo && v <= hi)) throw Error(`--${name} must be an integer from ${lo} to ${hi}`);
    return v;
  };
  const every = setting('creator-fee-seconds', 10, 3600, DEFAULTS.every / 1000) * 1000, lead = setting('creator-fee-lead', 10, 86_400, DEFAULTS.lead);
  // Refused here with the flags' names, and again by creatorFeeOptions (see narrowestWindow).
  const gap = longestGap(every, defaultJitter(every)), narrowest = narrowestWindow(lead);
  if (gap > narrowest * 1000) throw Error(`--creator-fee-seconds ${every / 1000} is too slow for --creator-fee-lead ${lead}: with its jitter a check can be ${gap / 1000} s after the last, `
    + `but a relay's collect window can be ${narrowest} s long, so epochs would pass uncollected; keep --creator-fee-seconds at most ${Math.floor((narrowest * 1000) / 1250)} or raise --creator-fee-lead`);
  return {
    every,
    lead,
    minLamports: setting('creator-fee-min', 10_000, 1_000_000_000_000, DEFAULTS.minLamports),
    epochBudget: setting('creator-fee-budget', 10_000, 100_000_000, DEFAULTS.epochBudget),
    priorityLamports: setting('creator-fee-priority', 0, 10_000_000, DEFAULTS.priorityLamports),
    // 1 pages on the first failed pass; a creator mismatch and pump 6049 always page at once.
    failuresBeforePage: setting('creator-fee-failures', 1, 100, DEFAULTS.failuresBeforePage),
    // WSOL fallbacks a UTC day (each fronts a token account's rent the relay never gets back); 0: off.
    fallbacksPerDay: setting('creator-fee-fallbacks', 0, 48, DEFAULTS.fallbacksPerDay),
  };
}

/** The program's epoch in seconds on mainnet (src/state.rs EPOCH_LEN = HOUR / 2). */
export const EPOCH_LEN_SECS = 1800;
/** The shortest collect window a relay can draw, in seconds: the window is min(lead, the epoch) before
 *  the close, less the key's stagger (up to half of it), and it ends when the epoch closes (the relay's
 *  own crank closes it soon after it is due). A check interval longer than this lets epochs go by with
 *  no pass inside the window: they skip without a page and their fees wait for a later epoch. */
export const narrowestWindow = (lead, epochSecs = EPOCH_LEN_SECS) => Math.ceil(Math.min(lead, epochSecs) / 2);
/** The longest time between two checks: `every` plus its jitter. */
const longestGap = (every, jitter) => every + jitter;
const defaultJitter = every => Math.floor(every / 4);

const pk = k => (k instanceof PublicKey ? k : new PublicKey(k));
const b58 = k => pk(k).toBase58();
const lamportsOf = a => (a ? BigInt(a.lamports) : 0n);
const sol = l => `${(Number(l) / 1e9).toFixed(6)} SOL`;
/** An error's first line as it goes into the log and a page: one line, no URL query (an RPC key rides
 *  in one) and no key=value secret. */
const scrub = text => String(text).replace(/(https?:\/\/[^\s"'?#]+)\?[^\s"']*/gi, '$1?…').replace(/\b((?:api[-_]?key|token|secret)=)[^&\s"']+/gi, '$1…');
const firstLine = e => oneLine(scrub(String(e?.message ?? e).split('\n')[0])).slice(0, 300);

/**
 * The creator check and the balances the crank moves, from ONE read of the accounts: the decoded path
 * (pump.mjs creatorStatus, creatorVaultBalances) and the raw path judge the same bytes. `pump` says
 * whether the mint has a pump.fun bonding curve at all; `problems` lists every way the fees would
 * not reach `vault`, each marked by the path that found it.
 */
export async function creatorCheck(reader, { mint, vault }) {
  mint = pk(mint); vault = pk(vault);
  const vaultWsol = P.ata(vault, P.NATIVE_MINT, P.TOKEN_PROGRAM_ID);
  const keys = [P.bondingCurvePda(mint), P.canonicalPoolPda(mint), P.sharingConfigPda(mint), P.ammCreatorVaultAta(vault), P.creatorVaultPda(vault), vaultWsol, vault, P.RENT_SYSVAR_ID];
  const got = await reader.getAccounts(keys);
  const same = { async getAccounts(ks) {
    return ks.map(k => { const i = keys.findIndex(x => x.equals(pk(k))); if (i < 0) throw Error(`creatorCheck: unexpected read of ${b58(k)}`); return got[i]; });
  } };
  const [curveAcc, poolAcc, , , , wsolAcc, vaultAcc, rentAcc] = got;
  let decoded;
  try { decoded = await P.creatorStatus(same, { mint, vault }); }
  catch (e) { decoded = { ok: false, problems: [`the accounts do not decode: ${e.message}`], complete: false }; }
  const raw = [];
  const creatorAt = (acc, label, owner, disc, offset) => {
    const d = Buffer.from(acc.data);
    if (!pk(acc.owner).equals(owner)) return raw.push(`the ${label} is owned by ${b58(acc.owner)}, not ${b58(owner)}`);
    if (d.length < offset + 32 || d.subarray(0, 8).toString('hex') !== disc) return raw.push(`the ${label} account does not hold its layout (${d.length} bytes)`);
    const creator = d.subarray(offset, offset + 32);
    if (!creator.equals(vault.toBuffer())) raw.push(`${label} bytes ${offset}..${offset + 32} name ${new PublicKey(creator).toBase58()}, not the vault`);
  };
  if (curveAcc) creatorAt(curveAcc, 'bonding curve', P.PUMP_PROGRAM_ID, P.ACCOUNT.BondingCurve, P.BONDING_CURVE_CREATOR_OFFSET);
  // An account at the pool PDA that PumpSwap does not own is anyone's SOL transfer, not a pool
  // (pump.mjs isAmmPool): the coin has not graduated, and migrate still creates the pool over it.
  const pool = P.isAmmPool(poolAcc) ? poolAcc : null;
  if (pool) creatorAt(pool, 'PumpSwap pool', P.PUMP_AMM_PROGRAM_ID, P.ACCOUNT.Pool, P.POOL_COIN_CREATOR_OFFSET);
  const problems = [...decoded.problems.filter(p => curveAcc || p !== 'bonding curve missing').map(p => `${p} (decoded)`), ...raw.map(p => `${p} (raw bytes)`)];
  const balances = await P.creatorVaultBalances(same, vault);
  const rent = rentAcc ? P.decodeRent(rentAcc.data) : P.LIVE_RENT_30_SEPT;
  const wsol = wsolAcc && pk(wsolAcc.owner).equals(P.TOKEN_PROGRAM_ID) ? P.decodeTokenAccount(Buffer.from(wsolAcc.data)) : null;
  return {
    pump: !!curveAcc, ok: problems.length === 0, problems, graduated: !!pool, complete: !!decoded.complete, balances,
    vault: lamportsOf(vaultAcc), ataRent: P.minimumBalance(rent, TOKEN_ACCOUNT),
    // A WSOL account of the vault (someone's collect_coin_creator_fee, or an unwrap that never ran):
    // only the Unwrap crank can close it into the vault.
    vaultWsol: wsol && wsol.mint.equals(P.NATIVE_MINT) && wsol.owner.equals(vault) ? { address: vaultWsol, lamports: lamportsOf(wsolAcc), amount: wsol.amount } : null,
  };
}

/** The program and custom error of a failed transaction: the innermost failing program in its logs,
 *  else the instruction its InstructionError names. Null when it failed for another reason. */
export function programError(e, ixs = []) {
  const logs = Array.isArray(e?.logs) ? e.logs : [];
  for (const line of logs) {
    const m = /^Program (\w+) failed: custom program error: 0x([0-9a-fA-F]+)/.exec(line);
    if (m) return named(m[1], parseInt(m[2], 16));
  }
  const text = `${e?.message ?? ''} ${JSON.stringify(e?.err ?? null)}`;
  const ie = /"InstructionError":\[(\d+),\{"Custom":(\d+)\}\]/.exec(text);
  if (ie) return named(ixs[Number(ie[1])]?.programId?.toBase58() ?? null, Number(ie[2]));
  const m = /custom program error: 0x([0-9a-fA-F]+)/.exec(text);
  return m ? named(null, parseInt(m[1], 16)) : null;
}
const named = (program, code) => ({ program, code, name: ERROR_NAMES[program]?.[code] ?? null });
/** Whether a program error says the creator moved to a sharing config (its fees then never reach the vault). */
export const creatorMigrated = err => !!err?.program && (CREATOR_MIGRATED[err.program] ?? []).includes(err.code);

/**
 * What became of a transaction the transport did not confirm: `failed` (it landed and failed: the
 * fee was paid), `unsent` (refused before it left, or never built: no fee), `expired` (its blockhash
 * expired unseen: no fee), `uncertain` (it may still land). A send that returns has `landed`.
 */
export function outcomeOf(e) {
  if (e?.refused) return e.unsent ? 'unsent' : 'failed';
  if (/did not land within \d+ blockhash/i.test(e?.message ?? '')) return 'expired';
  return e?.signature ? 'uncertain' : 'unsent';
}

const readJson = (path, fallback) => { try { return JSON.parse(readFileSync(path, 'utf8')); } catch (e) { if (e.code === 'ENOENT') return fallback; throw Error(`${path} cannot be read: ${e.message}`); } };
const json = x => JSON.stringify(x, (_, v) => (typeof v === 'bigint' ? v.toString() : v instanceof PublicKey ? v.toBase58() : v));

/** The crank's options with their defaults, refused when out of range: a relay checks them before it
 *  pays for anything (its registration). */
export function creatorFeeOptions({ dir, ammPath = 'auto', every = DEFAULTS.every, jitter = defaultJitter(every), lead = DEFAULTS.lead, minLamports = DEFAULTS.minLamports,
  feeMultiple = DEFAULTS.feeMultiple, epochBudget = DEFAULTS.epochBudget, priorityLamports = DEFAULTS.priorityLamports, failuresBeforePage = DEFAULTS.failuresBeforePage,
  repeatMs = DEFAULTS.repeatMs, pendingMs = DEFAULTS.pendingMs, fallbacksPerDay = DEFAULTS.fallbacksPerDay, ...rest } = {}) {
  if (!dir) throw Error('the creator-fee crank needs a state directory (--state): its epoch record and signature log live there');
  for (const [name, v, lo] of [['every', every, 1], ['lead', lead, 1], ['min lamports', minLamports, 1], ['fee multiple', feeMultiple, 1], ['epoch budget', epochBudget, 0],
    ['priority lamports', priorityLamports, 0], ['failures before a page', failuresBeforePage, 1], ['repeat', repeatMs, 0], ['pending wait', pendingMs, 0], ['fallbacks a day', fallbacksPerDay, 0]])
    if (!Number.isSafeInteger(v) || v < lo) throw Error(`creator-fee crank: ${name} must be an integer of at least ${lo}`);
  if (!Number.isSafeInteger(jitter) || jitter < 0 || jitter >= every) throw Error('creator-fee crank: jitter must be a non-negative integer below every');
  if (longestGap(every, jitter) > narrowestWindow(lead) * 1000)
    throw Error(`creator-fee crank: every ${every} ms plus jitter ${jitter} ms is longer than the narrowest collect window (${narrowestWindow(lead)} s for a lead of ${lead} s): epochs would pass uncollected`);
  if (!['auto', 'fallback'].includes(ammPath)) throw Error('creator-fee crank: ammPath must be auto or fallback');
  if (ammPath === 'fallback' && fallbacksPerDay === 0) throw Error('creator-fee crank: ammPath fallback needs at least one fallback a day');
  return { ...rest, dir, ammPath, every, jitter, lead, minLamports, feeMultiple, epochBudget, priorityLamports, failuresBeforePage, repeatMs, pendingMs, fallbacksPerDay };
}

/**
 * The crank, for relay-server.mjs (in process, like the other cranks): `pass()` checks and does at
 * most one epoch's collect; `start()` checks every `every` ms (jittered, the first anywhere in the
 * first period, so relays started together spread out); `status()` is what GET /v2 shows.
 * `c` is the relay's Council, `payer` its wallet (the fee payer), `dir` a directory of its own.
 * `notifier` pages (null: pages go to `error`); `ledger` is the relay's spend ledger (relay-spend.mjs);
 * `requirePump` pages when the configured mint has no pump.fun bonding curve (default: only where the
 * RPC answers mainnet's genesis, sdk/cluster.mjs, so a devnet instance with a plain test mint stays
 * idle); `ammPath: 'fallback'` skips the transfer path after graduation (an incident switch; the
 * fallback also runs by itself when the transfer path fails), within `fallbacksPerDay` either way. `now` is the wall clock (ms), `sleep` its wait.
 * A pass still running after `stall` ms (an RPC request that never answers; default as the relay's
 * crank, at least 10 minutes) is written off as a failed pass, which counts toward the page like any
 * other, and the schedule moves on; it sends nothing more (review, 2 October: one hung request stopped
 * every later pass, and no page said so).
 */
export function creatorFeeCranker(c, payer, options = {}) {
  const { dir, notifier = null, ledger = null, requirePump = null, ammPath, every, jitter, random = Math.random, lead, minLamports, feeMultiple, epochBudget,
    priorityLamports, failuresBeforePage, repeatMs, pendingMs, fallbacksPerDay, now = Date.now, sleep = ms => new Promise(r => setTimeout(r, ms)),
    log = m => console.log(new Date().toISOString(), m), error = m => console.error(new Date().toISOString(), m), stall = Math.max(10 * every, 600_000) } = creatorFeeOptions(options);
  if (!Number.isSafeInteger(stall) || stall < 1) throw Error('creator-fee crank: stall must be a positive integer of milliseconds');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const t = c.t, vault = c.vault, program = c.program.toBase58(), relay = payer.publicKey.toBase58();
  const statePath = join(dir, 'state.json'), logPath = join(dir, 'signatures.jsonl');
  const quiet = f => m => { try { f(m); } catch { /* a broken log sink never stops the crank */ } }, say = quiet(log), cry = quiet(error);
  // `epoch`: the last epoch handled; `spent`: this wallet's lamports in epoch `spent.epoch`; `pending`:
  // a transaction that may still land; `mismatch`, `migrated`, `transferFailed`, `failures`: the open
  // page conditions; `windowFailures`: how many of the run's failures were failed window attempts;
  // `fallbacks`: the WSOL fallbacks sent on UTC day `fallbacks.day` that may have cost the relay rent;
  // `mint`: the mint the last config read named, which keys the pages across a restart.
  const fresh = { program, epoch: null, spent: { epoch: null, lamports: 0 }, fallbacks: { day: null, sent: 0 }, pending: null, failures: 0, windowFailures: 0, lastError: null, mismatch: null, migrated: null, transferFailed: null, lastCollect: null, mint: null };
  const stored = readJson(statePath, null);
  // A state directory carried over from another program (the mainnet move) starts again.
  let state = stored?.program === program ? { ...fresh, ...stored } : fresh;
  if (stored && stored.program !== program) cry(`creator fees: ${statePath} belongs to program ${stored.program}; starting afresh for ${program}`);
  const save = () => { const tmp = `${statePath}.${randomBytes(4).toString('hex')}`; writeFileSync(tmp, json(state), { mode: 0o600 }); renameSync(tmp, statePath); };
  // Append-only: every transaction the crank sends, in full, whatever became of it.
  const record = entry => {
    try { appendFileSync(logPath, `${json({ at: new Date(now()).toISOString(), program, relay, ...entry })}\n`, { mode: 0o600 }); }
    catch (e) { cry(`creator fees: the signature log cannot be written: ${e.message}`); }
  };
  const status = { every, lead, minLamports, feeMultiple, epochBudget, priorityLamports, fallbacksPerDay, stall, passes: 0, running: false, last: null };
  // Each pass runs in its own context: { off } once it is written off as stalled.
  const fence = new AsyncLocalStorage();
  // A pump transaction loads pump, PumpSwap and the token programs (live devnet: 56k to 71k CU).
  const TX = { computeUnitLimit: 200_000, loadedAccountsDataSizeLimit: 8 * 1024 * 1024, priorityFeeLamports: BigInt(priorityLamports) };
  const worstOf = extra => TX_FEE + priorityLamports + Number(extra);
  const beats = (amount, worst) => amount >= BigInt(Math.max(minLamports, feeMultiple * worst));
  let mintNow = null, pumpRequired = requirePump;
  // Both our seats run this crank: each starts at its own point of the window's first half, drawn from
  // its key, so the one that comes second re-reads dust instead of racing the first.
  const keyDraw = createHash('sha256').update(payer.publicKey.toBuffer()).digest().readUInt32LE(0);
  const stagger = window => (window >= 2 ? keyDraw % Math.floor(window / 2) : 0);

  const spentIn = n => (state.spent.epoch === n ? state.spent.lamports : 0);
  // A late charge for an epoch already passed (a pass written off as stalled whose send came back)
  // never replaces the current epoch's record; the day's ledger still counts it.
  const charge = (n, lamports) => { if (state.spent.epoch > n) return; state.spent = { epoch: n, lamports: spentIn(n) + lamports }; };
  const today = () => new Date(now()).toISOString().slice(0, 10);
  const fallbacksToday = () => (state.fallbacks?.day === today() ? state.fallbacks.sent : 0);
  /** The payer's cost and the vault's gain in one transaction: from the transaction itself on an RPC
   *  (other transactions may move the vault meanwhile), from the balances on the simulator. */
  const effects = (signature, vaultBefore) => measure(signature, vaultBefore).catch(() => ({ cost: null, gained: null }));
  const measure = async (signature, vaultBefore) => {
    if (typeof t.call === 'function') {
      for (let i = 0; i < 3; i++) {
        const tx = await t.call('getTransaction', [signature, { encoding: 'json', commitment: 'confirmed', maxSupportedTransactionVersion: 1 }]).catch(() => null);
        if (tx?.meta) {
          const keys = [...tx.transaction.message.accountKeys.map(k => (typeof k === 'string' ? k : k.pubkey)), ...(tx.meta.loadedAddresses?.writable ?? []), ...(tx.meta.loadedAddresses?.readonly ?? [])];
          const v = keys.indexOf(vault.toBase58());
          return { cost: Math.max(0, tx.meta.preBalances[0] - tx.meta.postBalances[0]), gained: v < 0 ? 0n : BigInt(tx.meta.postBalances[v] - tx.meta.preBalances[v]) };
        }
        await sleep(1000);
      }
      return { cost: null, gained: null };
    }
    const tx = await t.transaction(signature).catch(() => null), after = await t.getAccount(vault);
    return { cost: typeof tx?.payerDelta === 'number' ? Math.max(0, -tx.payerDelta) : null, gained: after ? BigInt(after.lamports) - vaultBefore : null };
  };
  /** Sends one transaction within the epoch's bound and the day's ledger and logs its signature,
   *  whatever becomes of it. Throws the transport's error marked with its `outcome` and `programError`. */
  const send = async (n, kind, what, ixs, worst, expected) => {
    // A pass written off as stalled sends nothing more: the passes after it decide.
    if (fence.getStore()?.off) throw Object.assign(Error('the pass was written off as stalled'), { outcome: 'unsent', kind });
    if (spentIn(n) + worst > epochBudget) throw Object.assign(Error(`the epoch's cost bound is spent: ${spentIn(n)} of ${epochBudget} lamports used, the ${kind} may cost ${worst}`), { outcome: 'bounded', kind });
    const vaultBefore = lamportsOf(await t.getAccount(vault));
    // Asked again: the read above can hang past the write-off, and the passes after it decide.
    if (fence.getStore()?.off) throw Object.assign(Error('the pass was written off as stalled'), { outcome: 'unsent', kind });
    const ticket = ledger ? ledger.reserve(worst, { exposure: worst }) : null;
    let signature = null, outcome = 'landed', err = null, cost = 0, gained = null;
    try { signature = await t.send(ixs, payer, [], TX); }
    catch (e) { err = e; signature = e.signature ?? null; outcome = outcomeOf(e); }
    try {
      if (outcome === 'landed' || outcome === 'failed') ({ cost, gained } = await effects(signature, vaultBefore));
      else if (outcome === 'uncertain') cost = null;
    } finally {
      // An unknown cost is the whole hold.
      charge(n, cost ?? worst);
      // A fallback that landed, or may land, fronted the rent: it counts toward the day's cap.
      if (kind === 'fallback' && (outcome === 'landed' || outcome === 'uncertain')) state.fallbacks = { day: today(), sent: fallbacksToday() + 1 };
      try { ledger?.settle(ticket, cost); } catch (e) { cry(`creator fees: spend ledger: ${e.message}`); }
    }
    const perr = err ? programError(err, ixs) : null;
    record({ epoch: n, mint: mintNow, kind, what, signature, outcome, expected, collected: outcome === 'landed' ? gained : 0n, cost: cost ?? worst,
      ...(err ? { error: firstLine(err), ...(perr ? { programError: perr } : {}) } : {}) });
    if (outcome === 'uncertain') { state.pending = { signature, kind, epoch: n, at: now(), expected: String(expected) }; save(); }
    if (err) throw Object.assign(err, { outcome, kind, signature, programError: perr });
    say(`creator fees: epoch ${n}: ${what} moved ${gained === null ? 'an unknown amount' : sol(gained)} into the vault (expected ${sol(expected)}), cost ${cost ?? worst} lamports: ${signature}`);
    return { signature, gained };
  };
  /** A transaction of unknown outcome: found landed or failed, it is logged and done; unseen past
   *  `pendingMs` it can no longer land (its blockhash lives about a minute). True once settled. */
  const settlePending = async () => {
    const p = state.pending;
    // An RPC error is no answer: the pass fails (and counts toward a page) rather than taking a
    // transaction the node could not look up for one it never saw.
    let tx;
    try { tx = await t.transaction(p.signature); }
    catch (e) { throw Error(`cannot learn whether ${p.signature} landed: ${firstLine(e)}`); }
    if (!tx) {
      if (now() - p.at < pendingMs) return false;
      record({ epoch: p.epoch, mint: mintNow, kind: 'settled', what: p.kind, signature: p.signature, outcome: 'dropped' });
    } else record({ epoch: p.epoch, mint: mintNow, kind: 'settled', what: p.kind, signature: p.signature, outcome: tx.error ? 'failed' : 'landed',
      cost: typeof tx.payerDelta === 'number' ? Math.max(0, -tx.payerDelta) : null });
    state.pending = null; save();
    return true;
  };
  // Our program refunds the Unwrap only to a registered relayer (a relay always is); any other payer
  // runs it self-paid, as the program allows anyone.
  const unwrapIx = async wsol => c.crankIx('unwrap', [wsol, P.TOKEN_PROGRAM_ID], payer, (await c.raw(c.relayerAddress(payer.publicKey))) ? {} : { selfPaid: true });
  const recheck = async () => {
    const x = await creatorCheck(t, { mint: mintNow, vault });
    if (!x.ok) throw Object.assign(Error(`the creator changed during the pass: ${x.problems.join('; ')}`), { mismatch: x.problems });
    return x;
  };

  /** The epoch's work once the creator check passed: a WSOL account of the vault, then the fees. Every
   *  step is tried; a failure of any fails the pass, after the others ran. */
  const collect = async (n, check) => {
    const done = [], errors = [];
    // Each step's own failure is kept; the creator moving to a sharing config stops the pass at once,
    // and so does a step whose outcome is unknown: nothing more is sent until the next pass settles it.
    const run = async (kind, what, ixs, worst, expected) => {
      try { await send(n, kind, what, await ixs(), worst, expected); done.push(kind); return null; }
      catch (e) { if (creatorMigrated(e.programError) || e.outcome === 'uncertain') throw e; return e; }
    };
    if (check.vaultWsol) {
      // Refunded as our program's own crank: the vault gains the account's WSOL and rent.
      const e = await run('unwrap', 'Crank::Unwrap of the vault\'s WSOL account', async () => [await unwrapIx(check.vaultWsol.address)], worstOf(0), check.vaultWsol.lamports);
      if (e) errors.push(e);
      check = await recheck();
    }
    const { pump, amm } = check.balances;
    const includeAmm = ammPath === 'auto' && amm.exists && amm.amount > 0n;
    const expected = pump.collectable + (includeAmm ? amm.amount : 0n);
    let fallback = ammPath === 'fallback', broken = null, curveAgain = false, transferRefused = false, seen = expected, held = null;
    // The incident switch is on: the transfer path is not tried, so its page has done its job.
    if (fallback) state.transferFailed = null;
    if (beats(expected, worstOf(0))) {
      const e = await run('collect', includeAmm ? 'transfer_creator_fees_to_pump + collect_creator_fee_v2' : 'collect_creator_fee_v2',
        async () => P.feeCrankInstructions({ vault, includeAmm }), worstOf(0), expected);
      // The transfer path refused for another reason: the WSOL fallback takes PumpSwap's part, and
      // the curve's part goes alone unless pump itself refused the collect.
      if (e && includeAmm && ['failed', 'unsent'].includes(e.outcome)) {
        broken = e; fallback = true; curveAgain = e.programError?.program !== PUMP;
        // Only a program's error other than pump's blames the transfer instruction; a refusal no
        // program reported (the relay wallet cannot pay, say) fails the pass as any other error.
        transferRefused = !!e.programError && curveAgain;
        say(`creator fees: epoch ${n}: the transfer path failed (${firstLine(e)}); trying the WSOL fallback`);
        // An error even when the fallback carries the fees (it costs the relay the WSOL account's rent
        // each time): it stays open and paged until the transfer path lands again.
        if (transferRefused) state.transferFailed = { epoch: n, error: firstLine(e), signature: e.signature ?? null, programError: e.programError ?? null };
      } else if (e) errors.push(e);
      else if (includeAmm) state.transferFailed = null;
    }
    if (fallback) {
      check = await recheck();
      const b = check.balances, worst = worstOf(check.ataRent);
      seen = b.pump.collectable + b.amm.amount;
      if (broken && !transferRefused) errors.push(broken);
      if (curveAgain && beats(b.pump.collectable, worstOf(0))) {
        const e = await run('collect', 'collect_creator_fee_v2', async () => P.feeCrankInstructions({ vault, includeAmm: false }), worstOf(0), b.pump.collectable);
        if (e) errors.push(e);
      }
      if (b.amm.exists && beats(b.amm.amount, worst) && fallbacksToday() >= fallbacksPerDay) {
        // The day's fallbacks are spent (or turned off): PumpSwap's fees wait, the relay's rent is kept.
        held = `the WSOL fallback waits: ${fallbacksToday()} of ${fallbacksPerDay} sent today; PumpSwap holds ${sol(b.amm.amount)}`;
        say(`creator fees: epoch ${n}: ${held}`);
      } else if (b.amm.exists && beats(b.amm.amount, worst)) {
        const e = await run('fallback', 'collect_coin_creator_fee + Crank::Unwrap', async () => [
          P.createAtaIdempotentInstruction({ payer: payer.publicKey, owner: vault, mint: P.NATIVE_MINT, tokenProgram: P.TOKEN_PROGRAM_ID }),
          P.collectCoinCreatorFeeInstruction({ coinCreator: vault }), await unwrapIx(P.ata(vault, P.NATIVE_MINT, P.TOKEN_PROGRAM_ID))], worst, b.amm.amount + check.ataRent);
        if (e) errors.push(e);
      } else if (transferRefused) errors.push(Object.assign(Error(`the transfer path failed (${firstLine(broken)}) and PumpSwap's ${sol(b.amm.amount)} is below the WSOL fallback's threshold`), { programError: broken.programError }));
    }
    if (errors.length) throw Object.assign(Error(errors.map(firstLine).join('; ')), { steps: done, programError: errors.find(x => x.programError)?.programError ?? null });
    return { done, seen, held };
  };

  const alerts = mint => {
    const out = [], m = mint ? b58(mint) : 'the configured mint';
    if (state.mismatch) out.push({ rule: 'creator-mismatch', key: `creator-mismatch:${m}`, message: `creator fees of ${m} no longer reach the vault ${vault.toBase58()}; the crank sends nothing until this is looked at: ${state.mismatch.join('; ')}` });
    if (state.migrated) out.push({ rule: 'creator-migrated', key: `creator-migrated:${m}`, message: `the ${state.migrated.kind} failed with ${state.migrated.name ?? 'error'} ${state.migrated.code} of ${state.migrated.program}: the creator moved to a fee sharing config (${state.migrated.signature ?? 'no signature'})` });
    if (state.transferFailed) out.push({ rule: 'creator-fee-transfer-failing', key: `creator-fee-transfer-failing:${m}`, message: `transfer_creator_fees_to_pump failed in epoch ${state.transferFailed.epoch} (${state.transferFailed.error}; ${state.transferFailed.signature ?? 'no signature'}): ${fallbacksPerDay ? `the WSOL fallback now moves PumpSwap's fees, the relay fronting a WSOL account's rent each time (at most ${fallbacksPerDay} a UTC day; ${fallbacksToday()} today)` : 'the WSOL fallback is off (--creator-fee-fallbacks 0): PumpSwap\'s fees wait'}, until the transfer path lands again` });
    if (state.failures >= failuresBeforePage) out.push({ rule: 'creator-fee-crank-failing', key: `creator-fee-crank-failing:${m}`, message: `${state.failures} creator-fee passes failed in a row; last: ${state.lastError}` });
    return out;
  };
  const pager = notifier ?? { name: 'log', send: async msg => cry(msg.text) };
  const pageNow = async mint => {
    try { await page(alerts(mint), { notifier: pager, statePath: join(dir, 'alerts.json'), repeatMs, now: now(), source: `creator-fee crank ${relay}` }); }
    catch (e) { cry(`creator fees: page not delivered: ${oneLine(e?.message ?? e)}`); }
  };

  const pass = async () => {
    if (status.running) return { skipped: 'a pass is running' };
    const at = new Date(now()).toISOString();
    status.running = at;
    let result = null, cleared = false, inWindow = false;
    // Failures count in a row until a pass succeeds. A pass that found the epoch's work done read the
    // chain and has nothing left to do: it ends the run. One that waited for its window or for a
    // pending send read the chain without error, so it ends a run of failed reads: only the run's
    // failed window attempts stay counted (a crank failing in every window still pages).
    // A pass written off as stalled changes no state when it wakes: the pass after it decides.
    const token = { off: false }, keep = patch => { if (!token.off) Object.assign(state, patch); };
    let timer;
    const skip = (why, done = false) => {
      const kept = done ? 0 : Math.min(state.failures, state.windowFailures ?? 0);
      if (state.failures > kept && !token.off) { Object.assign(state, { failures: kept }, kept ? {} : { lastError: null }); cleared = true; }
      return (result = { skipped: why });
    };
    const stalled = new Promise((_, reject) => { timer = setTimeout(() => { token.off = true; reject(Error(`pass stalled for ${stall} ms`)); }, stall); timer.unref?.(); });
    try {
      return await Promise.race([fence.run(token, async () => {
        const cfg = await c.config();
        // Config read without error: with no mint there is nothing to do, and the pass succeeded.
        if (cfg.mint === NONE) { keep({ failures: 0, lastError: null }); return (result = { idle: 'no mint is set yet (SetMint)' }); }
        const mint = mintNow = new PublicKey(cfg.mint);
        keep({ mint: mint.toBase58() });
        const n = cfg.epoch, window = Math.min(lead, cfg.g.EPOCH_SECS), opens = cfg.epochStart + cfg.g.EPOCH_SECS - window + stagger(window);
        if (state.epoch === n) return skip(`epoch ${n} is done`, true);
        if (Math.floor(await t.now()) < opens) return skip(`epoch ${n}: the collect waits until ${new Date(opens * 1000).toISOString()}`);
        inWindow = true;
        if (state.pending && !(await settlePending())) return skip(`waiting to learn whether ${state.pending.signature} landed`);
        pumpRequired ??= clusterOfGenesis(await t.genesis()) === 'mainnet';
        const check = await creatorCheck(t, { mint, vault });
        if (!check.pump && !pumpRequired) {
          keep({ epoch: n, mismatch: null, failures: 0, lastError: null });
          return (result = { idle: `${mint.toBase58()} is not a pump.fun coin (it has no bonding curve)` });
        }
        const problems = check.pump ? check.problems : [`the configured mint ${mint.toBase58()} has no pump.fun bonding curve`];
        if (problems.length) {
          // Refused: nothing is sent while the creator is not the vault; the page says why.
          keep({ epoch: n, mismatch: problems, failures: 0, lastError: null });
          cry(`creator fees: epoch ${n}: refused, the creator is not the vault: ${problems.join('; ')}`);
          return (result = { refused: problems });
        }
        keep({ mismatch: null });
        const r = await collect(n, check);
        keep({ epoch: n, failures: 0, lastError: null });
        if (r.done.length) keep({ migrated: null, lastCollect: { epoch: n, at, steps: r.done } });
        return (result = { ...(r.done.length ? { collected: r.done } : { dust: sol(r.seen) }), ...(r.held ? { held: r.held } : {}) });
      }), stalled]);
    } catch (e) {
      if (e.mismatch) { Object.assign(state, { mismatch: e.mismatch, failures: 0 }); return (result = { refused: e.mismatch }); }
      // Count the run's failed window attempts apart from its read errors (a new run starts from this pass).
      state.windowFailures = (state.failures > 0 ? state.windowFailures ?? 0 : 0) + (inWindow ? 1 : 0);
      delete state.windowFailed;
      state.failures++; state.lastError = firstLine(e);
      if (creatorMigrated(e.programError)) state.migrated = { kind: e.kind ?? 'collect', ...e.programError, signature: e.signature ?? null };
      cry(`creator fees: pass failed (${state.failures} in a row): ${state.lastError}`);
      return (result = { failed: state.lastError });
    } finally {
      clearTimeout(timer);
      status.passes++; status.running = false; status.last = { at, ...(result ?? {}) };
      save();
      // Pages follow what a pass saw; one that only waited leaves them as they are, unless it ended a
      // run of failures (that page resolves). A pass that failed before the config returned keys them
      // by the mint the state last saw, so a restart never re-keys (and falsely resolves) an open page.
      if (result && (!result.skipped || cleared)) await pageNow(mintNow ?? state.mint);
    }
  };

  let timer = null, stopped = false;
  const schedule = first => {
    if (stopped) return;
    const r = Math.min(1, Math.max(0, Number(random()) || 0));
    timer = setTimeout(() => pass().catch(e => cry(`creator fees: ${e.message}`)).finally(() => schedule(false)), first ? Math.floor(r * every) : every + Math.round((2 * r - 1) * jitter));
    timer.unref?.();
  };
  return {
    pass, start: () => schedule(true), stop: () => { stopped = true; clearTimeout(timer); },
    status: () => ({ ...status, epoch: state.epoch, failures: state.failures, spent: { ...state.spent }, fallbacksToday: fallbacksToday(), pending: state.pending?.signature ?? null, lastCollect: state.lastCollect,
      open: [...(state.mismatch ? ['creator-mismatch'] : []), ...(state.migrated ? ['creator-migrated'] : []), ...(state.transferFailed ? ['creator-fee-transfer-failing'] : []), ...(state.failures >= failuresBeforePage ? ['creator-fee-crank-failing'] : [])] }),
  };
}
