// The operator's payout: what the relay key holds, what the program still owes it, and a transfer of
// everything above the float to the operator's own wallet (owner, 30 September: operators take their
// rewards out easily). The relay key IS the payout wallet: relay rewards are only ever paid to it.
// MIT licensed.
import { PublicKey, SystemProgram } from '@solana/web3.js';
import { decodeRelayer, RESERVED_KEYS, TAG } from './layout.mjs';
import { CLAIM_FEE } from './cranks.mjs';

/** A signature's network fee: one signature, no priority fee (v1.mjs builds with none). */
export const WITHDRAW_FEE = 5000;
/** The float a withdrawal leaves by default: what a relay runs on (operator guide, "Rewards and costs"). */
export const DEFAULT_KEEP = 200_000_000;
/** Fees kept beyond the rent-exempt minimum, whatever --keep says: the relay's next few transactions. */
export const FLOOR_FEES = 10;
const sol = lamports => `${(lamports / 1e9).toFixed(9).replace(/\.?0+$/, '')} SOL`;
const refuse = message => { throw Object.assign(Error(message), { refused: true }); };

/** `text` (SOL, a decimal such as 0.2) as lamports; refused unless it is a plain non-negative amount. */
export function parseSol(text, name = 'amount') {
  if (typeof text !== 'string' || !/^\d+(\.\d{1,9})?$/.test(text.trim())) refuse(`${name} must be an amount of SOL such as 0.2 (got ${text})`);
  const [whole, frac = ''] = text.trim().split('.');
  const lamports = Number(BigInt(whole) * 1_000_000_000n + BigInt(frac.padEnd(9, '0')));
  if (!Number.isSafeInteger(lamports)) refuse(`${name} is too large`);
  return lamports;
}

/** Why SOL sent to `to` would be lost or refused, or null: this key itself, a program-derived
 *  (off-curve) address, a reserved or program account, anything but an ordinary wallet. */
export function destinationProblem(to, from, account) {
  let dest; try { dest = new PublicKey(to); } catch { return `--to ${to} is not a Solana address`; }
  if (dest.equals(new PublicKey(from))) return '--to is this relay key itself: name your own wallet';
  if (RESERVED_KEYS.includes(dest.toBase58())) return `--to ${dest.toBase58()} is a reserved program or sysvar address`;
  if (!PublicKey.isOnCurve(dest.toBytes())) return `--to ${dest.toBase58()} is off-curve (a program-derived address no key can sign for): name an ordinary wallet address`;
  if (account?.executable) return `--to ${dest.toBase58()} is a program`;
  if (account && !new PublicKey(account.owner).equals(SystemProgram.programId)) return `--to ${dest.toBase58()} is an account held by the program ${new PublicKey(account.owner).toBase58()}, not a wallet`;
  if (account?.data?.length) return `--to ${dest.toBase58()} holds data: not an ordinary wallet`;
  return null;
}

/**
 * What a withdrawal from `from` would send, read now: { balance, keep, floor, amount, fee, to, ixs }.
 * `keep` (lamports) stays on the key; it is never below `floor` (the rent-exempt minimum plus a few
 * fees), which is refused rather than quietly raised. With `genesis`, a transport on another cluster
 * is refused before anything else is read. Throws an Error marked `refused` with the reason.
 */
export async function planWithdraw(t, { from, to, keep = DEFAULT_KEEP, genesis = null, network = 'this network' }) {
  if (genesis) {
    const actual = await t.genesis();
    if (actual !== genesis) refuse(`the RPC serves another cluster (genesis ${actual}), not ${network}: nothing was sent`);
  }
  const fromKey = new PublicKey(from);
  let dest; try { dest = new PublicKey(to); } catch { refuse(`--to ${to} is not a Solana address`); }
  const [mine, there, rentMin] = await Promise.all([t.getAccount(fromKey), t.getAccount(dest), t.rent(0)]);
  const bad = destinationProblem(dest, fromKey, there);
  if (bad) refuse(bad);
  const floor = Number(rentMin) + FLOOR_FEES * WITHDRAW_FEE, balance = mine?.lamports ?? 0;
  if (!Number.isSafeInteger(keep) || keep < 0) refuse('--keep must be a non-negative amount of SOL');
  if (keep < floor) refuse(`--keep ${sol(keep)} is below what this key needs to stay open and pay its next fees (${sol(floor)}): keep at least that`);
  const amount = balance - keep - WITHDRAW_FEE;
  if (amount <= 0) refuse(`nothing to withdraw: this key holds ${sol(balance)}, and ${sol(keep)} stays as its float (plus the ${sol(WITHDRAW_FEE)} fee)`);
  if ((there?.lamports ?? 0) + amount < Number(rentMin)) refuse(`${dest.toBase58()} holds no SOL yet, and ${sol(amount)} would not open it (at least ${sol(Number(rentMin) - (there?.lamports ?? 0))}): keep less or withdraw later`);
  return { from: fromKey.toBase58(), to: dest.toBase58(), balance, keep, floor, amount, fee: WITHDRAW_FEE, recipientBalance: there?.lamports ?? 0,
    ixs: [SystemProgram.transfer({ fromPubkey: fromKey, toPubkey: dest, lamports: amount })] };
}

/** Sends a plan from `planWithdraw`, signed by `payer` (the relay key); returns the signature. The
 *  balance is read again first: a relay cranking meanwhile may have spent fees, and the planned amount
 *  is sent only while the float and the fee still stay behind. */
export async function sendWithdraw(t, plan, payer) {
  if (payer.publicKey.toBase58() !== plan.from) refuse('the plan was made for another key');
  const now = (await t.getAccount(payer.publicKey))?.lamports ?? 0;
  if (now < plan.amount + plan.keep + plan.fee) refuse(`this key now holds ${sol(now)}, less than the planned ${sol(plan.amount)} plus the ${sol(plan.keep)} float and the fee (it spent meanwhile, a relay cranking perhaps): run it again`);
  return t.send(plan.ixs, payer);
}

/**
 * What the program still owes the relay key `key`, read from its relayer record and the epoch records:
 * { registered, accrued, claimable, claimableUnits, tooSmall, tooSmallUnits, openUnits, minPayout }.
 * `accrued` sits in the record until it reaches MIN_PAYOUT (the current setting: the program compares
 * at each claim, rewards.rs); `claimable` estimates the closed epochs' unclaimed shares the crank
 * claims each pass, those worth more than a claim's fee (cranks.mjs CLAIM_FEE); `tooSmall` is the rest,
 * never claimed, rolled forward when the epoch retires a day after it ended; `openUnits` is work in
 * the epoch still open, priced when it closes.
 */
export async function pendingRewards(council, key) {
  const cfg = await council.config();
  const record = await council.maybe(council.relayerAddress(new PublicKey(key)), decodeRelayer);
  const out = { registered: !!record, accrued: record?.accrued ?? 0, claimable: 0, claimableUnits: 0, tooSmall: 0, tooSmallUnits: 0, openUnits: 0, minPayout: cfg.g.MIN_PAYOUT };
  const unclaimed = (record?.work ?? []).filter(w => w.units > 0 && !w.claimed);
  if (!unclaimed.length) return out;
  const epochs = await council.all(TAG.EPOCH);
  for (const w of unclaimed) {
    const e = epochs.find(x => x.workKey === w.epoch && x.relayerPaid < x.relayerPool);
    if (e) {
      const share = Math.floor(e.relayerPool * w.units / Math.max(1, e.work));
      if (share > CLAIM_FEE) { out.claimable += share; out.claimableUnits += w.units; } else { out.tooSmall += share; out.tooSmallUnits += w.units; }
    } else if (w.epoch >= cfg.workKey) out.openUnits += w.units;
  }
  return out;
}
