// A relay wallet's own spending: a daily ceiling with an alert. Only lamports the relay is out of
// pocket count; vault refunds in the same transaction do not. No relay takes a payment (self-pay
// mode, owner 30 September: an agent that pays signs its action self-paid and its own key is the fee
// payer), so there is nothing to credit. Persisted, so a restart never resets the day.
import { mkdirSync, readFileSync, writeFileSync, renameSync } from 'node:fs';
import { join } from 'node:path';
const DAY_MS = 86_400_000;
const refuse = (status, message, extra = {}) => Object.assign(Error(message), { status, ...extra });
/** What an agent is told when this wallet will spend no more today: pay with its own key, or come back. */
const CEILING = 'this relay has reached its daily spend ceiling: pay for the action with your own key (sign it self-paid, "selfPaid": true, and sign the transactions the 402 returns as their fee payer), or try again after 00:00 UTC or through another relay';
export function spendLedger(directory, { ceiling = 100_000_000, warnAt = 0.8, now = Date.now, alert = line => console.error(line) } = {}) {
  if (!Number.isSafeInteger(ceiling) || ceiling < 0) throw Error('daily spend ceiling must be a non-negative integer of lamports');
  const file = directory && join(directory, 'spend.json');
  if (directory) mkdirSync(directory, { recursive: true, mode: 0o700 });
  let s = { day: 0, spent: 0, alerted: 0 };
  if (file) try { s = { ...s, ...JSON.parse(readFileSync(file, 'utf8')) }; } catch (e) { if (e.code !== 'ENOENT') throw e; }
  let pending = 0;
  const save = () => { if (file) { writeFileSync(file + '.tmp', JSON.stringify(s), { mode: 0o600 }); renameSync(file + '.tmp', file); } };
  const roll = () => { const d = Math.floor(now() / DAY_MS); if (s.day !== d) { s.day = d; s.spent = 0; s.alerted = 0; save(); } };
  const level = () => s.spent >= ceiling ? 2 : s.spent >= ceiling * warnAt ? 1 : 0;
  const raise = to => {
    if (to <= s.alerted) return;
    s.alerted = to; save();
    alert(`AC_ALERT relay-spend level=${to === 2 ? 'ceiling' : 'warning'} spent=${s.spent} pending=${pending} ceiling=${ceiling} day=${new Date(s.day * DAY_MS).toISOString().slice(0, 10)}`);
  };
  const status = () => { roll(); return { day: new Date(s.day * DAY_MS).toISOString().slice(0, 10), spent: s.spent, pending, ceiling,
    remaining: Math.max(0, ceiling - s.spent - pending), alert: ['ok', 'warning', 'ceiling'][Math.max(level(), s.alerted)] }; };
  return {
    status,
    /**
     * Holds `worst` lamports before anything is sent: what the wallet can lose, `exposure` (for a
     * vault-funded action, what a moved chain would leave it paying: its `atRisk`), comes out of
     * today's ceiling. Refused with 402 when the ceiling would be crossed, so concurrent requests can
     * never overshoot it together. Whatever is lost still settles.
     */
    reserve(worst, { exposure = worst } = {}) {
      roll();
      const own = Math.max(0, Math.min(worst, exposure));
      if (own > 0 && s.spent + own > ceiling) { raise(2); throw refuse(402, CEILING, { detail: { spend: status() } }); }
      // Refused before anything is sent (`unsent`): a caller may try again without fear of a double.
      if (own > 0 && s.spent + pending + own > ceiling) throw refuse(503, 'the rest of today\'s spend ceiling is held by transactions in flight; retry shortly', { unsent: true });
      pending += own; save();
      return { own, worst };
    },
    /** `actual` is what the wallet really lost (null when unknown: then the whole hold is spent). */
    settle(ticket, actual) {
      roll();
      pending -= ticket.own;
      const cost = actual == null ? ticket.worst : Math.max(0, actual);
      s.spent += cost; save();
      raise(level());
      return cost;
    },
  };
}
