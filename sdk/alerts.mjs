// Paging rules for operators (hardening plan 6.7), evaluated on raw program accounts so a snapshot,
// a fixture or a live read all go through the same decoder. Rules are pure: state and clock in,
// alerts out. Delivery goes through a notifier ({ name, send(message) }): Colony DMs (notify.mjs,
// owner 29 September). Alerts carry a stable key so a persisting condition pages once, then again only
// after the repeat interval, and a cleared one is reported as resolved.
import { readFileSync, writeFileSync, renameSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { TAG, DECODERS, PublicKey, APPLICATION_TTL_DAYS, SPENT_WEEKS } from './index.mjs';
import { oneLine } from './notify.mjs';

/** `passSecs`: one cranker pass, its jitter and a slow RPC included: what a crank-owed fix may take. */
export const LIMITS = { graceSecs: 15 * 60, passSecs: 5 * 60, distributionSecs: 3600, claimSecs: 86400, floatLamports: 100_000_000, runwayWeeks: 4 };
const ZERO_KEY = '11111111111111111111111111111111';
const iso = s => new Date(s * 1000).toISOString();
const sol = l => `${(l / 1e9).toFixed(4)} SOL`;

/** Decodes the accounts the rules read; an account of a watched kind that fails to decode is itself an alert. */
export function chainState(accounts) {
  const state = { config: null, proposals: [], uploads: [], epochs: [], relayers: [], agents: [], artifacts: [], bans: [], undecodable: [] };
  const into = { [TAG.CONFIG]: 'config', [TAG.PROPOSAL]: 'proposals', [TAG.UPLOAD]: 'uploads', [TAG.EPOCH]: 'epochs', [TAG.RELAYER]: 'relayers',
    [TAG.AGENT]: 'agents', [TAG.ARTIFACT]: 'artifacts', [TAG.RECORD]: 'bans' };
  for (const a of accounts) {
    const data = Buffer.isBuffer(a.data) || a.data instanceof Uint8Array ? Buffer.from(a.data) : Buffer.from(a.data, 'base64');
    const slot = into[data[0]]; if (!slot) continue;
    let value; try { value = { address: a.address, ...DECODERS[data[0]](data) }; } catch (e) { state.undecodable.push({ address: a.address, error: e.message }); continue; }
    if (slot === 'config') { if (state.config) state.undecodable.push({ address: a.address, error: 'second config account' }); else state.config = value; }
    // Of the records, only bans are read: when each agent was banned.
    else if (slot === 'bans') { if (value.kind === 'ban') state.bans.push({ agent: value.subject, time: value.time }); }
    else state[slot].push(value);
  }
  return state;
}

/** Weekly vault spending the reserve must cover: the average of the completed weeks on record (up
 *  to four), the basis of the reserve target (owner, 29 September: the target follows real
 *  spending), or the running week's when that is already more. No spending, no runway to run out. */
export function weeklySpend(config) {
  const n = Math.min(config.spentWeeks ?? 0, SPENT_WEEKS), weeks = (config.spent ?? []).slice(0, n);
  const average = n ? Math.floor(weeks.reduce((s, v) => s + v, 0) / n) : 0;
  return Math.max(average, config.weekSpent ?? 0);
}

/** The book's problems as check-devnet reports them. No weekly-cap check (review round 6): the
 *  program lets protocol records past the room (owner, 28 September) and a fee refund lowers the cap
 *  under deposits already taken (29 September), so `weekDeposits` above `weeklyCap` is a valid book. */
export function bookProblems(config, treasury) {
  const problems = [];
  // A cutover whose after-import step refused or was skipped (review round 7): the program refuses
  // every agent's signed action while the migration is open, and the setup key keeps its powers.
  if (config.migrationOpen) problems.push('the migration is still open: FinishMigration never ran, so the program refuses every agent action');
  if (config.setup !== undefined && config.setup !== ZERO_KEY) problems.push('setup is not finished: the setup key can still trust gateways and seed the vault');
  if (treasury === null || treasury < config.reserve + config.liabilities + config.carryHolder + config.carryRelayer) problems.push('treasury does not cover its book');
  return problems;
}

/** What AC_CHECK_REWARDS adds to check-devnet. Never a reserve under CAP_FLOOR (review round 6): a
 *  close refills only up to the target, then pays its epoch record from the reserve (owner,
 *  29 September), so a healthy low-spending book sits just under the floor; the reserve-runway alert
 *  judges the reserve. */
export function rewardProblems(config) {
  const problems = [];
  if (config.mint === ZERO_KEY) problems.push('devnet holder payout mint is not configured');
  if (config.paidTotal <= 0) problems.push('no treasury rewards paid yet');
  return problems;
}

/** `wallets`: [{ name, address, lamports (null if unreadable), float? }]. `now` in unix seconds;
 *  `day` the program's day in seconds (120 in the short-days test build). */
export function alertRules(state, { now, day = 86400, wallets = [], limits = {} }) {
  const L = { ...LIMITS, ...limits }, out = [];
  const alert = (rule, key, message) => out.push({ rule, key: `${rule}:${key}`, message });
  if (!Number.isFinite(now)) throw Error('alert rules need the current time');
  for (const u of state.undecodable ?? []) alert('undecodable-account', u.address, `account ${u.address} does not decode: ${u.error}`);
  const c = state.config;
  if (!c) alert('config-missing', 'config', 'program config account missing from state');
  else {
    const due = c.epochStart + c.g.EPOCH_SECS;
    if (now > due + L.graceSecs) alert('epoch-overdue', `epoch-${c.epoch}`, `epoch ${c.epoch} was due to close at ${iso(due)} and is still open`);
    if (c.distributing !== null) {
      const e = state.epochs.find(x => x.n === c.distributing), closed = e?.end ?? c.epochStart;
      if (now > closed + L.distributionSecs) alert('distribution-stalled', `epoch-${c.distributing}`, `holder distribution of epoch ${c.distributing} open since ${iso(closed)} (over ${L.distributionSecs / 60} minutes)`);
    }
    const spend = weeklySpend(c);
    if (spend > 0 && c.reserve < L.runwayWeeks * spend) alert('reserve-runway', 'reserve', `reserve ${sol(c.reserve)} covers ${(c.reserve / spend).toFixed(2)} weeks of the vault's recent spending (${sol(spend)} a week); floor is ${L.runwayWeeks} weeks`);
  }
  for (const p of state.proposals) if (p.status === 'voting' && now > p.closes + L.graceSecs) alert('proposal-unresolved', p.address, `proposal ${p.address} closed at ${iso(p.closes)} and is still voting`);
  for (const u of state.uploads) if (u.locked === ZERO_KEY && now > u.expires + L.graceSecs) alert('upload-expired', u.address, `upload ${u.address} expired at ${iso(u.expires)} and was not reclaimed`);
  // The cranker prunes every seat of a banned agent at the start of each pass (29 September): until
  // then the seat still counts toward its council's standing. One seat left after a pass pages.
  const agents = new Map((state.agents ?? []).map(a => [a.id, a])), banned = new Map((state.bans ?? []).map(b => [b.agent, b.time]));
  for (const art of state.artifacts ?? []) for (const m of art.members) {
    if (agents.get(m.id)?.status !== 'banned' || (art.id === 0 && art.members.length === 1)) continue;
    const since = banned.get(m.id) ?? -Infinity;
    if (now > since + L.passSecs) alert('ban-unpruned', `${art.address}:${m.id}`, `banned agent ${m.id} still holds its seat on ${art.name ?? art.address}${Number.isFinite(since) ? ` since its ban at ${iso(since)}` : ''}: the cranker did not prune it`);
  }
  // An application unanswered for its 30 days is the expiry crank's to close, charging its skips.
  for (const a of state.agents ?? []) for (const s of a.applications ?? []) {
    const due = s.at + APPLICATION_TTL_DAYS * day;
    if (now > due + L.passSecs) alert('application-expired-uncranked', `${a.id}:${s.artifact}`, `application of ${a.id} to ${s.artifact} expired at ${iso(due)} and was not cranked`);
  }
  // Relayer rewards unclaimed a day after the close: the record still open with work unclaimed, or
  // already retired with a relayer's work never claimed, which forfeits it to the relayer carry. The
  // program retires earlier only when every lamport owed is paid (an epoch with no relayer pool, for
  // one), so a retire inside the day forfeits nothing. Visible until the next epoch closes.
  for (const e of state.epochs) {
    if (c && c.distributing === e.n) continue;
    if (e.claimedWork < e.work && now > e.end + L.claimSecs + L.graceSecs) alert('epoch-unclaimed', `epoch-${e.n}`, `epoch ${e.n} closed ${iso(e.end)}: ${e.claimedWork} of ${e.work} work units claimed after a day`);
  }
  const held = new Set(state.epochs.map(e => e.workKey ?? e.n));
  if (c) for (const r of state.relayers) for (const w of r.work ?? [])
    if (w.units > 0 && !w.claimed && w.epoch === c.epoch - 1 && !held.has(w.epoch) && w.epoch !== c.workKey && now > c.epochStart + L.claimSecs) alert('epoch-unclaimed', `epoch-${w.epoch}:${r.key}`, `epoch ${w.epoch} was retired with ${w.units} work units of relayer ${r.key} unclaimed; that reward is forfeited to the relayer carry`);
  for (const w of wallets) {
    const float = w.float ?? L.floatLamports;
    if (w.lamports === null || w.lamports === undefined || !Number.isFinite(w.lamports)) alert('wallet-unreadable', w.address, `${w.name} wallet ${w.address} balance could not be read`);
    else if (w.lamports < float) alert('wallet-float', w.address, `${w.name} wallet ${w.address} holds ${sol(w.lamports)}, under its ${sol(float)} float`);
  }
  return out;
}

/** "name:ADDRESS[:floatLamports],..." → [{ name, address, float }]. Any malformed entry throws. */
export function parseWallets(text, floatLamports = LIMITS.floatLamports) {
  const seen = new Set();
  return String(text ?? '').split(',').map(s => s.trim()).filter(Boolean).map(entry => {
    const [name, address, float, extra] = entry.split(':');
    if (!name || !address || extra !== undefined || !/^[\w-]{1,32}$/.test(name)) throw Error(`bad operator wallet entry "${entry}"`);
    try { new PublicKey(address); } catch { throw Error(`bad operator wallet address for ${name}`); }
    const f = float === undefined ? floatLamports : Number(float);
    if (!Number.isSafeInteger(f) || f <= 0) throw Error(`bad float for operator wallet ${name}`);
    if (seen.has(address)) throw Error(`operator wallet ${address} listed twice`); seen.add(address);
    return { name, address, float: f };
  });
}

const readState = path => { try { const s = JSON.parse(readFileSync(path, 'utf8')); return s && typeof s.open === 'object' && s.open ? s : { open: {} }; } catch { return { open: {} }; } };
/** Sends what is new, due again, or resolved; records it only once the notifier accepted it.
 *  `now` in milliseconds. Returns { sent, firing, resolved }. A notifier failure throws. Each alert is
 *  one line of the DM: a message may carry chain data (an artifact name), shown by `oneLine`. */
export async function page(alerts, { notifier, statePath, now = Date.now(), repeatMs = 3_600_000, source = 'artifact-council', resolve = true }) {
  const state = readState(statePath), open = state.open, current = new Map(alerts.map(a => [a.key, a]));
  const firing = alerts.filter(a => !open[a.key] || now - open[a.key].paged >= repeatMs);
  const resolved = resolve ? Object.keys(open).filter(k => !current.has(k)) : [];
  if (!firing.length && !resolved.length) return { sent: false, firing: [], resolved: [] };
  if (!notifier) throw Error('alerts need paging but no notifier is configured (load the colony-api-key credential or set AC_COLONY_KEY_FILE)');
  const text = [`${source}: ${alerts.length} alert${alerts.length === 1 ? '' : 's'} open`, ...firing.map(a => `FIRING ${oneLine(a.message)}`), ...resolved.map(k => `RESOLVED ${oneLine(k)}`)].join('\n');
  await notifier.send({ source, at: new Date(now).toISOString(), text, open: alerts.length,
    firing: firing.map(a => ({ ...a, since: new Date(open[a.key]?.since ?? now).toISOString() })), resolved });
  for (const a of firing) open[a.key] = { since: open[a.key]?.since ?? now, paged: now };
  for (const k of resolved) delete open[k];
  mkdirSync(dirname(statePath), { recursive: true, mode: 0o700 });
  const tmp = `${statePath}.${randomBytes(4).toString('hex')}`;
  writeFileSync(tmp, JSON.stringify({ open }, null, 2), { mode: 0o600 }); renameSync(tmp, statePath);
  return { sent: true, firing, resolved };
}
