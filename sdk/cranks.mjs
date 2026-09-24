// One pass over every time-based step the protocol has. Anyone can run it; none of it needs a
// server of ours. Each step is idempotent and skipped when there is nothing to do.
import { TAG } from './layout.mjs';

const clears = (a, r, of, ab, rb) => of > 0 && a * 10000 > of * ab && r * 10000 < of * rb;

export async function crankOnce(c, payer, { log = () => {} } = {}) {
  const now = Math.floor(await c.t.now()); const done = [];
  const step = async (name, f) => { try { await f(); done.push(name); log(name); } catch (e) { log(`${name}: ${e.message.split('\n')[0]}`); } };
  for (const p of await c.all(TAG.PROPOSAL)) {
    if (p.status === 'voting' && (now >= p.closes || clears(p.approve, p.reject, p.roster.length, p.approveBps, p.rejectBps))) await step(`resolve ${p.address}`, () => c.resolve(p.address, payer));
    if (p.status === 'confirmation_pending' && now >= p.confirmUntil) await step(`expire ${p.address}`, () => c.expire(p.address, payer));
  }
  const cfg = await c.config();
  if (cfg.pending.some(q => q.at <= now)) await step('apply global settings', () => c.applyGlobal(payer));
  if (cfg.distributing !== null) await step(`distribute epoch ${cfg.distributing}`, () => c.distribute(payer));
  else if (now >= cfg.epochStart + cfg.epochLen) {
    await step(`close epoch ${cfg.epoch}`, () => c.closeEpoch(payer));
    if ((await c.config()).distributing !== null) await step('distribute', () => c.distribute(payer));
  }
  const relayers = await c.all(TAG.RELAYER);
  for (const e of await c.all(TAG.EPOCH)) {
    for (const r of relayers) for (const w of r.work) if (w.epoch === e.n && w.units > 0 && !w.claimed) await step(`claim ${e.n} for ${r.key}`, () => c.claim(e.n, r.key, payer));
    const fresh = await c.maybe(c.epochAddress(e.n), (await import('./layout.mjs')).decodeEpoch);
    if (fresh && (await c.config()).distributing !== e.n && (fresh.claimedWork === fresh.work || now >= fresh.end + (c.day ?? 86400))) await step(`retire epoch ${e.n}`, () => c.retire(e.n, payer));
  }
  for (const u of await c.all(TAG.UPLOAD)) if (u.locked === '11111111111111111111111111111111' && now >= u.expires) await step(`expire upload ${u.address}`, () => c.expireUpload(u.address, payer));
  return done;
}
