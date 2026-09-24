// Bounded, expiring public upload frames. Program-bound; keys and tokens never enter this store.
import { mkdirSync, readdirSync, readFileSync, writeFileSync, renameSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { chain } from './layout.mjs';
export function uploadJobs(directory, program, { ttl = 20 * 60_000, maximum = 1024 } = {}) {
  const memory = new Map();
  if (directory) mkdirSync(directory, { recursive: true, mode: 0o700 });
  const valid = root => { if (!/^[a-f0-9]{64}$/.test(root)) throw Error('invalid upload fingerprint'); return root; };
  const file = root => join(directory, valid(root) + '.json');
  const remove = root => { memory.delete(root); if (directory) try { unlinkSync(file(root)); } catch (e) { if (e.code !== 'ENOENT') throw e; } };
  const get = root => {
    valid(root); let job = memory.get(root);
    if (!job && directory) try { job = JSON.parse(readFileSync(file(root), 'utf8')); } catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (!job) return null;
    if (job.program !== program || job.at + ttl < Date.now()) { remove(root); return null; }
    const rebuilt = chain(Buffer.from(job.frame, 'base64'));
    if (rebuilt.root.toString('hex') !== root) throw Error('stored upload fingerprint mismatch');
    return { writes: rebuilt.writes, at: job.at };
  };
  return { get, remove, set(root, writes) {
    valid(root);
    const roots = directory ? readdirSync(directory).filter(f => /^[a-f0-9]{64}\.json$/.test(f)).map(f => f.slice(0,-5)) : [...memory.keys()];
    for (const key of roots) get(key); // Expire old jobs before enforcing the bound.
    const count = directory ? readdirSync(directory).filter(f => f.endsWith('.json')).length : memory.size;
    if (!get(root) && count >= maximum) throw Object.assign(Error('upload preparation queue full; retry later'), { status: 503 });
    const frame = Buffer.concat(writes.map(w => w.chunk));
    if (chain(frame).root.toString('hex') !== root) throw Error('upload fingerprint mismatch');
    const job = { program, at: Date.now(), frame: frame.toString('base64') };
    if (directory) { const target=file(root), temp=target+'.tmp'; writeFileSync(temp, JSON.stringify(job), { mode: 0o600 }); renameSync(temp,target); }
    else memory.set(root,job);
  } };
}
