// Content-addressed copies of sealed page frames, keyed by their on-chain fingerprint (the chain
// root under the protocol's fixed chunking). Transaction history is a provider's retention policy;
// these copies are not trusted either: every byte read back must hash to the record's fingerprint.
// A store is { name, put(frame) → key, get(key) → Buffer | null, has(key) }; a source needs only get.
import { mkdirSync, writeFileSync, renameSync, existsSync, unlinkSync, openSync, fstatSync, readSync, closeSync, constants } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { chain, decodeFrame, MAX_TEXT, MAX_CHARS, TAG } from './layout.mjs';

export const MAX_FRAME = MAX_TEXT + 12;
const KEY = /^[0-9a-f]{64}$/;
const hexOf = root => Buffer.isBuffer(root) || root instanceof Uint8Array ? Buffer.from(root).toString('hex') : String(root);
export const frameKey = frame => chain(Buffer.from(frame)).root.toString('hex');
export function checkKey(key) { key = hexOf(key); if (!KEY.test(key)) throw Error('frame key must be a 32-byte hex fingerprint'); return key; }

/** The page bytes of `frame` if it is exactly the text a record names: same length, same chain root,
 *  one well-formed frame of valid UTF-8 within the page limit. Anything else throws. */
export function frameText(frame, { root, len }) {
  frame = Buffer.from(frame);
  if (len !== undefined && frame.length !== len) throw Error('frame has the wrong length');
  if (frame.length > MAX_FRAME) throw Error('frame exceeds the page limit');
  if (frameKey(frame) !== checkKey(root)) throw Error('frame does not hash to its fingerprint');
  const text = decodeFrame(frame);
  const s = new TextDecoder('utf-8', { fatal: true }).decode(text);
  if ([...s].length > MAX_CHARS) throw Error('frame exceeds the character limit');
  return text;
}

/** At most one frame from a regular file; null if absent. A store may be an untrusted mirror, so a
 *  device, a pipe or an oversized file is refused before anything is read into memory. */
function readFrameFile(file) {
  let fd;
  try { fd = openSync(file, constants.O_RDONLY | constants.O_NONBLOCK); } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) throw Error('frame copy is not a regular file');
    if (st.size > MAX_FRAME) throw Error('frame copy is larger than one frame');
    const buf = Buffer.alloc(MAX_FRAME + 1); let n = 0, r;
    while (n < buf.length && (r = readSync(fd, buf, n, buf.length - n, n)) > 0) n += r;
    if (n > MAX_FRAME) throw Error('frame copy is larger than one frame');
    return buf.subarray(0, n);
  } finally { closeSync(fd); }
}

/** A directory store: `<dir>/<2 hex>/<64 hex>`, written atomically, never overwritten with other bytes. */
export function localFrameStore(dir) {
  const path = key => join(dir, key.slice(0, 2), key);
  const valid = (file, key) => { try { const b = readFrameFile(file); return b && frameKey(b) === key ? b : null; } catch { return null; } };
  return {
    name: `dir:${dir}`,
    async put(frame) {
      frame = Buffer.from(frame);
      if (frame.length > MAX_FRAME) throw Error('frame exceeds the page limit');
      decodeFrame(frame);
      const key = frameKey(frame), file = path(key);
      if (valid(file, key)) return key;
      mkdirSync(join(dir, key.slice(0, 2)), { recursive: true, mode: 0o755 });
      const tmp = `${file}.tmp-${randomBytes(6).toString('hex')}`;
      try { writeFileSync(tmp, frame, { mode: 0o644, flag: 'wx' }); renameSync(tmp, file); }
      finally { if (existsSync(tmp)) unlinkSync(tmp); }
      return key;
    },
    async get(key) { return readFrameFile(path(checkKey(key))); },
    async has(key) { key = checkKey(key); return !!valid(path(key), key); },
  };
}

/** A read-only source over any HTTP(S) mirror that serves `<base>/<64 hex>`: a public bucket, a
 *  gateway, another operator's store. Bytes are capped at one frame and checked by the caller. */
export function httpFrameSource(base, { fetch = globalThis.fetch, timeoutMs = 15_000 } = {}) {
  const url = new URL(base); if (!['https:', 'http:'].includes(url.protocol)) throw Error('frame source must be an http(s) URL');
  const prefix = url.href.replace(/\/?$/, '/');
  return {
    name: `url:${url.origin}${url.pathname}`,
    async get(key) {
      key = checkKey(key);
      const res = await fetch(prefix + key, { signal: AbortSignal.timeout(timeoutMs), redirect: 'error' });
      if (res.status === 404) return null;
      if (!res.ok) throw Error(`frame source answered ${res.status}`);
      if (Number(res.headers.get('content-length') ?? 0) > MAX_FRAME) throw Error('frame source sent more than one frame');
      const parts = []; let n = 0;
      for await (const part of res.body) { n += part.length; if (n > MAX_FRAME) throw Error('frame source sent more than one frame'); parts.push(Buffer.from(part)); }
      return Buffer.concat(parts);
    },
  };
}

/** Copies one frame to every store; succeeds if at least one holds it afterwards. */
export async function archiveFrame(stores, frame) {
  if (!stores.length) throw Error('no frame store configured');
  const stored = [], failed = []; let key;
  for (const s of stores) {
    try { key = await s.put(frame); if (await s.has(key)) stored.push(s.name); else failed.push({ store: s.name, error: 'not readable after write' }); }
    catch (e) { failed.push({ store: s.name, error: e.message }); }
  }
  if (!stored.length) throw Error(`frame not archived: ${failed.map(f => `${f.store}: ${f.error}`).join('; ')}`);
  return { key, stored, failed };
}

/** The first source's bytes that are exactly the named text; bad or unreachable sources are skipped. */
export async function textFromSources(sources, ref) {
  const rejected = [];
  for (const s of sources) {
    try {
      const bytes = await s.get(checkKey(ref.root));
      if (!bytes) continue;
      return { text: frameText(bytes, ref), source: s.name, rejected };
    } catch (e) { rejected.push({ source: s.name, error: e.message }); }
  }
  return { text: null, source: null, rejected };
}

const TEXT_KINDS = ['genesis', 'content', 'imported'];
/** One sweep: every recorded text version and every completed upload not yet held by all stores is
 *  rebuilt from chain history (checked against its fingerprint) and copied. */
export async function archiveSealed(council, stores, { log = () => {} } = {}) {
  const refs = new Map();
  for (const r of await council.all(TAG.RECORD)) if (TEXT_KINDS.includes(r.kind) && r.len > 0) refs.set(r.content.toString('hex'), { subject: r.subject, len: r.len, root: r.content });
  for (const u of await council.all(TAG.UPLOAD)) if (u.complete && u.len > 0 && !refs.has(u.root.toString('hex'))) refs.set(u.root.toString('hex'), { subject: u.address, len: u.len, root: u.root });
  const report = { texts: refs.size, archived: 0, present: 0, failed: [] };
  for (const [key, ref] of refs) {
    const missing = [];
    for (const s of stores) if (!(await s.has(key).catch(() => false))) missing.push(s);
    if (!missing.length) { report.present++; continue; }
    try {
      const frame = await council.frameFromTransactions(ref.subject, ref.len, ref.root);
      frameText(frame, ref);
      const { failed } = await archiveFrame(missing, frame);
      for (const f of failed) report.failed.push({ key, ...f });
      report.archived++; log(`archived ${key}`);
    } catch (e) { report.failed.push({ key, error: e.message }); log(`could not archive ${key}: ${e.message}`); }
  }
  return report;
}
