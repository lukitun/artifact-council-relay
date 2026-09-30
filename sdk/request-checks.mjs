// Shape checks a relay runs on every request body before planning anything: an address that is not
// a base58 string of a 32-byte key, a settings patch naming a key the program does not have, or a
// thread that is not a short string, is the caller's error (400), never a thrown TypeError answered
// as a relay fault (502).
import { PublicKey } from '@solana/web3.js';
import { C, G, MAX_THREAD } from './layout.mjs';

const KEYS = ['agent', 'artifact', 'proposal', 'author', 'upload', 'target', 'key', 'recovery', 'cofounder', 'cofounderVia', 'via', 'preferred', 'feePayer'];
const PAYLOAD_KEYS = ['agent', 'to', 'key', 'upload'];
const refuse = message => Object.assign(Error(message), { status: 400 });

function address(v, name) {
  if (typeof v !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(v)) throw refuse(`${name} must be a base58 address`);
  try { new PublicKey(v); } catch { throw refuse(`${name} must be a base58 address`); }
}
function patch(p, names, max, kind) {
  if (!p || typeof p !== 'object' || Array.isArray(p) || !Object.keys(p).length) throw refuse(`a ${kind} payload needs a patch object`);
  for (const [k, v] of Object.entries(p)) {
    if (!names.includes(k)) throw refuse(`unknown ${kind} setting ${k}`);
    if (!Number.isSafeInteger(v) || v < 0 || v > max) throw refuse(`${kind} setting ${k} must be a whole number from 0 to ${max}`);
  }
}

/**
 * Throws a 400 naming the first malformed field. `required` names fields that must be present;
 * `secrets` names fields that are not addresses on this route (a renew's recovery secret).
 */
export function checkRequest(body, { required = [], secrets = [] } = {}) {
  for (const f of required) if (body[f] === undefined) throw refuse(`${f} is required`);
  for (const f of KEYS) if (body[f] !== undefined && !secrets.includes(f) && !(f === 'recovery' && body[f] === null)) address(body[f], f);
  // A thread goes into the signed bytes as a string of at most MAX_THREAD bytes (the program's limit).
  if (body.thread !== undefined && (typeof body.thread !== 'string' || Buffer.byteLength(body.thread) > MAX_THREAD)) throw refuse(`thread must be a string of at most ${MAX_THREAD} bytes`);
  if (body.payload === undefined) return;
  const p = body.payload;
  if (!p || typeof p !== 'object' || Array.isArray(p)) throw refuse('payload must be an object');
  for (const f of PAYLOAD_KEYS) if (p[f] !== undefined) address(p[f], `payload.${f}`);
  if (p.kind === 'settings') patch(p.patch, C, 0xffffffff, 'council');
  if (p.kind === 'global') patch(p.patch, G, Number.MAX_SAFE_INTEGER, 'global');
}
