// The rate-limit bucket for a request. X-Forwarded-For is read only when the TCP peer is a trusted
// proxy, and then only its last entry: the address that proxy itself appended or wrote. Every entry
// before it came from the client and is ignored. IPv6 clients share one bucket per /64, since a
// single host usually controls the whole prefix.
// The site proxies /v2 through Netlify, so behind nginx every such request comes from a Netlify edge
// address. Netlify signs those proxied requests (`signed = ...` in netlify.toml): an X-Nf-Sign JWS
// (HS256) under a secret shared with the gateway. Only a request carrying a valid signature, through
// a trusted proxy, is bucketed by the X-Nf-Client-Connection-Ip Netlify wrote.
import { isIP } from 'node:net';
import { createHmac, timingSafeEqual } from 'node:crypto';

export const LOOPBACK = ['127.0.0.1', '::1'];
const mapped = a => a.replace(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i, '$1');
export function normalizeAddress(a) {
  a = String(a ?? '').trim().replace(/^\[(.*)\]$/, '$1').replace(/%.*$/, '').toLowerCase();
  return isIP(a) ? mapped(a) : null;
}
function hextets(a) {
  let [head, tail = null] = a.split('::');
  const part = s => s ? s.split(':') : [];
  const v4 = x => { const m = x.at(-1)?.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/); if (m) x.splice(-1, 1, ((+m[1] << 8) | +m[2]).toString(16), ((+m[3] << 8) | +m[4]).toString(16)); return x; };
  const h = v4(part(head)), t = tail === null ? [] : v4(part(tail));
  return [...h, ...Array(8 - h.length - t.length).fill('0'), ...t].map(x => parseInt(x, 16));
}
export function bucketOf(address) {
  const a = normalizeAddress(address);
  if (!a) return 'unknown';
  if (isIP(a) === 4) return a;
  const h = hextets(a);
  if (h.slice(0, 5).every(x => x === 0) && h[5] === 0xffff) return [h[6] >> 8, h[6] & 255, h[7] >> 8, h[7] & 255].join('.');
  return `${h.slice(0, 4).map(x => x.toString(16)).join(':')}::/64`;
}
const one = h => Array.isArray(h) ? (h.length === 1 ? h[0] : null) : h ?? null;
/** True when `token` is a Netlify proxy signature (HS256 JWS) under `secret` that has not expired. */
export function edgeSigned(token, secret, now = Date.now() / 1000) {
  if (!secret || typeof token !== 'string') return false;
  const parts = token.trim().split('.');
  if (parts.length !== 3 || parts.some(p => !/^[A-Za-z0-9_-]+$/.test(p))) return false;
  try {
    const head = JSON.parse(Buffer.from(parts[0], 'base64url')), claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
    if (head?.alg !== 'HS256' || !claims || typeof claims !== 'object') return false;
    const want = createHmac('sha256', secret).update(`${parts[0]}.${parts[1]}`).digest(), got = Buffer.from(parts[2], 'base64url');
    if (got.length !== want.length || !timingSafeEqual(got, want)) return false;
    if (claims.iss !== undefined && claims.iss !== 'netlify') return false;
    return claims.exp === undefined || (typeof claims.exp === 'number' && claims.exp > now);
  } catch { return false; }
}
/** `trusted` lists the proxies' own addresses (default: loopback only); `edgeSecret` is the Netlify
 * proxy signing secret, when the site's edge proxies to this relay. */
export function clientAddress(req, trusted = LOOPBACK, { edgeSecret } = {}) {
  const peer = normalizeAddress(req.socket?.remoteAddress);
  const proxies = new Set(trusted.map(normalizeAddress).filter(Boolean));
  if (!peer || !proxies.has(peer)) return peer ?? 'unknown';
  if (edgeSecret && edgeSigned(one(req.headers['x-nf-sign']), edgeSecret)) {
    const edge = normalizeAddress(one(req.headers['x-nf-client-connection-ip']));
    if (edge) return edge;
  }
  const header = req.headers['x-forwarded-for'];
  const entries = (Array.isArray(header) ? header.join(',') : String(header ?? '')).split(',').map(s => s.trim()).filter(Boolean);
  return normalizeAddress(entries.at(-1)) ?? peer;
}
export const clientBucket = (req, trusted, edge) => bucketOf(clientAddress(req, trusted, edge));
