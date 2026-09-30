// Operator pages as thecolony.cc DMs from @agentpedia to the owner's Colony account (owner, 29 September:
// no Slack, Discord or email). The API key reaches a unit only as a systemd credential, named by
// AC_COLONY_KEY_FILE; it is exchanged for a JWT (24h) and neither ever appears in an error or a log.
// The same key sends the members' inbox digest (inbox-digest.mjs) through `colonyMessenger`.
import { readFileSync } from 'node:fs';
import { isIP } from 'node:net';
import { COLONY_API, COLONY_USERNAME, breakCodes } from './colony.mjs';

export const ALERT_RECIPIENT = 'lukitun';
/** Colony DM bodies stay short: a long page keeps its head and says how much it dropped. */
export const MAX_DM = 4000;
const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

// thecolony.cc usernames, underscores included (owner, 30 September).
const USERNAME = COLONY_USERNAME;
/** Colony DM bodies stay short: a long text keeps its head and says how much it dropped. */
const clip = text => text.length <= MAX_DM ? text : `${text.slice(0, MAX_DM - 40)}\n… ${text.length - (MAX_DM - 40)} more characters`;
/** Text from the chain (a handle, an artifact name) or an alert, as it goes into a DM or a post
 *  template: on one line, control, line-break and bidirectional-override characters shown as escapes
 *  (`\n`, `\u202e`), so none can start a line of its own or reorder the text around it; and any
 *  sign-in code in it broken (colony.mjs `breakCodes`), so quoting it proves no one's sign-in. */
export const oneLine = text => breakCodes(String(text ?? '').replace(/[\p{Cc}\p{Zl}\p{Zp}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
  ch => ({ '\n': '\\n', '\r': '\\r', '\t': '\\t' })[ch] ?? `\\u${ch.codePointAt(0).toString(16).padStart(4, '0')}`));

/** DMs from @agentpedia to any Colony username, one JWT shared by every recipient: `send(to, text)`.
 *  `api` is https, or plain http only to this machine (tests). */
export function colonyMessenger({ apiKey, api = COLONY_API, fetch = globalThis.fetch, timeoutMs = 10_000, now = Date.now }) {
  if (typeof apiKey !== 'string' || !apiKey.trim()) throw Error('the Colony alert key is empty');
  let u; try { u = new URL(api); } catch { throw Error('the Colony API is not a valid URL'); }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (LOCAL_HOSTS.has(u.hostname) || (isIP(u.hostname) === 4 && u.hostname.startsWith('127.')))))
    throw Error('the Colony API must be https (plain http only to this machine)');
  const base = u.href.replace(/\/+$/, ''), key = apiKey.trim();
  let jwt = null;
  const post = async (where, path, body, bearer) => {
    try {
      return await fetch(`${base}${path}`, { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
        headers: { 'content-type': 'application/json', ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) }, body: JSON.stringify(body) });
    } catch (e) {
      // `unreachable`: Colony did not answer. A timed-out request may still have been delivered
      // (`uncertain`); one that failed to connect was not.
      const timedOut = e.name === 'TimeoutError';
      throw Object.assign(Error(`${where} unreachable: ${timedOut ? 'timed out' : 'request failed'}`), { unreachable: true, uncertain: timedOut });
    }
  };
  async function token(where) {
    if (jwt && jwt.expires > now()) return jwt.value;
    // Every failure here is the key's or Colony's, never the recipient's: `auth` tells a caller
    // sending to many recipients to stop rather than try the exchange again for each.
    let r;
    try { r = await post(where, '/auth/token', { api_key: key }); } catch (e) { throw Object.assign(e, { auth: true, uncertain: false }); }
    if (!r.ok) throw Object.assign(Error(`${where}: token exchange answered ${r.status}`), { auth: true, tokenStatus: r.status });
    const value = (await r.json().catch(() => null))?.access_token;
    if (typeof value !== 'string' || !value) throw Object.assign(Error(`${where}: token exchange returned no access_token`), { auth: true });
    jwt = { value, expires: now() + 23 * 3600_000 };
    return value;
  }
  return {
    /** Sends `text` to @`to`. A refusal throws with the HTTP status in `status` (429: slow down); a
     *  failed token exchange throws with `auth`; no answer throws with `unreachable`, and with
     *  `uncertain` when the DM itself timed out and may have been delivered. */
    async send(to, text) {
      if (!USERNAME.test(to)) throw Error('invalid Colony recipient');
      const where = `Colony DM to @${to}`, body = clip(String(text ?? ''));
      let r = await post(where, `/messages/send/${to}`, { body }, await token(where));
      // A JWT revoked early is exchanged once more; a second refusal is the key's fault.
      if (r.status === 401) { jwt = null; r = await post(where, `/messages/send/${to}`, { body }, await token(where)); }
      if (!r.ok) throw Object.assign(Error(`${where} answered ${r.status}`), { status: r.status });
    },
  };
}

/** Sends `message.text` as a DM to `to`. `api` is https, or plain http only to this machine (tests). */
export function colonyNotifier({ apiKey, to = ALERT_RECIPIENT, api = COLONY_API, fetch = globalThis.fetch, timeoutMs = 10_000, now = Date.now }) {
  if (typeof apiKey !== 'string' || !apiKey.trim()) throw Error('the Colony alert key is empty');
  if (!USERNAME.test(to)) throw Error('invalid Colony alert recipient');
  const messenger = colonyMessenger({ apiKey, api, fetch, timeoutMs, now });
  return { name: `colony @${to}`, send: message => messenger.send(to, message?.text) };
}

/** The notifier the units run: null when AC_COLONY_KEY_FILE is unset; a named but unreadable key throws. */
export function notifierFromEnv(env = process.env, opts = {}) {
  const file = env.AC_COLONY_KEY_FILE; if (!file) return null;
  let apiKey; try { apiKey = readFileSync(file, 'utf8'); } catch { throw Error('the Colony alert key (AC_COLONY_KEY_FILE) cannot be read'); }
  return colonyNotifier({ apiKey, ...(env.AC_COLONY_API ? { api: env.AC_COLONY_API } : {}), ...opts });
}

/** The digest's messenger: null when AC_COLONY_KEY_FILE is unset; a named but unreadable key throws. */
export function messengerFromEnv(env = process.env, opts = {}) {
  const file = env.AC_COLONY_KEY_FILE; if (!file) return null;
  let apiKey; try { apiKey = readFileSync(file, 'utf8'); } catch { throw Error('the Colony key (AC_COLONY_KEY_FILE) cannot be read'); }
  return colonyMessenger({ apiKey, ...(env.AC_COLONY_API ? { api: env.AC_COLONY_API } : {}), ...opts });
}
