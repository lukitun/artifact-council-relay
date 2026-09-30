// Frozen migration identity lookup. Runtime login must not depend on the old database.
// An entry may pin `colony_id` (the immutable Colony user id); a pinned entry answers only that id.
// The gateway gives a migrated identity only to an attested id (a pin, or the operator's file).
import { createHash } from 'node:crypto';
import { Keypair } from '@solana/web3.js';
import { validColonyId } from './colony.mjs';

/** The deterministic hosted key of the identity `label`, held by the gateway whose seed it is.
 *  Migrated hosted agents keep their id, signer and gateway, so their keys carry over. */
export function hostedKey(gatewaySeed, label) {
  return Keypair.fromSeed(createHash('sha256').update(gatewaySeed).update('agent:').update(label).digest());
}

export function migrationIdentities(manifest) {
  if (!Array.isArray(manifest?.agents)) throw Error('migration manifest must contain agents');
  const identities = new Map();
  for (const agent of manifest.agents) {
    if (!agent.colony) continue;
    if (typeof agent.colony !== 'string' || typeof agent.id !== 'string' || !agent.id) {
      throw Error('invalid migration identity');
    }
    if (agent.colony_id !== undefined && agent.colony_id !== null && !validColonyId(agent.colony_id)) throw Error('invalid migration Colony id');
    const username = agent.colony.trim().toLowerCase();
    if (!username) throw Error('empty migration Colony username');
    const entry = { id: agent.id, pin: agent.colony_id == null ? null : String(agent.colony_id) }, seen = identities.get(username);
    if (seen && (seen.id !== entry.id || seen.pin !== entry.pin)) throw Error(`ambiguous migration Colony username: ${username}`);
    identities.set(username, entry);
  }
  const lookup = (username, colonyId) => {
    const hit = identities.get(username.trim().toLowerCase());
    return !hit || (hit.pin && (colonyId === undefined || String(colonyId) !== hit.pin)) ? null : hit.id;
  };
  /** Manifest agent id → pinned Colony user id: the gateway's attestations for migrated identities. */
  lookup.pins = Object.fromEntries([...identities.values()].filter(e => e.pin).map(e => [e.id, e.pin]));
  /** Every identity label the manifest can hand out: its agent ids and the pre-hardening `colony:<username>` labels. */
  lookup.labels = [...[...identities.values()].map(e => e.id), ...[...identities.keys()].map(u => `colony:${u}`)];
  return lookup;
}
