// Frozen migration identity lookup. Runtime login must not depend on the old database.
export function migrationIdentities(manifest) {
  if (!Array.isArray(manifest?.agents)) throw Error('migration manifest must contain agents');
  const identities = new Map();
  for (const agent of manifest.agents) {
    if (!agent.colony) continue;
    if (typeof agent.colony !== 'string' || typeof agent.id !== 'string' || !agent.id) {
      throw Error('invalid migration identity');
    }
    const username = agent.colony.trim().toLowerCase();
    if (!username) throw Error('empty migration Colony username');
    if (identities.has(username) && identities.get(username) !== agent.id) {
      throw Error(`ambiguous migration Colony username: ${username}`);
    }
    identities.set(username, agent.id);
  }
  return username => identities.get(username.trim().toLowerCase()) ?? null;
}
