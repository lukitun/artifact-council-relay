// The one cluster setting (owner, 30 September 2026: mainnet launch on 5 October). The relay, its
// cranker and seat, the operator commands, the checks and the relay package all read AC_CLUSTER
// (devnet or mainnet; devnet when unset) and refuse an RPC whose genesis hash is another cluster's.
// Mainnet has no public fallback RPC: every mainnet process names its paid RPC (Helius, owner 30
// September), so a missing AC_RPC can never silently read devnet. Devnet-only tools (the fee
// simulator, the devnet release setup, the devnet deploy) refuse mainnet by setting and by genesis.

export const GENESIS = Object.freeze({
  devnet: 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
  mainnet: '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
});
export const CLUSTERS = Object.freeze(Object.keys(GENESIS));
export const DEVNET_GENESIS = GENESIS.devnet;
export const MAINNET_GENESIS = GENESIS.mainnet;
/** The RPC a cluster falls back to when none is named: devnet's public endpoint; none on mainnet. */
export const PUBLIC_RPC = Object.freeze({ devnet: 'https://api.devnet.solana.com', mainnet: null });

/** The cluster a setting names: devnet when unset or empty; anything but devnet or mainnet is refused. */
export function clusterOf(value = process.env.AC_CLUSTER, name = 'AC_CLUSTER') {
  if (value === undefined || value === null || String(value).trim() === '') return 'devnet';
  const v = String(value).trim().toLowerCase();
  if (!CLUSTERS.includes(v)) throw Error(`${name} must be devnet or mainnet, not ${JSON.stringify(String(value))}`);
  return v;
}
/** The cluster whose genesis hash this is, or null. */
export const clusterOfGenesis = hash => CLUSTERS.find(c => GENESIS[c] === hash) ?? null;
/** The RPC to use on `cluster`: `rpc` when named, else the public devnet endpoint; mainnet needs one named. */
export function rpcFor(cluster, rpc) {
  if (rpc) return rpc;
  if (PUBLIC_RPC[cluster]) return PUBLIC_RPC[cluster];
  throw Error(`${cluster} has no public fallback RPC: set AC_RPC (or --rpc) to this cluster's paid RPC`);
}
/** "devnet SOL" on devnet, plain "SOL" on mainnet: what an operator funds a wallet with. */
export const solName = cluster => (cluster === 'mainnet' ? 'SOL' : 'devnet SOL');

/** Reads the genesis hash through an SDK transport (`genesis()`) or a web3.js Connection (`getGenesisHash()`). */
const genesisOf = t => (typeof t.genesis === 'function' ? t.genesis() : t.getGenesisHash());
/**
 * Refuses, before anything is read or sent for real, when `transport` answers another cluster's
 * genesis than `cluster`'s. `what` names the RPC in the refusal, `reason` why `cluster` is expected
 * (the cluster setting by default). Returns the cluster.
 */
export async function checkCluster(transport, cluster, what = 'the RPC', reason = null) {
  cluster = clusterOf(cluster);
  const hash = await genesisOf(transport), other = clusterOfGenesis(hash);
  if (hash !== GENESIS[cluster]) {
    throw Object.assign(Error(`${what} answers ${other ? `the ${other} genesis` : `an unknown genesis hash (${hash})`}, but ${reason ?? `the cluster setting is ${cluster} (AC_CLUSTER)`}: refusing before anything is sent`),
      { code: 'cluster-mismatch', cluster, answered: other ?? hash });
  }
  return cluster;
}
/**
 * For devnet-only tools: refuses AC_CLUSTER=mainnet before any RPC call, then any RPC that is not
 * devnet's (when `transport` is given). `tool` names the script in the refusal, `instead` says
 * what to use on mainnet.
 */
export async function devnetOnly(tool, { transport = null, env = process.env, instead = '' } = {}) {
  const cluster = clusterOf(env.AC_CLUSTER);
  if (cluster !== 'devnet') throw Object.assign(Error(`${tool} runs on devnet only, and AC_CLUSTER is ${cluster}${instead ? `: ${instead}` : ''}`), { code: 'devnet-only' });
  if (transport) {
    try { await checkCluster(transport, 'devnet', `${tool}'s RPC`); }
    catch (e) { if (e.code !== 'cluster-mismatch') throw e; throw Object.assign(Error(`${tool} runs on devnet only: ${e.message}${instead ? `; ${instead}` : ''}`), { code: 'devnet-only' }); }
  }
  return 'devnet';
}
