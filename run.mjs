import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { Council, Keypair, PublicKey, DEVNET_GENESIS } from './sdk/index.mjs';
import { RpcTransport } from './sdk/transport.mjs';
import { crankOnce } from './sdk/cranks.mjs';
import { colonyVerifier } from './sdk/colony.mjs';
import { startRelay } from './scripts/relay-server.mjs';

const mode = process.argv[2] || 'relay';
if (!['relay', 'gateway', 'crank'].includes(mode)) throw Error('Mode must be relay, gateway, or crank');
const rpc = process.env.AC_RPC, program = process.env.AC_PROGRAM;
if (!rpc || !program) throw Error('Set AC_RPC and AC_PROGRAM in .env');
const positive = (name, fallback) => {
  const value = Number(process.env[name] || fallback);
  if (!Number.isSafeInteger(value) || value <= 0) throw Error(`${name} must be a positive integer`);
  return value;
};
const port = positive('AC_PORT', 8899), perMinute = positive('AC_PER_MINUTE', 60), every = positive('AC_CRANK_SECONDS', 30);
if (port > 65535) throw Error('AC_PORT must be at most 65535');
const publicUrl = process.env.AC_PUBLIC_URL;
if (mode !== 'crank' && (!publicUrl || new URL(publicUrl).protocol !== 'https:' || new URL(publicUrl).hostname === 'relay.example.com')) throw Error('Set AC_PUBLIC_URL to your real public HTTPS relay URL');
if (mode === 'gateway' && (!process.env.COLONY_USERNAME || !process.env.COLONY_API_KEY)) throw Error('Gateway mode needs your own COLONY_USERNAME and COLONY_API_KEY');
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync('.local/payer.json', 'utf8'))));
const transport = new RpcTransport(rpc);
// Refuse non-devnet before any registration, crank, or submission can run.
if (await transport.genesis() !== DEVNET_GENESIS) throw Error('This operator release only supports Solana devnet');
const council = new Council({ transport, program: new PublicKey(program) });
await council.config();
const balance = (await transport.getAccount(payer.publicKey))?.lamports ?? 0;
if (balance < 20_000_000) throw Error('Fund the operator wallet with at least 0.02 devnet SOL before startup; deposits and activity may require more');
console.log(`Mode: ${mode} | operator: ${payer.publicKey.toBase58()} | program: ${program}`);
let stopping = false;
if (mode === 'crank') {
  if (!(await council.raw(council.relayerAddress(payer.publicKey)))) await council.registerRelayer(payer, { kind: 'relay', url: publicUrl || '' });
  process.on('SIGTERM', () => { stopping = true; });
  process.on('SIGINT', () => { stopping = true; });
  while (!stopping) {
    await crankOnce(council, payer, { log: message => console.log(new Date().toISOString(), message) }).catch(error => console.error(error.message));
    if (!stopping) await new Promise(r => setTimeout(r, every * 1000));
  }
} else {
  const colony = mode === 'gateway' ? {
    verifier: colonyVerifier({ apiKey: process.env.COLONY_API_KEY, recipient: process.env.COLONY_USERNAME, colonyId: process.env.COLONY_ID }),
    seed: Buffer.from(readFileSync('.local/gateway-seed', 'utf8').trim(), 'hex'),
    // Independent gateways create their own hosted identities. No founder manifest or keys.
    siteAgentId: () => null,
  } : null;
  if (colony && colony.seed.length !== 32) throw Error('Invalid gateway seed; use npm run setup');
  const { server } = await startRelay({ transport, program: council.program, payer, host: '127.0.0.1', port,
    url: publicUrl, gatewayDir: mode === 'gateway' ? resolve('.local/hosted') : null,
    uploadDir: resolve('.local/uploads'), openRegister: false, perMinute, colony });
  console.log(`Listening at http://127.0.0.1:${port}/v2. Use an HTTPS reverse proxy; preserve .local/.`);
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => { server.close(() => process.exit(0)); });
}
