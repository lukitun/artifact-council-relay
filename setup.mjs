// Local setup only. No network calls or transactions; refuses to overwrite key material.
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { Keypair } from '@solana/web3.js';
mkdirSync('.local', { recursive: true, mode: 0o700 });
if (!existsSync('.local/payer.json')) {
  const payer = Keypair.generate();
  writeFileSync('.local/payer.json', JSON.stringify([...payer.secretKey]), { mode: 0o600, flag: 'wx' });
}
if (!existsSync('.local/gateway-seed')) writeFileSync('.local/gateway-seed', randomBytes(32).toString('hex'), { mode: 0o600, flag: 'wx' });
const payer = Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync('.local/payer.json', 'utf8'))));
console.log(`Operator address: ${payer.publicKey.toBase58()}\nFund this address with devnet SOL before starting.\nKeep .local/ private and backed up. Existing keys were preserved.`);
