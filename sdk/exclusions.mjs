// Wallets the holder snapshot never pays (`holder-exclusions.txt`, also compiled into the program as
// rewards.rs `excluded_holder`): pools, the vault, burn addresses.
import { readFileSync } from 'node:fs';
import { PublicKey } from '@solana/web3.js';

export function parseExclusions(text) {
  return new Set(text.split('\n').map(line => line.split('#')[0].trim()).filter(Boolean)
    .map(address => new PublicKey(address).toBase58()));
}
/** The exclusion list the program was built with. */
export const exclusions = () => parseExclusions(readFileSync(new URL('../holder-exclusions.txt', import.meta.url), 'utf8'));
