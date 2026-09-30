// pump.mjs — pump.fun bonding curve + PumpSwap instruction builders and a read-only verifier for the
// Artifact Council launch (owner plan, 30 September: create_v2 with the vault PDA as a plain creator
// address, SOL pairing, Token-2022 mint, one buy in the same transaction; creator fees collected
// into the vault without any vault signature).
//
// The pump rehearsal's tested module (30 September, sha256 165d9202…), brought into the SDK for the
// relays' creator-fee crank (creator-fees.mjs). Only the web3 import changed: every builder, decoder
// and quote is byte for byte the rehearsal's, and the launch kit keeps its own reviewed copy.
//
// Dependency-light: only @solana/web3.js. No Anchor, no spl-token. Nothing here sends a
// transaction: builders return TransactionInstructions, readers only read accounts.
//
// Sources, checked by solana/test/pump-idl.test.mjs and pump-sdk.test.mjs: pump-public-docs IDLs
// (pump.json, pump_amm.json, pump_fees.json, repo pump-fun/pump-public-docs at cb188ce; copies kept outside git
// with the pump fixtures, solana/scripts/fetch-pump-fixtures.mjs) and the official SDKs @pump-fun/pump-sdk 2.0.0 and
// @pump-fun/pump-swap-sdk 1.20.0 (instruction bytes and account lists compared one to one), plus an
// offline LiteSVM run of the real devnet binaries (rehearsal-svm.mjs; the pump fixtures, outside git, hold
// the same binaries and state). What that run showed:
// - create_v2 + ATA + legacy buy fit one legacy transaction (1211 bytes with a 48-byte uri; the limit
//   is 1232, so a 67+ byte IPFS uri plus a priority-fee instruction no longer fits). With buy_v2 it
//   needs a v1 transaction (1457 bytes; mainnet accepts v1). ~205k CU. At most 2 extra buyers fit
//   (instruction trace limit 64), each signing the transaction. A v1 launch transaction must set
//   loadedAccountsDataSizeLimit >= 5 MiB (8 MiB advised): it loads 4,695,775 bytes (buy_v2) /
//   4,586,362 (legacy buy), so the repo's buildV1 default of 4 MiB fails with
//   MaxLoadedAccountsDataSizeExceeded (unsigned simulation on live devnet, never sent).
// - bonding_curve.creator = the vault; the vault never signs anything. Mint: Token-2022, 6 decimals,
//   supply 1e15, mint and freeze authority none, extensions MetadataPointer + TokenMetadata only,
//   metadata update authority none (immutable). New curves are 174 bytes.
// - Creator fee 30 bps of every bonding-curve trade (devnet and mainnet), as lamports in
//   creator_vault(vault), ONE vault per creator address (shared by all its coins).
//   collect_creator_fee_v2 moves everything above the rent floor to the vault (650,240 lamports on live
//   clusters; LiteSVM's default rent says 890,880); payer pays 5,000. Also simulated on live devnet.
// - A completing buy sets complete; trades then fail with 6005 until anyone runs migrate (~340k CU,
//   caller pays ~0.00204 SOL rent + fee). pool.coin_creator = the vault. ~20.7% of the quote goes to a
//   boost vault and the pool carries it as virtual_quote_reserves (price on effective reserves).
// - PumpSwap creator fees (30 bps below 420 SOL market cap) accrue as WSOL in
//   ammCreatorVaultAta(vault); transfer_creator_fees_to_pump (v1, no signer) or _v2 moves them into
//   creator_vault(vault) as lamports, then collect_creator_fee_v2; both in one transaction.
import { createHash } from 'node:crypto';
import * as web3 from '@solana/web3.js';

export { web3 };
const { PublicKey, TransactionInstruction, SystemProgram, ComputeBudgetProgram } = web3;

// ---------------------------------------------------------------------------------------------
// Program ids and fixed addresses (identical on devnet and mainnet)
// ---------------------------------------------------------------------------------------------
export const PUMP_PROGRAM_ID = new PublicKey('6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P');
export const PUMP_AMM_PROGRAM_ID = new PublicKey('pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA');
export const PUMP_FEES_PROGRAM_ID = new PublicKey('pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ');
export const MAYHEM_PROGRAM_ID = new PublicKey('MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e');
export const TOKEN_PROGRAM_ID = new PublicKey('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const TOKEN_2022_PROGRAM_ID = new PublicKey('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
export const SYSTEM_PROGRAM_ID = SystemProgram.programId;
export const RENT_SYSVAR_ID = new PublicKey('SysvarRent111111111111111111111111111111111');
/** Legacy wrapped SOL. SOL-paired coins pass it as `quote_mint` (with the SPL Token program). */
export const NATIVE_MINT = new PublicKey('So11111111111111111111111111111111111111112');
export const ZERO_KEY = PublicKey.default;

/** Token amounts: every pump coin has 6 decimals and a 1,000,000,000-token supply. */
export const TOKEN_DECIMALS = 6;
export const ONE_BILLION_SUPPLY = 1_000_000_000_000_000n;
/**
 * Rent: read the Rent sysvar, never hardcode it. On 30 September 2026 devnet and mainnet both hold
 * lamports_per_byte_year 5080 with threshold 1.0, so a 0-byte account's rent-exempt minimum (the
 * floor collect_creator_fee_v2 leaves in the creator vault) is 650,240 lamports and a 165-byte token
 * account's 1,488,440 (the old 890,880 / 2,039,280 assumed 6960/byte, LiteSVM's default).
 */
export const decodeRent = (data) => ({ lamportsPerByteYear: Buffer.from(data).readBigUInt64LE(0), exemptionThreshold: Buffer.from(data).readDoubleLE(8), burnPercent: data[16] });
export const ACCOUNT_STORAGE_OVERHEAD = 128n;
export const minimumBalance = (rent, dataLen) => BigInt(Math.floor(Number((ACCOUNT_STORAGE_OVERHEAD + BigInt(dataLen)) * rent.lamportsPerByteYear) * rent.exemptionThreshold));
export const LIVE_RENT_30_SEPT = Object.freeze({ lamportsPerByteYear: 5080n, exemptionThreshold: 1, burnPercent: 50 });

// ---------------------------------------------------------------------------------------------
// Discriminators (from the IDLs; each equals sha256("global:<name>")[0..8], asserted by the tests)
// ---------------------------------------------------------------------------------------------
export const IX = Object.freeze({
  // pump
  create_v2: 'd6904cec5f8b31b4',
  buy: '66063d1201daebea',
  sell: '33e685a4017f83ad',
  buy_v2: 'b817ee6167c5d33d',
  sell_v2: '5df6823ce7e940b2',
  buy_exact_quote_in_v2: 'c2ab1c46684d5b2f',
  collect_creator_fee: '1416567bc61cdb84',
  collect_creator_fee_v2: 'cf118af204221338',
  migrate: '9beae792ec9ea21e',
  migrate_v2: 'bbcb121fceedfe29',
  extend_account: 'ea66c2cb96483ee5',
  // pump_amm (buy/sell share their names, and so their discriminators, with the pump program)
  amm_buy: '66063d1201daebea',
  amm_sell: '33e685a4017f83ad',
  collect_coin_creator_fee: 'a039592ab58b2b42',
  transfer_creator_fees_to_pump: '8b348655e4e56cf1',
  transfer_creator_fees_to_pump_v2: '01214eb921432c5c',
});
export const ACCOUNT = Object.freeze({
  BondingCurve: '17b7f83760d8ac60', Global: 'a7e8e8b1c86c727f', FeeConfig: '8f3492bbdb7b4c9b',
  SharingConfig: 'd84a0900388c5d4b', Pool: 'f19a6d0411b16dbc', GlobalConfig: '95089ccaa0fcb0d9',
});
export const EVENT = Object.freeze({
  CreateEvent: '1b72a94ddeeb6376', TradeEvent: 'bddb7fd34ee661ee', CompleteEvent: '5f72619cd42e9808',
  CollectCreatorFeeEvent: '7a027f010ebf0caf', CompletePumpAmmMigrationEvent: 'bde95db95c94ea94',
  CollectCoinCreatorFeeEvent: 'e8f5c2eeeada3a59', BuyEvent: '67f4521f2cf57777', SellEvent: '3e2f370aa503dc2a',
  CreatePoolEvent: 'b1310cd2a076a774',
});
/** Anchor's emit_cpi! tag: a self-CPI whose data starts with these 8 bytes carries an event. */
export const EVENT_IX_TAG = 'e445a52e51cb9a1d';
/** The name → 8-byte discriminator rule Anchor uses (namespace "global" for instructions). */
export const anchorDiscriminator = (name, namespace = 'global') => createHash('sha256').update(`${namespace}:${name}`).digest().subarray(0, 8);
const disc = (key) => Buffer.from(IX[key], 'hex');

/** pump errors worth naming in alerts (pump program codes). */
export const PUMP_ERRORS = Object.freeze({
  6002: 'TooMuchSolRequired (buy slippage)', 6003: 'TooLittleSolReceived (sell slippage)', 6005: 'BondingCurveComplete',
  6006: 'BondingCurveNotComplete', 6042: 'BuySlippageBelowMinTokensOut', 6043: 'NameTooLong', 6044: 'SymbolTooLong',
  6045: 'UriTooLong', 6046: 'CreateV2Disabled', 6049: 'CreatorMigratedToSharingConfig', 6057: 'BuybackFeeRecipientNotAuthorized',
  6082: 'CashbackDeprecated', 6084: 'HolderRewardDisabled',
});
/** pump_amm errors worth naming (6047/6048: the coin creator was moved to a sharing config). */
export const AMM_ERRORS = Object.freeze({
  6004: 'ExceededSlippage', 6040: 'BuySlippageBelowMinBaseAmountOut', 6047: 'CoinCreatorMigratedToSharingConfig',
  6048: 'CreatorVaultMigratedToSharingConfig', 6053: 'BuybackFeeRecipientNotAuthorized', 6062: 'InvalidPoolV2',
});

// ---------------------------------------------------------------------------------------------
// PDAs
// ---------------------------------------------------------------------------------------------
const seed = (s) => (typeof s === 'string' ? Buffer.from(s) : s instanceof PublicKey ? s.toBuffer() : Buffer.from(s));
export const pda = (seeds, programId) => PublicKey.findProgramAddressSync(seeds.map(seed), programId)[0];
const memo = new Map();
const once = (key, f) => { if (!memo.has(key)) memo.set(key, f()); return memo.get(key); };
const pk = (k) => (k instanceof PublicKey ? k : new PublicKey(k));

/** Associated token account of `owner` (on or off curve) for `mint` under `tokenProgram`. */
export const ata = (owner, mint, tokenProgram = TOKEN_PROGRAM_ID) => pda([pk(owner), pk(tokenProgram), pk(mint)], ASSOCIATED_TOKEN_PROGRAM_ID);

// pump
export const globalPda = () => once('global', () => pda(['global'], PUMP_PROGRAM_ID));
export const mintAuthorityPda = () => once('mint-authority', () => pda(['mint-authority'], PUMP_PROGRAM_ID));
export const eventAuthorityPda = (programId = PUMP_PROGRAM_ID) => once(`ea:${programId}`, () => pda(['__event_authority'], pk(programId)));
export const globalVolumeAccumulatorPda = (programId = PUMP_PROGRAM_ID) => once(`gva:${programId}`, () => pda(['global_volume_accumulator'], pk(programId)));
export const userVolumeAccumulatorPda = (user, programId = PUMP_PROGRAM_ID) => pda(['user_volume_accumulator', pk(user)], pk(programId));
export const bondingCurvePda = (mint) => pda(['bonding-curve', pk(mint)], PUMP_PROGRAM_ID);
export const bondingCurveV2Pda = (mint) => pda(['bonding-curve-v2', pk(mint)], PUMP_PROGRAM_ID);
/** The pump creator vault: a 0-byte system-owned PDA holding the creator's bonding-curve fees as lamports. */
export const creatorVaultPda = (creator) => pda(['creator-vault', pk(creator)], PUMP_PROGRAM_ID);
export const poolAuthorityPda = (mint) => pda(['pool-authority', pk(mint)], PUMP_PROGRAM_ID);
export const holderRewardsPda = (mint) => pda(['holder-rewards', pk(mint)], PUMP_PROGRAM_ID);
export const quoteControlPda = () => once('quote-control', () => pda(['quote-control'], PUMP_PROGRAM_ID));
// pump_fees
/** `fee_config` for a program (pump or pump_amm) under the fees program. */
export const feeConfigPda = (forProgram = PUMP_PROGRAM_ID) => once(`fc:${forProgram}`, () => pda(['fee_config', pk(forProgram)], PUMP_FEES_PROGRAM_ID));
/** Exists only if someone (the creator or pump.fun's admin_set_creator_authority) opted the coin into fee sharing. */
export const sharingConfigPda = (mint) => pda(['sharing-config', pk(mint)], PUMP_FEES_PROGRAM_ID);
// mayhem (create_v2 always lists these, mayhem or not)
export const mayhemGlobalParamsPda = () => once('mgp', () => pda(['global-params'], MAYHEM_PROGRAM_ID));
export const mayhemSolVaultPda = () => once('msv', () => pda(['sol-vault'], MAYHEM_PROGRAM_ID));
export const mayhemStatePda = (mint) => pda(['mayhem-state', pk(mint)], MAYHEM_PROGRAM_ID);
export const mayhemTokenVault = (mint) => ata(mayhemSolVaultPda(), mint, TOKEN_2022_PROGRAM_ID);
// pump_amm
export const ammGlobalConfigPda = () => once('amm-gc', () => pda(['global_config'], PUMP_AMM_PROGRAM_ID));
const u16le = (n) => { const b = Buffer.alloc(2); b.writeUInt16LE(n); return b; };
export const poolPda = (index, creator, baseMint, quoteMint) => pda(['pool', u16le(index), pk(creator), pk(baseMint), pk(quoteMint)], PUMP_AMM_PROGRAM_ID);
/** The canonical PumpSwap pool `migrate` creates: index 0, creator = pump pool-authority PDA. */
export const canonicalPoolPda = (mint, quoteMint = NATIVE_MINT) => poolPda(0, poolAuthorityPda(mint), mint, quoteMint);
export const lpMintPda = (pool) => pda(['pool_lp_mint', pk(pool)], PUMP_AMM_PROGRAM_ID);
export const poolV2Pda = (baseMint) => pda(['pool-v2', pk(baseMint)], PUMP_AMM_PROGRAM_ID);
export const boostVaultAuthorityPda = (pool) => pda(['boost_vault', pk(pool)], PUMP_AMM_PROGRAM_ID);
/** The AMM creator vault authority (note the underscore: "creator_vault", not pump's "creator-vault"). */
export const ammCreatorVaultAuthorityPda = (coinCreator) => pda(['creator_vault', pk(coinCreator)], PUMP_AMM_PROGRAM_ID);
export const ammCreatorVaultAta = (coinCreator, quoteMint = NATIVE_MINT, quoteTokenProgram = TOKEN_PROGRAM_ID) =>
  ata(ammCreatorVaultAuthorityPda(coinCreator), quoteMint, quoteTokenProgram);
// Artifact Council
/** The AC treasury vault: a system-owned PDA `["treasury"]` of the AC program (solana/src/treasury.rs). */
export const acVaultPda = (acProgramId) => pda(['treasury'], pk(acProgramId));

// ---------------------------------------------------------------------------------------------
// Borsh encoding
// ---------------------------------------------------------------------------------------------
const U64_MAX = (1n << 64n) - 1n;
export function u64(v) {
  const n = BigInt(v);
  if (n < 0n || n > U64_MAX) throw new RangeError(`u64 out of range: ${v}`);
  const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b;
}
const bool = (v) => Buffer.from([v ? 1 : 0]);
function str(s) {
  const b = Buffer.from(s, 'utf8'); const l = Buffer.alloc(4); l.writeUInt32LE(b.length);
  return Buffer.concat([l, b]);
}
const meta = (pubkey, isWritable = false, isSigner = false) => ({ pubkey: pk(pubkey), isWritable, isSigner });
const R = (k) => meta(k), W = (k) => meta(k, true), WS = (k) => meta(k, true, true);

// ---------------------------------------------------------------------------------------------
// create_v2
// ---------------------------------------------------------------------------------------------
/** Limits create_v2 enforces (6043/6044/6045); checked here on UTF-8 byte length. */
export const LIMITS = Object.freeze({ name: 32, symbol: 13, uri: 200 });

/**
 * create_v2: a Token-2022 mint (6 decimals, metadata pointer + token metadata on the mint itself)
 * and its bonding curve. `creator` is a plain argument, never a signer: the curve records it as
 * `bonding_curve.creator`, and every creator fee then accrues to `creatorVaultPda(creator)`.
 * Signers: `mint` (new keypair) and `user` (payer).
 *
 * Trailing args are always encoded (the program reads missing ones as false/0, the SDK encodes
 * all): is_cashback_enabled (must be false: 6082), creator_fee_bps (ignored on SOL pairs),
 * is_holder_reward (true would replace `creator` with holderRewardsPda(mint); we keep false).
 * No remaining accounts = SOL-paired (bonding_curve.quote_mint stays the zero key).
 */
export function createV2Instruction({ mint, user, creator, name, symbol, uri, mayhemMode = false, holderReward = false, cashback = false, creatorFeeBps = 0n }) {
  for (const [field, value] of Object.entries({ name, symbol, uri })) {
    if (typeof value !== 'string') throw new TypeError(`${field} must be a string`);
    const bytes = Buffer.byteLength(value, 'utf8');
    if (bytes > LIMITS[field]) throw new RangeError(`${field} is ${bytes} bytes; create_v2 allows ${LIMITS[field]}`);
  }
  creator = pk(creator);
  if (creator.equals(ZERO_KEY)) throw new Error('creator must not be the zero key (6030)');
  if (cashback) throw new Error('cashback coins can no longer be created (6082)');
  mint = pk(mint); user = pk(user);
  const bondingCurve = bondingCurvePda(mint);
  const keys = [
    WS(mint), R(mintAuthorityPda()), W(bondingCurve), W(ata(bondingCurve, mint, TOKEN_2022_PROGRAM_ID)), R(globalPda()), WS(user),
    R(SYSTEM_PROGRAM_ID), R(TOKEN_2022_PROGRAM_ID), R(ASSOCIATED_TOKEN_PROGRAM_ID),
    W(MAYHEM_PROGRAM_ID), R(mayhemGlobalParamsPda()), W(mayhemSolVaultPda()), W(mayhemStatePda(mint)), W(mayhemTokenVault(mint)),
    R(eventAuthorityPda(PUMP_PROGRAM_ID)), R(PUMP_PROGRAM_ID),
  ];
  const data = Buffer.concat([disc('create_v2'), str(name), str(symbol), str(uri), creator.toBuffer(), bool(mayhemMode), bool(false), u64(creatorFeeBps), bool(holderReward)]);
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data });
}

// ---------------------------------------------------------------------------------------------
// Bonding-curve trades
// ---------------------------------------------------------------------------------------------
/**
 * The 26/27 accounts buy_v2, sell_v2 and buy_exact_quote_in_v2 share (buys add
 * global_volume_accumulator at index 19). For a SOL coin: quoteMint = WSOL, quoteTokenProgram =
 * SPL Token; the quote ATAs are only seed-checked and never created or touched.
 * `creator` must be bonding_curve.creator (the create argument, in a create+buy transaction).
 */
function tradeV2Keys({ isBuy, mint, user, creator, feeRecipient, buybackFeeRecipient, baseTokenProgram, quoteMint, quoteTokenProgram }) {
  mint = pk(mint); user = pk(user);
  const q = (owner) => ata(owner, quoteMint, quoteTokenProgram);
  const bondingCurve = bondingCurvePda(mint);
  const creatorVault = creatorVaultPda(creator);
  const uva = userVolumeAccumulatorPda(user);
  return [
    R(globalPda()), R(mint), R(quoteMint), R(baseTokenProgram), R(quoteTokenProgram), R(ASSOCIATED_TOKEN_PROGRAM_ID),
    W(feeRecipient), W(q(feeRecipient)), W(buybackFeeRecipient), W(q(buybackFeeRecipient)),
    W(bondingCurve), W(ata(bondingCurve, mint, baseTokenProgram)), W(q(bondingCurve)),
    WS(user), W(ata(user, mint, baseTokenProgram)), W(q(user)),
    W(creatorVault), W(q(creatorVault)), R(sharingConfigPda(mint)),
    ...(isBuy ? [R(globalVolumeAccumulatorPda())] : []),
    W(uva), W(q(uva)), R(feeConfigPda(PUMP_PROGRAM_ID)), R(PUMP_FEES_PROGRAM_ID), R(SYSTEM_PROGRAM_ID),
    R(eventAuthorityPda(PUMP_PROGRAM_ID)), R(PUMP_PROGRAM_ID),
  ];
}
const tradeDefaults = { baseTokenProgram: TOKEN_2022_PROGRAM_ID, quoteMint: NATIVE_MINT, quoteTokenProgram: TOKEN_PROGRAM_ID };

/** buy_v2: exactly `amount` base units for at most `maxSolCost` lamports (fees included). */
export function buyV2Instruction({ amount, maxSolCost, ...a }) {
  const keys = tradeV2Keys({ ...tradeDefaults, ...a, isBuy: true });
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: Buffer.concat([disc('buy_v2'), u64(amount), u64(maxSolCost)]) });
}
/** buy_exact_quote_in_v2: spend exactly `spendableQuoteIn` lamports (fees included), receive >= `minTokensOut`. */
export function buyExactQuoteInV2Instruction({ spendableQuoteIn, minTokensOut, ...a }) {
  const keys = tradeV2Keys({ ...tradeDefaults, ...a, isBuy: true });
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: Buffer.concat([disc('buy_exact_quote_in_v2'), u64(spendableQuoteIn), u64(minTokensOut)]) });
}
/** sell_v2: exactly `amount` base units for at least `minSolOutput` lamports after fees. */
export function sellV2Instruction({ amount, minSolOutput, ...a }) {
  const keys = tradeV2Keys({ ...tradeDefaults, ...a, isBuy: false });
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: Buffer.concat([disc('sell_v2'), u64(amount), u64(minSolOutput)]) });
}

/**
 * Legacy `buy` (16 IDL accounts + remaining [bonding_curve_v2, buyback_fee_recipient] = 18). Kept
 * because it is compact: create_v2 + ATA + this buy fits a 1232-byte legacy transaction, while
 * create_v2 + buy_v2 needs a v1 (4096-byte) transaction or a lookup table.
 * track_volume is encoded as OptionBool(true), as the SDK does.
 */
export function buyInstruction({ mint, user, creator, amount, maxSolCost, feeRecipient, buybackFeeRecipient, tokenProgram = TOKEN_2022_PROGRAM_ID, trackVolume = true }) {
  mint = pk(mint); user = pk(user);
  const bondingCurve = bondingCurvePda(mint);
  const keys = [
    R(globalPda()), W(feeRecipient), R(mint), W(bondingCurve), W(ata(bondingCurve, mint, tokenProgram)), W(ata(user, mint, tokenProgram)),
    WS(user), R(SYSTEM_PROGRAM_ID), R(tokenProgram), W(creatorVaultPda(creator)), R(eventAuthorityPda(PUMP_PROGRAM_ID)), R(PUMP_PROGRAM_ID),
    R(globalVolumeAccumulatorPda()), W(userVolumeAccumulatorPda(user)), R(feeConfigPda(PUMP_PROGRAM_ID)), R(PUMP_FEES_PROGRAM_ID),
    R(bondingCurveV2Pda(mint)), W(buybackFeeRecipient),
  ];
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: Buffer.concat([disc('buy'), u64(amount), u64(maxSolCost), bool(trackVolume)]) });
}
/** Legacy `sell` (14 IDL accounts + remaining [bonding_curve_v2, buyback_fee_recipient]; non-cashback coins). */
export function sellInstruction({ mint, user, creator, amount, minSolOutput, feeRecipient, buybackFeeRecipient, tokenProgram = TOKEN_2022_PROGRAM_ID }) {
  mint = pk(mint); user = pk(user);
  const bondingCurve = bondingCurvePda(mint);
  const keys = [
    R(globalPda()), W(feeRecipient), R(mint), W(bondingCurve), W(ata(bondingCurve, mint, tokenProgram)), W(ata(user, mint, tokenProgram)),
    WS(user), R(SYSTEM_PROGRAM_ID), W(creatorVaultPda(creator)), R(tokenProgram), R(eventAuthorityPda(PUMP_PROGRAM_ID)), R(PUMP_PROGRAM_ID),
    R(feeConfigPda(PUMP_PROGRAM_ID)), R(PUMP_FEES_PROGRAM_ID),
    R(bondingCurveV2Pda(mint)), W(buybackFeeRecipient),
  ];
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: Buffer.concat([disc('sell'), u64(amount), u64(minSolOutput)]) });
}

// ---------------------------------------------------------------------------------------------
// Creator fees on the bonding curve
// ---------------------------------------------------------------------------------------------
/**
 * collect_creator_fee_v2: permissionless. `creator` is writable but NOT a signer: the program
 * moves creator_vault's lamports above its rent-exempt minimum (650,240 on live clusters since the
 * rent change; read the Rent sysvar) to `creator` (SOL coins). Any fee
 * payer can crank it. Fails with 6049 once the coin was moved to a sharing config.
 * `creator` must not be executable nor owned by the fees program; the AC vault (system-owned PDA)
 * qualifies. creator_token_account / creator_vault_token_account are unused for WSOL.
 */
export function collectCreatorFeeV2Instruction({ creator, quoteMint = NATIVE_MINT, quoteTokenProgram = TOKEN_PROGRAM_ID }) {
  creator = pk(creator);
  const vault = creatorVaultPda(creator);
  const keys = [
    W(creator), W(ata(creator, quoteMint, quoteTokenProgram)), W(vault), W(ata(vault, quoteMint, quoteTokenProgram)),
    R(quoteMint), R(quoteTokenProgram), R(ASSOCIATED_TOKEN_PROGRAM_ID), R(SYSTEM_PROGRAM_ID), R(eventAuthorityPda(PUMP_PROGRAM_ID)), R(PUMP_PROGRAM_ID),
  ];
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: disc('collect_creator_fee_v2') });
}
/** Legacy collect_creator_fee (SOL only, same effect; creator not a signer in the current IDL). */
export function collectCreatorFeeInstruction({ creator }) {
  creator = pk(creator);
  const keys = [W(creator), W(creatorVaultPda(creator)), R(SYSTEM_PROGRAM_ID), R(eventAuthorityPda(PUMP_PROGRAM_ID)), R(PUMP_PROGRAM_ID)];
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: disc('collect_creator_fee') });
}

// ---------------------------------------------------------------------------------------------
// Graduation: migrate (permissionless; any signer pays only the transaction fee)
// ---------------------------------------------------------------------------------------------
/**
 * migrate (v1, SOL coins): moves a complete curve (complete && real_token_reserves == 0) into the
 * canonical PumpSwap pool, pool.coin_creator = bonding_curve.creator. `withdrawAuthority` must be
 * Global.withdraw_authority (writable, not a signer; it receives the leftover of pool_migration_fee).
 * `baseTokenProgram` must be Token-2022 for create_v2 coins (the SDK defaults to SPL Token!).
 * Remaining accounts [boost_vault_authority, boost_vault] are required (27 accounts in all).
 * Idempotent: on an already migrated curve it does nothing.
 */
export function migrateInstruction({ mint, user, withdrawAuthority, baseTokenProgram = TOKEN_2022_PROGRAM_ID }) {
  mint = pk(mint);
  const bondingCurve = bondingCurvePda(mint), poolAuthority = poolAuthorityPda(mint), pool = canonicalPoolPda(mint, NATIVE_MINT);
  const lpMint = lpMintPda(pool), boostAuthority = boostVaultAuthorityPda(pool);
  const keys = [
    R(globalPda()), W(withdrawAuthority), R(mint), W(bondingCurve), W(ata(bondingCurve, mint, baseTokenProgram)), WS(user),
    R(SYSTEM_PROGRAM_ID), R(TOKEN_PROGRAM_ID), R(PUMP_AMM_PROGRAM_ID), W(pool), W(poolAuthority),
    W(ata(poolAuthority, mint, baseTokenProgram)), W(ata(poolAuthority, NATIVE_MINT, TOKEN_PROGRAM_ID)), R(ammGlobalConfigPda()), R(NATIVE_MINT),
    W(lpMint), W(ata(poolAuthority, lpMint, TOKEN_2022_PROGRAM_ID)), W(ata(pool, mint, baseTokenProgram)), W(ata(pool, NATIVE_MINT, TOKEN_PROGRAM_ID)),
    R(TOKEN_2022_PROGRAM_ID), R(ASSOCIATED_TOKEN_PROGRAM_ID), R(eventAuthorityPda(PUMP_AMM_PROGRAM_ID)), R(eventAuthorityPda(PUMP_PROGRAM_ID)),
    R(PUMP_PROGRAM_ID), R(RENT_SYSVAR_ID),
    R(boostAuthority), W(ata(boostAuthority, NATIVE_MINT, TOKEN_PROGRAM_ID)),
  ];
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: disc('migrate') });
}
/** migrate_v2: the quote-generic form (SOL: quoteMint = WSOL, quoteTokenProgram = SPL Token). 29 accounts. */
export function migrateV2Instruction({ mint, user, withdrawAuthority, quoteMint = NATIVE_MINT, baseTokenProgram = TOKEN_2022_PROGRAM_ID, quoteTokenProgram = TOKEN_PROGRAM_ID }) {
  mint = pk(mint); quoteMint = pk(quoteMint).equals(ZERO_KEY) ? NATIVE_MINT : pk(quoteMint);
  const bondingCurve = bondingCurvePda(mint), poolAuthority = poolAuthorityPda(mint), pool = canonicalPoolPda(mint, quoteMint);
  const lpMint = lpMintPda(pool), boostAuthority = boostVaultAuthorityPda(pool);
  const keys = [
    R(globalPda()), W(withdrawAuthority), R(mint), R(quoteMint), W(bondingCurve), W(ata(bondingCurve, mint, baseTokenProgram)),
    W(ata(bondingCurve, quoteMint, quoteTokenProgram)), WS(user), R(SYSTEM_PROGRAM_ID), R(PUMP_AMM_PROGRAM_ID), W(pool), W(poolAuthority),
    W(ata(poolAuthority, mint, baseTokenProgram)), W(ata(poolAuthority, quoteMint, quoteTokenProgram)), R(ammGlobalConfigPda()), W(lpMint),
    W(ata(poolAuthority, lpMint, TOKEN_2022_PROGRAM_ID)), W(ata(pool, mint, baseTokenProgram)), W(ata(pool, quoteMint, quoteTokenProgram)),
    R(baseTokenProgram), R(quoteTokenProgram), R(TOKEN_2022_PROGRAM_ID), R(ASSOCIATED_TOKEN_PROGRAM_ID), R(eventAuthorityPda(PUMP_AMM_PROGRAM_ID)),
    R(RENT_SYSVAR_ID), R(eventAuthorityPda(PUMP_PROGRAM_ID)), R(PUMP_PROGRAM_ID),
    R(boostAuthority), W(ata(boostAuthority, quoteMint, quoteTokenProgram)),
  ];
  return new TransactionInstruction({ programId: PUMP_PROGRAM_ID, keys, data: disc('migrate_v2') });
}
/** extend_account (pump or pump_amm): grows an old program account to the current layout. Not needed for new coins. */
export function extendAccountInstruction({ account, user, programId = PUMP_PROGRAM_ID }) {
  const keys = [W(account), WS(user), R(SYSTEM_PROGRAM_ID), R(eventAuthorityPda(programId)), R(programId)];
  return new TransactionInstruction({ programId: pk(programId), keys, data: disc('extend_account') });
}

// ---------------------------------------------------------------------------------------------
// PumpSwap (after graduation)
// ---------------------------------------------------------------------------------------------
/**
 * The 23 (buy) / 21 (sell) PumpSwap accounts plus the remaining ones the program requires:
 * [pool_v2 (when pool.coin_creator is set), buyback_fee_recipient, its quote ATA]. `poolState` is
 * decodePool(). `protocolFeeRecipient` must be one of GlobalConfig.protocol_fee_recipients (devnet's
 * differ from mainnet's) and its quote ATA must exist; `buybackFeeRecipient` one of
 * GlobalConfig.buyback_fee_recipients. User token accounts default to ATAs: the quote side is the
 * user's WSOL ATA, which the caller wraps and closes (wrapSolInstructions / closeAccountInstruction).
 */
function ammSwapKeys({ isBuy, pool, poolState, user, protocolFeeRecipient, buybackFeeRecipient, baseTokenProgram, quoteTokenProgram, userBaseTokenAccount, userQuoteTokenAccount }) {
  user = pk(user); pool = pk(pool);
  const { baseMint, quoteMint, poolBaseTokenAccount, poolQuoteTokenAccount, coinCreator, isCashbackCoin } = poolState;
  if (isCashbackCoin) throw new Error('cashback pools need extra remaining accounts; not supported here');
  const vaultAuthority = ammCreatorVaultAuthorityPda(coinCreator);
  const keys = [
    W(pool), WS(user), R(ammGlobalConfigPda()), R(baseMint), R(quoteMint),
    W(userBaseTokenAccount ?? ata(user, baseMint, baseTokenProgram)), W(userQuoteTokenAccount ?? ata(user, quoteMint, quoteTokenProgram)),
    W(poolBaseTokenAccount), W(poolQuoteTokenAccount), R(protocolFeeRecipient), W(ata(protocolFeeRecipient, quoteMint, quoteTokenProgram)),
    R(baseTokenProgram), R(quoteTokenProgram), R(SYSTEM_PROGRAM_ID), R(ASSOCIATED_TOKEN_PROGRAM_ID),
    R(eventAuthorityPda(PUMP_AMM_PROGRAM_ID)), R(PUMP_AMM_PROGRAM_ID),
    W(ata(vaultAuthority, quoteMint, quoteTokenProgram)), R(vaultAuthority),
    ...(isBuy ? [R(globalVolumeAccumulatorPda(PUMP_AMM_PROGRAM_ID)), W(userVolumeAccumulatorPda(user, PUMP_AMM_PROGRAM_ID))] : []),
    R(feeConfigPda(PUMP_AMM_PROGRAM_ID)), R(PUMP_FEES_PROGRAM_ID),
  ];
  if (!pk(coinCreator).equals(ZERO_KEY)) keys.push(R(poolV2Pda(baseMint)));
  keys.push(R(buybackFeeRecipient), W(ata(buybackFeeRecipient, quoteMint, quoteTokenProgram)));
  return keys;
}
const ammDefaults = { baseTokenProgram: TOKEN_2022_PROGRAM_ID, quoteTokenProgram: TOKEN_PROGRAM_ID };
/** PumpSwap buy: exactly `baseAmountOut` for at most `maxQuoteAmountIn` (WSOL units). */
export function ammBuyInstruction({ baseAmountOut, maxQuoteAmountIn, trackVolume = true, ...a }) {
  const keys = ammSwapKeys({ ...ammDefaults, ...a, isBuy: true });
  return new TransactionInstruction({ programId: PUMP_AMM_PROGRAM_ID, keys, data: Buffer.concat([disc('amm_buy'), u64(baseAmountOut), u64(maxQuoteAmountIn), bool(trackVolume)]) });
}
/** PumpSwap sell: exactly `baseAmountIn` for at least `minQuoteAmountOut` (WSOL units). */
export function ammSellInstruction({ baseAmountIn, minQuoteAmountOut, ...a }) {
  const keys = ammSwapKeys({ ...ammDefaults, ...a, isBuy: false });
  return new TransactionInstruction({ programId: PUMP_AMM_PROGRAM_ID, keys, data: Buffer.concat([disc('amm_sell'), u64(baseAmountIn), u64(minQuoteAmountOut)]) });
}
/**
 * collect_coin_creator_fee (PumpSwap): permissionless; coin_creator is NOT a signer. Moves the AMM
 * creator vault's WSOL into `coinCreatorTokenAccount` (a WSOL token account owned by the coin
 * creator; must exist). For the AC vault that is the vault's WSOL ATA, which only the AC program's
 * Crank::Unwrap can close into the vault. Prefer transfer_creator_fees_to_pump + collect_creator_fee_v2.
 */
export function collectCoinCreatorFeeInstruction({ coinCreator, coinCreatorTokenAccount, quoteMint = NATIVE_MINT, quoteTokenProgram = TOKEN_PROGRAM_ID }) {
  coinCreator = pk(coinCreator);
  const vaultAuthority = ammCreatorVaultAuthorityPda(coinCreator);
  const keys = [
    R(quoteMint), R(quoteTokenProgram), R(coinCreator), R(vaultAuthority), W(ata(vaultAuthority, quoteMint, quoteTokenProgram)),
    W(coinCreatorTokenAccount ?? ata(coinCreator, quoteMint, quoteTokenProgram)), R(eventAuthorityPda(PUMP_AMM_PROGRAM_ID)), R(PUMP_AMM_PROGRAM_ID),
  ];
  return new TransactionInstruction({ programId: PUMP_AMM_PROGRAM_ID, keys, data: disc('collect_coin_creator_fee') });
}
/**
 * transfer_creator_fees_to_pump (v1, WSOL only): no signer at all besides the fee payer. Unwraps the
 * AMM creator vault's WSOL into pump's creator_vault(coinCreator) as lamports (the vault ATA stays,
 * empty). The IDL says it skips below a token account's rent; the devnet binary (slot 503484127)
 * moved 185,415 lamports in the offline run. Fails with 3012 until the first PumpSwap trade has
 * created the ATA. Works for any coin_creator, not only sharing configs. Follow with
 * collectCreatorFeeV2Instruction.
 */
export function transferCreatorFeesToPumpInstruction({ coinCreator }) {
  coinCreator = pk(coinCreator);
  const vaultAuthority = ammCreatorVaultAuthorityPda(coinCreator);
  const keys = [
    R(NATIVE_MINT), R(TOKEN_PROGRAM_ID), R(SYSTEM_PROGRAM_ID), R(ASSOCIATED_TOKEN_PROGRAM_ID), R(coinCreator),
    W(vaultAuthority), W(ata(vaultAuthority, NATIVE_MINT, TOKEN_PROGRAM_ID)), W(creatorVaultPda(coinCreator)),
    R(eventAuthorityPda(PUMP_AMM_PROGRAM_ID)), R(PUMP_AMM_PROGRAM_ID),
  ];
  return new TransactionInstruction({ programId: PUMP_AMM_PROGRAM_ID, keys, data: disc('transfer_creator_fees_to_pump') });
}
/** transfer_creator_fees_to_pump_v2: same for any quote; `payer` signs (pays the pump vault ATA rent for token quotes only). */
export function transferCreatorFeesToPumpV2Instruction({ payer, coinCreator, quoteMint = NATIVE_MINT, quoteTokenProgram = TOKEN_PROGRAM_ID }) {
  coinCreator = pk(coinCreator);
  const vaultAuthority = ammCreatorVaultAuthorityPda(coinCreator), pumpVault = creatorVaultPda(coinCreator);
  const keys = [
    WS(payer), R(quoteMint), R(quoteTokenProgram), R(SYSTEM_PROGRAM_ID), R(ASSOCIATED_TOKEN_PROGRAM_ID), R(coinCreator),
    W(vaultAuthority), W(ata(vaultAuthority, quoteMint, quoteTokenProgram)), W(pumpVault), W(ata(pumpVault, quoteMint, quoteTokenProgram)),
    R(eventAuthorityPda(PUMP_AMM_PROGRAM_ID)), R(PUMP_AMM_PROGRAM_ID),
  ];
  return new TransactionInstruction({ programId: PUMP_AMM_PROGRAM_ID, keys, data: disc('transfer_creator_fees_to_pump_v2') });
}

// ---------------------------------------------------------------------------------------------
// Token helpers (SPL Token / Token-2022 / ATA program), compute budget
// ---------------------------------------------------------------------------------------------
/** ATA program CreateIdempotent (data [1]); works for off-curve owners such as PDAs. */
export function createAtaIdempotentInstruction({ payer, owner, mint, tokenProgram = TOKEN_PROGRAM_ID }) {
  const address = ata(owner, mint, tokenProgram);
  const keys = [WS(payer), W(address), R(owner), R(mint), R(SYSTEM_PROGRAM_ID), R(tokenProgram)];
  return new TransactionInstruction({ programId: ASSOCIATED_TOKEN_PROGRAM_ID, keys, data: Buffer.from([1]) });
}
export function syncNativeInstruction({ account, tokenProgram = TOKEN_PROGRAM_ID }) {
  return new TransactionInstruction({ programId: pk(tokenProgram), keys: [W(account)], data: Buffer.from([17]) });
}
/** CloseAccount (data [9]): a WSOL account's lamports all go to `destination`. `owner` signs. */
export function closeAccountInstruction({ account, destination, owner, tokenProgram = TOKEN_PROGRAM_ID }) {
  return new TransactionInstruction({ programId: pk(tokenProgram), keys: [W(account), W(destination), meta(owner, false, true)], data: Buffer.from([9]) });
}
/** TransferChecked (data [12, amount u64, decimals u8]); the safe transfer for Token-2022 mints (team wallet transfers). */
export function transferCheckedInstruction({ source, mint, destination, owner, amount, decimals = TOKEN_DECIMALS, tokenProgram = TOKEN_2022_PROGRAM_ID }) {
  return new TransactionInstruction({ programId: pk(tokenProgram), keys: [W(source), R(mint), W(destination), meta(owner, false, true)], data: Buffer.concat([Buffer.from([12]), u64(amount), Buffer.from([decimals])]) });
}
/** Wrap `lamports` into `owner`'s WSOL ATA (create idempotent, transfer, sync). Close it afterwards to unwrap. */
export function wrapSolInstructions({ owner, lamports, payer = owner }) {
  const account = ata(owner, NATIVE_MINT, TOKEN_PROGRAM_ID);
  return [
    createAtaIdempotentInstruction({ payer, owner, mint: NATIVE_MINT, tokenProgram: TOKEN_PROGRAM_ID }),
    SystemProgram.transfer({ fromPubkey: pk(owner), toPubkey: account, lamports: BigInt(lamports) }),
    syncNativeInstruction({ account }),
  ];
}
export const computeUnitLimitInstruction = (units) => ComputeBudgetProgram.setComputeUnitLimit({ units });
export const computeUnitPriceInstruction = (microLamports) => ComputeBudgetProgram.setComputeUnitPrice({ microLamports });

// ---------------------------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------------------------
class Reader {
  constructor(data, offset = 0) { this.d = Buffer.from(data); this.o = offset; }
  u8() { return this.d[this.o++]; }
  bool() { return this.u8() !== 0; }
  u16() { const v = this.d.readUInt16LE(this.o); this.o += 2; return v; }
  u32() { const v = this.d.readUInt32LE(this.o); this.o += 4; return v; }
  u64() { const v = this.d.readBigUInt64LE(this.o); this.o += 8; return v; }
  i64() { const v = this.d.readBigInt64LE(this.o); this.o += 8; return v; }
  u128() { const lo = this.u64(), hi = this.u64(); return (hi << 64n) | lo; }
  i128() { const v = this.u128(); return v >= 1n << 127n ? v - (1n << 128n) : v; }
  pubkey() { const v = new PublicKey(this.d.subarray(this.o, this.o + 32)); this.o += 32; return v; }
  string() { const n = this.u32(); const v = this.d.subarray(this.o, this.o + n).toString('utf8'); this.o += n; return v; }
  vec(f) { const n = this.u32(); const out = []; for (let i = 0; i < n; i++) out.push(f(this)); return out; }
  array(n, f) { const out = []; for (let i = 0; i < n; i++) out.push(f(this)); return out; }
}
const padTo = (data, size) => (data.length >= size ? Buffer.from(data) : Buffer.concat([Buffer.from(data), Buffer.alloc(size - data.length)]));
function expectDisc(data, name) {
  const got = Buffer.from(data).subarray(0, 8).toString('hex');
  if (got !== ACCOUNT[name]) throw new Error(`not a ${name} account (discriminator ${got})`);
}
/** Current layout sizes (discriminator included). Older accounts are shorter; missing trailing fields read as 0/false. */
export const SIZE = Object.freeze({ BondingCurve: 125, Global: 1087, Pool: 271, GlobalConfig: 949 });

/** BondingCurve. `creator` at byte 49 is where every creator fee of the coin goes. */
export function decodeBondingCurve(data) {
  expectDisc(data, 'BondingCurve');
  if (data.length < 49) throw new Error('bonding curve shorter than its initial layout');
  const r = new Reader(padTo(data, SIZE.BondingCurve), 8);
  return {
    virtualTokenReserves: r.u64(), virtualQuoteReserves: r.u64(), realTokenReserves: r.u64(), realQuoteReserves: r.u64(),
    tokenTotalSupply: r.u64(), complete: r.bool(), creator: r.pubkey(), isMayhemMode: r.bool(), isCashbackCoin: r.bool(),
    quoteMint: r.pubkey(), creatorFeeBps: r.u64(), canEditCreatorFee: r.bool(), isHolderReward: r.bool(), dataLength: data.length,
  };
}
export const BONDING_CURVE_CREATOR_OFFSET = 49;

export function decodeGlobal(data) {
  expectDisc(data, 'Global');
  const r = new Reader(padTo(data, SIZE.Global), 8);
  return {
    initialized: r.bool(), authority: r.pubkey(), feeRecipient: r.pubkey(), initialVirtualTokenReserves: r.u64(),
    initialVirtualSolReserves: r.u64(), initialRealTokenReserves: r.u64(), tokenTotalSupply: r.u64(), feeBasisPoints: r.u64(),
    withdrawAuthority: r.pubkey(), enableMigrate: r.bool(), poolMigrationFee: r.u64(), creatorFeeBasisPoints: r.u64(),
    feeRecipients: r.array(7, (x) => x.pubkey()), setCreatorAuthority: r.pubkey(), adminSetCreatorAuthority: r.pubkey(),
    createV2Enabled: r.bool(), whitelistPda: r.pubkey(), reservedFeeRecipient: r.pubkey(), mayhemModeEnabled: r.bool(),
    reservedFeeRecipients: r.array(7, (x) => x.pubkey()), isCashbackEnabled: r.bool(), buybackFeeRecipients: r.array(8, (x) => x.pubkey()),
    buybackBasisPoints: r.u64(), initialVirtualQuoteReserves: r.u64(), whitelistedQuoteMints: r.array(1, (x) => x.pubkey()),
    creatorFeeConfigurable: r.bool(), maxConfigurableCreatorFeeBps: r.u64(), holderRewardClaimAuthority: r.pubkey(),
    isHolderRewardEnabled: r.bool(), dataLength: data.length,
  };
}
const fees = (r) => ({ lpFeeBps: r.u64(), protocolFeeBps: r.u64(), creatorFeeBps: r.u64() });
/** FeeConfig (pump_fees): flat fees, market-cap tiers (SOL-like quotes), stable tiers, exotic flat fees. */
export function decodeFeeConfig(data) {
  expectDisc(data, 'FeeConfig');
  const r = new Reader(data, 8);
  const tier = (x) => ({ marketCapLamportsThreshold: x.u128(), fees: fees(x) });
  const out = { bump: r.u8(), admin: r.pubkey(), flatFees: fees(r), feeTiers: r.vec(tier) };
  out.stableFeeTiers = r.o + 4 <= data.length ? r.vec(tier) : [];
  out.exoticFlatFees = r.o + 24 <= data.length ? fees(r) : { lpFeeBps: 0n, protocolFeeBps: 0n, creatorFeeBps: 0n };
  return out;
}
export function decodeSharingConfig(data) {
  expectDisc(data, 'SharingConfig');
  const r = new Reader(data, 8);
  return { bump: r.u8(), version: r.u8(), status: ['Paused', 'Active'][r.u8()], mint: r.pubkey(), admin: r.pubkey(), adminRevoked: r.bool(),
    shareholders: r.vec((x) => ({ address: x.pubkey(), shareBps: x.u16() })) };
}
/** PumpSwap Pool. coin_creator (byte 211) receives the pool's creator fees (the vault after our migration). */
export function decodePool(data) {
  expectDisc(data, 'Pool');
  const r = new Reader(padTo(data, SIZE.Pool), 8);
  return {
    poolBump: r.u8(), index: r.u16(), creator: r.pubkey(), baseMint: r.pubkey(), quoteMint: r.pubkey(), lpMint: r.pubkey(),
    poolBaseTokenAccount: r.pubkey(), poolQuoteTokenAccount: r.pubkey(), lpSupply: r.u64(), coinCreator: r.pubkey(),
    isMayhemMode: r.bool(), isCashbackCoin: r.bool(), virtualQuoteReserves: r.i128(), creatorFeeBps: r.u64(),
    canEditCreatorFee: r.bool(), isHolderReward: r.bool(), dataLength: data.length,
  };
}
export const POOL_COIN_CREATOR_OFFSET = 211;
export function decodeAmmGlobalConfig(data) {
  expectDisc(data, 'GlobalConfig');
  const r = new Reader(padTo(data, SIZE.GlobalConfig), 8);
  return {
    admin: r.pubkey(), lpFeeBasisPoints: r.u64(), protocolFeeBasisPoints: r.u64(), disableFlags: r.u8(),
    protocolFeeRecipients: r.array(8, (x) => x.pubkey()), coinCreatorFeeBasisPoints: r.u64(), adminSetCoinCreatorAuthority: r.pubkey(),
    whitelistPda: r.pubkey(), reservedFeeRecipient: r.pubkey(), mayhemModeEnabled: r.bool(), reservedFeeRecipients: r.array(7, (x) => x.pubkey()),
    isCashbackEnabled: r.bool(), buybackFeeRecipients: r.array(8, (x) => x.pubkey()), buybackBasisPoints: r.u64(), boostAuthority: r.pubkey(),
    boostEnabled: r.bool(), creatorFeeConfigurable: r.bool(), maxConfigurableCreatorFeeBps: r.u64(),
  };
}
/** SPL Token / Token-2022 account base layout (165 bytes). */
export function decodeTokenAccount(data) {
  if (!data || data.length < 165) return null;
  const r = new Reader(data);
  const mint = r.pubkey(), owner = r.pubkey(), amount = r.u64();
  const state = data[108];
  const isNative = data.readUInt32LE(109) === 1 ? data.readBigUInt64LE(113) : null;
  return { mint, owner, amount, state: ['uninitialized', 'initialized', 'frozen'][state] ?? state, rentExemptReserve: isNative };
}
const EXTENSION_NAMES = {
  1: 'TransferFeeConfig', 3: 'MintCloseAuthority', 4: 'ConfidentialTransferMint', 6: 'DefaultAccountState', 9: 'NonTransferable',
  10: 'InterestBearingConfig', 12: 'PermanentDelegate', 14: 'TransferHook', 16: 'ConfidentialTransferFeeConfig', 18: 'MetadataPointer',
  19: 'TokenMetadata', 20: 'GroupPointer', 21: 'TokenGroup', 22: 'GroupMemberPointer', 23: 'TokenGroupMember', 24: 'ConfidentialMintBurn',
  25: 'ScaledUiAmount', 26: 'Pausable',
};
/** Extensions that would make the coin unsafe for plain wallet-to-wallet transfers or holder accounting. */
export const RISKY_MINT_EXTENSIONS = ['TransferFeeConfig', 'TransferHook', 'PermanentDelegate', 'NonTransferable', 'DefaultAccountState', 'MintCloseAuthority', 'Pausable', 'ConfidentialTransferMint', 'InterestBearingConfig', 'ScaledUiAmount'];
/** Mint (SPL or Token-2022) with its Token-2022 extensions and token metadata. */
export function decodeMint(data, owner) {
  const r = new Reader(data);
  const optKey = () => { const tag = r.u32(); const k = r.pubkey(); return tag ? k : null; };
  const out = { mintAuthority: optKey(), supply: r.u64(), decimals: r.u8(), isInitialized: r.bool(), freezeAuthority: optKey(), extensions: [], metadata: null, metadataPointer: null };
  if (owner) out.tokenProgram = pk(owner);
  if (data.length > 165 && data[165] === 1) {
    let o = 166;
    while (o + 4 <= data.length) {
      const type = data.readUInt16LE(o), len = data.readUInt16LE(o + 2); o += 4;
      if (type === 0 && len === 0) break;
      const v = data.subarray(o, o + len); o += len;
      const name = EXTENSION_NAMES[type] ?? `Unknown(${type})`;
      out.extensions.push(name);
      const optional = (b) => (b.equals(Buffer.alloc(32)) ? null : new PublicKey(b));
      if (name === 'MetadataPointer') out.metadataPointer = { authority: optional(v.subarray(0, 32)), metadataAddress: optional(v.subarray(32, 64)) };
      if (name === 'TokenMetadata') {
        const m = new Reader(v);
        const updateAuthority = optional(v.subarray(0, 32)); m.o = 32;
        const mint = m.pubkey(), name_ = m.string(), symbol = m.string(), uri = m.string();
        const additional = m.vec((x) => [x.string(), x.string()]);
        out.metadata = { updateAuthority, mint, name: name_, symbol, uri, additional };
      }
    }
  }
  return out;
}

// Events (Anchor emit_cpi!: inner instruction data = EVENT_IX_TAG + event discriminator + borsh body)
const EVENT_LAYOUTS = {
  CreateEvent: [['name', 'string'], ['symbol', 'string'], ['uri', 'string'], ['mint', 'pubkey'], ['bondingCurve', 'pubkey'], ['user', 'pubkey'], ['creator', 'pubkey'],
    ['timestamp', 'i64'], ['virtualTokenReserves', 'u64'], ['virtualSolReserves', 'u64'], ['realTokenReserves', 'u64'], ['tokenTotalSupply', 'u64'], ['tokenProgram', 'pubkey'],
    ['isMayhemMode', 'bool'], ['isCashbackEnabled', 'bool'], ['quoteMint', 'pubkey'], ['virtualQuoteReserves', 'u64'], ['creatorFeeBps', 'u64'], ['isHolderReward', 'bool']],
  TradeEvent: [['mint', 'pubkey'], ['solAmount', 'u64'], ['tokenAmount', 'u64'], ['isBuy', 'bool'], ['user', 'pubkey'], ['timestamp', 'i64'], ['virtualSolReserves', 'u64'],
    ['virtualTokenReserves', 'u64'], ['realSolReserves', 'u64'], ['realTokenReserves', 'u64'], ['feeRecipient', 'pubkey'], ['feeBasisPoints', 'u64'], ['fee', 'u64'],
    ['creator', 'pubkey'], ['creatorFeeBasisPoints', 'u64'], ['creatorFee', 'u64'], ['trackVolume', 'bool'], ['totalUnclaimedTokens', 'u64'], ['totalClaimedTokens', 'u64'],
    ['currentSolVolume', 'u64'], ['lastUpdateTimestamp', 'i64'], ['ixName', 'string'], ['mayhemMode', 'bool'], ['cashbackFeeBasisPoints', 'u64'], ['cashback', 'u64'],
    ['buybackFeeBasisPoints', 'u64'], ['buybackFee', 'u64'], ['shareholders', 'shareholders'], ['quoteMint', 'pubkey'], ['quoteAmount', 'u64'],
    ['virtualQuoteReserves', 'u64'], ['realQuoteReserves', 'u64'], ['holderRewardsBps', 'u64'], ['holderRewards', 'u64']],
  CompleteEvent: [['user', 'pubkey'], ['mint', 'pubkey'], ['bondingCurve', 'pubkey'], ['timestamp', 'i64'], ['quoteMint', 'pubkey']],
  CollectCreatorFeeEvent: [['timestamp', 'i64'], ['creator', 'pubkey'], ['creatorFee', 'u64'], ['quoteMint', 'pubkey']],
  CompletePumpAmmMigrationEvent: [['user', 'pubkey'], ['mint', 'pubkey'], ['mintAmount', 'u64'], ['solAmount', 'u64'], ['poolMigrationFee', 'u64'], ['bondingCurve', 'pubkey'],
    ['timestamp', 'i64'], ['pool', 'pubkey'], ['quoteMint', 'pubkey']],
  CollectCoinCreatorFeeEvent: [['timestamp', 'i64'], ['coinCreator', 'pubkey'], ['coinCreatorFee', 'u64'], ['coinCreatorVaultAta', 'pubkey'], ['coinCreatorTokenAccount', 'pubkey']],
};
export const EVENT_FIELDS = EVENT_LAYOUTS;
/** Decodes one event from self-CPI instruction data (tag + discriminator + body) as { event, ...fields }; null if not an event. Trailing fields missing from older logs read as defaults. */
export function decodeEventInstructionData(data) {
  const d = Buffer.from(data);
  if (d.length < 16 || d.subarray(0, 8).toString('hex') !== EVENT_IX_TAG) return null;
  const hex = d.subarray(8, 16).toString('hex');
  const name = Object.keys(EVENT).find((k) => EVENT[k] === hex);
  if (!name || !EVENT_LAYOUTS[name]) return name ? { event: name } : null;
  const r = new Reader(Buffer.concat([d.subarray(16), Buffer.alloc(64)]));
  const body = { event: name }; // `event`, not `name`: CreateEvent has a `name` field of its own
  for (const [field, type] of EVENT_LAYOUTS[name]) {
    body[field] = type === 'shareholders' ? r.vec((x) => ({ address: x.pubkey(), shareBps: x.u16() })) : r[type]();
  }
  return body;
}

// ---------------------------------------------------------------------------------------------
// Quotes (mirror @pump-fun/pump-sdk bondingCurve.ts / fees.ts)
// ---------------------------------------------------------------------------------------------
const ceilDiv = (a, b) => (a + b - 1n) / b;
export const feeOf = (amount, bps) => ceilDiv(BigInt(amount) * BigInt(bps), 10_000n);
/** Market cap in lamports: virtual_quote * supply / virtual_token (supply = 1e15 base units for non-mayhem coins). */
export const marketCapLamports = ({ virtualQuoteReserves, virtualTokenReserves }, supply = ONE_BILLION_SUPPLY) => (BigInt(virtualQuoteReserves) * supply) / BigInt(virtualTokenReserves);
function tierFees(tiers, marketCap) {
  if (!tiers.length) throw new Error('fee tiers cannot be empty');
  if (marketCap < tiers[0].marketCapLamportsThreshold) return tiers[0].fees;
  for (const t of [...tiers].reverse()) if (marketCap >= t.marketCapLamportsThreshold) return t.fees;
  return tiers[0].fees;
}
/** { protocolFeeBps, creatorFeeBps } for a SOL-paired curve: FeeConfig market-cap tier, else Global's flat bps. */
export function curveFeeBps({ global, feeConfig, curve }) {
  if (!feeConfig) return { protocolFeeBps: global.feeBasisPoints, creatorFeeBps: global.creatorFeeBasisPoints };
  const f = tierFees(feeConfig.feeTiers, marketCapLamports(curve));
  return { protocolFeeBps: f.protocolFeeBps, creatorFeeBps: f.creatorFeeBps };
}
/** The curve create_v2 initializes for a SOL-paired coin. */
export function newCurve(global) {
  return { virtualTokenReserves: global.initialVirtualTokenReserves, virtualQuoteReserves: global.initialVirtualSolReserves, realTokenReserves: global.initialRealTokenReserves,
    realQuoteReserves: 0n, tokenTotalSupply: global.tokenTotalSupply, complete: false, creator: null };
}
/** Lamports (fees included) that buying exactly `amount` base units costs now. */
export function buyCost({ global, feeConfig, curve, amount }) {
  const a = BigInt(amount) < curve.realTokenReserves ? BigInt(amount) : curve.realTokenReserves;
  const sol = (a * curve.virtualQuoteReserves) / (curve.virtualTokenReserves - a) + 1n;
  const { protocolFeeBps, creatorFeeBps } = curveFeeBps({ global, feeConfig, curve });
  const protocolFee = feeOf(sol, protocolFeeBps), creatorFee = feeOf(sol, creatorFeeBps);
  return { amount: a, sol, protocolFee, creatorFee, total: sol + protocolFee + creatorFee, protocolFeeBps, creatorFeeBps };
}
/** Base units a buy spending `lamports` (fees included) receives now (the SDK's getBuyTokenAmountFromSolAmount). */
export function buyTokensForSol({ global, feeConfig, curve, lamports }) {
  const { protocolFeeBps, creatorFeeBps } = curveFeeBps({ global, feeConfig, curve });
  const input = ((BigInt(lamports) - 1n) * 10_000n) / (protocolFeeBps + creatorFeeBps + 10_000n);
  const tokens = (input * curve.virtualTokenReserves) / (curve.virtualQuoteReserves + input);
  return tokens < curve.realTokenReserves ? tokens : curve.realTokenReserves;
}
/** Lamports a sell of `amount` base units returns after fees. */
export function sellProceeds({ global, feeConfig, curve, amount }) {
  const sol = (BigInt(amount) * curve.virtualQuoteReserves) / (curve.virtualTokenReserves + BigInt(amount));
  const { protocolFeeBps, creatorFeeBps } = curveFeeBps({ global, feeConfig, curve });
  const protocolFee = feeOf(sol, protocolFeeBps), creatorFee = feeOf(sol, creatorFeeBps);
  return { sol, protocolFee, creatorFee, net: sol - protocolFee - creatorFee };
}
/** Applies a buy to a curve copy (what the program does), for multi-buy planning. */
export function applyBuy(curve, amount, solIn) {
  const c = { ...curve };
  c.virtualTokenReserves -= amount; c.realTokenReserves -= amount; c.virtualQuoteReserves += solIn; c.realQuoteReserves += solIn;
  c.complete = c.realTokenReserves === 0n;
  return c;
}
export const withSlippageUp = (v, bps) => BigInt(v) + (BigInt(v) * BigInt(bps)) / 10_000n;
export const withSlippageDown = (v, bps) => BigInt(v) - (BigInt(v) * BigInt(bps)) / 10_000n;

// ---------------------------------------------------------------------------------------------
// The launch: create_v2 + first buy in one transaction
// ---------------------------------------------------------------------------------------------
/** Picks a fee recipient the program accepts: Global.fee_recipient or one of Global.fee_recipients (non-mayhem). */
export function pickFeeRecipient(global, { mayhem = false, index } = {}) {
  const list = mayhem ? [global.reservedFeeRecipient, ...global.reservedFeeRecipients] : [global.feeRecipient, ...global.feeRecipients];
  return list[index ?? Math.floor(Math.random() * list.length)];
}
export function pickBuybackFeeRecipient(globalOrConfig, { index } = {}) {
  const list = globalOrConfig.buybackFeeRecipients;
  return list[index ?? Math.floor(Math.random() * list.length)];
}

/**
 * Instructions for ONE transaction: [compute limit, (price)] + create_v2 (creator = vault as a
 * plain address) + the buyer's Token-2022 ATA (idempotent) + the first buy, quoted against the
 * fresh curve from Global (nothing can trade before it inside the same transaction).
 * `buy`: 'legacy' (fits a 1232-byte legacy/v0 transaction only with a short uri and no
 * priority-fee instruction), 'v2' (buy_v2; needs a v1 transaction or a lookup table),
 * 'exactQuoteIn' (buy_exact_quote_in_v2: spend exactly `lamports`; gets ~0.00005% fewer tokens
 * than the quote, covered by the slippage floor). For a v1 transaction pass computeUnits: 0 and put
 * computeUnitLimit (~300k) and loadedAccountsDataSizeLimit (8 MiB, not buildV1's 4 MiB) in its config.
 * Signers: `user` (fee payer) and `mint`.
 */
export function launchInstructions({ global, feeConfig, mint, user, creator, name, symbol, uri, lamports, slippageBps = 100, buy = 'legacy', computeUnits = 300_000, microLamports = 0, feeRecipient, buybackFeeRecipient }) {
  if (global.createV2Enabled === false) throw new Error('Global.create_v2_enabled is off (6046)');
  const curve = newCurve(global);
  const amount = buyTokensForSol({ global, feeConfig, curve, lamports });
  const cost = buyCost({ global, feeConfig, curve, amount });
  const maxSolCost = withSlippageUp(cost.total, slippageBps);
  feeRecipient ??= pickFeeRecipient(global);
  buybackFeeRecipient ??= pickBuybackFeeRecipient(global);
  const common = { mint, user, creator, feeRecipient, buybackFeeRecipient };
  // computeUnits: 0 omits the compute-budget instructions (a v1 transaction carries its limit and
  // priority fee in its own config, as the repo's buildV1 does).
  const ixs = computeUnits ? [computeUnitLimitInstruction(computeUnits)] : [];
  if (microLamports) ixs.push(computeUnitPriceInstruction(microLamports));
  ixs.push(createV2Instruction({ mint, user, creator, name, symbol, uri }));
  ixs.push(createAtaIdempotentInstruction({ payer: user, owner: user, mint, tokenProgram: TOKEN_2022_PROGRAM_ID }));
  if (buy === 'legacy') ixs.push(buyInstruction({ ...common, amount, maxSolCost }));
  else if (buy === 'v2') ixs.push(buyV2Instruction({ ...common, amount, maxSolCost }));
  else if (buy === 'exactQuoteIn') ixs.push(buyExactQuoteInV2Instruction({ ...common, spendableQuoteIn: BigInt(lamports), minTokensOut: withSlippageDown(amount, slippageBps) }));
  else throw new Error(`unknown buy kind ${buy}`);
  return { instructions: ixs, expected: { amount, cost, maxSolCost, curveAfter: applyBuy(curve, amount, cost.sol) } };
}
/** One more buyer inside the launch transaction (each extra buyer signs it). */
export function extraBuyerInstructions({ global, feeConfig, curve, mint, user, creator, lamports, slippageBps = 100, feeRecipient, buybackFeeRecipient }) {
  const amount = buyTokensForSol({ global, feeConfig, curve, lamports });
  const cost = buyCost({ global, feeConfig, curve, amount });
  return {
    instructions: [
      createAtaIdempotentInstruction({ payer: user, owner: user, mint, tokenProgram: TOKEN_2022_PROGRAM_ID }),
      buyInstruction({ mint, user, creator, amount, maxSolCost: withSlippageUp(cost.total, slippageBps), feeRecipient: feeRecipient ?? pickFeeRecipient(global), buybackFeeRecipient: buybackFeeRecipient ?? pickBuybackFeeRecipient(global) }),
    ],
    expected: { amount, cost, curveAfter: applyBuy(curve, amount, cost.sol) },
  };
}

// ---------------------------------------------------------------------------------------------
// Read-only verifier
// ---------------------------------------------------------------------------------------------
/**
 * A reader is anything with getAccounts(pubkeys) -> [{ data: Buffer, owner: PublicKey, lamports } | null].
 * rpcReader(url) speaks plain JSON-RPC (getMultipleAccounts only). The repo's RpcTransport and
 * SvmTransport already have this shape.
 */
export function rpcReader(url, { commitment = 'confirmed' } = {}) {
  let id = 0;
  return {
    async getAccounts(keys) {
      const out = [];
      for (let i = 0; i < keys.length; i += 100) {
        const chunk = keys.slice(i, i + 100).map((k) => pk(k).toBase58());
        const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method: 'getMultipleAccounts', params: [chunk, { encoding: 'base64', commitment }] }) });
        const j = await res.json();
        if (j.error) throw new Error(`getMultipleAccounts: ${j.error.message}`);
        out.push(...j.result.value.map((v) => (v ? { data: Buffer.from(v.data[0], 'base64'), owner: new PublicKey(v.owner), lamports: BigInt(v.lamports), executable: v.executable } : null)));
      }
      return out;
    },
  };
}
const lamportsOf = (a) => (a ? BigInt(a.lamports) : 0n);

/** Pump creator vault and PumpSwap creator vault balances of `creator` (both programs). */
export async function creatorVaultBalances(reader, creator, { quoteMint = NATIVE_MINT, quoteTokenProgram = TOKEN_PROGRAM_ID } = {}) {
  creator = pk(creator);
  const pumpVault = creatorVaultPda(creator), ammAuthority = ammCreatorVaultAuthorityPda(creator), ammAta = ata(ammAuthority, quoteMint, quoteTokenProgram);
  const creatorWsol = ata(creator, NATIVE_MINT, TOKEN_PROGRAM_ID);
  const [pv, aa, cw, c, rentAcc] = await reader.getAccounts([pumpVault, ammAta, creatorWsol, creator, RENT_SYSVAR_ID]);
  const rent = rentAcc ? decodeRent(rentAcc.data) : LIVE_RENT_30_SEPT;
  const floor = minimumBalance(rent, 0);
  const pvLamports = lamportsOf(pv), ammToken = aa ? decodeTokenAccount(aa.data) : null, wsol = cw ? decodeTokenAccount(cw.data) : null;
  return {
    creator: { address: creator, lamports: lamportsOf(c), owner: c ? pk(c.owner) : null },
    pump: { address: pumpVault, lamports: pvLamports, rentFloor: floor, collectable: pvLamports > floor ? pvLamports - floor : 0n },
    amm: { authority: ammAuthority, ata: ammAta, exists: !!aa, amount: ammToken ? ammToken.amount : 0n,
          // ATA rent the account holds besides the WSOL amount (not part of the fees).
      ataRent: aa ? lamportsOf(aa) - (ammToken ? ammToken.amount : 0n) : 0n },
    creatorWsolAta: { address: creatorWsol, exists: !!cw, amount: wsol ? wsol.amount : 0n },
  };
}

/**
 * Everything the launch must hold before any announcement. Returns { ok, checks[], curve, pool, mint, vaults }.
 * `expectedCreator`: the AC vault PDA. Checks: curve exists and is pump-owned, creator == vault,
 * regular coin (not holder-reward, not mayhem, not cashback), SOL-paired, no sharing config (6049
 * risk), mint is Token-2022 with 6 decimals, no transfer fee / hook / delegate / freeze authority,
 * metadata as expected, and (after graduation) pool.coin_creator == vault.
 */
export async function verifyCoin(reader, { mint, expectedCreator, expectedMetadata } = {}) {
  mint = pk(mint); expectedCreator = pk(expectedCreator);
  const curveKey = bondingCurvePda(mint), pool = canonicalPoolPda(mint), sharing = sharingConfigPda(mint);
  const [curveAcc, mintAcc, poolAcc, sharingAcc] = await reader.getAccounts([curveKey, mint, pool, sharing]);
  const checks = [];
  const check = (name, pass, detail) => checks.push({ name, pass: !!pass, detail });
  let curve = null, poolState = null, mintState = null;
  check('bonding curve exists and is owned by pump', curveAcc && pk(curveAcc.owner).equals(PUMP_PROGRAM_ID), curveKey.toBase58());
  if (curveAcc) {
    curve = decodeBondingCurve(curveAcc.data);
    check('bonding_curve.creator == AC vault', curve.creator.equals(expectedCreator), `${curve.creator.toBase58()} vs ${expectedCreator.toBase58()}`);
    check('regular creator-fee coin (not holder rewards)', !curve.isHolderReward, `is_holder_reward=${curve.isHolderReward}`);
    check('not mayhem mode', !curve.isMayhemMode, `is_mayhem_mode=${curve.isMayhemMode}`);
    check('not a cashback coin', !curve.isCashbackCoin, `is_cashback_coin=${curve.isCashbackCoin}`);
    check('SOL-paired (quote_mint is the zero key)', curve.quoteMint.equals(ZERO_KEY), curve.quoteMint.toBase58());
    check('schedule creator fee (creator_fee_bps = 0)', curve.creatorFeeBps === 0n, `${curve.creatorFeeBps}`);
  }
  check('no fee sharing config (else collect fails with 6049)', !isSharingConfig(sharingAcc), sharing.toBase58());
  check('mint exists', !!mintAcc, mint.toBase58());
  if (mintAcc) {
    mintState = decodeMint(mintAcc.data, mintAcc.owner);
    check('mint is Token-2022', pk(mintAcc.owner).equals(TOKEN_2022_PROGRAM_ID), pk(mintAcc.owner).toBase58());
    check('6 decimals', mintState.decimals === TOKEN_DECIMALS, `${mintState.decimals}`);
    check('no freeze authority', mintState.freezeAuthority === null, `${mintState.freezeAuthority?.toBase58() ?? 'none'}`);
    const risky = mintState.extensions.filter((e) => RISKY_MINT_EXTENSIONS.includes(e));
    check('no transfer fee / hook / delegate / pause extensions', risky.length === 0, mintState.extensions.join(',') || 'none');
    if (expectedMetadata && mintState.metadata) {
      for (const f of ['name', 'symbol', 'uri']) if (expectedMetadata[f] != null) check(`metadata ${f}`, mintState.metadata[f] === expectedMetadata[f], mintState.metadata[f]);
    }
  }
  if (isAmmPool(poolAcc)) {
    poolState = decodePool(poolAcc.data);
    check('pool.coin_creator == AC vault', poolState.coinCreator.equals(expectedCreator), poolState.coinCreator.toBase58());
    check('canonical pool creator is the pump pool authority', poolState.creator.equals(poolAuthorityPda(mint)), poolState.creator.toBase58());
  }
  const vaults = await creatorVaultBalances(reader, expectedCreator);
  return { ok: checks.every((c) => c.pass), checks, curve, pool: poolState ? { address: pool, ...poolState } : null, mint: mintState, vaults };
}

// Anyone can make an account exist at any address with a plain SOL transfer (a system-owned, empty
// account). Such an account at the sharing-config or the canonical pool PDA is neither: pump ignores
// it and migrate still creates the pool over it. Only what the owning program made counts; nothing
// else can sign for those PDAs, so an account it owns there is the real one.
/** Whether an account at sharingConfigPda(mint) is a fee sharing config: owned by pump_fees. */
export const isSharingConfig = (acc) => !!acc && pk(acc.owner).equals(PUMP_FEES_PROGRAM_ID);
/** Whether an account at canonicalPoolPda(mint) is the PumpSwap pool: owned by pump_amm. */
export const isAmmPool = (acc) => !!acc && pk(acc.owner).equals(PUMP_AMM_PROGRAM_ID);

/**
 * What the fee crank checks before each run (plan step 7): the curve's and, after graduation, the
 * pool's creator is still the vault, and no sharing config took the coin over (the collect would
 * fail with 6049 / 6047). Returns { ok, graduated, problems[] } for the alert.
 */
export async function creatorStatus(reader, { mint, vault }) {
  mint = pk(mint); vault = pk(vault);
  const [curveAcc, poolAcc, sharingAcc, ammAta] = await reader.getAccounts([bondingCurvePda(mint), canonicalPoolPda(mint), sharingConfigPda(mint), ammCreatorVaultAta(vault)]);
  const problems = [];
  if (!curveAcc) problems.push('bonding curve missing');
  const curve = curveAcc ? decodeBondingCurve(curveAcc.data) : null;
  if (curve && !curve.creator.equals(vault)) problems.push(`bonding_curve.creator is ${curve.creator.toBase58()}, not the vault`);
  if (curve?.isHolderReward) problems.push('the coin is now a holder-rewards coin');
  const pool = isAmmPool(poolAcc) ? decodePool(poolAcc.data) : null;
  if (pool && !pool.coinCreator.equals(vault)) problems.push(`pool.coin_creator is ${pool.coinCreator.toBase58()}, not the vault`);
  if (isSharingConfig(sharingAcc)) problems.push('a fee sharing config exists for the mint (creator migrated: 6049)');
  const ammVaultAmount = ammAta ? decodeTokenAccount(ammAta.data)?.amount ?? 0n : 0n;
  return { ok: problems.length === 0, graduated: !!pool, complete: !!curve?.complete, ammVaultExists: !!ammAta, ammVaultAmount, problems };
}
/**
 * The crank's one transaction (fee payer only; the vault never signs): when the PumpSwap creator
 * vault ATA exists (it is created by the first PumpSwap trade; before that the transfer fails with
 * 3012 AccountNotInitialized), first move its WSOL into pump's creator_vault (v1 transfer, no
 * signer), then collect_creator_fee_v2 into the vault. ~56k CU, ~624 bytes (offline run on the
 * devnet binaries). Pass `includeAmm: status.ammVaultExists` from creatorStatus().
 */
export function feeCrankInstructions({ vault, includeAmm }) {
  return [...(includeAmm ? [transferCreatorFeesToPumpInstruction({ coinCreator: vault })] : []), collectCreatorFeeV2Instruction({ creator: vault })];
}

// ---------------------------------------------------------------------------------------------
// Metadata JSON (what the create_v2 `uri` should point to; pump.fun reads these fields)
// ---------------------------------------------------------------------------------------------
/** The off-chain metadata JSON pump.fun's own upload produces. Links must exist at launch; omit empty ones. */
export function metadataJson({ name, symbol, description, image, twitter, telegram, website, showName = true, createdOn }) {
  const out = { name, symbol, description, image, showName };
  if (createdOn) out.createdOn = createdOn;
  for (const [k, v] of Object.entries({ twitter, telegram, website })) if (v) out[k] = v;
  return out;
}
