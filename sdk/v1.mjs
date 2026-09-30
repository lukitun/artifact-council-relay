import {address,appendTransactionMessageInstructions,getCompiledTransactionMessageDecoder,createKeyPairSignerFromBytes,createNoopSigner,createTransactionMessage,getBase64EncodedWireTransaction,getSignatureFromTransaction,partiallySignTransactionMessageWithSigners,setTransactionMessageConfig,setTransactionMessageFeePayerSigner,setTransactionMessageLifetimeUsingBlockhash,signTransactionMessageWithSigners} from '@solana/kit';
import nacl from 'tweetnacl';
import { PublicKey } from '@solana/web3.js';
import { chain, decodeEnvelope, ed25519Data, encodeDirect, encodeFrame } from './layout.mjs';
// Builds and signs a version 1 transaction: compute limit and account-data limit travel in the
// transaction's own config, so no compute-budget instruction occupies an instruction index.
// The loaded-data limit counts every program the transaction loads: this program (423 KB, counted
// again when init passes the program account itself) and Token-2022 (711 KB) for a page-unlock burn
// exceed 1 MiB on devnet. 4 MiB costs only its compute-unit charge; the priority fee stays zero.
export const LOADED_DATA_LIMIT = 4 * 1024 * 1024;
export async function buildV1(ixs,payer,signers,latest,config={}){
 const pairs=await Promise.all([payer,...signers].map(k=>createKeyPairSignerFromBytes(k.secretKey)));
 const transaction=await signTransactionMessageWithSigners(messageV1(ixs,pairs[0],pairs,latest,config));
 return wire(transaction);
}
function messageV1(ixs,feePayer,pairs,latest,config){
 const known=new Map(pairs.map(s=>[s.address,s]));
 let message=createTransactionMessage({version:1});
 message=setTransactionMessageFeePayerSigner(feePayer,message);
 message=setTransactionMessageLifetimeUsingBlockhash({blockhash:latest.blockhash,lastValidBlockHeight:BigInt(latest.lastValidBlockHeight)},message);
 message=appendTransactionMessageInstructions(ixs.map(ix=>({programAddress:address(ix.programId.toBase58()),data:ix.data,accounts:ix.keys.map(k=>{
  const a=address(k.pubkey.toBase58()),role=(k.isWritable?1:0)+(k.isSigner?2:0);return {address:a,role,...(k.isSigner&&known.has(a)?{signer:known.get(a)}:{})};})})),message);
 return setTransactionMessageConfig({computeUnitLimit:1400000,loadedAccountsDataSizeLimit:LOADED_DATA_LIMIT,priorityFeeLamports:0n,...config},message);
}
function wire(transaction){
 const raw=Buffer.from(getBase64EncodedWireTransaction(transaction),'base64');if(raw.length>4096)throw Error(`V1 transaction too large: ${raw.length}`);
 // A v1 wire transaction carries its signatures after the message, so take the fee payer's
 // signature from the signer rather than from a byte offset.
 return {transaction,raw,signature:getSignatureFromTransaction(transaction)};
}


/**
 * Self-pay mode (owner, 30 September): a transaction whose fee payer is a key this process does not
 * hold (an agent's own key). Built and signed by `signers` only; `message` is the exact bytes the fee
 * payer signs, and `sign(signature)` returns the wire transaction once it has.
 */
export async function compileV1(ixs,feePayer,signers,latest,config={}){
 const pairs=await Promise.all(signers.map(k=>createKeyPairSignerFromBytes(k.secretKey)));
 const payer=new PublicKey(feePayer).toBase58();
 const transaction=await partiallySignTransactionMessageWithSigners(messageV1(ixs,createNoopSigner(address(payer)),pairs,latest,config));
 const message=Buffer.from(transaction.messageBytes);
 return {message,feePayer:payer,latest,ixs,
  sign(signature){
   const sig=Buffer.from(signature);
   if(sig.length!==64||!nacl.sign.detached.verify(Uint8Array.from(message),Uint8Array.from(sig),new PublicKey(payer).toBytes()))throw Object.assign(Error('the fee payer\'s signature does not verify over this transaction\'s message'),{status:400});
   return wire({...transaction,signatures:{...transaction.signatures,[payer]:Uint8Array.from(sig)}});
  }};
}

const ED25519='Ed25519SigVerify111111111111111111111111111',SYSTEM='11111111111111111111111111111111',IX_SYSVAR='Sysvar1nstructions1111111111111111111111111';
/** The accounts every instruction the SDK builds for fee payer `payer` starts with (`Council.prefix`):
 *  the payer, config, vault, system program, the relayer slot and the instructions sysvar. The relayer
 *  slot (index 4) is the one account the SDK picks from chain state, so `slot` lists what it may be: the
 *  program id (no relayer record), the payer's relayer record, or, for a self-paid envelope only, the
 *  record of the gateway it prefers (`host`). */
function sdkPrefix(program,payer,host=null){
 const pda=(...seeds)=>PublicKey.findProgramAddressSync(seeds.map(s=>typeof s==='string'?Buffer.from(s):s.toBuffer()),program)[0].toBase58();
 const relayer=k=>pda('relayer',new PublicKey(k));
 return {prefix:[payer,pda('config'),pda('treasury'),SYSTEM,null,IX_SYSVAR],slot:[program.toBase58(),relayer(payer),...(host?[relayer(host)]:[])],pda};
}
const sameAccounts=(got,want,slot)=>got.length===want.length&&got.every((a,i)=>i===4?slot.includes(a):a===want[i]);
/**
 * Before a key signs a self-paid transaction a relay built for it as fee payer (owner, 30 September):
 * the fee payer is that key and the only signer, no priority fee is set, and the transaction is exactly
 * one the agent would build itself, since it signs only what it can verify it asked for (review, 30
 * September):
 * - the envelope's: the Ed25519 check, byte for byte the SDK's layout (`ed25519Data`) of exactly the
 *   envelope signatures the agent sent (`signatures`: [{ key, signature }], in order; one to three; on a
 *   second of a hosted newcomer's draft, the newcomer's consent after them, from `envelopeConsent`), then
 *   this program's instruction, data 0x01 followed by `envelope` (signed self-paid, for this program),
 *   over the accounts the SDK derives for it: the prefix, the agent's record, then the envelope's own
 *   accounts. Solana charges the fee payer for every signature a precompile verifies, so an extra entry,
 *   even a valid one by another key, would raise the fee; another layout or account list is another
 *   transaction, which the program refuses once the envelope's nonce is used, yet charges;
 * - or one chunk write of `upload` carrying, byte for byte, one of the agent's own chunks and its link
 *   (`writes`, as `chain(frame)` builds them from its page text; or `text` itself), over the prefix and
 *   the upload. The program refuses any other bytes, but the fee payer would pay for each.
 * Nothing else can spend the key's SOL: a transfer, another program, or a changed envelope is refused.
 * Returns { kind: 'envelope' } or { kind: 'write', chunk } (the chunk's index); throws otherwise.
 * One transaction's check cannot bound how many copies a relay asks for: `checkSelfPaidBatch` checks a
 * whole 402.
 */
export function checkSelfPaidMessage(message,{program,feePayer,envelope=null,upload=null,signatures=null,writes=null,text=null}){
 const m=getCompiledTransactionMessageDecoder().decode(Uint8Array.from(message));
 const keys=m.staticAccounts.map(String),prog=new PublicKey(program),p=prog.toBase58(),payer=new PublicKey(feePayer).toBase58(),refuse=why=>{throw Object.assign(Error(`refusing to sign this self-paid transaction: ${why}`),{status:400});};
 if(keys[0]!==payer)refuse('its fee payer is not the expected key');
 if(m.header.numSignerAccounts!==1)refuse('it needs signatures besides the fee payer\'s');
 for(const v of m.configValues??[])if(v.kind==='u64'&&BigInt(v.value)!==0n)refuse('it sets a priority fee');
 const up=upload?new PublicKey(upload).toBase58():null;
 const ixs=m.instructionHeaders.map((h,i)=>{const x=m.instructionPayloads[i];return{prog:keys[h.programAccountIndex],data:Buffer.from(x.instructionData??[]),accounts:(x.instructionAccountIndices??[]).map(j=>keys[j])};});
 const signed=envelope?Buffer.concat([Buffer.from([1]),Buffer.from(envelope)]):null;
 if(signed&&ixs.length===2&&ixs[1].prog===p&&ixs[1].data.equals(signed)){
  const {prog:verifier,data,accounts}=ixs[0],n=data.length?data[0]:0;
  if(verifier!==ED25519||accounts.length)refuse('instruction 0 is not the Ed25519 check');
  const sent=Array.isArray(signatures)?signatures.map(x=>({key:new PublicKey(x.key).toBuffer(),signature:typeof x.signature==='string'?Buffer.from(x.signature,'base64'):Buffer.from(x.signature)})):null;
  if(!sent)refuse('the envelope signatures it should verify were not given');
  if(!(sent.length>=1&&sent.length<=3))refuse(`an envelope carries one to three signatures, not ${sent.length}`);
  // Exactly the signatures the agent sent, laid out as the SDK lays them out: a relay's own extra entries
  // would pay precompile fees on a transaction the program then refuses (its signature count is exact,
  // lib.rs `verify`), and the same entries at other offsets make another transaction to charge for.
  if(n!==sent.length)refuse(`its Ed25519 check carries ${n} signature${n===1?'':'s'}, not the ${sent.length} sent`);
  if(!data.equals(ed25519Data(sent,envelope.length,1)))refuse('its Ed25519 check is not, byte for byte, the SDK\'s check of the envelope signatures sent');
  let env;try{env=decodeEnvelope(envelope);}catch(e){refuse(`its envelope cannot be read: ${e.message}`);}
  if(env.program!==p)refuse('its envelope is bound to another program');
  if(!env.selfPaid)refuse('its envelope is not signed self-paid');
  const host=env.preferred!==SYSTEM&&env.preferred!==payer?env.preferred:null,{prefix,slot,pda}=sdkPrefix(prog,payer,host);
  if(!sameAccounts(ixs[1].accounts,[...prefix,pda('agent',new PublicKey(env.agent)),...env.accounts],slot))refuse('its program instruction names accounts other than those the SDK derives for this envelope');
  return {kind:'envelope'};
 }
 if(ixs.length===1&&ixs[0].prog===p&&ixs[0].data[0]===3&&ixs[0].data[1]===1){
  if(!up)refuse('it is a chunk write, and no upload of the agent\'s was named');
  const own=writes??(text!=null?chain(encodeFrame(text)).writes:null);
  if(!own)refuse('it is a chunk write, and the agent\'s own page text was not given to check it against');
  const chunk=own.findIndex(x=>encodeDirect({type:'write',chunk:x.chunk,next:x.next}).equals(ixs[0].data));
  if(chunk<0)refuse('its chunk write carries bytes other than a chunk of the agent\'s own page text');
  const {prefix,slot}=sdkPrefix(prog,payer);
  if(!sameAccounts(ixs[0].accounts,[...prefix,up],slot))refuse('its chunk write names accounts other than the SDK\'s for a write of the upload');
  return {kind:'write',chunk};
 }
 refuse('it is neither exactly the Ed25519 check and the signed envelope, nor one chunk write of the upload');
}
/**
 * "Draft = consent" (owner, 30 September): a member seconds a hosted newcomer's draft with its own
 * signature alone, and the gateway that hosts the newcomer adds the newcomer's co-signature, the second
 * signature the program requires of a second with `join` (lib.rs `verify`). Self-paid, the transaction
 * that carries `envelope` in a 402 (`messages`) then verifies one Ed25519 entry more than the agent
 * `sent`. This returns that entry, { key, signature } (base58, base64), to add after `sent` in the
 * signatures `checkSelfPaidBatch` checks, only when all of these hold: `envelope` is a second with a
 * hosted `join`; its Ed25519 check carries exactly the one signature sent, then this one; this one is by
 * the second's `author` (the newcomer) and verifies over the exact envelope bytes; and the check is byte
 * for byte the SDK's `ed25519Data` of the two. It costs the fee payer one more signature fee (5,000
 * lamports), which the 402's quote includes. Null when that check carries no more than `sent` (or no
 * transaction carries the envelope): the batch check then applies unchanged. Throws on anything else:
 * two extra entries, one by another key, a bad signature, the newcomer's entry first, or an extra entry
 * on any other envelope.
 */
export function envelopeConsent(messages,envelope,sent){
 const refuse=why=>{throw Object.assign(Error(`refusing to sign these self-paid transactions: ${why}`),{status:400});};
 if(!Array.isArray(messages)||!envelope||!Array.isArray(sent))return null;
 const env=Buffer.from(envelope),signed=Buffer.concat([Buffer.from([1]),env]);
 let e;try{e=decodeEnvelope(env);}catch{return null;}
 const found=[];
 for(const bytes of messages){
  let m;try{m=getCompiledTransactionMessageDecoder().decode(Uint8Array.from(bytes));}catch{continue;}
  const keys=m.staticAccounts.map(String),ixs=m.instructionHeaders.map((h,i)=>({prog:keys[h.programAccountIndex],data:Buffer.from(m.instructionPayloads[i].instructionData??[])}));
  if(ixs.length===2&&ixs[0].prog===ED25519&&ixs[1].prog===e.program&&ixs[1].data.equals(signed))found.push(ixs[0].data);
 }
 if(found.length>1)refuse(`they carry the envelope ${found.length} times`);
 const data=found[0],n=data?.length?data[0]:0;
 if(!data||!sent.length||n<=sent.length)return null;
 const a=e.action,counted=`its Ed25519 check carries ${n} signatures, not the ${sent.length} sent`;
 if(a.type!=='second'||!a.join?.hosted)refuse(`${counted}: only a second of a hosted newcomer's draft carries one more, the newcomer's consent`);
 // A second with join is signed by exactly its seconder and the newcomer: one sent, one added.
 if(sent.length!==1||n!==2)refuse(`${counted}: a second of a hosted newcomer's draft carries two, the one sent and then the newcomer's`);
 const off=2+14*n,entry=i=>({key:data.subarray(off+96*i,off+96*i+32),signature:data.subarray(off+96*i+32,off+96*(i+1))});
 const layout='its Ed25519 check is not, byte for byte, the SDK\'s check of the signature sent and then the newcomer\'s';
 const mine={key:new PublicKey(sent[0].key).toBuffer(),signature:typeof sent[0].signature==='string'?Buffer.from(sent[0].signature,'base64'):Buffer.from(sent[0].signature)};
 // The count and offsets table depend only on the entry count and the envelope's length: the SDK's, or refused.
 if(data.length!==off+96*n||!data.subarray(0,off).equals(ed25519Data([mine,mine],env.length,1).subarray(0,off)))refuse(layout);
 if(!entry(0).key.equals(mine.key)||!entry(0).signature.equals(mine.signature))refuse('its Ed25519 check does not start with the signature sent: the newcomer\'s consent comes after it');
 const extra=entry(1),author=new PublicKey(a.author);
 if(!extra.key.equals(author.toBuffer()))refuse(`the extra signature in its Ed25519 check is by ${new PublicKey(extra.key).toBase58()}, not the newcomer ${a.author}, the second's author`);
 if(!nacl.sign.detached.verify(Uint8Array.from(env),Uint8Array.from(extra.signature),author.toBytes()))refuse('the newcomer\'s signature in its Ed25519 check does not verify over this envelope');
 if(!data.equals(ed25519Data([mine,{key:author.toBuffer(),signature:extra.signature}],env.length,1)))refuse(layout);
 return {key:author.toBase58(),signature:Buffer.from(extra.signature).toString('base64')};
}
/**
 * A self-paid 402's transactions (`messages`, their message bytes), checked together before the key signs
 * any (review, 30 September): each passes `checkSelfPaidMessage` with `expect`; with `envelope`, exactly one
 * of them carries it; and each of the agent's chunks is written at most once, so never more writes than
 * its page has chunks. Copies can differ in bytes that cost nothing (the compute limits, the blockhash),
 * so only these bounds stop a relay from charging the key for copies the program refuses: at most the
 * one envelope and the page's own writes, what the action costs anyway. Returns each one's kind; throws.
 */
export function checkSelfPaidBatch(messages,expect){
 const refuse=why=>{throw Object.assign(Error(`refusing to sign these self-paid transactions: ${why}`),{status:400});};
 if(!Array.isArray(messages))refuse('they are not a list');
 const writes=expect.writes??(expect.text!=null?chain(encodeFrame(expect.text)).writes:null);
 const kinds=messages.map(m=>checkSelfPaidMessage(m,{...expect,writes}));
 const envelopes=kinds.filter(k=>k.kind==='envelope').length;
 if(expect.envelope&&envelopes!==1)refuse(envelopes?`they carry the envelope ${envelopes} times`:'they do not carry the envelope');
 const seen=new Set();
 for(const k of kinds)if(k.kind==='write'){if(seen.has(k.chunk))refuse(`they write chunk ${k.chunk} of the page more than once`);seen.add(k.chunk);}
 return kinds;
}
