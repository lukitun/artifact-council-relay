import {address,appendTransactionMessageInstructions,createKeyPairSignerFromBytes,createTransactionMessage,getBase64EncodedWireTransaction,getSignatureFromTransaction,setTransactionMessageConfig,setTransactionMessageFeePayerSigner,setTransactionMessageLifetimeUsingBlockhash,signTransactionMessageWithSigners} from '@solana/kit';
// Builds and signs a version 1 transaction: compute limit and account-data limit travel in the
// transaction's own config, so no compute-budget instruction occupies an instruction index.
export async function buildV1(ixs,payer,signers,latest,config={}){
 const pairs=await Promise.all([payer,...signers].map(k=>createKeyPairSignerFromBytes(k.secretKey)));
 const known=new Map(pairs.map(s=>[s.address,s]));
 let message=createTransactionMessage({version:1});
 message=setTransactionMessageFeePayerSigner(pairs[0],message);
 message=setTransactionMessageLifetimeUsingBlockhash({blockhash:latest.blockhash,lastValidBlockHeight:BigInt(latest.lastValidBlockHeight)},message);
 message=appendTransactionMessageInstructions(ixs.map(ix=>({programAddress:address(ix.programId.toBase58()),data:ix.data,accounts:ix.keys.map(k=>{
  const a=address(k.pubkey.toBase58()),role=(k.isWritable?1:0)+(k.isSigner?2:0);return {address:a,role,...(k.isSigner&&known.has(a)?{signer:known.get(a)}:{})};})})),message);
 message=setTransactionMessageConfig({computeUnitLimit:1400000,loadedAccountsDataSizeLimit:1024*1024,priorityFeeLamports:0n,...config},message);
 const transaction=await signTransactionMessageWithSigners(message);
 const raw=Buffer.from(getBase64EncodedWireTransaction(transaction),'base64');if(raw.length>4096)throw Error(`V1 transaction too large: ${raw.length}`);
 // A v1 wire transaction carries its signatures after the message, so take the fee payer's
 // signature from the signer rather than from a byte offset.
 return {transaction,raw,signature:getSignatureFromTransaction(transaction)};
}
