// Public relay discovery and signed request routing. Hosted secrets never enter this module.
import { request } from 'node:https';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import { PublicKey } from '@solana/web3.js';
import { TAG, decodeEnvelope } from './layout.mjs';
const ZERO='11111111111111111111111111111111';
/** A routed envelope carries `hops`; one that already crossed MAX_HOPS relays is only ever served locally. */
export const MAX_HOPS=1;
/** Milliseconds a peer gets to answer a routed submission (health checks get 3 s). */
export const RELAY_TIMEOUT=20000;
/** A trial relay (no recent work) gets this long to answer, and is benched this long after a failure. */
export const TRIAL_TIMEOUT=5000, TRIAL_BENCH=600000;
/** Milliseconds of an envelope's life routing leaves for this relay's own submission. */
export const LOCAL_RESERVE=15000;
export function publicAddress(address) {
  if(isIP(address)===6) return /^[23][0-9a-f]{3}:/i.test(address) && !/^2001:(?:db8|0|10|20):/i.test(address) && !/^2002:/i.test(address);
  if(isIP(address)!==4)return false;
  const [a,b]=address.split('.').map(Number);
  return !(a===0||a===10||a===127||a>=224||(a===100&&b>=64&&b<=127)||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&(b===168||b===0||b===2))||(a===198&&(b===18||b===19||b===51))||(a===203&&b===0));
}
export function relayOrigin(value) {
  try {const u=new URL(value);if(u.protocol!=='https:'||u.username||u.password||u.port||u.search||u.hash||!['/','/v2','/v2/'].includes(u.pathname))return null;return u.origin;}catch{return null;}
}
export async function publicRelayRequest(origin,path,body,{timeout=body===undefined?3000:RELAY_TIMEOUT,resolve:dns=lookup}={}) {
  if(relayOrigin(origin)!==origin)throw Error('invalid public relay URL');
  // One deadline covers the DNS lookup and the request.
  const url=new URL(path,origin), host=url.hostname.replace(/^\[|\]$/g,''), until=Date.now()+timeout;
  let timer;
  const addresses=await Promise.race([dns(host,{all:true}),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('relay DNS timeout')),Math.min(3000,timeout));})]).finally(()=>clearTimeout(timer));
  if(!addresses.length||addresses.some(a=>!publicAddress(a.address)))throw Error('relay resolves to a non-public address');
  const pinned=addresses[0], payload=body===undefined?null:JSON.stringify(body);
  return new Promise((resolve,reject)=>{
    const req=request(url,{method:payload?'POST':'GET',autoSelectFamily:false,family:pinned.family,
      lookup:(_host,_options,callback)=>callback(null,pinned.address,pinned.family),
      headers:payload?{'content-type':'application/json','content-length':Buffer.byteLength(payload)}:{}},res=>{
      const chunks=[];let size=0;
      res.on('data',chunk=>{size+=chunk.length;if(size>250_000)req.destroy(Error('relay response too large'));else chunks.push(chunk);});
      res.on('error',reject);
      res.on('end',()=>resolve({status:res.statusCode,headers:new Headers(Object.entries(res.headers).filter(([,v])=>typeof v==='string')),text:Buffer.concat(chunks).toString('utf8')}));
    });
    const expiry=setTimeout(()=>req.destroy(Error('relay request timeout')),Math.max(1,until-Date.now()));
    req.on('close',()=>clearTimeout(expiry));req.on('error',reject);if(payload)req.write(payload);req.end();
  });
}
function authenticated(response,key) {
  const signer=response.headers.get('x-ac-signer'), time=response.headers.get('x-ac-time'), signature=response.headers.get('x-ac-signature');
  if(signer!==key||!time||!signature||Math.abs(Date.now()-Number(time))>60000||!Number.isFinite(Number(time)))throw Error('invalid relay receipt identity/time');
  if(!nacl.sign.detached.verify(Buffer.from(`${time}.${response.text}`),Buffer.from(signature,'base64'),new PublicKey(key).toBuffer()))throw Error('invalid relay receipt signature');
  const data=JSON.parse(response.text);
  // A signed refusal is an answer, not a dead peer: the envelope may be what is refused.
  if(response.status!==200)throw Object.assign(Error(data.error||`relay HTTP ${response.status}`),{refused:true});
  return {data,receipt:{signer,time,signature,body:response.text}};
}
/** Registers a hosted identity, whose custodian the program records as the fee payer: never routed. */
export const hostedRegistration=a=>(a.type==='register'&&a.hosted)||(a.type==='second'&&!!a.join?.hosted);
/**
 * Routes a funded signed envelope across registered relays that earned at least `minUnits` work
 * units in one of the last `recent` closed epochs (the open epoch does not count), ranked by the
 * message hash; the top `fanout` healthy ones are tried in turn, then this relay. A failure after
 * a peer was sent the envelope is checked against the chain and falls through: the agent nonce
 * lets the envelope land once, whoever sends it. A peer that hangs, forges or lies is benched for
 * 30 s; a signed refusal is not, since an envelope can make every honest relay refuse it. At most
 * `concurrency` outbound requests are open at once (past that the envelope is served here), each
 * bounded by `timeout`, all of them by `deadline` per envelope and by the envelope's expiry less
 * LOCAL_RESERVE. Forwarded envelopes carry `hops`; the receiving relay serves them locally
 * (MAX_HOPS), and only peers advertising relay-hops-v1 are routed to. A `trial` share of envelopes
 * (chosen by the message hash) first tries one relay with no recent work, so a new relay can earn
 * the work that qualifies it (owner, 1 October): it gets TRIAL_TIMEOUT, and a failure benches it for
 * TRIAL_BENCH before the envelope goes on to the ranked peers.
 */
export function relayPool(c,payer,{send=publicRelayRequest,now=Date.now,timeout=RELAY_TIMEOUT,concurrency=16,recent=24,minUnits=1,fanout=3,deadline=45000,trial=0.1}={}) {
  if(typeof trial!=='number'||!(trial>=0&&trial<=1))throw Error('relay pool trial must be a fraction from 0 to 1');
  for(const [k,v] of Object.entries({timeout,concurrency,recent,minUnits,fanout,deadline}))if(!Number.isSafeInteger(v)||v<(k==='recent'?0:1))throw Error(`relay pool ${k} must be a ${k==='recent'?'non-negative':'positive'} integer`);
  let cache=null, expires=0, open=0;
  const health=new Map(), self=payer.publicKey.toBase58();
  // null when the cap is reached. The slot frees when the request settles or its time is up.
  const call=(peer,path,body,ms)=>{
    if(open>=concurrency)return null;
    open++;let timer;
    return Promise.race([Promise.resolve().then(()=>send(peer.url,path,body,{timeout:ms})),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('relay request timeout')),ms);})])
      .finally(()=>{clearTimeout(timer);open--;});
  };
  async function candidates(){
    if(cache&&now()<expires)return cache;
    // Recency counts from the work key, as the program's seat check does: carried closes (relayer
    // pool under MIN_POT) keep crediting one key while the epoch counter runs on (review round 10).
    const {epoch,workKey}=await c.config();
    cache=(await c.all(TAG.RELAYER)).filter(r=>r.kind==='relay'&&r.key!==self&&relayOrigin(r.url))
      .map(r=>({key:r.key,url:relayOrigin(r.url),worked:r.work.some(w=>w.units>=minUnits&&w.epoch<epoch&&workKey-w.epoch<=recent)}));
    expires=now()+60000;return cache;
  }
  async function healthy(peer){
    const cached=health.get(peer.key);if(cached&&cached.until>now())return cached.ok;
    const pending=call(peer,'/v2',undefined,3000);if(!pending)return false;
    try{const {data}=authenticated(await pending,peer.key);const ok=data.program===c.program.toBase58()&&data.relay===peer.key&&data.kind==='relay'&&['signed-upload-frames-v1','relay-hops-v1'].every(x=>data.capabilities?.includes(x));health.set(peer.key,{ok,until:now()+30000});return ok;}
    catch{health.set(peer.key,{ok:false,until:now()+30000});return false;}
  }
  const match=async(tx,message,key)=>{
    if(!tx||tx.error)return false;
    for(const ix of tx.instructions){
      if(ix.program!==c.program.toBase58()||!Buffer.from(ix.data).equals(Buffer.concat([Buffer.from([1]),message])))continue;
      if(!key)return true;
      const accounts=ix.accounts;
      // Every relay pays its own fees (owner, 28 September): the relay's own wallet is the fee payer.
      if(accounts[0]!==tx.payer||accounts[1]!==c.configAddress.toBase58()||accounts[2]!==c.vault.toBase58()||accounts[3]!==ZERO||accounts[4]!==c.relayerAddress(key).toBase58())continue;
      if(tx.payer===key)return true;
    }
    return false;
  };
  async function recover(message,env){
    const agent=await c.agent(env.agent);if(!agent||agent.nonce<=env.nonce)return null;
    for(const tx of await c.t.recentTransactions(c.agentAddress(env.agent)))if(await match(tx,message))return {signature:tx.signature,relay:tx.payer,recovered:true,agent:env.agent,nonce:env.nonce,action:env.action.type};
    throw Object.assign(Error('agent nonce advanced with a different action; inspect chain state'),{status:409});
  }
  return {
    async status(){return {policy:`hash-ranked distribution across registered relays with ${minUnits}+ work units in one of the last ${recent} closed epochs, and ${Math.round(trial*100)}% of envelopes first to one relay without; the next peer, then local, on any failure`,relays:(await candidates()).map(p=>({...p,healthy:health.get(p.key)?.ok??null})),fallback:self,outbound:{open,concurrency}};},
    /** `route` false: recover from the chain or serve locally, never forward (a forwarded envelope). */
    async submit(body,local,{route=true}={}){
      const message=Buffer.from(body.message,'base64'),env=decodeEnvelope(message);
      const recovered=await recover(message,env);if(recovered)return recovered;
      // A peer given the envelope earlier may land it first; the local attempt then fails on its nonce.
      const fallback=async()=>{try{return await local();}catch(error){const r=await recover(message,env).catch(()=>null);if(r)return r;throw error;}};
      if(!route||env.preferred===self||hostedRegistration(env.action))return fallback();
      const preferred=env.preferred!==ZERO, all=await candidates();
      const score=p=>createHash('sha256').update(message).update(p.key).digest('hex');
      // An agent's own choice of relay needs no work record; the default ranking does.
      const peers=all.filter(p=>preferred?p.key===env.preferred:p.worked).sort((a,b)=>score(a).localeCompare(score(b))).slice(0,fanout);
      const benched=p=>{const h=health.get(p.key);return !!h&&!h.ok&&h.until>now();};
      const trialled=!preferred&&createHash('sha256').update('trial').update(message).digest().readUInt32BE(0)<trial*2**32;
      const newcomer=trialled?all.filter(p=>!p.worked&&!benched(p)).sort((a,b)=>score(a).localeCompare(score(b)))[0]:null;
      const bench=(peer,ms)=>health.set(peer.key,{ok:false,until:now()+ms});
      // Routing never eats into the time this relay needs to land the envelope itself (a preferred
      // envelope has no local attempt).
      const until=now()+Math.min(deadline,(env.expiry-Math.floor(await c.t.now()))*1000-(preferred?0:LOCAL_RESERVE)), packet={...body,hops:(Number.isSafeInteger(body.hops)&&body.hops>0?body.hops:0)+1};
      for(const peer of newcomer?[newcomer,...peers]:peers){
        const trying=peer===newcomer;
        if(until<=now())continue;
        if(!await healthy(peer)){if(trying)bench(peer,TRIAL_BENCH);continue;}
        const left=until-now();if(left<=0)break;
        const pending=call(peer,'/v2/relay',packet,Math.min(trying?TRIAL_TIMEOUT:timeout,left));
        if(!pending){if(preferred)throw Object.assign(Error('relay pool is at its outbound request limit; retry shortly'),{status:503});break;}
        try{
          const {data,receipt}=authenticated(await pending,peer.key);
          if(typeof data.signature!=='string')throw Error('relay omitted transaction signature');
          let tx;
          for(let i=0;i<4;i++){tx=await c.t.transaction(data.signature);if(tx)break;await new Promise(r=>setTimeout(r,300));}
          if(!await match(tx,message,peer.key))throw Error('relay response does not match a confirmed transaction');
          return {...data,relay:peer.key,relayUrl:peer.url,relayReceipt:receipt};
        }catch(error){
          if(!error.refused||trying)bench(peer,trying?TRIAL_BENCH:30000);
          const recovered=await recover(message,env);if(recovered)return recovered;
          // Only the named relay may submit a preferred envelope: nothing to fall through to.
          if(preferred)throw Object.assign(Error(`relay submission uncertain; retry the same signed envelope: ${error.message}`),{status:503});
        }
      }
      if(preferred)throw Object.assign(Error('preferred relay is unavailable'),{status:503});
      return fallback();
    },
  };
}
