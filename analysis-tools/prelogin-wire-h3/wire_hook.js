'use strict';
// Passive observer: no argument, result, certificate or target-buffer modification.
const sockets=new Map(), contexts=new Map(), hooked=new Set(), depth=new Map(), pending=new Map();
let sequence=0,nextSocket=0,nextContext=0,nextOperation=0,emitted=0,limited=false;
const MAX=131072, CAPACITY=67108864;
const REASONS=new Set(['bounded','buffer_count','data_layout','stream_layout','socket_limit','context_limit','accepted_bounds','pending_limit','overlapped_reuse','callback_unsupported','completion_unmatched']);
function emit(e,b){if(emitted>=1024){if(!limited){limited=true;send({kind:'limit'});}return;}emitted++;e.sequence=++sequence;send(e,b||undefined);}
function fault(reason){throw Error(reason);}
function diagnostic(api,phase,error){const r=REASONS.has(error.message)?error.message:'memory_access';emit({kind:'read_error',api:api,phase:phase,reason:r});}
function enter(c,g){c.guard=g+':'+Process.getCurrentThreadId();const n=depth.get(c.guard)||0;depth.set(c.guard,n+1);c.outer=n===0;}
function leave(c){const n=(depth.get(c.guard)||1)-1;if(n)depth.set(c.guard,n);else depth.delete(c.guard);}
function socket(h){const k=h.toString();if(!sockets.has(k)&&sockets.size<512)sockets.set(k,{id:'s'+(++nextSocket),activeSend:0,activeRecv:0,pendingSend:0,pendingRecv:0,ambiguous:false});return sockets.get(k);}
function context(p){const k=p.readPointer().toString()+':'+p.add(Process.pointerSize).readPointer().toString();if(!contexts.has(k)&&contexts.size<256)contexts.set(k,'c'+(++nextContext));const x=contexts.get(k);if(!x)fault('context_limit');return x;}
function joined(arrays,limit){
  let total=0;for(const a of arrays){if(!Number.isSafeInteger(a[1])||a[1]<0||total+a[1]>CAPACITY)fault('bounded');total+=a[1];}
  const wanted=limit===undefined?total:limit;
  if(!Number.isInteger(wanted)||wanted<0||wanted>total||wanted>MAX)fault('bounded');
  const b=new Uint8Array(wanted);let offset=0;
  for(const [p,n] of arrays){const take=Math.min(n,wanted-offset);if(take>0){b.set(new Uint8Array(p.readByteArray(take)),offset);offset+=take;}if(offset===wanted)break;}
  return b;
}
function buffers(desc){const n=desc.add(4).readU32(),p=desc.add(8).readPointer(),width=Process.pointerSize===8?16:12;if(n>16)fault('buffer_count');const out=[];for(let i=0;i<n;i++){const b=p.add(i*width);out.push({type:b.add(4).readU32()&0xffff,n:b.readU32(),p:b.add(8).readPointer()});}return out;}
function messageDescriptor(api,args){if(api==='EncryptMessage')return args[2];if(api==='DecryptMessage')return args[1];fault('data_layout');}
function tls(mod){
  if(!['secur32.dll','sspicli.dll'].includes(mod.name.toLowerCase()))return;
  for(const api of ['EncryptMessage','DecryptMessage']){
    let address;try{address=mod.getExportByName(api);}catch(_){continue;}
    if(hooked.has(address.toString()))continue;hooked.add(address.toString());
    Interceptor.attach(address,{
      onEnter(args){enter(this,'tls:'+api);this.item=null;if(!this.outer)return;try{this.desc=messageDescriptor(api,args);this.tag=context(args[0]);const data=buffers(this.desc).filter(x=>x.type===1);if(data.length!==1)fault('data_layout');this.item={before:joined(data.map(x=>[x.p,x.n])),order:++sequence};}catch(e){diagnostic(api,'enter',e);}},
      onLeave(ret){try{if(this.item){const code=ret.toInt32();let after=new Uint8Array(0);if(code===0){const bs=buffers(this.desc),chosen=api==='EncryptMessage'?[7,1,6].map(t=>bs.filter(x=>x.type===t)):[bs.filter(x=>x.type===1)];if(chosen.some(x=>x.length!==1))fault('stream_layout');after=joined(chosen.flat().map(x=>[x.p,x.n]));}const first=this.item.before,all=new Uint8Array(first.length+after.length);all.set(first);all.set(after,first.length);emit({kind:api==='EncryptMessage'?'encrypt':'decrypt',api:api,context:this.tag,order:this.item.order,return_code:code,before_bytes:first.length,after_bytes:after.length,complete:true},all.buffer);}}catch(e){diagnostic(api,'leave',e);}finally{leave(this);}}
    });emit({kind:'installed',api:api});
  }
  try{const a=mod.getExportByName('DeleteSecurityContext');if(hooked.has(a.toString()))return;hooked.add(a.toString());Interceptor.attach(a,{onEnter(args){try{contexts.delete(args[0].readPointer().toString()+':'+args[0].add(Process.pointerSize).readPointer().toString());}catch(_){}}});}catch(_){}
}
function network(mod){
  if(mod.name.toLowerCase()!=='ws2_32.dll')return;
  function attach(api,cbs){try{const a=mod.getExportByName(api);if(hooked.has(a.toString()))return;hooked.add(a.toString());Interceptor.attach(a,cbs);emit({kind:'installed',api:api});}catch(_){emit({kind:'install_error',api:api,phase:'install',reason:'missing_export'});}}
  for(const api of ['connect','WSAConnect'])attach(api,{onEnter(args){sockets.delete(args[0].toString());socket(args[0]);}});
  attach('closesocket',{onEnter(args){const s=sockets.get(args[0].toString());if(s)for(const [k,p] of pending){if(p.state===s)pending.delete(k);}sockets.delete(args[0].toString());}});
  for(const api of ['send','WSASend','recv','WSARecv'])attach(api,{
    onEnter(args){const sending=api==='send'||api==='WSASend';enter(this,sending?'send':'recv');this.item=null;if(!this.outer)return;try{
      const s=socket(args[0]);if(!s)fault('socket_limit');const field=sending?'activeSend':'activeRecv',pf=sending?'pendingSend':'pendingRecv';s[field]++;if(s[field]>1||s[pf])s.ambiguous=true;this.state=s;this.field=field;
      let arrays=[],declared=0,async=false,out=null,key=null;
      if(api==='send'||api==='recv'){declared=args[2].toInt32();arrays=[[args[1],declared]];}
      else{const n=args[2].toUInt32(),width=Process.pointerSize===8?16:8;if(n>16)fault('buffer_count');for(let i=0;i<n;i++){const b=args[1].add(i*width),len=b.readU32();declared+=len;arrays.push([b.add(Process.pointerSize===8?8:4).readPointer(),len]);}out=args[3];async=!args[5].isNull();if(async){key=s.id+':'+args[5].toString();if(!args[6].isNull())fault('callback_unsupported');if(pending.has(key)){if(pending.get(key).immediate)pending.delete(key);else {emit({kind:'probe',api:api,phase:'reuse',state:pending.get(key).return_class||'unknown_error'});fault('overlapped_reuse');}}if(pending.size>=64)fault('pending_limit');}}
      if(declared<0||declared>CAPACITY)fault('bounded');
      const x={arrays:arrays,declared:declared,async:async,out:out,order:++sequence,before:sending?joined(arrays):null,sending:sending,operation:async?'o'+(++nextOperation):null,state:s,pf:pf,api:api,immediate:false,counted:async};this.item=x;
      if(async){pending.set(key,x);s[pf]++;}
    }catch(e){diagnostic(api,'enter',e);}},
    onLeave(ret){try{const x=this.item,s=this.state;if(x&&s){const code=ret.toInt32();x.return_class=x.async?(code===0?'immediate':(Number.isInteger(this.lastError)?(this.lastError===997?'pending':'non_pending_error'):'unknown_error')):'synchronous';emit({kind:'probe',api:api,phase:'submission',state:x.return_class});if(x.async&&code===0){x.immediate=true;if(x.counted){s[x.pf]--;x.counted=false;}}let accepted=null;if(!x.async){if(api==='send'||api==='recv'){if(code>=0)accepted=code;}else if(code===0&&!x.out.isNull())accepted=x.out.readU32();}if(accepted!==null&&(accepted<0||accepted>x.declared))fault('accepted_bounds');const raw=x.sending?x.before:(accepted!==null?joined(x.arrays,accepted):new Uint8Array(0));emit({kind:x.sending?'send':'recv',api:api,socket:s.id,order:x.order,return_code:code,accepted_bytes:accepted,declared_bytes:x.declared,asynchronous:x.async,completion_proven:false,immediate_completion:x.immediate,operation:x.operation,ambiguous:s.ambiguous,complete:true},raw.buffer);}}catch(e){diagnostic(api,'leave',e);}finally{if(this.state)this.state[this.field]--;leave(this);}}
  });
  attach('WSAGetOverlappedResult',{
    onEnter(args){this.s=sockets.get(args[0].toString());this.key=this.s?this.s.id+':'+args[1].toString():null;this.out=args[2];},
    onLeave(ret){if(ret.toInt32()===0)return;try{const x=pending.get(this.key);if(!x)fault('completion_unmatched');const n=this.out.readU32();if(n>x.declared)fault('accepted_bounds');const raw=x.sending?x.before.slice(0,n):joined(x.arrays,n);pending.delete(this.key);if(x.counted)x.state[x.pf]--;emit({kind:'socket_complete',api:'WSAGetOverlappedResult',socket:x.state.id,operation:x.operation,accepted_bytes:n,ambiguous:x.state.ambiguous,complete:true},raw.buffer);}catch(e){diagnostic('WSAGetOverlappedResult','completion',e);}}
  });
}
// Census only. These callbacks do not promote any bytes or completion evidence.
function completionCensus(mod){
 const name=mod.name.toLowerCase();let apis=[];
 if(['kernelbase.dll','kernel32.dll'].includes(name))apis=['GetQueuedCompletionStatus','GetQueuedCompletionStatusEx','GetOverlappedResult','GetOverlappedResultEx'];
 if(name==='ntdll.dll')apis=['NtRemoveIoCompletion','NtRemoveIoCompletionEx'];
 for(const api of apis){let a;try{a=mod.getExportByName(api);}catch(_){continue;}if(hooked.has(a.toString()))continue;hooked.add(a.toString());
  Interceptor.attach(a,{onEnter(){enter(this,'census:'+api);},onLeave(ret){try{if(this.outer)emit({kind:'probe',api:api,phase:'completion_call',state:(api.startsWith('Nt')?ret.toInt32()===0:ret.toInt32()!==0)?'true':'false'});}finally{leave(this);}}});
 }
}
const observer=Process.attachModuleObserver({onAdded(mod){network(mod);tls(mod);completionCensus(mod);}});
emit({kind:'ready',pointer_bits:Process.pointerSize*8});
