'use strict';
// Observe only: never change arguments, results, TLS verification or target buffers.
const sockets=new Map(), contexts=new Map(), hooked=new Set(), depth=new Map();
let sequence=0, nextSocket=0, nextContext=0, emitted=0, limited=false;
const MAX=131072;
function emit(event,bytes) {
  if(emitted>=1024) {if(!limited){limited=true;send({kind:'limit'});}return;}
  emitted++; event.sequence=++sequence; send(event,bytes || undefined);
}
function enter(ctx,group) {
  ctx.guard=group+':'+Process.getCurrentThreadId();
  const n=depth.get(ctx.guard)||0;depth.set(ctx.guard,n+1);ctx.outer=n===0;
}
function leave(ctx) {const n=(depth.get(ctx.guard)||1)-1;if(n)depth.set(ctx.guard,n);else depth.delete(ctx.guard);}
function socket(h) {
  const k=h.toString(); if(!sockets.has(k)&&sockets.size<512)
    sockets.set(k,{id:'s'+(++nextSocket),activeSend:0,activeRecv:0,ambiguous:false});
  return sockets.get(k);
}
function context(p) {
  const k=p.readPointer().toString()+':'+p.add(Process.pointerSize).readPointer().toString();
  if(!contexts.has(k)&&contexts.size<256)contexts.set(k,'c'+(++nextContext));
  return contexts.get(k);
}
function joined(arrays) {
  let size=0;const pieces=[];
  for(const [p,n] of arrays){if(n<0 || size+n>MAX)throw Error('bounded');pieces.push(new Uint8Array(p.readByteArray(n)));size+=n;}
  const b=new Uint8Array(size);let offset=0;for(const p of pieces){b.set(p,offset);offset+=p.length;}return b;
}
function buffers(desc) {
  const n=desc.add(4).readU32(),p=desc.add(8).readPointer(),width=Process.pointerSize===8?16:12;
  if(n>16)throw Error('count');const out=[];
  for(let i=0;i<n;i++){const b=p.add(i*width);out.push({type:b.add(4).readU32()&0xffff,n:b.readU32(),p:b.add(8).readPointer()});}
  return out;
}
function tls(mod) {
  if(!['secur32.dll','sspicli.dll'].includes(mod.name.toLowerCase()))return;
  for(const api of ['EncryptMessage','DecryptMessage']) {
    let address;try{address=mod.getExportByName(api);}catch(_){continue;}
    if(hooked.has(address.toString()))continue;hooked.add(address.toString());
    Interceptor.attach(address,{
      onEnter(args){
        enter(this,'tls:'+api);this.item=null;if(!this.outer)return;
        try {
          this.desc=args[2];this.tag=context(args[0]);
          const bs=buffers(this.desc),data=bs.filter(x=>x.type===1);
          if(!this.tag||data.length!==1)throw Error('data');
          this.item={before:joined(data.map(x=>[x.p,x.n])),order:++sequence};
        }catch(_){emit({kind:'read_error',api:api});}
      },
      onLeave(ret){
        try {
          if(this.item){
            const code=ret.toInt32();let after=new Uint8Array(0),complete=true;
            if(code===0){
              const bs=buffers(this.desc);
              const chosen=api==='EncryptMessage' ? [7,1,6].map(t=>bs.filter(x=>x.type===t)) : [bs.filter(x=>x.type===1)];
              if(chosen.some(x=>x.length!==1))throw Error('layout');
              after=joined(chosen.flat().map(x=>[x.p,x.n]));
            }
            const first=this.item.before,all=new Uint8Array(first.length+after.length);all.set(first);all.set(after,first.length);
            emit({kind:api==='EncryptMessage'?'encrypt':'decrypt',api:api,context:this.tag,
              order:this.item.order,return_code:code,before_bytes:first.length,after_bytes:after.length,complete:complete},all.buffer);
          }
        }catch(_){emit({kind:'read_error',api:api});}finally{leave(this);}
      }
    }); emit({kind:'installed',api:api});
  }
  try {
    const a=mod.getExportByName('DeleteSecurityContext');if(hooked.has(a.toString()))return;hooked.add(a.toString());
    Interceptor.attach(a,{onEnter(args){try{const k=args[0].readPointer().toString()+':'+args[0].add(Process.pointerSize).readPointer().toString();contexts.delete(k);}catch(_){}}});
  }catch(_){}
}
function network(mod) {
  if(mod.name.toLowerCase()!=='ws2_32.dll')return;
  function attach(api,cbs){try{const a=mod.getExportByName(api);if(hooked.has(a.toString()))return;hooked.add(a.toString());Interceptor.attach(a,cbs);emit({kind:'installed',api:api});}catch(_){emit({kind:'install_error',api:api});}}
  for(const api of ['connect','WSAConnect'])attach(api,{onEnter(args){sockets.delete(args[0].toString());socket(args[0]);}});
  attach('closesocket',{onEnter(args){sockets.delete(args[0].toString());}});
  for(const api of ['send','WSASend','recv','WSARecv'])attach(api,{
    onEnter(args){
      const sending=api==='send'||api==='WSASend';enter(this,sending?'send':'recv');this.item=null;if(!this.outer)return;
      try {
        const s=socket(args[0]);if(!s)throw Error('socket_limit');
        const field=sending?'activeSend':'activeRecv';s[field]++;if(s[field]>1)s.ambiguous=true;
        this.state=s;this.field=field;
        let arrays=[],declared=0,async=false,out=null;
        if(api==='send'||api==='recv'){declared=args[2].toInt32();arrays=[[args[1],declared]];}
        else {
          const n=args[2].toUInt32(),width=Process.pointerSize===8?16:8;if(n>16)throw Error('buffers');
          for(let i=0;i<n;i++){const b=args[1].add(i*width),len=b.readU32();declared+=len;arrays.push([b.add(Process.pointerSize===8?8:4).readPointer(),len]);}
          out=args[3];async=!args[5].isNull();
        }
        if(declared<0||declared>MAX)throw Error('size');
        this.item={arrays:arrays,declared:declared,async:async,out:out,order:++sequence,
          before:sending?joined(arrays):null,sending:sending};
      }catch(_){emit({kind:'read_error',api:api});}
    },
    onLeave(ret){
      try {
        const x=this.item,s=this.state;if(x&&s){
          const code=ret.toInt32();let accepted=null;
          if(!x.async){if(api==='send'||api==='recv'){if(code>=0)accepted=code;}
          else if(code===0&&!x.out.isNull())accepted=x.out.readU32();}
          if(accepted!==null&&(accepted<0||accepted>x.declared))throw Error('accepted');
          const raw=x.sending?x.before:(accepted!==null?joined(x.arrays).slice(0,accepted):new Uint8Array(0));
          emit({kind:x.sending?'send':'recv',api:api,socket:s.id,order:x.order,return_code:code,
            accepted_bytes:accepted,declared_bytes:x.declared,asynchronous:x.async,ambiguous:s.ambiguous,complete:true},raw.buffer);
        }
      }catch(_){emit({kind:'read_error',api:api});}finally{if(this.state)this.state[this.field]--;leave(this);}
    }
  });
}
const observer=Process.attachModuleObserver({onAdded(mod){network(mod);tls(mod);}});
emit({kind:'ready'});
