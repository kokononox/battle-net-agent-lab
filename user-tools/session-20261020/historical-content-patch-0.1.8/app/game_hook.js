'use strict';
// Observe only. Never replace arguments, return values, buffers or TLS settings.
const sockets = new Map(), depths = new Map(), attached = new Set();
let nextSocket = 0, sequence = 0, events = 0, binaryEvents = 0;
const limitsSent=new Set();
function limit(name){if(!limitsSent.has(name)){limitsSent.add(name);send({kind:'limit',api:name});}}
function sock(s) {
  const key = s.toString();
  if (!sockets.has(key) && sockets.size < 512)
    sockets.set(key, {alias:'s'+(++nextSocket), port:null, interesting:false});
  if(!sockets.has(key))limit('socket_map');
  return sockets.get(key) || null;
}
function portOf(p) {
  try {
    const family = p.readU16();
    if (family !== 2 && family !== 23) return null;
    return p.add(2).readU8()*256 + p.add(3).readU8();
  } catch (_) { return null; }
}
let peerApi = null, wireEvents = 0;
function peerOf(handle) {
  try {
    if(!peerApi) peerApi=new NativeFunction(Process.getModuleByName('ws2_32.dll').getExportByName('getpeername'),'int',['pointer','pointer','pointer']);
    const out=Memory.alloc(128),len=Memory.alloc(4);len.writeS32(128);
    if(peerApi(handle,out,len)!==0)return null;
    const family=out.readU16(),port=portOf(out);let address=null;
    if(family===2){let b=[];for(let i=0;i<4;i++)b.push(out.add(4+i).readU8());address=b.join('.');}
    if(family===23){let b=[];for(let i=0;i<8;i++)b.push((out.add(8+i*2).readU8()*256+out.add(9+i*2).readU8()).toString(16));address=b.join(':');}
    return address?{address:address,port:port}:null;
  } catch(_){return null;}
}
function begin(ctx) {
  ctx.labItem = null; ctx.labMeta=null;
  const id = Process.getCurrentThreadId();
  const n = depths.get(id) || 0;
  depths.set(id, n+1); ctx.labTid = id; ctx.labOuter = n===0;
}
function end(ctx) {
  const n = (depths.get(ctx.labTid)||1)-1;
  if (n) depths.set(ctx.labTid,n); else depths.delete(ctx.labTid);
}
function collect(ctx, handle, arrays, declared, api, outPointer) {
  ctx.labItem = null;
  if(events>=50000){limit('winsock');return;}
  if (!ctx.labOuter || declared<0 || declared>16777216) return;
  const state = sock(handle); if (!state) return;
  const peer=peerOf(handle);if(peer)state.port=peer.port;
  if(wireEvents<50000){ctx.labMeta={kind:'winsock_meta',socket:state.alias,api:api,peer:peer,declared_bytes:declared,out:outPointer};wireEvents++;}
  else limit('winsock_metadata');
  let size=0, pieces=[];
  try {
    for (const [p,n] of arrays) {
      const amount = Math.min(n, 16384-size);
      if (amount>0) { pieces.push(new Uint8Array(p.readByteArray(amount))); size+=amount; }
      if(size>=16384) break;
    }
  } catch (_) { send({kind:'read_error',api:api}); return; }
  if (!size) return;
  const bytes = new Uint8Array(size); let at=0;
  for(const piece of pieces){bytes.set(piece,at);at+=piece.length;}
  const sni=tlsSni(bytes.buffer);
  if(sni)domainEvent('TLS_ClientHello_SNI',sni,{socket:state.alias,peer:peer,evidence:'same_socket_clienthello_outer_name',declared_bytes:declared});
  // A bounded prefix is read in RAM for marker checks; never exported as raw bytes in the report.
  if(binaryEvents<8192){binaryEvents++;send({kind:'binary_prefix',socket:state.alias,api:api,peer:peer,declared_bytes:declared,truncated:declared>size},bytes.buffer);}
  else limit('binary_prefix_events');
  const head=String.fromCharCode.apply(null,Array.from(bytes.slice(0,12)));
  if (/^(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|CONNECT) /.test(head)) state.interesting=true;
  // TLS/ciphertext and unrelated sockets are not exported or assembled.
  if (!state.interesting) return;
  events++;
  ctx.labItem={info:{kind:'input',api:api,socket:state.alias,peer_port:state.port,
    sequence:++sequence,declared_bytes:declared,truncated:declared>size,peer:peer},
    bytes:bytes.buffer,out:outPointer};
}
function finish(ctx, ret) {
  const meta=ctx.labMeta;
  if(meta){
    const code=ret.toInt32();let accepted=null;
    if(meta.api==='send' && code>=0)accepted=code;
    if(meta.api==='WSASend' && code===0 && meta.out && !meta.out.isNull()){try{accepted=meta.out.readU32();}catch(_){}}
    delete meta.out;meta.accepted_bytes=accepted;meta.return_code=code;send(meta);
  }
  const item=ctx.labItem;
  if(item) {
    const code=ret.toInt32(); let accepted=null;
    if(item.info.api==='send' && code>=0) accepted=code;
    if(item.info.api==='WSASend' && code===0 && item.out && !item.out.isNull()) {
      try {accepted=item.out.readU32();}catch(_){}
    }
    item.info.return_code=code; item.info.accepted_bytes=accepted;
    send(item.info,item.bytes);
  }
  end(ctx);
}
function install(mod) {
  if(mod.name.toLowerCase()!=='ws2_32.dll') return;
  function hook(name, callbacks) {
    if(attached.has(name))return;
    try { Interceptor.attach(mod.getExportByName(name),callbacks);attached.add(name);send({kind:'installed',api:name}); }
    catch(_){send({kind:'install_error',api:name});}
  }
  for(const api of ['connect','WSAConnect']) hook(api,{
    onEnter(args){
      sockets.delete(args[0].toString());
      const state=sock(args[0]);if(state)state.port=portOf(args[1]);
    }
  });
  hook('closesocket',{onEnter(args){sockets.delete(args[0].toString());}});
  hook('send',{
    onEnter(args){begin(this);collect(this,args[0],[[args[1],args[2].toInt32()]],args[2].toInt32(),'send',null);},
    onLeave(ret){finish(this,ret);}
  });
  hook('WSASend',{
    onEnter(args){
      begin(this);
      let arrays=[],total=0;
      try {
        const count=args[2].toUInt32(), width=Process.pointerSize===8?16:8;
        if(count>16)return;
        for(let i=0;i<count;i++){
          const entry=args[1].add(i*width),n=entry.readU32();
          total+=n;if(total>16777216)return;
          arrays.push([entry.add(Process.pointerSize===8?8:4).readPointer(),n]);
        }
        collect(this,args[0],arrays,total,'WSASend',args[3]);
      } catch(_){send({kind:'read_error',api:'WSASend'});}
    },onLeave(ret){finish(this,ret);}
  });
}
// Synchronous module observer is installed before resuming application code.

const tlsAddresses=new Set(), contexts=new Map();
let tlsEvents=0;
function tlsInstall(mod) {
  if(!['secur32.dll','sspicli.dll'].includes(mod.name.toLowerCase()))return;
  try {
    const address=mod.getExportByName('EncryptMessage');
    if(tlsAddresses.has(address.toString()))return;
    Interceptor.attach(address,{
      onEnter(args) {
        this.labTls=[];
        if(tlsEvents>=50000){limit('sspi');return;}
        const key=args[0].toString();
        if(!contexts.has(key) && contexts.size<128)contexts.set(key,'ctx'+(contexts.size+1));
        const tag=contexts.get(key);if(!tag){limit('context_map');return;}
        try {
          const d=args[2],count=d.add(4).readU32(),base=d.add(8).readPointer();
          if(count>16)return;
          const width=Process.pointerSize===8?16:12;
          for(let i=0;i<count && this.labTls.length<2 && tlsEvents<50000;i++) {
            const b=base.add(i*width),n=b.readU32();
            if((b.add(4).readU32()&0xffff)!==1 || n>16777216)continue;
            const bytes=n?b.add(8).readPointer().readByteArray(Math.min(n,16384)):new ArrayBuffer(0);
            tlsEvents++;
            this.labTls.push({bytes:bytes,info:{kind:'input',api:'EncryptMessage',socket:tag,
              sequence:++sequence,declared_bytes:n,truncated:n>16384}});
          }
        } catch(_) {send({kind:'read_error',api:'EncryptMessage'});}
      },
      onLeave(ret) {
        for(const item of this.labTls||[]) {
          item.info.return_code=ret.toInt32();
          // Success means local encryption accepted, never proof of send/receipt.
          item.info.accepted_bytes=ret.toInt32()===0?item.info.declared_bytes:null;
          send(item.info,item.bytes);
        }
      }
    });
    tlsAddresses.add(address.toString());send({kind:'installed',api:'EncryptMessage'});
  } catch(_) {send({kind:'install_error',api:'EncryptMessage'});}
}
// Domain observations are not a DNS->socket proof unless tied to an actual socket below.
let domainEvents=0;
const domainHooks=new Set();
function domainName(s){
  if(typeof s!=='string')return null;
  s=s.toLowerCase().replace(/\.$/,'');
  if(s.length<1||s.length>253||/^\d+(\.\d+){3}$/.test(s))return null;
  return s.split('.').every(x=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(x))?s:null;
}
function domainEvent(api,name,extra){
  const d=domainName(name);if(!d)return;
  if(domainEvents>=8192){limit('domain_events');return;}domainEvents++;
  send(Object.assign({kind:'domain_meta',api:api,domain:d},extra||{}));
}
function tlsSni(bytes){
  try{
    const b=new Uint8Array(bytes),u16=i=>b[i]*256+b[i+1];
    if(b.length<9||b[0]!==22||b[1]!==3||b[5]!==1)return null;
    const recordEnd=5+u16(3),helloEnd=9+b[6]*65536+b[7]*256+b[8];
    if(recordEnd>b.length||helloEnd>recordEnd||helloEnd<44)return null;
    let p=43;
    const take=n=>{if(p+n>helloEnd)throw Error('bounds');const old=p;p+=n;return old;};
    let n=b[take(1)];take(n);n=u16(take(2));take(n);n=b[take(1)];take(n);
    n=u16(take(2));const end=p+n;if(end>helloEnd)return null;
    while(p+4<=end){const type=u16(take(2)),size=u16(take(2)),start=take(size);
      if(type!==0)continue;
      if(size<5)return null;let q=start+2;const listEnd=q+u16(start);if(listEnd>start+size)return null;
      while(q+3<=listEnd){const t=b[q],len=u16(q+1);q+=3;if(q+len>listEnd)return null;
        if(t===0&&len<=253)return domainName(String.fromCharCode.apply(null,Array.from(b.slice(q,q+len))));q+=len;}
    }
  }catch(_){}return null;
}
function readDomain(p,wide){
 let s='';for(let i=0;i<254;i++){const n=wide?p.add(i*2).readU16():p.add(i).readU8();if(n===0)return s;if(n>127)return null;s+=String.fromCharCode(n);}return null;
}
function installDomainHooks(mod){
 const module=mod.name.toLowerCase();
 const defs=module==='ws2_32.dll'?[['getaddrinfo',false],['GetAddrInfoW',true]]:
   module==='dnsapi.dll'?[['DnsQuery_A',false],['DnsQuery_W',true]]:[];
 for(const [api,wide] of defs){
  try{
   const addr=mod.getExportByName(api),key=addr.toString();if(domainHooks.has(key))continue;
   Interceptor.attach(addr,{onEnter(args){this.domain=null;try{this.domain=readDomain(args[0],wide);}catch(_){}},
    onLeave(ret){if(this.domain)domainEvent(api,this.domain,{return_code:ret.toInt32(),evidence:'process_name_lookup_not_socket_bound'});}});
   domainHooks.add(key);send({kind:'domain_hook_installed',api:api});
  }catch(_){}
 }
 if(module==='winhttp.dll'){
  for(const api of ['WinHttpConnect'])try{
   const addr=mod.getExportByName(api),key=addr.toString();if(domainHooks.has(key))continue;
   Interceptor.attach(addr,{onEnter(args){try{domainEvent(api,readDomain(args[1],true),{port:args[2].toUInt32()&65535,evidence:'http_connect_target_not_socket_bound'});}catch(_){}}});
   domainHooks.add(key);send({kind:'domain_hook_installed',api:api});
  }catch(_){}
 }
}
const domainObserver=Process.attachModuleObserver({onAdded(mod){installDomainHooks(mod);}});

const observer=Process.attachModuleObserver({onAdded(mod){install(mod);tlsInstall(mod);}});
send({kind:'ready'});