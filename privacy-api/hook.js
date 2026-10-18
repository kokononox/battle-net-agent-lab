'use strict';
// Observe only. Never replace arguments, return values, buffers or TLS settings.
const sockets = new Map(), depths = new Map(), attached = new Set();
let nextSocket = 0, sequence = 0, events = 0;
function sock(s) {
  const key = s.toString();
  if (!sockets.has(key) && sockets.size < 512)
    sockets.set(key, {alias:'s'+(++nextSocket), port:null, interesting:false});
  return sockets.get(key) || null;
}
function portOf(p) {
  try {
    const family = p.readU16();
    if (family !== 2 && family !== 23) return null;
    return p.add(2).readU8()*256 + p.add(3).readU8();
  } catch (_) { return null; }
}
function begin(ctx) {
  ctx.labItem = null;
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
  if (!ctx.labOuter || events>=256 || declared<0 || declared>16777216) return;
  const state = sock(handle); if (!state) return;
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
  const head=String.fromCharCode.apply(null,Array.from(bytes.slice(0,12)));
  if (/^(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS|CONNECT) /.test(head)) state.interesting=true;
  // TLS/ciphertext and unrelated sockets are not exported or assembled.
  if (!state.interesting) return;
  events++;
  ctx.labItem={info:{kind:'input',api:api,socket:state.alias,peer_port:state.port,
    sequence:++sequence,declared_bytes:declared,truncated:declared>size},
    bytes:bytes.buffer,out:outPointer};
}
function finish(ctx, ret) {
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
const observer=Process.attachModuleObserver({onAdded:install});
send({kind:'ready'});