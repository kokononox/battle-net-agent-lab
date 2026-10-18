'use strict';
// Bounded observation only. Does not replace return values or write buffers.
const installed = new Set(), addresses = new Set(), connections = new Map(), requests = new Map();
let emitted = 0; const contexts=new Map();
function contextTag(p){const k=p.toString();if(!contexts.has(k)&&contexts.size<128)contexts.set(k,'ctx'+(contexts.size+1));return contexts.get(k)||null;}
const methods = new Set(['GET','POST','PUT','HEAD','OPTIONS','CONNECT','DELETE','PATCH']);
function text(p,wide) { try { if(p.isNull())return null; let s=''; for(let i=0;i<253;i++){const n=wide?p.add(i*2).readU16():p.add(i).readU8();if(n===0)return s;if(n<32||n>126)return null;s+=String.fromCharCode(n);}return null;}catch(_){return null;} }
function lookup(h) { return requests.get(h.toString()) || {host:null,method:null}; }
function remember(map,k,v) { if(map.size<256) map.set(k.toString(),v); }
function observe(p,n,api,meta) {
 if(emitted>=128 || n>67108864 || n<0) return null;
 emitted++;
 let bytes=null;
 try { if(n>0 && !p.isNull()) bytes=p.readByteArray(Math.min(n,16384)); } catch (_) {}
 return {info:{kind:'buffer',api:api,host:meta.host,method:meta.method,declared_length:n,readable:n===0||bytes!==null,truncated:n>16384},bytes:bytes};
}
function publish(item,retval,positive) {
 if(!item)return;
 item.info.api_success=positive ? retval.toInt32()>0 : retval.toInt32()===0;
 send(item.info,item.bytes);
}
function install(moduleName,api,callbacks) {
 const key=moduleName+'!'+api;if(installed.has(key))return;
 try {
  const mod=Process.getModuleByName(moduleName);const address=mod.getExportByName(api);
  installed.add(key);
  if(addresses.has(address.toString()))return;
  Interceptor.attach(address,callbacks);addresses.add(address.toString());send({kind:'installed',api:api});
 } catch (_) {}
}
function addHooks() {
 install('winhttp.dll','WinHttpConnect',{
  onEnter(args){this.h=text(args[1],true);},onLeave(ret){if(!ret.isNull())remember(connections,ret,{host:this.h});}
 });
 install('winhttp.dll','WinHttpOpenRequest',{
  onEnter(args){this.c=connections.get(args[0].toString());const m=text(args[1],true);this.m=methods.has(m)?m:null;},
  onLeave(ret){if(!ret.isNull())remember(requests,ret,{host:this.c?this.c.host:null,method:this.m});}
 });
 install('winhttp.dll','WinHttpSendRequest',{
  onEnter(args){this.item=observe(args[3],args[4].toUInt32(),'WinHttpSendRequest',lookup(args[0]));},onLeave(ret){publish(this.item,ret,true);}
 });
 install('winhttp.dll','WinHttpWriteData',{
  onEnter(args){this.item=observe(args[1],args[2].toUInt32(),'WinHttpWriteData',lookup(args[0]));},onLeave(ret){publish(this.item,ret,true);}
 });
 install('winhttp.dll','WinHttpCloseHandle',{onEnter(args){connections.delete(args[0].toString());requests.delete(args[0].toString());}});
 for(const wide of [true,false]){
  const suffix=wide?'W':'A';
  install('wininet.dll','InternetConnect'+suffix,{
   onEnter(args){this.h=text(args[1],wide);},onLeave(ret){if(!ret.isNull())remember(connections,ret,{host:this.h});}
  });
  install('wininet.dll','HttpOpenRequest'+suffix,{
   onEnter(args){this.c=connections.get(args[0].toString());const m=text(args[1],wide);this.m=methods.has(m)?m:null;},
   onLeave(ret){if(!ret.isNull())remember(requests,ret,{host:this.c?this.c.host:null,method:this.m});}
  });
  install('wininet.dll','HttpSendRequest'+suffix,{
   onEnter(args){this.item=observe(args[3],args[4].toUInt32(),'HttpSendRequest'+suffix,lookup(args[0]));},onLeave(ret){publish(this.item,ret,true);}
  });
 }
 install('wininet.dll','InternetWriteFile',{
  onEnter(args){this.item=observe(args[1],args[2].toUInt32(),'InternetWriteFile',lookup(args[0]));},onLeave(ret){publish(this.item,ret,true);}
 });
 install('wininet.dll','InternetCloseHandle',{onEnter(args){connections.delete(args[0].toString());requests.delete(args[0].toString());}});
 for(const moduleName of ['secur32.dll','sspicli.dll']){
  install(moduleName,'EncryptMessage',{
   onEnter(args){
    this.items=[];this.context=contextTag(args[0]);
    try{
     const d=args[2],count=d.add(4).readU32(),base=d.add(8).readPointer();if(count>16)return;
     const width=Process.pointerSize===8?16:12;
     for(let i=0;i<count && this.items.length<2;i++){
      const p=base.add(i*width);if((p.add(4).readU32()&0xffff)!==1)continue;
      this.items.push(observe(p.add(8).readPointer(),p.readU32(),'EncryptMessage',{host:null,method:null}));
     }
    }catch(_){}
   },onLeave(ret){for(const item of this.items||[]){if(item)item.info.context=this.context;publish(item,ret,false);}}
  });
 }
 // Dynamically linked OpenSSL only. Static/nonexported implementations are a gap.
 for(const mod of Process.enumerateModules()){
  if(!/^libssl.*\.dll$/i.test(mod.name))continue;
  for(const api of ['SSL_write','SSL_write_ex']){
   install(mod.name,api,{
    onEnter(args){this.item=observe(args[1],args[2].toUInt32(),api,{host:null,method:null});},onLeave(ret){publish(this.item,ret,true);}
   });
  }
 }
}
addHooks();setInterval(addHooks,500);
