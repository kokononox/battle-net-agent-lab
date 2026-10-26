'use strict';
let installed=false;
function install(ws){
if(installed)return;installed=true;
const peer=new NativeFunction(ws.getExportByName('getpeername'),'int',['pointer','pointer','pointer']);
let emitted=0;
function endpoint(s){const a=Memory.alloc(128),n=Memory.alloc(4);n.writeS32(128);if(peer(s,a,n)!==0)return null;
 const family=a.readU16(),port=a.add(2).readU8()*256+a.add(3).readU8();
 if(family===2){let b=[];for(let i=0;i<4;i++)b.push(a.add(4+i).readU8());return {ip:b.join('.'),port:port};}
 if(family===23){let b=[];for(let i=0;i<16;i+=2)b.push((a.add(8+i).readU8()*256+a.add(9+i).readU8()).toString(16));return {ip:b.join(':'),port:port};}return null;}
function emit(s,data,api){if(emitted+data.byteLength>16777216){send({kind:'cap'});return;}emitted+=data.byteLength;
 send({kind:'bytes',socket:s.toString(),peer:endpoint(s),api:api},data);}
Interceptor.attach(ws.getExportByName('send'),{onEnter(a){this.s=a[0];this.n=a[2].toInt32();this.buf=null;
 if(this.n>0&&this.n<=1048576)this.buf=a[1].readByteArray(this.n);},onLeave(r){const n=r.toInt32();if(n>0&&this.buf)emit(this.s,this.buf.slice(0,Math.min(n,this.n)),'send');else if(n>0)send({kind:'unobserved_large_send'});}});
Interceptor.attach(ws.getExportByName('WSASend'),{onEnter(a){this.s=a[0];this.out=a[3];this.parts=[];this.total=0;
 const count=a[2].toUInt32(),stride=Process.pointerSize===8?16:8,off=Process.pointerSize===8?8:4;
 if(count>64){this.parts=null;return;}for(let i=0;i<count;i++){const b=a[1].add(i*stride),n=b.readU32();this.total+=n;if(this.total>1048576){this.parts=null;return;}this.parts.push(new Uint8Array(b.add(off).readPointer().readByteArray(n)));}},
 onLeave(r){if(r.toInt32()!==0){send({kind:'wsasend_nonzero_completion_unobserved'});return;}
 if(!this.parts||this.out.isNull()){send({kind:'unobserved_wsasend'});return;}
 const n=this.out.readU32();if(n>this.total){send({kind:'unobserved_wsasend'});return;}
 const all=new Uint8Array(this.total);let at=0;for(const p of this.parts){all.set(p,at);at+=p.length;}if(n)emit(this.s,all.buffer.slice(0,n),'WSASend');}});
send({kind:'hooks_installed',arch:Process.arch});
}
Process.attachModuleObserver({onAdded(module){if(module.name.toLowerCase()==='ws2_32.dll')install(module);}});
send({kind:'ready',arch:Process.arch});
// WinINet observation is a distinct API-input layer, not confirmed wire traffic.
let inetInstalled=false;
function installInet(mod){
 if(inetInstalled)return;inetInstalled=true;
 const connections=new Map(),requests=new Map(),openers=new Map();
 function str(p,n){if(p.isNull())return '';return n===undefined?p.readCString(65536):p.readCString(Math.min(n,65536));}
 Interceptor.attach(mod.getExportByName('InternetOpenA'),{onEnter(a){this.agent=str(a[0]);},onLeave(r){if(!r.isNull())openers.set(r.toString(),this.agent);}});
 Interceptor.attach(mod.getExportByName('InternetConnectA'),{onEnter(a){this.meta={server:str(a[1]).toLowerCase(),port:a[2].toUInt32()&65535,agent:openers.get(a[0].toString())||'',username_argument_present:!a[3].isNull(),password_argument_present:!a[4].isNull()};},onLeave(r){if(!r.isNull())connections.set(r.toString(),this.meta);else send({kind:'wininet_connect_failed',error:this.lastError});}});
 Interceptor.attach(mod.getExportByName('HttpOpenRequestA'),{onEnter(a){this.meta=Object.assign({},connections.get(a[0].toString())||{server:'',port:0},{method:str(a[1])||'GET',path:str(a[2]),secure:(a[6].toUInt32()&0x00800000)!==0});},onLeave(r){if(!r.isNull())requests.set(r.toString(),this.meta);else send({kind:'wininet_open_request_failed',error:this.lastError});}});
 Interceptor.attach(mod.getExportByName('HttpSendRequestA'),{onEnter(a){
  this.meta=Object.assign({},requests.get(a[0].toString())||{server:'',method:'',path:'',port:0});
  let n=a[2].toUInt32();this.meta.headers=str(a[1],n===0xffffffff?undefined:n);this.meta.body_declared_bytes=a[4].toUInt32();
  this.body=null;this.meta.body_observed_complete=this.meta.body_declared_bytes<=1048576;
  if(this.meta.body_declared_bytes>0&&this.meta.body_observed_complete&&!a[3].isNull())this.body=a[3].readByteArray(this.meta.body_declared_bytes);
  if(this.meta.body_declared_bytes>0&&a[3].isNull())this.meta.body_observed_complete=false;
 },onLeave(r){this.meta.kind='wininet_request_input';this.meta.api_returned_true=r.toInt32()!==0;this.meta.error=this.meta.api_returned_true?0:this.lastError;send(this.meta,this.body);}});
 Interceptor.attach(mod.getExportByName('InternetCloseHandle'),{onEnter(a){this.h=a[0].toString();},onLeave(r){if(r.toInt32()!==0){connections.delete(this.h);requests.delete(this.h);openers.delete(this.h);}}});
 send({kind:'wininet_hooks_installed'});
}
Process.attachModuleObserver({onAdded(module){if(module.name.toLowerCase()==='wininet.dll')installInet(module);}});
