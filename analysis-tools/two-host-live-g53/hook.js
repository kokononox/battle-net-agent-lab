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
function emit(s,data){if(emitted+data.byteLength>16777216){send({kind:'cap'});return;}emitted+=data.byteLength;
 send({kind:'bytes',socket:s.toString(),peer:endpoint(s)},data);}
Interceptor.attach(ws.getExportByName('send'),{onEnter(a){this.s=a[0];this.n=a[2].toInt32();this.buf=null;
 if(this.n>0&&this.n<=1048576)this.buf=a[1].readByteArray(this.n);},onLeave(r){const n=r.toInt32();if(n>0&&this.buf)emit(this.s,this.buf.slice(0,Math.min(n,this.n)));else if(n>0)send({kind:'unobserved_large_send'});}});
Interceptor.attach(ws.getExportByName('WSASend'),{onEnter(a){this.s=a[0];this.out=a[3];this.parts=[];this.total=0;
 const count=a[2].toUInt32(),stride=Process.pointerSize===8?16:8,off=Process.pointerSize===8?8:4;
 if(count>64){this.parts=null;return;}for(let i=0;i<count;i++){const b=a[1].add(i*stride),n=b.readU32();this.total+=n;if(this.total>1048576){this.parts=null;return;}this.parts.push(new Uint8Array(b.add(off).readPointer().readByteArray(n)));}},
 onLeave(r){if(r.toInt32()!==0){send({kind:'wsasend_nonzero_completion_unobserved'});return;}
 if(!this.parts||this.out.isNull()){send({kind:'unobserved_wsasend'});return;}
 const n=this.out.readU32();if(n>this.total){send({kind:'unobserved_wsasend'});return;}
 const all=new Uint8Array(this.total);let at=0;for(const p of this.parts){all.set(p,at);at+=p.length;}if(n)emit(this.s,all.buffer.slice(0,n));}});
send({kind:'hooks_installed',arch:Process.arch});
}
Process.attachModuleObserver({onAdded(module){if(module.name.toLowerCase()==='ws2_32.dll')install(module);}});
send({kind:'ready',arch:Process.arch});
