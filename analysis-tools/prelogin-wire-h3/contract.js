// Actual observer code executed against synthetic memory, both pointer widths.
const fs=require('fs'),vm=require('vm'),assert=require('assert');
function fixture(bits){
  const words=new Map(),blobs=new Map(),reads=[],events=[],hooks=new Map();
  class P {constructor(v){this.v=v;}add(n){return new P(this.v+n);}readU32(){if(!words.has(this.v))throw Error('PRIVATE_ADDRESS_SECRET');return words.get(this.v)>>>0;}readPointer(){if(!words.has(this.v))throw Error('PRIVATE_ADDRESS_SECRET');return new P(words.get(this.v));}readByteArray(n){reads.push([this.v,n]);const x=blobs.get(this.v);if(!x||n>x.length)throw Error('PRIVATE_ADDRESS_SECRET');return Uint8Array.from(x.slice(0,n)).buffer;}toString(){return '0x'+this.v.toString(16);}toInt32(){return this.v|0;}toUInt32(){return this.v>>>0;}isNull(){return this.v===0;}}
  const c=vm.createContext({send(e,b){events.push({e:JSON.parse(JSON.stringify(e)),raw:b?Array.from(new Uint8Array(b)):[]});},Process:{pointerSize:bits/8,getCurrentThreadId(){return 1;},attachModuleObserver(){return {};}},Interceptor:{attach(a,cb){hooks.set(a,cb);}}});
  vm.runInContext(fs.readFileSync(process.argv[2],'utf8'),c);
  function setup(name){c.mod={name:name,getExportByName(api){return api;}};vm.runInContext((name==='ws2_32.dll'?'network':'tls')+'(mod)',c);}
  setup('ws2_32.dll');setup('secur32.dll');events.length=0;
  function args(a){return a.map(x=>new P(x));}
  function invoke(api,a,ret,middle){const x={},h=hooks.get(api);if(h.onEnter)h.onEnter.call(x,args(a));if(middle)middle(x);if(h.onLeave)h.onLeave.call(x,new P(ret));return x;}
  function buf(addr,length,data){words.set(addr,length);words.set(addr+(bits===64?8:4),data);}
  function payload(addr,n){const x=Array.from({length:n},(_,i)=>i%251);blobs.set(addr,x);return x;}
  function last(kind){return events.filter(x=>x.e.kind===kind).at(-1);}
  return {c,P,words,blobs,reads,events,hooks,invoke,buf,payload,last};
}
let count=0;
function check(fn){fn();count++;}
for(const bits of [32,64]){
 check(()=>{const f=fixture(bits);f.payload(1000,96);f.invoke('recv',[7,1000,1048576,0],96);assert.equal(f.last('recv').raw.length,96);assert.deepEqual(f.reads,[[1000,96]]);});
 check(()=>{const f=fixture(bits),w=bits===64?16:8;f.buf(100,32,1000);f.buf(100+w,1048576,2000);f.payload(1000,32);f.payload(2000,64);f.invoke('WSARecv',[7,100,2,300,0,0,0],0,()=>f.words.set(300,96));assert.equal(f.last('recv').raw.length,96);assert.deepEqual(f.reads,[[1000,32],[2000,64]]);});
 check(()=>{const f=fixture(bits);f.words.set(300,0);f.buf(100,1048576,9999);f.invoke('WSARecv',[7,100,1,300,0,0,0],0);assert.equal(f.last('recv').raw.length,0);assert.equal(f.reads.length,0);});
 check(()=>{const f=fixture(bits);f.invoke('recv',[7,1000,1048576,0],-1);assert.equal(f.last('recv').e.accepted_bytes,null);assert.equal(f.reads.length,0);});
 check(()=>{const f=fixture(bits);f.invoke('recv',[7,1000,10,0],11);assert.equal(f.last('read_error').e.reason,'accepted_bounds');assert(!f.last('recv'));});
 check(()=>{const f=fixture(bits);f.invoke('recv',[7,1000,1048576,0],131073);assert.equal(f.last('read_error').e.reason,'bounded');assert(!f.last('recv'));});
 check(()=>{const f=fixture(bits);f.invoke('send',[7,1000,131073,0],131073);assert.equal(f.last('read_error').e.reason,'bounded');assert(!f.last('send'));});
 check(()=>{const f=fixture(bits);f.invoke('recv',[7,1000,10,0],10);assert.equal(f.last('read_error').e.reason,'memory_access');assert(!JSON.stringify(f.events).includes('PRIVATE'));});
 check(()=>{const f=fixture(bits);f.buf(100,1048576,1000);f.invoke('WSARecv',[7,100,1,300,0,400,0],-1);assert.equal(f.last('recv').e.accepted_bytes,null);assert.equal(f.reads.length,0);f.invoke('WSAGetOverlappedResult',[7,400,300,0,500],0);assert(!f.last('socket_complete'));f.words.set(300,96);f.payload(1000,96);f.invoke('WSAGetOverlappedResult',[7,400,300,1,500],1);assert.equal(f.last('socket_complete').raw.length,96);assert.deepEqual(f.reads,[[1000,96]]);});
 check(()=>{const f=fixture(bits);f.buf(100,96,1000);const p=f.payload(1000,96);f.invoke('WSASend',[7,100,1,300,0,400,0],0);f.words.set(300,80);f.invoke('WSAGetOverlappedResult',[7,400,300,1,500],1);assert.deepEqual(f.last('socket_complete').raw,p.slice(0,80));assert.equal(f.last('socket_complete').e.operation,f.last('send').e.operation);});
 check(()=>{const f=fixture(bits);f.buf(100,96,1000);f.payload(1000,96);f.invoke('WSARecv',[7,100,1,300,0,400,0],-1);f.words.set(300,96);f.invoke('WSAGetOverlappedResult',[7,400,300,1,500],1);f.invoke('WSAGetOverlappedResult',[7,400,300,1,500],1);assert.equal(f.events.filter(x=>x.e.kind==='socket_complete').length,1);assert.equal(f.last('read_error').e.reason,'completion_unmatched');});
 check(()=>{const f=fixture(bits);f.buf(100,96,1000);f.invoke('WSARecv',[7,100,1,300,0,400,999],-1);assert.equal(f.last('read_error').e.reason,'callback_unsupported');assert(!f.last('recv'));});
 check(()=>{const f=fixture(bits);f.buf(100,96,1000);f.invoke('WSARecv',[7,100,1,300,0,400,0],-1);f.invoke('WSARecv',[7,100,1,300,0,400,0],-1);assert.equal(f.last('read_error').e.reason,'overlapped_reuse');f.words.set(300,96);f.payload(1000,96);f.invoke('WSAGetOverlappedResult',[7,400,300,1,500],1);assert.equal(f.last('socket_complete').e.ambiguous,true);});
 check(()=>{const f=fixture(bits);f.buf(100,96,1000);f.invoke('WSARecv',[7,100,1,300,0,400,0],-1);f.invoke('closesocket',[7],0);f.words.set(300,96);f.invoke('WSAGetOverlappedResult',[7,400,300,1,500],1);assert(!f.last('socket_complete'));});
 check(()=>{const f=fixture(bits);f.words.set(10,1);f.words.set(10+bits/8,2);f.words.set(24,1);f.words.set(28,100);f.words.set(100,96);f.words.set(104,1);f.words.set(108,1000);f.payload(1000,96);f.invoke('EncryptMessage',[10,0,20,0],-1);assert.equal(f.last('encrypt').e.return_code,-1);assert.equal(f.last('encrypt').e.after_bytes,0);});
 check(()=>{const f=fixture(bits);f.words.set(10,1);f.words.set(10+bits/8,2);f.words.set(24,1);f.words.set(28,100);f.words.set(100,96);f.words.set(104,1);f.words.set(108,1000);f.payload(1000,96);f.invoke('EncryptMessage',[10,0,20,0],0);assert.equal(f.last('read_error').e.reason,'stream_layout');assert.equal(f.last('read_error').e.phase,'leave');assert(!f.last('encrypt'));});
 check(()=>{const f=fixture(bits);f.c.a=[100,101,102];assert.equal(vm.runInContext("messageDescriptor('EncryptMessage',a)",f.c),102);assert.equal(vm.runInContext("messageDescriptor('DecryptMessage',a)",f.c),101);});
}
console.log(JSON.stringify({actual_js_contract_checks:count,architectures:[32,64]}));
