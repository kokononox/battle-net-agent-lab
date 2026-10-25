// Executes the actual hook with deterministic Win32 pointer/API mocks, not a reimplementation.
const fs=require('fs'),vm=require('vm'),assert=require('assert');let checks=0;
for(const bits of [32,64]){
 const memory=new Map(),hooks=new Map(),events=[];let stackMode="normal";let next=0x100000;
 class P{
  constructor(n){this.n=BigInt(n);}
  add(n){return new P(this.n+BigInt(n));}sub(p){return new P(this.n-p.n);}
  toUInt32(){return Number(this.n&0xffffffffn);}toInt32(){return this.toUInt32()|0;}
  compare(p){return this.n<p.n?-1:this.n>p.n?1:0;}isNull(){return this.n===0n;}toString(){return '0x'+this.n.toString(16);}
  readU8(){const x=memory.get(this.n);if(x===undefined)throw Error('unmapped');return x;}
  readU16(){return this.readU8()+this.add(1).readU8()*256;}
  readU32(){return this.readU16()+this.add(2).readU16()*65536;}
  readPointer(){let n=0n;for(let i=bits/8-1;i>=0;i--)n=n*256n+BigInt(this.add(i).readU8());return new P(n);}
  readByteArray(n){return Uint8Array.from(Array.from({length:n},(_,i)=>this.add(i).readU8())).buffer;}
 }
 const p=n=>new P(n);function put(b){const a=p(next);next+=b.length+32;[...b].forEach((v,i)=>memory.set(a.n+BigInt(i),v));return a;}
 const str=(s,w)=>put(Buffer.from(s+'\0',w?'utf16le':'ascii'));
 const u32=n=>put(Buffer.from([n&255,(n>>>8)&255,(n>>>16)&255,(n>>>24)&255]));
 const hp=n=>{let v=BigInt(n),b=[];for(let i=0;i<bits/8;i++){b.push(Number(v&255n));v>>=8n;}return put(b);};
 const apis=['RegOpenKeyExA','RegOpenKeyExW','RegCreateKeyExA','RegCreateKeyExW','RegQueryValueExA','RegQueryValueExW','RegGetValueA','RegGetValueW','RegSetValueExA','RegSetValueExW','RegCloseKey'];
 const mod={name:'ADVAPI32.dll',getExportByName:a=>a};
 vm.runInNewContext(fs.readFileSync(__dirname+'/registry_hook.js','utf8'),{Backtracer:{ACCURATE:'accurate'},Thread:{backtrace(c,mode){assert.equal(mode,'accurate');if(stackMode==='failed')throw Error('owned');return stackMode==='external'?[p(0x700000)]:[p(0x700000),p(0x401234),p(0x401255),p(0x401234)];}},Process:{pointerSize:bits/8,mainModule:{base:p(0x400000),size:0x100000},attachModuleObserver(o){o.onAdded(mod);}},Interceptor:{attach(a,c){hooks.set(a,c);}},send(e,b){events.push({e,b:b?Buffer.from(b):Buffer.alloc(0)});}});
 const call=(api,args,ret=0,addr=0x401234)=>{const c={returnAddress:p(addr),context:{owned:true}};hooks.get(api).onEnter.call(c,args);hooks.get(api).onLeave.call(c,p(ret));};
 const root=p(bits===64?0xffffffff80000001n:0x80000001n),h=p(55);
 call('RegOpenKeyExW',[root,str('Software\\Blizzard Entertainment\\Blizzard Error',true),p(0),p(0),hp(55)]);
 const syn='abcdefab-abcd-4abc-abcd-abcdefabcdef';
 let b=Buffer.from(syn+'\0','utf16le');call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),put(b),u32(b.length)]);
 let x=events.filter(x=>x.e.kind==='reg_value');assert.equal(x.length,1);assert.equal(x[0].b.toString('utf16le'),syn+'\0');assert.equal(x[0].e.caller_rva,0x1234);checks+=3;
 b=Buffer.from(syn+'\0');call('RegQueryValueExA',[h,str('useruuid',false),p(0),u32(1),put(b),u32(b.length)]);
 x=events.filter(x=>x.e.kind==='reg_value');assert.equal(x.length,2);assert.equal(x[1].b.toString('ascii'),syn+'\0');checks+=2;
 call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),p(0),u32(0)]);
 x=events.filter(x=>x.e.kind==='reg_value');assert.equal(x[2].b.length,0);checks++;
 call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(0xdead),put(b),u32(b.length)],2);
 x=events.filter(x=>x.e.kind==='reg_value');assert.equal(x[3].b.length,0);assert.equal(x[3].e.value_type,null);checks+=2;
 call('RegQueryValueExW',[h,str('OtherName',true),p(0),u32(1),put(b),u32(b.length)]);assert.equal(events.filter(x=>x.e.kind==='reg_value').length,4);checks++;
 call('RegSetValueExW',[h,str('UserUUID',true),p(0),p(1),put(b),p(b.length)]);x=events.filter(x=>x.e.kind==='reg_value');assert.equal(x[4].e.operation,'write');assert.equal(x[4].b.length,b.length);checks+=2;
 call('RegGetValueW',[root,str('Software\\Blizzard Entertainment\\Blizzard Error',true),str('UserUUID',true),p(2),u32(1),put(b),u32(b.length)]);x=events.filter(x=>x.e.kind==='reg_value');assert.equal(x[5].e.operation,'read');assert.equal(x[5].b.length,b.length);checks+=2;
 call('RegCloseKey',[h]);call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),put(b),u32(b.length)]);assert.equal(events.filter(x=>x.e.kind==='reg_value').length,6);checks++;
 call('RegOpenKeyExW',[root,str('Software\\Unrelated',true),p(0),p(0),hp(56)]);call('RegQueryValueExW',[p(56),str('UserUUID',true),p(0),u32(1),put(b),u32(b.length)]);assert.equal(events.filter(x=>x.e.kind==='reg_value').length,6);checks++;
 call('RegOpenKeyExW',[root,str('Software\\Blizzard Entertainment\\Blizzard Error',true),p(0),p(0),hp(55)]);
 call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),put(Buffer.from(syn+'\0','utf16le')),u32(74)],0,0x700000);
 x=events.filter(x=>x.e.kind==='reg_value').at(-1);assert.equal(x.e.caller_rva,null);assert.equal(x.e.stack_status,'captured');assert.deepEqual(Array.from(x.e.main_module_stack_rvas),[0x1234,0x1255]);checks+=3;
 stackMode='external';call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),put(Buffer.from(syn+'\0','utf16le')),u32(74)],0,0x700000);
 x=events.filter(x=>x.e.kind==='reg_value').at(-1);assert.equal(x.e.caller_rva,null);assert.equal(x.e.stack_status,'captured');assert.equal(x.e.main_module_stack_rvas.length,0);checks+=3;
 stackMode='failed';call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),put(Buffer.from(syn+'\0','utf16le')),u32(74)]);
 x=events.filter(x=>x.e.kind==='reg_value').at(-1);assert.equal(x.e.stack_status,'failed');assert.equal(x.e.main_module_stack_rvas.length,0);checks+=2;
 call('RegOpenKeyExW',[root,str('Software\\Blizzard Entertainment\\Blizzard Error',true),p(0),p(0),hp(55)]);
 call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),put(Buffer.from(syn+'\0','utf16le')),u32(74)],0,0x700000);
 x=events.filter(x=>x.e.kind==='reg_value').at(-1);assert.equal(x.e.caller_rva,null);assert.equal(x.e.stack_status,'captured');assert.deepEqual(Array.from(x.e.main_module_stack_rvas),[0x1234,0x1255]);checks+=3;
 stackMode='external';call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),put(Buffer.from(syn+'\0','utf16le')),u32(74)],0,0x700000);
 x=events.filter(x=>x.e.kind==='reg_value').at(-1);assert.equal(x.e.caller_rva,null);assert.equal(x.e.stack_status,'captured');assert.equal(x.e.main_module_stack_rvas.length,0);checks+=3;
 stackMode='failed';call('RegQueryValueExW',[h,str('UserUUID',true),p(0),u32(1),put(Buffer.from(syn+'\0','utf16le')),u32(74)]);
 x=events.filter(x=>x.e.kind==='reg_value').at(-1);assert.equal(x.e.stack_status,'failed');assert.equal(x.e.main_module_stack_rvas.length,0);checks+=2;
 assert.equal(events.filter(x=>x.e.kind==='reg_error').length,0);assert.equal(events.filter(x=>x.e.kind==='reg_ready').length,1);checks+=2;
}
console.log(JSON.stringify({actual_hook_checks:checks,passed:true,architectures:[32,64]}));
