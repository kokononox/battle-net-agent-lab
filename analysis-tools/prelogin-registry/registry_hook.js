// Passive, fixed-key registry observation. Never replaces arguments or return values.
(function registryTrace(){
'use strict';
const handles=new Map(),installed=new Set();let count=0;
const target='hkcu\\software\\blizzard entertainment\\blizzard error';
const probe='hkcu\\software\\battlenetagentlab\\registryprobe';
function emit(e,b){if(count++>=256){if(count===257)send({kind:'reg_limit'});return;}send(e,b||undefined);}
function path(h){const n=h.toUInt32();if(n===0x80000001)return 'hkcu';if(n===0x80000002)return 'hklm';return handles.get(h.toString())||null;}
function text(p,w){if(p.isNull())return '';let s='';for(let i=0;i<512;i++){const c=w?p.add(i*2).readU16():p.add(i).readU8();if(c===0)return s;if(c>127)return '#non_ascii#';s+=String.fromCharCode(c);}return '#too_long#';}
function join(p,s){return p===null?null:(p+(s?'\\'+s:'' )).toLowerCase().replace(/\\+$/,'');}
function relevant(p){return p!==null&&[target,probe].some(x=>x===p||x.startsWith(p+'\\'));}
function label(p){return p===target?'target':p===probe?'probe':null;}
function fault(){emit({kind:'reg_error'});}
function caller(c){try{const m=Process.mainModule;if(c.returnAddress.compare(m.base)>=0&&c.returnAddress.compare(m.base.add(m.size))<0)return c.returnAddress.sub(m.base).toUInt32();}catch(_){}return null;}
function event(c,status,raw,type){emit({kind:'reg_value',api:c.api,operation:c.operation,label:c.label,status:status,value_type:type,caller_rva:c.rva},raw);}
function hook(mod,api){let a;try{a=mod.getExportByName(api);}catch(_){return;}if(installed.has(a.toString()))return;installed.add(a.toString());const wide=api.endsWith('W');
try{Interceptor.attach(a,{
 onEnter(args){this.api=api;this.active=false;try{
 if(api==='RegCloseKey'){this.h=args[0].toString();return;}
 if(api.startsWith('RegOpenKeyEx')||api.startsWith('RegCreateKeyEx')){this.open=true;this.p=join(path(args[0]),text(args[1],wide));this.out=args[api.startsWith('RegOpen')?4:7];return;}
 let p=path(args[0]),name;
 if(api.startsWith('RegGetValue')){p=join(p,text(args[1],wide));name=text(args[2],wide);this.type=args[4];this.buf=args[5];this.len=args[6];this.operation='read';}
 else {name=text(args[1],wide);if(api.startsWith('RegQueryValueEx')){this.type=args[3];this.buf=args[4];this.len=args[5];this.operation='read';}
 else {this.settype=args[3].toUInt32();this.buf=args[4];this.setlen=args[5].toUInt32();this.operation='write';}}
 this.label=label(p);if(!this.label||name.toLowerCase()!=='useruuid')return;
 this.active=true;this.rva=caller(this);this.capacity=this.operation==='read'&&!this.len.isNull()?this.len.readU32():this.setlen;
 if(this.operation==='write'&&this.capacity<=256&&!this.buf.isNull())this.raw=this.buf.readByteArray(this.capacity);
 }catch(_){fault();this.active=false;}},
 onLeave(ret){try{const status=ret.toInt32();if(api==='RegCloseKey'){if(status===0)handles.delete(this.h);return;}
 if(this.open){if(status===0&&relevant(this.p)){if(handles.size>=256){emit({kind:'reg_limit'});return;}handles.set(this.out.readPointer().toString(),this.p);}return;}
 if(!this.active)return;let raw=null,t=null;
 if(this.operation==='read'){if(status===0&&!this.type.isNull())t=this.type.readU32();if(status===0&&!this.len.isNull()&&!this.buf.isNull()){const n=this.len.readU32();if(n>256||n>this.capacity){fault();return;}raw=this.buf.readByteArray(n);}}
 else {t=this.settype;if(status===0)raw=this.raw||null;}
 event(this,status,raw,t);
 }catch(_){fault();}}
 });emit({kind:'reg_installed',api:api});}catch(_){fault();}
}
Process.attachModuleObserver({onAdded(mod){if(['advapi32.dll','kernelbase.dll'].includes(mod.name.toLowerCase()))for(const api of ['RegOpenKeyExA','RegOpenKeyExW','RegCreateKeyExA','RegCreateKeyExW','RegQueryValueExA','RegQueryValueExW','RegGetValueA','RegGetValueW','RegSetValueExA','RegSetValueExW','RegCloseKey'])hook(mod,api);}});
send({kind:'reg_ready',pointer_bits:Process.pointerSize*8});
})();
