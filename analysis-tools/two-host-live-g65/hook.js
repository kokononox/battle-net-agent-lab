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
 const connections=new Map(),requests=new Map(),openers=new Map();let requestSerial=0;let responseBytes=0;
 function str(p,n){if(p.isNull())return '';const limit=n===undefined?65536:Math.min(n,65536);let out='';for(let i=0;i<limit;i++){const b=p.add(i).readU8();if(b===0)break;out+=String.fromCharCode(b);}return out;}
 function wstr(p,n){if(p.isNull())return '';const limit=n===undefined?32768:Math.min(n,32768);let out='';for(let i=0;i<limit;i++){const c=p.add(i*2).readU16();if(c===0)break;out+=String.fromCharCode(c);}return out;}
 Interceptor.attach(mod.getExportByName('InternetOpenA'),{onEnter(a){this.agent=str(a[0]);},onLeave(r){if(!r.isNull())openers.set(r.toString(),this.agent);}});
 Interceptor.attach(mod.getExportByName('InternetConnectA'),{onEnter(a){this.meta={server:str(a[1]).toLowerCase(),port:a[2].toUInt32()&65535,agent:openers.get(a[0].toString())||'',username_argument_present:!a[3].isNull(),password_argument_present:!a[4].isNull()};},onLeave(r){if(!r.isNull())connections.set(r.toString(),this.meta);else send({kind:'wininet_connect_failed',error:this.lastError});}});
 Interceptor.attach(mod.getExportByName('HttpOpenRequestA'),{onEnter(a){this.meta=Object.assign({},connections.get(a[0].toString())||{server:'',port:0},{method:str(a[1])||'GET',path:str(a[2]),secure:(a[6].toUInt32()&0x00800000)!==0});},onLeave(r){if(!r.isNull())requests.set(r.toString(),this.meta);else send({kind:'wininet_open_request_failed',error:this.lastError});}});
 Interceptor.attach(mod.getExportByName('HttpSendRequestA'),{onEnter(a){
  this.meta=Object.assign({},requests.get(a[0].toString())||{server:'',method:'',path:'',port:0});
  let n=a[2].toUInt32();this.meta.headers=str(a[1],n===0xffffffff?undefined:n);this.meta.body_declared_bytes=a[4].toUInt32();
  this.body=null;this.meta.body_observed_complete=this.meta.body_declared_bytes<=1048576;
  if(this.meta.body_declared_bytes>0&&this.meta.body_observed_complete&&!a[3].isNull())this.body=a[3].readByteArray(this.meta.body_declared_bytes);
  if(this.meta.body_declared_bytes>0&&a[3].isNull())this.meta.body_observed_complete=false;
  this.meta.call_id=Process.id+':'+(++requestSerial);send(Object.assign({},this.meta,{kind:'wininet_request_begun'}),this.body);
 },onLeave(r){this.meta.kind='wininet_request_input';this.meta.api_returned_true=r.toInt32()!==0;this.meta.error=this.meta.api_returned_true?0:this.lastError;send(this.meta,this.body);}});
 Interceptor.attach(mod.getExportByName('InternetOpenW'),{onEnter(a){this.agent=wstr(a[0]);},onLeave(r){if(!r.isNull())openers.set(r.toString(),this.agent);}});
 Interceptor.attach(mod.getExportByName('InternetConnectW'),{onEnter(a){this.meta={server:wstr(a[1]).toLowerCase(),port:a[2].toUInt32()&65535,agent:openers.get(a[0].toString())||'',username_argument_present:!a[3].isNull(),password_argument_present:!a[4].isNull()};},onLeave(r){if(!r.isNull())connections.set(r.toString(),this.meta);else send({kind:'wininet_connect_failed',error:this.lastError});}});
 Interceptor.attach(mod.getExportByName('HttpOpenRequestW'),{onEnter(a){this.meta=Object.assign({},connections.get(a[0].toString())||{server:'',port:0},{method:wstr(a[1])||'GET',path:wstr(a[2]),secure:(a[6].toUInt32()&0x00800000)!==0});},onLeave(r){if(!r.isNull())requests.set(r.toString(),this.meta);else send({kind:'wininet_open_request_failed',error:this.lastError});}});
 Interceptor.attach(mod.getExportByName('HttpSendRequestW'),{onEnter(a){
  this.meta=Object.assign({},requests.get(a[0].toString())||{server:'',method:'',path:'',port:0});
  let n=a[2].toUInt32();this.meta.headers=wstr(a[1],n===0xffffffff?undefined:n);this.meta.body_declared_bytes=a[4].toUInt32();
  this.body=null;this.meta.body_observed_complete=this.meta.body_declared_bytes<=1048576;
  if(this.meta.body_declared_bytes>0&&this.meta.body_observed_complete&&!a[3].isNull())this.body=a[3].readByteArray(this.meta.body_declared_bytes);
  if(this.meta.body_declared_bytes>0&&a[3].isNull())this.meta.body_observed_complete=false;
  this.meta.call_id=Process.id+':'+(++requestSerial);send(Object.assign({},this.meta,{kind:'wininet_request_begun'}),this.body);
 },onLeave(r){this.meta.kind='wininet_request_input';this.meta.api_returned_true=r.toInt32()!==0;this.meta.error=this.meta.api_returned_true?0:this.lastError;send(this.meta,this.body);}});
 function emitRead(handle,api,buffer,n,capacity){
  if(n>capacity||n>1048576||responseBytes+n>16777216){send({kind:'wininet_response_limit'});return;}
  responseBytes+=n;const meta=Object.assign({},requests.get(handle.toString())||{server:'',port:0},{kind:'wininet_response_bytes',api:api,bytes:n});
  send(meta,n>0?buffer.readByteArray(n):null);
 }
 Interceptor.attach(mod.getExportByName('InternetReadFile'),{onEnter(a){this.h=a[0];this.buf=a[1];this.capacity=a[2].toUInt32();this.count=a[3];},onLeave(r){
  if(r.toInt32()!==0&&!this.count.isNull())emitRead(this.h,'InternetReadFile',this.buf,this.count.readU32(),this.capacity);
  else send({kind:'wininet_read_incomplete',api:'InternetReadFile',error:this.lastError});
 }});
 for(const api of ['InternetReadFileExA','InternetReadFileExW']){
  Interceptor.attach(mod.getExportByName(api),{onEnter(a){this.h=a[0];this.struct=a[1];this.valid=false;
   if(this.struct.isNull())return;
   const bOff=Process.pointerSize===8?32:20,nOff=bOff+Process.pointerSize,nextOff=Process.pointerSize===8?8:4;
   if(!this.struct.add(nextOff).readPointer().isNull()){send({kind:'wininet_linked_read_unsupported'});return;}
   this.buf=this.struct.add(bOff).readPointer();this.nOff=nOff;this.capacity=this.struct.add(nOff).readU32();this.valid=true;
  },onLeave(r){
   if(r.toInt32()!==0&&this.valid)emitRead(this.h,api,this.buf,this.struct.add(this.nOff).readU32(),this.capacity);
   else send({kind:'wininet_read_incomplete',api:api,error:this.lastError});
  }});
 }
 Interceptor.attach(mod.getExportByName('InternetCloseHandle'),{onEnter(a){this.h=a[0].toString();},onLeave(r){if(r.toInt32()!==0){connections.delete(this.h);requests.delete(this.h);openers.delete(this.h);}}});
 send({kind:'wininet_hooks_installed'});
}
Process.attachModuleObserver({onAdded(module){if(module.name.toLowerCase()==='wininet.dll')installInet(module);}});

// Only module categories are exported; no paths or arbitrary module names.
Process.attachModuleObserver({onAdded(m){const n=m.name.toLowerCase();let category=null;
 if(n==='schannel.dll'||n==='secur32.dll'||n==='sspicli.dll')category='Windows_SSPI_TLS';
 else if(n==='wininet.dll')category='WinINet';else if(n==='winhttp.dll')category='WinHTTP';
 else if(n.includes('libssl')||n.includes('libcrypto'))category='OpenSSL_named_module';
 else if(n==='libcef.dll'||n==='chrome.dll')category='Chromium_named_module';
 if(category)send({kind:'network_module_category',category:category});}});
// WinHTTP is a separate family. Observe inputs before calls; skip async outputs.
let httpInstalled=false;
function installHttp(mod){
 if(httpInstalled)return;httpInstalled=true;
 const sessions=new Map(),connections=new Map(),requests=new Map();let serial=0,responseBytes=0;
 function wstr(p,n){if(p.isNull())return '';let out='';const limit=n===undefined?32768:Math.min(n,32768);for(let i=0;i<limit;i++){const c=p.add(i*2).readU16();if(c===0)break;out+=String.fromCharCode(c);}return out;}
 function meta(h){return Object.assign({server:'',port:0,api_family:'WinHTTP'},requests.get(h.toString())||{});}
 Interceptor.attach(mod.getExportByName('WinHttpOpen'),{onEnter(a){this.m={agent:wstr(a[0]),async_mode:(a[4].toUInt32()&0x10000000)!==0,api_family:'WinHTTP'};},onLeave(r){if(!r.isNull())sessions.set(r.toString(),this.m);}});
 Interceptor.attach(mod.getExportByName('WinHttpConnect'),{onEnter(a){this.m=Object.assign({},sessions.get(a[0].toString())||{async_mode:true},{server:wstr(a[1]).toLowerCase(),port:a[2].toUInt32()&65535,api_family:'WinHTTP'});},onLeave(r){if(!r.isNull())connections.set(r.toString(),this.m);}});
 Interceptor.attach(mod.getExportByName('WinHttpOpenRequest'),{onEnter(a){this.m=Object.assign({},connections.get(a[0].toString())||{async_mode:true},{method:wstr(a[1])||'GET',path:wstr(a[2]),secure:(a[6].toUInt32()&0x00800000)!==0,api_family:'WinHTTP'});},onLeave(r){if(!r.isNull())requests.set(r.toString(),this.m);}});
 Interceptor.attach(mod.getExportByName('WinHttpSendRequest'),{onEnter(a){
  this.m=meta(a[0]);this.m.api='WinHttpSendRequest';const n=a[2].toUInt32();this.m.headers=wstr(a[1],n===0xffffffff?undefined:n);
  this.m.body_declared_bytes=a[4].toUInt32();this.m.additional_total_bytes=a[5].toUInt32();this.m.call_id=Process.id+':http:'+(++serial);
  this.m.body_observed_complete=this.m.body_declared_bytes<=1048576&&(this.m.body_declared_bytes===0||!a[3].isNull());this.data=null;
  if(this.m.body_declared_bytes&&this.m.body_observed_complete)this.data=a[3].readByteArray(this.m.body_declared_bytes);
  send(Object.assign({},this.m,{kind:'wininet_request_begun'}),this.data);
 },onLeave(r){send(Object.assign({},this.m,{kind:'wininet_request_input',api_returned_true:r.toInt32()!==0,error:r.toInt32()!==0?0:this.lastError}),this.data);}});
 Interceptor.attach(mod.getExportByName('WinHttpWriteData'),{onEnter(a){
  this.m=meta(a[0]);this.m.api='WinHttpWriteData';this.m.body_declared_bytes=a[2].toUInt32();this.m.headers='';this.m.call_id=Process.id+':http:'+(++serial);
  this.m.body_observed_complete=this.m.body_declared_bytes<=1048576&&(this.m.body_declared_bytes===0||!a[1].isNull());this.data=null;
  if(this.m.body_declared_bytes&&this.m.body_observed_complete)this.data=a[1].readByteArray(this.m.body_declared_bytes);
  send(Object.assign({},this.m,{kind:'wininet_request_begun'}),this.data);
 },onLeave(r){send(Object.assign({},this.m,{kind:'wininet_request_input',api_returned_true:r.toInt32()!==0,error:r.toInt32()!==0?0:this.lastError}),this.data);}});
 Interceptor.attach(mod.getExportByName('WinHttpReadData'),{onEnter(a){this.m=meta(a[0]);this.buf=a[1];this.capacity=a[2].toUInt32();this.count=a[3];},onLeave(r){
  if(r.toInt32()===0||this.m.async_mode!==false||this.count.isNull()){send({kind:'winhttp_read_output_unobserved',async_or_unknown:this.m.async_mode!==false});return;}
  const n=this.count.readU32();if(n>this.capacity||n>1048576||responseBytes+n>16777216){send({kind:'winhttp_response_limit'});return;}responseBytes+=n;
  send(Object.assign({},this.m,{kind:'wininet_response_bytes',api:'WinHttpReadData',bytes:n}),n?this.buf.readByteArray(n):null);
 }});
 Interceptor.attach(mod.getExportByName('WinHttpReceiveResponse'),{onLeave(r){send({kind:'winhttp_receive_response',api_returned_true:r.toInt32()!==0,error:r.toInt32()!==0?0:this.lastError});}});
 Interceptor.attach(mod.getExportByName('WinHttpCloseHandle'),{onEnter(a){this.h=a[0].toString();},onLeave(r){if(r.toInt32()!==0){sessions.delete(this.h);connections.delete(this.h);requests.delete(this.h);}}});
 send({kind:'winhttp_hooks_installed'});
}
Process.attachModuleObserver({onAdded(m){if(m.name.toLowerCase()==='winhttp.dll')installHttp(m);}});
// Fixed-schema startup diagnostics: no command lines, paths or arbitrary DNS names exported.
let diagCount=0;const diagnosed=new Set();
function diag(p){if(diagCount++<500)send(Object.assign({kind:'startup_diagnostic'},p));}
function boundedName(p,wide){if(p.isNull())return '';let out='';for(let i=0;i<512;i++){let c=wide?p.add(i*2).readU16():p.add(i).readU8();if(!c)break;out+=String.fromCharCode(c);}return out.toLowerCase();}
function hookDiagnostic(m,name,style){
 const key=m.name.toLowerCase()+':'+name;if(diagnosed.has(key))return;const ptr=m.findExportByName(name);if(!ptr)return;diagnosed.add(key);
 Interceptor.attach(ptr,{onEnter(a){
  this.d={api:name};if(style==='dns'){let n=boundedName(a[0],name==='GetAddrInfoW');this.d.destination_class=n==='level3.blizzard.com'||n==='us.version.battle.net'?n:n==='localhost'||n==='127.0.0.1'||n==='::1'?'loopback':'other_or_empty';}
 },onLeave(r){
  const ok=style==='dns'?r.toInt32()===0:style==='handle'?!r.isNull():r.toInt32()!==0;
  this.d.succeeded=ok;this.d.error_code=ok?0:style==='dns'?r.toInt32():this.lastError;diag(this.d);
 }});
}
Process.attachModuleObserver({onAdded(m){const n=m.name.toLowerCase();
 if(n==='ws2_32.dll'){for(const api of ['getaddrinfo','GetAddrInfoW'])hookDiagnostic(m,api,'dns');}
 if(n==='wininet.dll'){
  for(const api of ['InternetOpenA','InternetOpenW','InternetConnectA','InternetConnectW','HttpOpenRequestA','HttpOpenRequestW','InternetOpenUrlA','InternetOpenUrlW'])hookDiagnostic(m,api,'handle');
  for(const api of ['InternetGetConnectedState','InternetCheckConnectionA','InternetCheckConnectionW'])hookDiagnostic(m,api,'bool');
 }
 if(n==='winhttp.dll'){for(const api of ['WinHttpOpen','WinHttpConnect','WinHttpOpenRequest'])hookDiagnostic(m,api,'handle');}
 if(n==='kernel32.dll'){hookDiagnostic(m,'CreateProcessW','bool');}
 if(n==='advapi32.dll'){for(const api of ['CreateProcessAsUserW','CreateProcessWithTokenW'])hookDiagnostic(m,api,'bool');}
}});
// SSPI observation only: never replace return values or write application buffers.
const sspiHooks=new Set(),tlsCreds=new Set(),tlsContexts=new Map();let tlsSerial=0,tlsBytes=0,tlsEvents=0;
function sspiSend(p,data){if(tlsEvents++<1000)send(p,data);}
function sspiKey(p){if(p.isNull())return null;return p.readPointer().toString()+':'+p.add(Process.pointerSize).readPointer().toString();}
function sspiText(p,wide){if(p.isNull())return '';let out='';for(let i=0;i<512;i++){const n=wide?p.add(i*2).readU16():p.add(i).readU8();if(!n)break;out+=String.fromCharCode(n);}return out.toLowerCase();}
function tlsHost(s){if(s==='level3.blizzard.com'||s==='us.version.battle.net')return s;if(globalThis.SSPI_FIXTURE===true&&s==='localhost')return s;return null;}
function safeSSPI(f){try{return f();}catch(e){sspiSend({kind:'sspi_observation_error'});return null;}}
function tlsParts(desc){
 if(desc.isNull()||desc.readU32()!==0)throw Error('descriptor_version');const count=desc.add(4).readU32();if(count>32)throw Error('buffer_count');
 const p=desc.add(8).readPointer(),stride=Process.pointerSize===8?16:12;let parts=[],total=0;
 for(let i=0;i<count;i++){const b=p.add(i*stride),n=b.readU32(),type=b.add(4).readU32();if((type&0x0fffffff)!==1||(type&0xf0000000)!==0||n===0)continue;
  if(n>1048576||total+n>1048576)throw Error('buffer_cap');const address=b.add(8).readPointer();if(address.isNull())throw Error('null_buffer');parts.push(address.readByteArray(n));total+=n;}
 return parts;
}
function emitTLS(meta,direction,parts,status){for(const data of parts){if(tlsBytes+data.byteLength>16777216){sspiSend({kind:'sspi_byte_limit'});return;}tlsBytes+=data.byteLength;
 sspiSend({kind:'sspi_plaintext',server:meta.server,context_index:meta.index,direction:direction,status:status,observed_bytes:data.byteLength,wire_receipt_proven:false},data);}}
function hookSSPI(m,name,callbacks){const p=m.findExportByName(name);if(!p||sspiHooks.has(p.toString()))return;sspiHooks.add(p.toString());Interceptor.attach(p,callbacks);sspiSend({kind:'sspi_hook_installed',api:name});}
function installSSPI(m){
 for(const suffix of ['A','W']){
  hookSSPI(m,'AcquireCredentialsHandle'+suffix,{onEnter(a){safeSSPI(()=>{const pkg=sspiText(a[1],suffix==='W');this.tls=pkg==='schannel'||pkg==='microsoft unified security protocol provider';this.out=a[7];});},onLeave(r){if(this.tls&&r.toInt32()===0)safeSSPI(()=>{tlsCreds.add(sspiKey(this.out));sspiSend({kind:'sspi_tls_credential_acquired'});});}});
  hookSSPI(m,'InitializeSecurityContext'+suffix,{onEnter(a){safeSSPI(()=>{
   this.oldKey=sspiKey(a[1]);this.previous=this.oldKey?tlsContexts.get(this.oldKey):null;
   this.host=tlsHost(sspiText(a[2],suffix==='W'))||(this.previous?this.previous.server:null);
   this.enabled=!!this.host&&(tlsCreds.has(sspiKey(a[0]))||!!this.previous);this.output=a[8];
  });},onLeave(r){if(!this.enabled)return;safeSSPI(()=>{
   const code=r.toUInt32(),meta=this.previous||{server:this.host,index:++tlsSerial};
   // Keep association through handshake failures for diagnosis; no success is inferred.
   if(!this.output.isNull()){const key=sspiKey(this.output);if(key&&key!=='0x0:0x0'&&key!=='0xffffffff:0xffffffff'&&key!=='0xffffffffffffffff:0xffffffffffffffff')tlsContexts.set(key,meta);}
   sspiSend({kind:'sspi_handshake_status',server:meta.server,context_index:meta.index,status_hex:'0x'+code.toString(16).padStart(8,'0'),succeeded:code===0,continuation:code===0x90312});
  });}});
 }
 hookSSPI(m,'EncryptMessage',{onEnter(a){safeSSPI(()=>{this.meta=tlsContexts.get(sspiKey(a[0]));if(this.meta)this.parts=tlsParts(a[2]);});},onLeave(r){if(this.meta&&this.parts)safeSSPI(()=>{emitTLS(this.meta,'outgoing_pre_encrypt',this.parts,'0x'+r.toUInt32().toString(16).padStart(8,'0'));});}});
 hookSSPI(m,'DecryptMessage',{onEnter(a){safeSSPI(()=>{this.meta=tlsContexts.get(sspiKey(a[0]));this.desc=a[1];});},onLeave(r){if(!this.meta)return;safeSSPI(()=>{const code=r.toUInt32();sspiSend({kind:'sspi_decrypt_status',server:this.meta.server,context_index:this.meta.index,status_hex:'0x'+code.toString(16).padStart(8,'0')});if(code===0)emitTLS(this.meta,'incoming_post_decrypt',tlsParts(this.desc),'0x00000000');});}});
 hookSSPI(m,'DeleteSecurityContext',{onEnter(a){safeSSPI(()=>{this.key=sspiKey(a[0]);});},onLeave(r){if(r.toInt32()===0)tlsContexts.delete(this.key);}});
 hookSSPI(m,'FreeCredentialsHandle',{onEnter(a){safeSSPI(()=>{this.key=sspiKey(a[0]);});},onLeave(r){if(r.toInt32()===0)tlsCreds.delete(this.key);}});
}
Process.attachModuleObserver({onAdded(m){if(['secur32.dll','sspicli.dll'].includes(m.name.toLowerCase()))installSSPI(m);}});
