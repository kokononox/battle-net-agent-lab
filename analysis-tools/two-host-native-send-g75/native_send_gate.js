'use strict';
// FIXTURE ONLY. Config is injected by the trusted controller, never client data.
// No onLeave decision. Denials never call the original send/WSASend.
let installed=false,serial=0;const used=new Set();
function install(m){
 if(installed)return;installed=true;
 const getPeer=new NativeFunction(m.getExportByName('getpeername'),'int',['pointer','pointer','pointer']);
 const setError=new NativeFunction(m.getExportByName('WSASetLastError'),'void',['int']);
 const sendPtr=m.getExportByName('send');
 const originalSend=new SystemFunction(sendPtr,'int',['pointer','pointer','int','int']);
 function peerOK(s){
  const a=Memory.alloc(128),n=Memory.alloc(4);n.writeS32(128);
  return getPeer(s,a,n)===0&&a.readU16()===2&&a.add(4).readU8()===127&&
   a.add(5).readU8()===0&&a.add(6).readU8()===0&&a.add(7).readU8()===1&&
   a.add(2).readU8()*256+a.add(3).readU8()===G75_CONFIG.port;
 }
 function denied(id,reason,api,ctx){
  try{send({kind:'native_result',id:id,api:api,original_called:false,result:-1,reason:reason});}catch(e){}
  setError(10013);ctx.lastError=10013;return -1;
 }
 Interceptor.replace(sendPtr,new NativeCallback(function(s,b,n,flags){
  const id=++serial;let called=false;
  try{
   if(id>64)return denied(id,'call_cap','send',this);
   if(flags!==0)return denied(id,'send_flags_unsupported','send',this);
   if(n<=0||n>16384||b.isNull())return denied(id,'input_bound','send',this);
   if(!peerOK(s))return denied(id,'peer_binding','send',this);
   const key=s.toString();
   if(used.has(key))return denied(id,'socket_already_used','send',this);
   // Consume the per-socket slot BEFORE waiting for the host decision.
   used.add(key);
   const snapshot=b.readByteArray(n);
   const privateCopy=Memory.alloc(n);privateCopy.writeByteArray(snapshot);
   send({kind:'candidate',id:id,bytes:n,peer_exact_fixture:true},snapshot);
   let allow=false;
   recv('g75-admit-'+id,function(message){allow=!!message.payload&&message.payload.allow===true;}).wait();
   if(!allow)return denied(id,'policy_or_reply_rejected','send',this);
   // A private copy binds the approved snapshot to these exact outgoing bytes,
   // even when another application thread mutates its original buffer meanwhile.
   called=true;const actual=originalSend(s,privateCopy,n,0);
   const result=actual.value;
   try{send({kind:'native_result',id:id,api:'send',original_called:true,result:result,
         approved_copy_used:true,reason:'exact_canonical_public_input'});}catch(e){}
   this.lastError=actual.lastError;
   return result;
  }catch(e){
   if(called){
    try{send({kind:'native_result',id:id,api:'send',original_called:true,result:-1,
              reason:'original_call_exception_unknown'});}catch(ignore){}
    setError(10013);this.lastError=10013;return -1;
   }
   return denied(id,'adapter_exception','send',this);
  }
 },'int',['pointer','pointer','int','int']));
 // Unsupported adjacent API fails closed in this fixture instead of bypassing
 // the send guard. No claim is made about every Winsock/kernel entry point.
 Interceptor.replace(m.getExportByName('WSASend'),new NativeCallback(function(s,b,count,out,flags,ov,cb){
  const id=++serial;let called=false;
  try{if(!out.isNull())out.writeU32(0);}catch(e){}
  return denied(id,'WSASend_unsupported','WSASend',this);
 },'int',['pointer','pointer','uint','pointer','uint','pointer','pointer']));
 Interceptor.attach(m.getExportByName('closesocket'),{onEnter(a){this.key=a[0].toString();},
  onLeave(r){if(r.toInt32()===0)used.delete(this.key);}});
 send({kind:'native_hooks_installed',arch:Process.arch,send_replaced:true,WSASend_denied:true});
}
Process.attachModuleObserver({onAdded(m){if(m.name.toLowerCase()==='ws2_32.dll')install(m);}});
send({kind:'native_script_ready',arch:Process.arch});
