// Development test only: simulated exception records, not native Windows debug events.
using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Reflection;
using System.Runtime.InteropServices;
public static class SyntheticFixtureTests {
 public static int Run(){
  string path=Path.Combine(Path.GetTempPath(),"cdb-fixture-test-"+Guid.NewGuid().ToString("N"));File.WriteAllBytes(path,new byte[64]);
  IntPtr code=Marshal.AllocHGlobal(2),record=Marshal.AllocHGlobal(160),ctx=Marshal.AllocHGlobal(512),ptrs=Marshal.AllocHGlobal(16);
  var t=typeof(ControlFixture);var flags=BindingFlags.Static|BindingFlags.NonPublic;int checks=0;
  Action<string,object> set=delegate(string k,object v){t.GetField(k,flags).SetValue(null,v);};
  try{using(var map=MemoryMappedFile.CreateFromFile(path,FileMode.Open,null,64))using(var view=map.CreateViewAccessor()){
   set("proof",view);set("expected",code);Marshal.WriteByte(code,0,0xcc);Marshal.WriteByte(code,1,0xc3);
   Marshal.WriteIntPtr(ptrs,0,record);Marshal.WriteIntPtr(ptrs,8,ctx);
   for(int test=0;test<8;test++){
    for(int i=0;i<16;i++)view.Write(i*4,0);set("handled",test==5?1:0);set("armed",test!=6);
    Marshal.WriteInt32(record,unchecked((int)(test==2?0x80000004:0x80000003)));
    Marshal.WriteIntPtr(record,16,test==3?new IntPtr(code.ToInt64()+1):code);
    long rip=code.ToInt64()+(test==1?1:test==4?2:0);Marshal.WriteInt64(ctx,248,rip);Marshal.WriteByte(code,0,test==7?(byte)0x90:(byte)0xcc);
    int result=(int)t.GetMethod("OnException",flags).Invoke(null,new object[]{ptrs});
    bool expectedSuccess=test<2;
    if(expectedSuccess){if(result!=-1||Marshal.ReadInt64(ctx,248)!=code.ToInt64()+1||view.ReadInt32(12)!=1||view.ReadInt32(28)!=(test==0?1:0))throw new Exception("synthetic_success_"+test);}
    else if(result!=0||Marshal.ReadInt64(ctx,248)!=rip)throw new Exception("synthetic_rejection_"+test);
    checks++;
   }
  }}finally{set("proof",null);set("armed",false);Marshal.FreeHGlobal(code);Marshal.FreeHGlobal(record);Marshal.FreeHGlobal(ctx);Marshal.FreeHGlobal(ptrs);File.Delete(path);}
  return checks;
 }
}
