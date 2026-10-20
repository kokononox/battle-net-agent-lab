using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using CdbControl;
static class ControlFixture {
 delegate int Handler(IntPtr exceptionPointers);
 [DllImport("kernel32.dll")]static extern uint GetCurrentProcessId();
 [DllImport("kernel32.dll")]static extern bool IsDebuggerPresent();
 [DllImport("kernel32.dll")]static extern IntPtr AddVectoredExceptionHandler(uint first,Handler callback);
 [DllImport("kernel32.dll")]static extern uint RemoveVectoredExceptionHandler(IntPtr handle);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)]static extern IntPtr GetModuleHandle(string module);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi,ExactSpelling=true)]static extern IntPtr GetProcAddress(IntPtr module,string name);
 [DllImport("ntdll.dll")]static extern void DbgBreakPoint();
 static MemoryMappedViewAccessor proof;static IntPtr expected;static bool armed;static int handled;
 static void Set(int slot,int value){proof.Write(slot*4,value);}
 static int OnException(IntPtr p){
  try{IntPtr record=Marshal.ReadIntPtr(p);uint code=unchecked((uint)Marshal.ReadInt32(record));IntPtr address=Marshal.ReadIntPtr(record,16);
   if(!armed||code!=0x80000003||address!=expected)return 0;
   Set(2,4);Set(4,unchecked((int)code));Set(5,1);
   byte opcode=Marshal.ReadByte(expected);
   if(!Shared.Allowed(code,unchecked((ulong)address.ToInt64()),unchecked((ulong)expected.ToInt64()),opcode,handled,armed)){Set(10,31);return 0;}
   IntPtr context=Marshal.ReadIntPtr(p,IntPtr.Size);long rip=Marshal.ReadInt64(context,Shared.RipOffset);
   int ipCase=Shared.IpCase(unchecked((ulong)rip),unchecked((ulong)expected.ToInt64()));Set(6,ipCase);
   if(ipCase==3){Set(10,32);return 0;}
   handled++;Set(3,handled);
   // Only OUR fixture's exception context is changed, never a game/process context.
   if(ipCase==1){Marshal.WriteInt64(context,Shared.RipOffset,expected.ToInt64()+1);Set(7,1);}else Set(7,0);
   Set(2,5);return -1;
  }catch{try{Set(10,33);}catch{}return 0;}
 }
 static int Main(string[] args){
  if(IntPtr.Size!=8||args.Length!=1)return 40;
  try{if(new FileInfo(args[0]).Length!=Shared.Size)return 41;
   using(var map=MemoryMappedFile.CreateFromFile(args[0],FileMode.Open,null,Shared.Size))
   using(proof=map.CreateViewAccessor(0,Shared.Size,MemoryMappedFileAccess.ReadWrite)){
    for(int i=0;i<16;i++)Set(i,0);Set(0,Shared.Magic);Set(1,Shared.Version);Set(2,1);
    expected=GetProcAddress(GetModuleHandle("ntdll.dll"),"DbgBreakPoint");
    if(expected==IntPtr.Zero||Marshal.ReadByte(expected)!=0xcc||Marshal.ReadByte(expected,1)!=0xc3){Set(10,42);return 42;}
    Handler callback=OnException;IntPtr h=AddVectoredExceptionHandler(1,callback);if(h==IntPtr.Zero){Set(10,43);return 43;}
    try{Set(2,2);if(GetCurrentProcessId()==0){Set(10,44);return 44;}armed=true;Set(2,3);DbgBreakPoint();armed=false;
     Set(2,6);Set(11,IsDebuggerPresent()?1:0);int result=handled==1?0:45;Set(8,1);Set(9,result);Set(2,9);proof.Flush();return result;
    }finally{armed=false;RemoveVectoredExceptionHandler(h);GC.KeepAlive(callback);}
   }
  }catch{return 46;}
 }
}
