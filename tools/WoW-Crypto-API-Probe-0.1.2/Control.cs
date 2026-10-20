using System;
using System.Runtime.InteropServices;
static class ProbeControl {
 delegate int Handler(IntPtr exceptionPointers);
 [DllImport("kernel32.dll")]static extern uint GetCurrentProcessId();
 [DllImport("kernel32.dll")]static extern IntPtr AddVectoredExceptionHandler(uint first,Handler callback);
 [DllImport("kernel32.dll")]static extern uint RemoveVectoredExceptionHandler(IntPtr handle);
 [DllImport("ntdll.dll")]static extern void DbgBreakPoint();
 static int handled;
 static int OnException(IntPtr p){try{IntPtr record=Marshal.ReadIntPtr(p);if(unchecked((uint)Marshal.ReadInt32(record))==0x80000003){handled++;return handled==1?-1:0;}}catch{}return 0;}
 static int Main(){
  Handler callback=OnException;IntPtr h=AddVectoredExceptionHandler(1,callback);if(h==IntPtr.Zero)return 21;
  try{if(GetCurrentProcessId()==0)return 22;DbgBreakPoint();return handled==1?0:23;}
  finally{RemoveVectoredExceptionHandler(h);GC.KeepAlive(callback);}
 }
}
