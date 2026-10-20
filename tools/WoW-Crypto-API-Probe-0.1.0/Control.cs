using System.Runtime.InteropServices;
static class ProbeControl {
 [DllImport("kernel32.dll")] static extern uint GetCurrentProcessId();
 static int Main(){return GetCurrentProcessId()>0?0:1;}
}
