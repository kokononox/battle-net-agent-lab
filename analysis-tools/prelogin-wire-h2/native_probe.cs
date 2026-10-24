// Owned fixture only: ordinary certificate-validated HTTPS; no target code here.
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Text;
class NativeProbe {
  [StructLayout(LayoutKind.Sequential)] struct Buffer {public uint size,kind;public IntPtr data;}
  [StructLayout(LayoutKind.Sequential)] struct Desc {public uint version,count;public IntPtr buffers;}
  [DllImport("secur32.dll")] static extern int EncryptMessage(IntPtr context,uint qop,ref Desc desc,uint seq);
  static void Negative() {
    byte[] data=Encoding.ASCII.GetBytes("SYNTHETIC_INVALID_CONTEXT_NOT_TARGET");
    IntPtr raw=Marshal.AllocHGlobal(data.Length),b=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(Buffer))),c=Marshal.AllocHGlobal(16);
    try {
      Marshal.Copy(data,0,raw,data.Length);Marshal.WriteInt64(c,0,0);Marshal.WriteInt64(c,8,0);
      Marshal.StructureToPtr(new Buffer{size=(uint)data.Length,kind=1,data=raw},b,false);
      Desc d=new Desc{version=0,count=1,buffers=b};if(EncryptMessage(c,0,ref d,0)==0)throw new Exception();
    }finally{Marshal.FreeHGlobal(raw);Marshal.FreeHGlobal(b);Marshal.FreeHGlobal(c);}
  }
  static void Probe() {
    using(TcpClient client=new TcpClient()) {
      client.SendTimeout=10000;client.ReceiveTimeout=10000;
      var pending=client.BeginConnect("example.com",443,null,null);
      if(!pending.AsyncWaitHandle.WaitOne(10000))throw new Exception();client.EndConnect(pending);
      using(SslStream tls=new SslStream(client.GetStream(),false)) {
        // Default system certificate validation. No accept-all callback or CA changes.
        tls.AuthenticateAsClient("example.com",null,SslProtocols.Tls12,true);
        byte[] request=Encoding.ASCII.GetBytes("HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\nX-Lab-Fixture: synthetic-only\r\n\r\n");
        tls.Write(request,0,request.Length);tls.Flush();
        byte[] response=new byte[16384];int length=0;
        while(length<response.Length) {int n=tls.Read(response,length,response.Length-length);if(n==0)break;length+=n;
          if(Encoding.ASCII.GetString(response,0,length).Contains("\r\n\r\n"))break;}
        if(!Encoding.ASCII.GetString(response,0,length).StartsWith("HTTP/1."))throw new Exception();
      }
    }
  }
  static int Main(string[] args) {
    try {
      Probe();
      if(args.Length==0) {
        ProcessStartInfo info=new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,"child");
        info.UseShellExecute=false;info.CreateNoWindow=true;
        using(Process p=Process.Start(info)){if(!p.WaitForExit(35000)){p.Kill();return 8;}if(p.ExitCode!=0)return 9;}
      }else Negative();
      return 0;
    }catch{return 7;}
  }
}
