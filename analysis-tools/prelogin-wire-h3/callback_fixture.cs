// Owned TCP loopback probes for registered Windows I/O callbacks; no target code.
using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
class CallbackFixture {
 [StructLayout(LayoutKind.Sequential)] struct Buf {public uint len;public IntPtr data;}
 [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void BoundCallback(uint error,uint n,IntPtr ov);
 [UnmanagedFunctionPointer(CallingConvention.Winapi)] delegate void TpCallback(IntPtr instance,IntPtr context,IntPtr ov,uint error,UIntPtr n,IntPtr io);
 [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] static extern bool BindIoCompletionCallback(IntPtr file,BoundCallback callback,uint flags);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateThreadpoolIo(IntPtr file,TpCallback callback,IntPtr context,IntPtr env);
 [DllImport("kernel32.dll")] static extern void StartThreadpoolIo(IntPtr io);
 [DllImport("kernel32.dll")] static extern void CancelThreadpoolIo(IntPtr io);
 [DllImport("kernel32.dll")] static extern void WaitForThreadpoolIoCallbacks(IntPtr io,[MarshalAs(UnmanagedType.Bool)] bool cancel);
 [DllImport("kernel32.dll")] static extern void CloseThreadpoolIo(IntPtr io);
 [DllImport("ws2_32.dll",SetLastError=true)] static extern int WSARecv(IntPtr s,[In] Buf[] b,uint count,IntPtr received,ref uint flags,IntPtr ov,IntPtr cb);
 [DllImport("ws2_32.dll")] static extern int WSAGetLastError();
 [DllImport("ws2_32.dll")] static extern int send(IntPtr s,byte[] b,int n,int flags);
 static void Check(bool ok){if(!ok)throw new Exception();}
 public static void Probe(bool tp) {
  TcpListener listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
  using(Socket client=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)) {
   client.Connect(listener.LocalEndpoint);
   using(Socket peer=listener.AcceptSocket())using(AutoResetEvent done=new AutoResetEvent(false)) {
    peer.SendTimeout=10000;
    byte[] expected=Encoding.ASCII.GetBytes(("SYNTHETIC_H3_"+(tp?"TP_RECV":"BOUND_RECV")+"_ONLY_").PadRight(96,'Z'));
    IntPtr raw=Marshal.AllocHGlobal(96),ov=Marshal.AllocHGlobal(IntPtr.Size==8?32:20),io=IntPtr.Zero;
    bool valid=false,started=false,issued=false;
    for(int i=0;i<(IntPtr.Size==8?32:20);i++)Marshal.WriteByte(ov,i,0);
    Action<uint,ulong,IntPtr> verify=delegate(uint error,ulong n,IntPtr actual) {
     try {valid=error==0&&n==96&&actual==ov;if(valid){byte[] got=new byte[96];Marshal.Copy(raw,got,0,96);for(int i=0;i<96;i++)if(got[i]!=expected[i])valid=false;}}
     catch{valid=false;}finally{done.Set();}
    };
    BoundCallback cb=delegate(uint e,uint n,IntPtr actual){verify(e,n,actual);};
    TpCallback tpcb=delegate(IntPtr a,IntPtr b,IntPtr actual,uint e,UIntPtr n,IntPtr c){verify(e,n.ToUInt64(),actual);};
    try {
     if(tp){io=CreateThreadpoolIo(client.Handle,tpcb,IntPtr.Zero,IntPtr.Zero);Check(io!=IntPtr.Zero);StartThreadpoolIo(io);started=true;}
     else Check(BindIoCompletionCallback(client.Handle,cb,0));
     uint flags=0;int code=WSARecv(client.Handle,new Buf[]{new Buf{len=96,data=raw}},1,IntPtr.Zero,ref flags,ov,IntPtr.Zero);
     issued=code==0||(code==-1&&WSAGetLastError()==997);Check(issued);Check(code==-1);
     Check(send(peer.Handle,expected,96,0)==96);Check(done.WaitOne(10000));Check(valid);
    } finally {
     client.Close();
     if(tp&&io!=IntPtr.Zero){if(started&&!issued)CancelThreadpoolIo(io);WaitForThreadpoolIoCallbacks(io,true);CloseThreadpoolIo(io);}
     GC.KeepAlive(cb);GC.KeepAlive(tpcb);
     Marshal.FreeHGlobal(raw);Marshal.FreeHGlobal(ov);
    }
   }
  }
  listener.Stop();
 }
}
