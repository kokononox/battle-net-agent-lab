// Owned loopback only; synthetic constants, no Blizzard/game/user data.
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
class SocketFixture {
  [StructLayout(LayoutKind.Sequential)] struct Buf { public uint len;public IntPtr data; }
  [DllImport("ws2_32.dll",SetLastError=true)] static extern int recv(IntPtr s,IntPtr b,int n,int f);
  [DllImport("ws2_32.dll",SetLastError=true)] static extern int send(IntPtr s,byte[] b,int n,int f);
  [DllImport("ws2_32.dll",SetLastError=true)] static extern int WSASend(IntPtr s,[In] Buf[] b,uint count,ref uint sent,uint f,IntPtr ov,IntPtr cb);
  [DllImport("ws2_32.dll",SetLastError=true)] static extern int WSARecv(IntPtr s,[In] Buf[] b,uint count,ref uint received,ref uint f,IntPtr ov,IntPtr cb);
  [DllImport("ws2_32.dll")] static extern int WSAGetLastError();
  [DllImport("ws2_32.dll")] static extern IntPtr WSACreateEvent();
  [DllImport("ws2_32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool WSACloseEvent(IntPtr e);
  [DllImport("ws2_32.dll")] [return:MarshalAs(UnmanagedType.Bool)] static extern bool WSAGetOverlappedResult(IntPtr s,IntPtr ov,out uint n,[MarshalAs(UnmanagedType.Bool)] bool wait,out uint flags);
  static byte[] Marker(string type) {return Encoding.ASCII.GetBytes(("SYNTHETIC_H3_"+type+"_ONLY_").PadRight(96,'Z'));}
  static void Check(bool ok){if(!ok)throw new Exception();}
  static void Push(Socket s,byte[] b){Check(send(s.Handle,b,b.Length,0)==b.Length);}
  static void Compare(IntPtr a,IntPtr b,int split,byte[] expected) {
    byte[] got=new byte[expected.Length];Marshal.Copy(a,got,0,Math.Min(split,got.Length));
    if(got.Length>split)Marshal.Copy(b,got,split,got.Length-split);
    for(int i=0;i<got.Length;i++)Check(got[i]==expected[i]);
  }
  static IntPtr Overlap(IntPtr ev) {int size=IntPtr.Size==8?32:20;IntPtr p=Marshal.AllocHGlobal(size);for(int i=0;i<size;i++)Marshal.WriteByte(p,i,0);Marshal.WriteIntPtr(p,IntPtr.Size==8?24:16,ev);return p;}
  public static void Run() {
    TcpListener listener=new TcpListener(IPAddress.Loopback,0);listener.Start();
    using(Socket client=new Socket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.Tcp)) {
      client.ReceiveTimeout=10000;client.SendTimeout=10000;client.Connect(listener.LocalEndpoint);
      using(Socket peer=listener.AcceptSocket()) {
        peer.ReceiveTimeout=10000;peer.SendTimeout=10000;
        IntPtr a=Marshal.AllocHGlobal(1048576),b=Marshal.AllocHGlobal(1048576),ev=IntPtr.Zero,ov=IntPtr.Zero;
        try {
          byte[] m=Marker("LARGE_RECV");Push(peer,m);Check(recv(client.Handle,a,1048576,0)==96);Compare(a,b,96,m);
          Buf[] buffers=new Buf[]{new Buf{len=32,data=a},new Buf{len=1048576,data=b}};
          m=Marker("MULTIBUFFER_RECV");Push(peer,m);uint n=0,flags=0;
          Check(WSARecv(client.Handle,buffers,2,ref n,ref flags,IntPtr.Zero,IntPtr.Zero)==0&&n==96);Compare(a,b,32,m);
          ev=WSACreateEvent();Check(ev!=IntPtr.Zero);ov=Overlap(ev);n=0;flags=0;
          int code=WSARecv(client.Handle,buffers,2,ref n,ref flags,ov,IntPtr.Zero);
          Check(code==-1&&WSAGetLastError()==997);
          uint completed,cf;Check(!WSAGetOverlappedResult(client.Handle,ov,out completed,false,out cf));Check(WSAGetLastError()==996);
          m=Marker("ASYNC_RECV");Push(peer,m);
          Check(WSAGetOverlappedResult(client.Handle,ov,out completed,true,out cf)&&completed==96);Compare(a,b,32,m);
          Marshal.FreeHGlobal(ov);ov=IntPtr.Zero;WSACloseEvent(ev);ev=IntPtr.Zero;
          m=Marker("ASYNC_SEND");Marshal.Copy(m,0,a,32);Marshal.Copy(m,32,b,64);
          buffers[1].len=64;ev=WSACreateEvent();ov=Overlap(ev);n=0;
          code=WSASend(client.Handle,buffers,2,ref n,0,ov,IntPtr.Zero);
          Check(code==0||(code==-1&&WSAGetLastError()==997));
          Check(WSAGetOverlappedResult(client.Handle,ov,out completed,true,out cf)&&completed==96);
          // Receiver-side witness is independent of the collector's completion event.
          int got=0;while(got<96){int r=recv(peer.Handle,a,96-got,0);Check(r>0);byte[] part=new byte[r];Marshal.Copy(a,part,0,r);for(int i=0;i<r;i++)Check(part[i]==m[got+i]);got+=r;}
          File.WriteAllText(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName+".witness.json","{\"large_recv\":true,\"multibuffer_recv\":true,\"pending_recv\":true,\"false_completion_checked\":true,\"async_recv\":true,\"async_send\":true}");
        } finally {if(ov!=IntPtr.Zero)Marshal.FreeHGlobal(ov);if(ev!=IntPtr.Zero)WSACloseEvent(ev);Marshal.FreeHGlobal(a);Marshal.FreeHGlobal(b);}
      }
    }
    listener.Stop();
  }
}
