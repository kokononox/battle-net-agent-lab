using System;
using System.Text;
using System.Runtime.InteropServices;
public class Fixture {
 [StructLayout(LayoutKind.Sequential)]struct Addr{public ushort family;public ushort port;public uint address;[MarshalAs(UnmanagedType.ByValArray,SizeConst=8)]public byte[] zero;}
 [StructLayout(LayoutKind.Sequential)]struct Buffer{public uint length;public IntPtr data;}
 [DllImport("ws2_32.dll")]static extern int WSAStartup(ushort v,[Out]byte[] d);
 [DllImport("ws2_32.dll")]static extern IntPtr socket(int af,int type,int protocol);
 [DllImport("ws2_32.dll")]static extern int connect(IntPtr s,ref Addr a,int n);
 [DllImport("ws2_32.dll")]static extern int send(IntPtr s,byte[] b,int n,int f);
 [DllImport("ws2_32.dll")]static extern int WSASend(IntPtr s,[In]Buffer[] b,uint count,out uint sent,uint flags,IntPtr ov,IntPtr cb);
 [DllImport("ws2_32.dll")]static extern int closesocket(IntPtr s);
 [DllImport("ws2_32.dll")]static extern int WSACleanup();
 public static int Main(string[] args){
  int port;if(args.Length!=1||!Int32.TryParse(args[0],out port)||port<1||port>65535)return 2;
  if(WSAStartup(0x202,new byte[512])!=0)return 3;
  IntPtr s=socket(2,1,6);if(s==new IntPtr(-1))return 4;
  try{
   Addr a=new Addr{family=2,port=(ushort)(((port&255)<<8)|(port>>8)),address=0x0100007f,zero=new byte[8]};
   if(connect(s,ref a,16)!=0)return 5;
   byte[] one=Encoding.ASCII.GetBytes("GET /agent/versions HTTP/1.1\r\nHost: us.version.battle.net\r\n\r\n");
   if(send(s,one,one.Length,0)!=one.Length)return 6;
   byte[] two=Encoding.ASCII.GetBytes("GET /tpr/fixture HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n");
   int cut=13;IntPtr p=Marshal.AllocHGlobal(two.Length);
   try{Marshal.Copy(two,0,p,two.Length);Buffer[] b={new Buffer{length=(uint)cut,data=p},new Buffer{length=(uint)(two.Length-cut),data=IntPtr.Add(p,cut)}};
    uint n;if(WSASend(s,b,2,out n,0,IntPtr.Zero,IntPtr.Zero)!=0||n!=two.Length)return 7;
   }finally{Marshal.FreeHGlobal(p);}
   System.Threading.Thread.Sleep(300);return 0;
  }finally{closesocket(s);WSACleanup();}
 }
}
