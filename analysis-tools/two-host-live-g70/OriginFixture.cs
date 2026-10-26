using System;
using System.Text;
using System.Runtime.InteropServices;
public class OriginFixture {
 [StructLayout(LayoutKind.Sequential)]struct Addr{public ushort family;public ushort port;public uint address;[MarshalAs(UnmanagedType.ByValArray,SizeConst=8)]public byte[] zero;}
 [StructLayout(LayoutKind.Sequential)]struct Buffer{public uint length;public IntPtr data;}
 [DllImport("ws2_32.dll")]static extern int WSAStartup(ushort v,[Out]byte[] d);
 [DllImport("ws2_32.dll")]static extern IntPtr socket(int af,int type,int protocol);
 [DllImport("ws2_32.dll")]static extern int connect(IntPtr s,ref Addr a,int n);
 [DllImport("ws2_32.dll")]static extern int send(IntPtr s,byte[] b,int n,int f);
 [DllImport("ws2_32.dll")]static extern int recv(IntPtr s,byte[] b,int n,int f);
 [DllImport("ws2_32.dll")]static extern int WSARecv(IntPtr s,[In,Out]Buffer[] b,uint count,out uint received,ref uint flags,IntPtr ov,IntPtr cb);
 [DllImport("ws2_32.dll")]static extern int closesocket(IntPtr s);
 [DllImport("ws2_32.dll")]static extern int WSACleanup();
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool ReadFile(IntPtr h,byte[] b,uint n,out uint got,IntPtr ov);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 const string K1="0123456789abcdef0123456789abcdef",K2="123456789abcdef0123456789abcdef0",K3="23456789abcdef0123456789abcdef01";
 static bool Request(IntPtr s,string key){byte[] b=Encoding.ASCII.GetBytes("GET /tpr/fixture/data/"+key.Substring(0,2)+"/"+key.Substring(2,2)+"/"+key+" HTTP/1.1\r\nHost: level3.blizzard.com\r\n\r\n");return send(s,b,b.Length,0)==b.Length;}
 public static int Main(string[] args){
  if(args.Length!=2)return 2;int port=Int32.Parse(args[0]);string path=args[1];
  System.IO.File.WriteAllBytes(path,Encoding.ASCII.GetBytes("fixture:"+K1));
  IntPtr h=CreateFileW(path,0x80000000,1,IntPtr.Zero,3,0,IntPtr.Zero);if(h==new IntPtr(-1))return 3;
  try{byte[] b=new byte[40];uint n;if(!ReadFile(h,b,40,out n,IntPtr.Zero)||n!=40)return 4;}finally{CloseHandle(h);}
  if(WSAStartup(0x202,new byte[512])!=0)return 5;IntPtr s=socket(2,1,6);
  try{Addr a=new Addr{family=2,port=(ushort)(((port&255)<<8)|(port>>8)),address=0x0100007f,zero=new byte[8]};if(connect(s,ref a,16)!=0)return 6;
   if(!Request(s,K1))return 7;byte[] b=new byte[32];int got=0;while(got<32){byte[] part=new byte[32-got];int n=recv(s,part,part.Length,0);if(n<=0)return 8;Array.Copy(part,0,b,got,n);got+=n;}if(Encoding.ASCII.GetString(b)!=K2)return 9;
   if(!Request(s,K2))return 10;IntPtr p=Marshal.AllocHGlobal(32);
   try{Buffer[] bufs={new Buffer{length=32,data=p}};uint n,flags=0;if(WSARecv(s,bufs,1,out n,ref flags,IntPtr.Zero,IntPtr.Zero)!=0||n!=32)return 11;Marshal.Copy(p,b,0,32);if(Encoding.ASCII.GetString(b)!=K3)return 12;}finally{Marshal.FreeHGlobal(p);}
   if(!Request(s,K3))return 13;System.Threading.Thread.Sleep(300);return 0;
  }finally{closesocket(s);WSACleanup();try{System.IO.File.Delete(path);}catch{}}
 }
}
