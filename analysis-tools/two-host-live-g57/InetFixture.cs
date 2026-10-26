using System;
using System.Text;
using System.Runtime.InteropServices;
public class InetFixture {
 [DllImport("wininet.dll",CharSet=CharSet.Ansi,SetLastError=true)]static extern IntPtr InternetOpenA(string a,uint access,string proxy,string bypass,uint flags);
 [DllImport("wininet.dll",CharSet=CharSet.Ansi,SetLastError=true)]static extern IntPtr InternetConnectA(IntPtr s,string host,ushort port,string user,string pass,uint service,uint flags,UIntPtr context);
 [DllImport("wininet.dll",CharSet=CharSet.Ansi,SetLastError=true)]static extern IntPtr HttpOpenRequestA(IntPtr c,string verb,string path,string version,string referer,IntPtr accept,uint flags,UIntPtr context);
 [DllImport("wininet.dll",CharSet=CharSet.Ansi,SetLastError=true)]static extern bool HttpSendRequestA(IntPtr r,string headers,uint n,byte[] body,uint length);
 [DllImport("wininet.dll")]static extern bool InternetCloseHandle(IntPtr h);
 public static int Main(string[] args){
  ushort port;if(args.Length!=1||!UInt16.TryParse(args[0],out port)||port==0)return 2;
  IntPtr s=InternetOpenA("G57-Synthetic-Control",1,null,null,0),c=IntPtr.Zero,r=IntPtr.Zero;if(s==IntPtr.Zero)return 3;
  try{c=InternetConnectA(s,"127.0.0.1",port,null,null,3,0,UIntPtr.Zero);if(c==IntPtr.Zero)return 4;
   r=HttpOpenRequestA(c,"POST","/agent/versions?fixture=1","HTTP/1.1",null,IntPtr.Zero,0x84000000,UIntPtr.Zero);if(r==IntPtr.Zero)return 5;
   byte[] body=Encoding.ASCII.GetBytes("device=synthetic-control");string headers="Content-Type: application/x-www-form-urlencoded\r\n";
   return HttpSendRequestA(r,headers,(uint)headers.Length,body,(uint)body.Length)?0:6;
  }finally{if(r!=IntPtr.Zero)InternetCloseHandle(r);if(c!=IntPtr.Zero)InternetCloseHandle(c);InternetCloseHandle(s);}
 }
}
