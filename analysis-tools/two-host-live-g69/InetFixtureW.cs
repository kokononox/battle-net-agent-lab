using System;
using System.Text;
using System.Runtime.InteropServices;
public class InetFixtureW {
 [StructLayout(LayoutKind.Sequential)]struct InternetBuffers{public uint size;public IntPtr next;public IntPtr header;public uint headerLength,headerTotal;public IntPtr buffer;public uint length,total,offsetLow,offsetHigh;}
 [DllImport("wininet.dll",ExactSpelling=true,SetLastError=true)]static extern bool InternetReadFile(IntPtr h,[Out]byte[] buffer,uint count,out uint read);
 [DllImport("wininet.dll",ExactSpelling=true,SetLastError=true)]static extern bool InternetReadFileExW(IntPtr h,ref InternetBuffers b,uint flags,UIntPtr context);

 [DllImport("wininet.dll",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr InternetOpenW(string a,uint access,string proxy,string bypass,uint flags);
 [DllImport("wininet.dll",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr InternetConnectW(IntPtr s,string host,ushort port,string user,string pass,uint service,uint flags,UIntPtr context);
 [DllImport("wininet.dll",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr HttpOpenRequestW(IntPtr c,string verb,string path,string version,string referer,IntPtr accept,uint flags,UIntPtr context);
 [DllImport("wininet.dll",ExactSpelling=true,CharSet=CharSet.Unicode,SetLastError=true)]static extern bool HttpSendRequestW(IntPtr r,string headers,uint n,byte[] body,uint length);
 [DllImport("wininet.dll")]static extern bool InternetCloseHandle(IntPtr h);
 public static int Main(string[] args){
  ushort port;if(args.Length!=1||!UInt16.TryParse(args[0],out port)||port==0)return 2;
  IntPtr s=InternetOpenW("G69-Synthetic-Control",1,null,null,0),c=IntPtr.Zero,r=IntPtr.Zero;if(s==IntPtr.Zero)return 3;
  try{c=InternetConnectW(s,"127.0.0.1",port,null,null,3,0,UIntPtr.Zero);if(c==IntPtr.Zero)return 4;
   r=HttpOpenRequestW(c,"POST","/agent/versions?fixture=1","HTTP/1.1",null,IntPtr.Zero,0x84000000,UIntPtr.Zero);if(r==IntPtr.Zero)return 5;
   byte[] body=Encoding.ASCII.GetBytes("device=synthetic-control");string headers="Content-Type: application/x-www-form-urlencoded\r\n";
   if(!HttpSendRequestW(r,headers,(uint)headers.Length,body,(uint)body.Length))return 6;
   byte[] first=new byte[5];uint read;if(!InternetReadFile(r,first,5,out read)||read!=5||Encoding.ASCII.GetString(first)!="G69-R")return 7;
   IntPtr buffer=Marshal.AllocHGlobal(64);
   try{InternetBuffers b=new InternetBuffers{size=(uint)Marshal.SizeOf(typeof(InternetBuffers)),buffer=buffer,length=64};
    if(!InternetReadFileExW(r,ref b,4,UIntPtr.Zero))return 8;
    byte[] rest=new byte[b.length];Marshal.Copy(buffer,rest,0,rest.Length);return Encoding.ASCII.GetString(rest)=="ESPONSE-PLAIN"?0:9;
   }finally{Marshal.FreeHGlobal(buffer);}
  }finally{if(r!=IntPtr.Zero)InternetCloseHandle(r);if(c!=IntPtr.Zero)InternetCloseHandle(c);InternetCloseHandle(s);}
 }
}
