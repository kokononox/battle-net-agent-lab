using System;
using System.Text;
using System.Runtime.InteropServices;
public class HttpFixture {
 [DllImport("winhttp.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern IntPtr WinHttpOpen(string agent,uint access,string proxy,string bypass,uint flags);
 [DllImport("winhttp.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern IntPtr WinHttpConnect(IntPtr session,string host,ushort port,uint reserved);
 [DllImport("winhttp.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern IntPtr WinHttpOpenRequest(IntPtr c,string verb,string path,string version,string referer,IntPtr accept,uint flags);
 [DllImport("winhttp.dll",CharSet=CharSet.Unicode,ExactSpelling=true,SetLastError=true)]static extern bool WinHttpSendRequest(IntPtr r,string headers,uint n,byte[] body,uint length,uint total,UIntPtr context);
 [DllImport("winhttp.dll",ExactSpelling=true,SetLastError=true)]static extern bool WinHttpWriteData(IntPtr r,byte[] buffer,uint length,out uint written);
 [DllImport("winhttp.dll",ExactSpelling=true,SetLastError=true)]static extern bool WinHttpReceiveResponse(IntPtr r,IntPtr reserved);
 [DllImport("winhttp.dll",ExactSpelling=true,SetLastError=true)]static extern bool WinHttpReadData(IntPtr r,[Out]byte[] buffer,uint length,out uint read);
 [DllImport("winhttp.dll",ExactSpelling=true)]static extern bool WinHttpCloseHandle(IntPtr h);
 public static int Main(string[] args){
  ushort port;if(args.Length!=1||!UInt16.TryParse(args[0],out port)||port==0)return 2;
  IntPtr s=WinHttpOpen("G65-Synthetic-Control",1,null,null,0),c=IntPtr.Zero,r=IntPtr.Zero;if(s==IntPtr.Zero)return 3;
  try{c=WinHttpConnect(s,"127.0.0.1",port,0);if(c==IntPtr.Zero)return 4;
   r=WinHttpOpenRequest(c,"POST","/agent/versions?fixture=1","HTTP/1.1",null,IntPtr.Zero,0);if(r==IntPtr.Zero)return 5;
   byte[] first=Encoding.ASCII.GetBytes("device="),last=Encoding.ASCII.GetBytes("synthetic-control");string headers="Content-Type: application/x-www-form-urlencoded\r\n";
   if(!WinHttpSendRequest(r,headers,(uint)headers.Length,first,(uint)first.Length,(uint)(first.Length+last.Length),UIntPtr.Zero))return 6;
   uint written;if(!WinHttpWriteData(r,last,(uint)last.Length,out written)||written!=last.Length)return 7;
   if(!WinHttpReceiveResponse(r,IntPtr.Zero))return 8;
   byte[] buffer=new byte[64];uint read;if(!WinHttpReadData(r,buffer,64,out read))return 9;
   return Encoding.ASCII.GetString(buffer,0,(int)read)=="G65-RESPONSE-PLAIN"?0:10;
  }finally{if(r!=IntPtr.Zero)WinHttpCloseHandle(r);if(c!=IntPtr.Zero)WinHttpCloseHandle(c);WinHttpCloseHandle(s);}
 }
}
