// Inert loopback-only HTTP / synthetic ClientHello fixture. No real TLS or installer.
using System;using System.IO;using System.Net;using System.Net.Sockets;using System.Text;using System.Threading;using System.Diagnostics;using System.Web.Script.Serialization;
public class PeerClient {
 static void Wait(string path){var w=Stopwatch.StartNew();while(!File.Exists(path)&&w.ElapsedMilliseconds<20000)Thread.Sleep(20);if(!File.Exists(path))throw new Exception();}
 static byte[] Join(params byte[][] parts){using(var s=new MemoryStream()){foreach(var p in parts)s.Write(p,0,p.Length);return s.ToArray();}}
 static byte[] U16(int n){return new byte[]{(byte)(n>>8),(byte)n};}
 static byte[] Hello(){byte[] host=Encoding.ASCII.GetBytes("level3.blizzard.com");byte[] names=Join(new byte[]{0},U16(host.Length),host);byte[] data=Join(U16(names.Length),names);byte[] ext=Join(new byte[]{0,0},U16(data.Length),data);byte[] body=Join(new byte[]{3,3},new byte[32],new byte[]{0,0,2,0x13,1,1,0},U16(ext.Length),ext);byte[] h=Join(new byte[]{1,0,(byte)(body.Length>>8),(byte)body.Length},body);return Join(new byte[]{22,3,1},U16(h.Length),h);}
 static string Header(NetworkStream s){var b=new MemoryStream();while(b.Length<4096){int c=s.ReadByte();if(c<0)break;b.WriteByte((byte)c);if(b.Length>=4){var a=b.GetBuffer();int n=(int)b.Length;if(a[n-4]==13&&a[n-3]==10&&a[n-2]==13&&a[n-1]==10)break;}}return Encoding.ASCII.GetString(b.ToArray());}
 static void Send(NetworkStream s,byte[] b){s.Write(b,0,b.Length);}
 static int Main(string[] args){try{
  if(args.Length!=5)return 4;string mode=args[0];if(mode!="http"&&mode!="version_http"&&mode!="tls"&&mode!="connect"&&mode!="connect_paused")return 4;
  IPAddress ip=IPAddress.Parse(args[1]);if(!IPAddress.IsLoopback(ip))return 4;int port=int.Parse(args[2]);if(port<1||port>65535)return 4;
  string ready=Path.GetFullPath(args[3]),go=Path.GetFullPath(args[4]);string prefix=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"BNetPeerG15")+"\\";
  if(!ready.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)||!go.StartsWith(prefix,StringComparison.OrdinalIgnoreCase))return 4;
  using(var p=Process.GetCurrentProcess()){File.WriteAllText(ready,new JavaScriptSerializer().Serialize(new{pid=p.Id,created=p.StartTime.ToFileTimeUtc(),image=p.MainModule.FileName}),new UTF8Encoding(false));}
  Wait(go);bool http200=false,connect200=false;string result="closed_or_refused";
  try{using(var tcp=new TcpClient(ip.AddressFamily)){
   if(!tcp.ConnectAsync(ip,port).Wait(3000))throw new Exception();tcp.ReceiveTimeout=5000;tcp.SendTimeout=5000;var s=tcp.GetStream();
   if(mode=="http"||mode=="version_http"){
    string host=mode=="http"?"level3.blizzard.com":"us.version.battle.net:1119";Send(s,Encoding.ASCII.GetBytes("GET /g15-fixture HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"));string h=Header(s);http200=h.StartsWith("HTTP/1.1 200 ");result=http200?"fixture_http200":"closed_or_refused";
   }else{
    if(mode=="connect"||mode=="connect_paused"){
     Send(s,Encoding.ASCII.GetBytes("CONNECT level3.blizzard.com:443 HTTP/1.1\r\nHost: level3.blizzard.com:443\r\n\r\n"));connect200=Header(s).StartsWith("HTTP/1.1 200 ");
     if(!connect200){Console.WriteLine(new JavaScriptSerializer().Serialize(new{http200=false,connect200=false,result=result}));return 0;}
     if(mode=="connect_paused"){File.WriteAllText(ready+".paused","ready");Wait(go+".continue");}
    }
    Send(s,Hello());int n=s.ReadByte();result=n==21?"fixture_tls_marker":"closed_or_refused";
   }
  }}catch{result="closed_or_refused";}
  Console.WriteLine(new JavaScriptSerializer().Serialize(new{http200=http200,connect200=connect200,result=result}));return 0;
 }catch{return 3;}}
}
