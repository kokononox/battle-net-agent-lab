using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
public class TlsFixture {
 static byte[] request=Encoding.ASCII.GetBytes("G62-REQUEST-PLAINTEXT"),response=Encoding.ASCII.GetBytes("G62-RESPONSE-PLAINTEXT");
 static bool ReadExact(Stream s,byte[] expected){byte[] b=new byte[expected.Length];int n=0;while(n<b.Length){int k=s.Read(b,n,b.Length-n);if(k<=0)return false;n+=k;}return Encoding.ASCII.GetString(b)==Encoding.ASCII.GetString(expected);}
 public static int Main(string[] args){
  if(args.Length!=2)return 2;
  var store=new X509Store(StoreName.My,StoreLocation.CurrentUser);store.Open(OpenFlags.ReadOnly);
  var found=store.Certificates.Find(X509FindType.FindByThumbprint,args[0],false);if(found.Count!=1)return 3;var cert=found[0];store.Close();
  var listener=new TcpListener(IPAddress.Loopback,0);listener.Start();int port=((IPEndPoint)listener.LocalEndpoint).Port;bool serverOK=false;Exception serverError=null;
  var thread=new Thread(delegate(){try{using(var tcp=listener.AcceptTcpClient()){tcp.ReceiveTimeout=10000;tcp.SendTimeout=10000;using(var ssl=new SslStream(tcp.GetStream(),false)){ssl.ReadTimeout=10000;ssl.WriteTimeout=10000;ssl.AuthenticateAsServer(cert,false,SslProtocols.Tls12,false);serverOK=ReadExact(ssl,request);if(serverOK){ssl.Write(response,0,response.Length);ssl.Flush();}}}}catch(Exception e){serverError=e;}});
  thread.IsBackground=true;thread.Start();
  try{bool clientOK=false;using(var tcp=new TcpClient()){tcp.Connect(IPAddress.Loopback,port);using(var ssl=new SslStream(tcp.GetStream(),false)){ssl.ReadTimeout=10000;ssl.WriteTimeout=10000;
   // Standard validation: no custom validation callback or certificate-error bypass.
   ssl.AuthenticateAsClient("localhost",null,SslProtocols.Tls12,false);if(!ssl.IsEncrypted||!ssl.IsAuthenticated)return 4;
   ssl.Write(request,0,request.Length);ssl.Flush();clientOK=ReadExact(ssl,response);
  }}if(!thread.Join(12000))return 5;if(clientOK&&serverOK&&serverError==null){using(var f=new FileStream(args[1],FileMode.CreateNew)){byte[] mark=Encoding.ASCII.GetBytes("G62_TLS_BOTH_ENDPOINTS_EXACT");f.Write(mark,0,mark.Length);}return 0;}return 6;}catch{return 7;}finally{listener.Stop();}
 }
}
