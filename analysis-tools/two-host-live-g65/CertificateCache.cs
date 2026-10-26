using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;
using System.Web.Script.Serialization;
public class CertificateCache {
 public static int Main(string[] args){
  if(args.Length!=3||(args[0]!="Online"&&args[0]!="Offline"))return 2;
  string mode=args[0],root=Path.GetFullPath(args[1]);IPAddress ip;
  if(!IPAddress.TryParse(args[2],out ip))return 3;
  var report=new Dictionary<string,object>{{"mode",mode},{"host","us.version.battle.net"},{"standard_certificate_validation",true},{"check_certificate_revocation",true},{"validation_callback_used",false},{"certificate_policy_bypass_used",false},{"successful",false},{"TLS_application_request_sent",false}};
  int code=1;
  try{
   X509Certificate2 leaf;
   if(mode=="Online"){
    using(var tcp=new TcpClient(ip.AddressFamily)){
     var connect=tcp.ConnectAsync(ip,443);if(!connect.Wait(10000))throw new TimeoutException();connect.GetAwaiter().GetResult();
     using(var ssl=new SslStream(tcp.GetStream(),false)){
      var task=ssl.AuthenticateAsClientAsync("us.version.battle.net",new X509CertificateCollection(),SslProtocols.Tls12,true);
      if(!task.Wait(20000))throw new TimeoutException();task.GetAwaiter().GetResult();
      report["TLS_authenticated"]=ssl.IsAuthenticated&&ssl.IsEncrypted;
      if(!ssl.IsAuthenticated||!ssl.IsEncrypted)throw new AuthenticationException();
      leaf=new X509Certificate2(ssl.RemoteCertificate);File.WriteAllBytes(Path.Combine(root,"tls-leaf.PRIVATE.cer"),leaf.RawData);
     }
    }
   }else{leaf=new X509Certificate2(File.ReadAllBytes(Path.Combine(root,"tls-leaf.PRIVATE.cer")));}
   using(var chain=new X509Chain()){
    chain.ChainPolicy.RevocationMode=mode=="Online"?X509RevocationMode.Online:X509RevocationMode.Offline;
    chain.ChainPolicy.RevocationFlag=X509RevocationFlag.ExcludeRoot;
    chain.ChainPolicy.VerificationFlags=X509VerificationFlags.NoFlag;
    chain.ChainPolicy.UrlRetrievalTimeout=TimeSpan.FromSeconds(mode=="Online"?10:2);
    chain.ChainPolicy.VerificationTime=DateTime.Now;
    if(mode=="Offline")foreach(string file in Directory.GetFiles(root,"tls-chain-*.PRIVATE.cer"))chain.ChainPolicy.ExtraStore.Add(new X509Certificate2(File.ReadAllBytes(file)));
    bool valid=chain.Build(leaf);var statuses=new List<string>();foreach(var s in chain.ChainStatus)statuses.Add(s.Status.ToString());
    report["chain_valid"]=valid;report["chain_status_flags"]=statuses;report["chain_elements"]=chain.ChainElements.Count;
    report["revocation_mode"]=chain.ChainPolicy.RevocationMode.ToString();report["verification_flags"]=chain.ChainPolicy.VerificationFlags.ToString();
    report["leaf_valid_at_probe_time"]=DateTime.Now>=leaf.NotBefore&&DateTime.Now<=leaf.NotAfter;
    if(mode=="Online"&&valid){for(int i=0;i<chain.ChainElements.Count;i++)File.WriteAllBytes(Path.Combine(root,"tls-chain-"+i+".PRIVATE.cer"),chain.ChainElements[i].Certificate.RawData);}
    report["successful"]=valid;code=valid?0:1;
   }
  }catch(Exception e){
   while(e is AggregateException&&e.InnerException!=null)e=e.InnerException;
   report["error_type"]=e.GetType().Name;report["hresult"]="0x"+unchecked((uint)e.HResult).ToString("x8");
   if(e.InnerException!=null){report["inner_error_type"]=e.InnerException.GetType().Name;report["inner_hresult"]="0x"+unchecked((uint)e.InnerException.HResult).ToString("x8");}
  }
  Console.WriteLine(new JavaScriptSerializer().Serialize(report));return code;
 }
}
