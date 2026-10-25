// One native Windows TLS handshake. Online revocation stays on, no HTTP body or account.
using System;using System.IO;using System.Text;using System.Net;using System.Net.Sockets;using System.Net.Security;using System.Security.Authentication;using System.Security.Cryptography;using System.Security.Cryptography.X509Certificates;using System.Collections.Generic;using System.Web.Script.Serialization;using System.Diagnostics;using System.Threading.Tasks;
public static class CertificatePrep {
 static string Host="us.version.battle.net";static object Sync=new object();static JavaScriptSerializer J=new JavaScriptSerializer();static Dictionary<string,object> R;
 public static bool Accept(SslPolicyErrors errors,X509ChainStatusFlags[] flags,bool online){
  if(!online||errors!=SslPolicyErrors.None||flags==null)return false;
  foreach(var f in flags)if(f!=X509ChainStatusFlags.NoError)return false;
  return true;
 }
 static string Hex(int value){return "0x"+unchecked((uint)value).ToString("x8");}
 static string Kind(Exception e){if(e is AuthenticationException)return "AuthenticationException";if(e is IOException)return "IOException";if(e is SocketException)return "SocketException";if(e is TimeoutException)return "TimeoutException";return "other_exception";}
 static void Save(string root){string p=Path.Combine(root,"certificate-preparation-native.json"),t=p+".tmp";lock(Sync){File.WriteAllText(t,J.Serialize(R),new UTF8Encoding(false));if(File.Exists(p))File.Delete(p);File.Move(t,p);}}
 static bool Certificate(object sender,X509Certificate certificate,X509Chain chain,SslPolicyErrors errors){
  lock(Sync){
   R["callback_observed"]=true;R["ssl_policy_errors"]=(int)errors;var statuses=new List<object>();var flags=new List<X509ChainStatusFlags>();
   bool online=chain!=null&&chain.ChainPolicy.RevocationMode==X509RevocationMode.Online;
   R["chain_revocation_mode"]=chain==null?"unavailable":chain.ChainPolicy.RevocationMode.ToString();
   if(chain!=null){
    var endpoints=new HashSet<string>();
    foreach(X509ChainElement element in chain.ChainElements){foreach(X509Extension extension in element.Certificate.Extensions){
     if(extension.Oid.Value!="2.5.29.31"&&extension.Oid.Value!="1.3.6.1.5.5.7.1.1")continue;
     foreach(System.Text.RegularExpressions.Match match in System.Text.RegularExpressions.Regex.Matches(extension.Format(true),@"https?://[^\s<>""']+")){
      Uri uri;if(Uri.TryCreate(match.Value,UriKind.Absolute,out uri)&&uri.UserInfo==""&&uri.IsDefaultPort&&System.Text.RegularExpressions.Regex.IsMatch(uri.DnsSafeHost,@"^[a-zA-Z0-9.-]{1,253}$")&&endpoints.Count<24)endpoints.Add(uri.DnsSafeHost.ToLowerInvariant());
     }
    }}
    R["advertised_ca_hosts_not_fetch_log"]=new List<string>(endpoints);
    foreach(var s in chain.ChainStatus){flags.Add(s.Status);statuses.Add(new{flags=(int)s.Status,names=s.Status.ToString()});}R["chain_element_count"]=chain.ChainElements.Count;}
   R["chain_statuses"]=statuses;R["certificate_present"]=certificate!=null;
   if(certificate!=null){using(var sha=SHA256.Create())R["leaf_certificate_sha256"]=BitConverter.ToString(sha.ComputeHash(certificate.GetRawCertData())).Replace("-","").ToLowerInvariant();}
   bool accepted=certificate!=null&&Accept(errors,flags.ToArray(),online);R["callback_accepted"]=accepted;return accepted;
  }
 }
 public static int Run(string root){
  var watch=Stopwatch.StartNew();R=new Dictionary<string,object>{{"schema","certificate_preparation_native_v1"},{"host","us.version.battle.net"},{"client","dotnet_sslstream_schannel"},{"revocation_check_requested",true},{"cache_warming_requested",true},{"cache_cleared",false},{"preexisting_cache_state","not_measured"},{"callback_observed",false},{"callback_accepted",false},{"certificate_present",false},{"ssl_policy_errors",0},{"chain_revocation_mode","unavailable"},{"chain_element_count",0},{"chain_statuses",new object[0]},{"tls_authenticated",false},{"application_request_sent",false},{"status","started"},{"exception_codes",new object[0]}};
  Save(root);
  try{
   using(var tcp=new TcpClient(AddressFamily.InterNetwork)){
    if(!tcp.ConnectAsync(Host,443).Wait(5000))throw new TimeoutException();
    using(var ssl=new SslStream(tcp.GetStream(),false,Certificate)){
     // These overload arguments are never derived from remote data.
     Task auth=ssl.AuthenticateAsClientAsync(Host,new X509CertificateCollection(),SslProtocols.None,true);
     if(!auth.Wait(45000)){lock(Sync){R["status"]="authentication_timeout";}ssl.Close();}
     else{lock(Sync){R["tls_authenticated"]=ssl.IsAuthenticated&&ssl.IsEncrypted&&ssl.CheckCertRevocationStatus&&(bool)R["callback_accepted"];R["tls_protocol"]=ssl.SslProtocol.ToString();R["status"]=(bool)R["tls_authenticated"]?"authenticated":"authentication_not_verified";}}
    }
   }
  }catch(Exception ex){
   var agg=ex as AggregateException;if(agg!=null)ex=agg.GetBaseException();var codes=new List<object>();int depth=0;
   for(var e=ex;e!=null&&depth++<4;e=e.InnerException){var win=e as System.ComponentModel.Win32Exception;codes.Add(new{type=Kind(e),hresult=Hex(e.HResult),native_code=win==null?null:Hex(win.NativeErrorCode)});}
   lock(Sync){R["status"]="authentication_failed";R["exception_codes"]=codes;}
  }
  lock(Sync){R["elapsed_ms"]=(int)Math.Min(watch.ElapsedMilliseconds,120000);}
  Save(root);return (bool)R["tls_authenticated"]?0:3;
 }
 public static int Main(string[] args){
  try{
   if(args.Length==1&&args[0]=="selftest")return SelfTest();
   if(args.Length!=1||Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true"||Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted"||Environment.GetEnvironmentVariable("BNET_ONLINE_G31")!="lab: approved ambient no Setup control G31 20261025")return 4;
   string root=Path.GetFullPath(args[0]);string allowed=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"BNetOnlineG31")+Path.DirectorySeparatorChar;
   if(!root.StartsWith(allowed,StringComparison.OrdinalIgnoreCase)||!Directory.Exists(root)||File.Exists(Path.Combine(root,"before.wfw")))return 4;
   return Run(root);
  }catch{return 5;}
 }
 public static int SelfTest(){
  int n=0;
  if(!Accept(SslPolicyErrors.None,new X509ChainStatusFlags[0],true))throw new Exception("control_policy_rejects_clean_chain");n++;
  foreach(SslPolicyErrors e in new[]{SslPolicyErrors.RemoteCertificateNameMismatch,SslPolicyErrors.RemoteCertificateChainErrors,SslPolicyErrors.RemoteCertificateNotAvailable}){if(Accept(e,new X509ChainStatusFlags[0],true))throw new Exception("control_policy_errors_bypassed");n++;}
  foreach(X509ChainStatusFlags f in new[]{X509ChainStatusFlags.Revoked,X509ChainStatusFlags.OfflineRevocation,X509ChainStatusFlags.RevocationStatusUnknown,X509ChainStatusFlags.UntrustedRoot,X509ChainStatusFlags.NotTimeValid}){if(Accept(SslPolicyErrors.None,new[]{f},true))throw new Exception("control_chain_errors_bypassed");n++;}
  if(Accept(SslPolicyErrors.None,new X509ChainStatusFlags[0],false))throw new Exception("control_revocation_disabled");n++;
  if(Accept(SslPolicyErrors.None,null,true))throw new Exception("control_null_chain_accepted");n++;
  Console.WriteLine(J.Serialize(new{schema="native_tls_policy_tests_v1",all_passed=true,case_count=n}));return 0;
 }
}
