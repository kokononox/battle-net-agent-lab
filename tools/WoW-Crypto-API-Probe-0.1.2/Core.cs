using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
namespace WowCryptoProbe {
 public static class Core {
  public const string LoaderHash="c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c";
  public const string Hash="1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a";
  public const int MaxRead=4*1024*1024;
  public static readonly string[] Markers={"WCP_READY_01","WCP_SCAN_01","WCP_SSPI_01","WCP_SSLWRITE_01","WCP_SSLWRITEEX_01","WCP_CONTROL_01","WCP_CONTROL_INT3_DISPATCH_01","WCP_LOADER_INT3_DISPATCH_01"};
  public static string Sha(string p){using(var f=File.OpenRead(p))using(var s=SHA256.Create())return BitConverter.ToString(s.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
  public static Dictionary<string,bool> Parse(string text){
   var d=new Dictionary<string,bool>();foreach(string m in Markers)d[m]=false;
   using(var r=new StringReader(text)){string line;while((line=r.ReadLine())!=null){string s=line.Trim();foreach(string m in Markers)if(s==m)d[m]=true;}}
   return d;
  }
  public static string Hit(int reg,string marker){return ".if (@$t"+reg+" == 0) { .echo "+marker+"; r @$t"+reg+"=1; }; gh";}
  public static string Arm(string module,uint rva){
   if(!ModuleOK(module)||rva==0)throw new ArgumentException("invalid_sspi_binding");return
   "bu /1 "+module+"+0x"+rva.ToString("x")+" \""+Hit(0,"WCP_SSPI_01")+"\"\r\n"+
   "bm /1 *!SSL_write \""+Hit(1,"WCP_SSLWRITE_01")+"\"\r\n"+
   "bm /1 *!SSL_write_ex \""+Hit(2,"WCP_SSLWRITEEX_01")+"\"\r\n"+
   ".echo WCP_SCAN_01\r\ng\r\n";
  }
  public static string ControlArm(){return "bu /1 kernelbase!GetCurrentProcessId \".echo WCP_CONTROL_01; gh\"\r\n"+
   "bu /1 kernel32!GetCurrentProcessId \".echo WCP_CONTROL_01; gh\"\r\n"+
   "bu /1 ntdll!DbgBreakPoint \".echo WCP_CONTROL_INT3_DISPATCH_01; gN\"\r\n"+
   ".echo WCP_SCAN_01\r\ng\r\n";}
  public static bool ModuleOK(string s){if(String.IsNullOrEmpty(s)||s.Length>96)return false;foreach(char c in s)if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'))return false;return true;}
  public static string Boot(bool control,string[] modules,string sspiModule,uint sspiRva){
   string pre="r @$t0=0\r\nr @$t1=0\r\nr @$t2=0\r\nsxn ld\r\n.echo WCP_READY_01\r\n";
   if(control)return pre+ControlArm();
   var d=new StringBuilder(pre);
   foreach(string m in modules){if(!ModuleOK(m))throw new ArgumentException("unsafe_module_name");
    d.Append("bu /1 "+m+"!SSL_write \""+Hit(1,"WCP_SSLWRITE_01")+"\"\r\n");
    d.Append("bu /1 "+m+"!SSL_write_ex \""+Hit(2,"WCP_SSLWRITEEX_01")+"\"\r\n");}
   d.Append("bu /1 wow_loader+0x1e4f20c \".echo WCP_LOADER_INT3_DISPATCH_01; gN\"\r\n");
   return d.ToString()+Arm(sspiModule,sspiRva);
  }
  // Windows CRT argv quoting; never run through cmd.exe or a shell.
  public static string Quote(string value){var b=new StringBuilder("\"");int slashes=0;foreach(char c in value){if(c=='\\'){slashes++;continue;}if(c=='\"'){b.Append('\\',slashes*2+1);b.Append(c);slashes=0;continue;}b.Append('\\',slashes);slashes=0;b.Append(c);}b.Append('\\',slashes*2);return b.Append('"').ToString();}
  public static int Tests(){int n=0;Action<bool> ok=delegate(bool b){n++;if(!b)throw new Exception("test_"+n);};
   ok(Parse("WCP_SSPI_01\r\n")["WCP_SSPI_01"]);
   ok(!Parse(".echo WCP_SSPI_01")["WCP_SSPI_01"]);
   ok(!Parse("bu x \".echo WCP_SSLWRITE_01;gh\"")["WCP_SSLWRITE_01"]);
   ok(!Parse("path WCP_READY_01")["WCP_READY_01"]);ok(!Parse("WCP_READY_01 suffix")["WCP_READY_01"]);
   ok(Parse("  WCP_READY_01  \n")["WCP_READY_01"]);ok(!Parse("")["WCP_READY_01"]);
   ok(ModuleOK("libssl_3_x64"));ok(!ModuleOK("name with space"));ok(!ModuleOK("name;g"));ok(!ModuleOK("آزمون"));
   string ctl=Boot(true,new string[0],"sspicli",0x1234),game=Boot(false,new string[]{"libssl_3_x64"},"sspicli",0x1234);
   ok(!ctl.Contains("$$><"));ok(!game.Contains("sxe -c"));ok(!game.Contains("sxd bpe"));ok(!game.Contains("sxi"));
   ok(!ctl.Contains("SSL_write"));ok(ctl.Contains("WCP_CONTROL_INT3_DISPATCH_01; gN"));
   ok(game.Contains("bu /1 wow_loader+0x1e4f20c \".echo WCP_LOADER_INT3_DISPATCH_01; gN\""));
   ok(game.Contains("bu /1 sspicli+0x1234"));ok(!game.Contains("!EncryptMessage"));
   ok(!game.Contains(".if (@$t0 == 0) { bu"));ok(!game.Contains("db ")&&!game.Contains("du ")&&!game.Contains(".dump"));
   ok(Hit(0,"WCP_SSPI_01").EndsWith("; gh"));
   ok(Quote(@"C:\has space\x.exe")=="\"C:\\has space\\x.exe\"");
   ok(Quote("a\"b")=="\"a\\\"b\"");ok(Quote("x\\")=="\"x\\\\\"");
   bool threw=false;try{Boot(false,new string[]{"x;g"},"sspicli",1);}catch(ArgumentException){threw=true;}ok(threw);
   threw=false;try{Arm("x;g",1);}catch(ArgumentException){threw=true;}ok(threw);
   threw=false;try{Arm("sspicli",0);}catch(ArgumentException){threw=true;}ok(threw);
   ok(Parse("WCP_LOADER_INT3_DISPATCH_01\n")["WCP_LOADER_INT3_DISPATCH_01"]);
   return n;
  }
 }
}
