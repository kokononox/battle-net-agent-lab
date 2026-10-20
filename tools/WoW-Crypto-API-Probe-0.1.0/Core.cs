using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
namespace WowCryptoProbe {
 public static class Core {
  public const string Hash="1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a";
  public const int MaxRead=4*1024*1024;
  public static readonly string[] Markers={"WCP_READY_01","WCP_SCAN_01","WCP_SSPI_01","WCP_SSLWRITE_01","WCP_SSLWRITEEX_01","WCP_CONTROL_01"};
  public static string Sha(string p){using(var f=File.OpenRead(p))using(var s=SHA256.Create())return BitConverter.ToString(s.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
  public static Dictionary<string,bool> Parse(string text){
   var d=new Dictionary<string,bool>();foreach(string m in Markers)d[m]=false;
   using(var r=new StringReader(text)){string line;while((line=r.ReadLine())!=null){string s=line.Trim();foreach(string m in Markers)if(s==m)d[m]=true;}}
   return d;
  }
  public static string Hit(int reg,string marker){return ".if (@$t"+reg+" == 0) { .echo "+marker+"; r @$t"+reg+"=1; }; gc";}
  public static string Arm(){return
   ".if (@$t0 == 0) { bu /1 sspicli!EncryptMessage \""+Hit(0,"WCP_SSPI_01")+"\"; bu /1 secur32!EncryptMessage \""+Hit(0,"WCP_SSPI_01")+"\"; }\r\n"+
   ".if (@$t1 == 0) { bm /1 *!SSL_write \""+Hit(1,"WCP_SSLWRITE_01")+"\"; }\r\n"+
   ".if (@$t2 == 0) { bm /1 *!SSL_write_ex \""+Hit(2,"WCP_SSLWRITEEX_01")+"\"; }\r\n"+
   ".echo WCP_SCAN_01\r\ng\r\n";}
  public static string ControlArm(){return "bu /1 kernelbase!GetCurrentProcessId \".echo WCP_CONTROL_01; gc\"\r\n"+
   "bu /1 kernel32!GetCurrentProcessId \".echo WCP_CONTROL_01; gc\"\r\n"+Arm();}
  public static bool ScriptPathOK(string s){if(String.IsNullOrEmpty(s))return false;foreach(char c in s)if(c>126 || c<33 || "\";<>|&".IndexOf(c)>=0)return false;return true;}
  public static string Boot(string arm){if(!ScriptPathOK(arm))throw new ArgumentException("script_path_unsupported");return
   "r @$t0=0\r\nr @$t1=0\r\nr @$t2=0\r\n"+
   "sxe -c \"$$><"+arm+"\" ld\r\n"+
   ".echo WCP_READY_01\r\n$$><"+arm+"\r\n";}
  // Windows CRT argv quoting; never run through cmd.exe or a shell.
  public static string Quote(string value){var b=new StringBuilder("\"");int slashes=0;foreach(char c in value){if(c=='\\'){slashes++;continue;}if(c=='\"'){b.Append('\\',slashes*2+1);b.Append(c);slashes=0;continue;}b.Append('\\',slashes);slashes=0;b.Append(c);}b.Append('\\',slashes*2);return b.Append('"').ToString();}
  public static int Tests(){int n=0;Action<bool> ok=delegate(bool b){n++;if(!b)throw new Exception("test_"+n);};
   ok(Parse("WCP_SSPI_01\r\n")["WCP_SSPI_01"]);
   ok(!Parse(".echo WCP_SSPI_01")["WCP_SSPI_01"]);
   ok(!Parse("bu x \".echo WCP_SSLWRITE_01;gc\"")["WCP_SSLWRITE_01"]);
   ok(!Parse("path WCP_READY_01")["WCP_READY_01"]);
   ok(!Parse("WCP_READY_01 suffix")["WCP_READY_01"]);
   ok(Parse("  WCP_READY_01  \n")["WCP_READY_01"]);
   ok(!Parse("")["WCP_READY_01"]);
   ok(ScriptPathOK(@"C:\Users\SAMU~1\AppData\Local\Temp\wcp\arm.txt"));
   ok(!ScriptPathOK(@"C:\User Name\arm.txt"));ok(!ScriptPathOK("C:\\a;g"));ok(!ScriptPathOK("C:\\آزمون\\a"));
   ok(Boot(@"C:\wcp\arm.txt").Contains("sxe -c \"$$><C:\\wcp\\arm.txt\" ld"));
   ok(Arm().Contains("bm /1 *!SSL_write_ex"));ok(Arm().Contains("bu /1 sspicli!EncryptMessage"));
   ok(!Arm().Contains("db ")&&!Arm().Contains("du ")&&!Arm().Contains(".dump"));
   ok(Quote(@"C:\has space\x.exe")=="\"C:\\has space\\x.exe\"");
   ok(Quote("a\"b")=="\"a\\\"b\"");ok(Quote("x\\")=="\"x\\\\\"");
   ok(ControlArm().Contains("WCP_CONTROL_01"));ok(Parse("WCP_CONTROL_01")["WCP_CONTROL_01"]);
   return n;
  }
 }
}
