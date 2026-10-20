using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text.RegularExpressions;
namespace StopSurvey {
 public static class Core {
  public const string WowHash="1c51e68c00e7183c2c187606d2c443c27252a629406454de4afec336e8c5753a",LoaderHash="c0a3c393db5cee834387e4f151fb97b109370330a0ed02310f597cad999b6b0c";
  public const string Capture=".echo WGS_BEGIN_01; .lastevent; r rip; lm a @rip; .echo WGS_END_01";
  public const string Boot="sxn ld\r\n.echo WGS_READY_01\r\ng\r\n";
  public static string Sha(string p){using(var f=File.OpenRead(p))using(var h=SHA256.Create())return BitConverter.ToString(h.ComputeHash(f)).Replace("-","").ToLowerInvariant();}
  public static string Quote(string s){var b=new StringBuilder("\"");int n=0;foreach(char c in s){if(c=='\\'){n++;continue;}if(c=='\"'){b.Append('\\',2*n+1);b.Append(c);n=0;continue;}b.Append('\\',n);n=0;b.Append(c);}return b.Append('\\',2*n).Append('"').ToString();}
  static bool Hex(string s,out ulong v){return UInt64.TryParse(s.Replace("`",""),System.Globalization.NumberStyles.HexNumber,System.Globalization.CultureInfo.InvariantCulture,out v);}
  public static Dictionary<string,object> Parse(string text){
   bool ready=false,inside=false,complete=false;var block=new StringBuilder();string last=null;
   using(var r=new StringReader(text)){string l;while((l=r.ReadLine())!=null){string t=l.Trim();if(t=="WGS_READY_01")ready=true;if(t=="WGS_BEGIN_01"){inside=true;block.Length=0;continue;}if(t=="WGS_END_01"){if(inside){last=block.ToString();complete=true;}inside=false;continue;}if(inside&&block.Length<262144)block.AppendLine(l);}}
   string code=null,chance=null,module=null,rva=null;bool matched=false;ulong rip=0;bool haveRip=false;
   if(complete){var rm=Regex.Match(last,@"(?im)^\s*rip=([0-9a-f`]{8,17})\s*$");if(rm.Success)haveRip=Hex(rm.Groups[1].Value,out rip);
    var em=Regex.Match(last,@"(?im)^\s*Last event:.*?\bcode\s+([0-9a-f]{8})\s+\((first|second) chance\)");if(em.Success){code=em.Groups[1].Value.ToUpperInvariant();chance=em.Groups[2].Value.ToLowerInvariant();}
    foreach(Match m in Regex.Matches(last,@"(?im)^\s*([0-9a-f`]{8,17})\s+([0-9a-f`]{8,17})\s+([a-z0-9_]{1,64})(?:\s|$)")){ulong lo,hi;if(haveRip&&Hex(m.Groups[1].Value,out lo)&&Hex(m.Groups[2].Value,out hi)&&lo<=rip&&rip<hi){string name=m.Groups[3].Value.ToLowerInvariant();module=Array.IndexOf(new string[]{"wow","wow_loader","ntdll","kernelbase","kernel32"},name)>=0?name:"other_module";rva=(rip-lo).ToString("x");matched=true;break;}}
   }
   return new Dictionary<string,object>{{"ready_marker",ready},{"complete_stop_block",complete},{"newer_incomplete_block",inside},{"exception_code_hex",code},{"exception_chance",chance},{"rip_parsed",haveRip},{"module_range_matched",matched},{"module_category",module},{"module_relative_rip_hex",rva},{"matches_previous_loader_stop_rva",module=="wow_loader"&&rva=="1e4f20c"}};
  }
  public static int Tests(){int n=0;Action<bool> ok=delegate(bool b){n++;if(!b)throw new Exception("test_"+n);};
   string body="Last event: 100.200: Break instruction exception - code 80000003 (first chance)\nrip=00007ffd37d7f20c\n00007ffd35f30000 00007ffd39000000 wow_loader (deferred)\n";
   string good="WGS_READY_01\nWGS_BEGIN_01\n"+body+"WGS_END_01\n";var p=Parse(good);
   ok((bool)p["ready_marker"]);ok((bool)p["complete_stop_block"]);ok((bool)p["rip_parsed"]);ok((bool)p["module_range_matched"]);ok((string)p["exception_code_hex"]=="80000003");ok((string)p["exception_chance"]=="first");ok((string)p["module_category"]=="wow_loader");ok((string)p["module_relative_rip_hex"]=="1e4f20c");ok((bool)p["matches_previous_loader_stop_rva"]);
   ok(!(bool)Parse(".echo WGS_READY_01\n")["ready_marker"]);ok(!(bool)Parse("WGS_BEGIN_01\n"+body)["complete_stop_block"]);ok(!(bool)Parse("0:000> "+Capture)["complete_stop_block"]);
   ok((bool)Parse(good+"WGS_BEGIN_01\n")["newer_incomplete_block"]);
   ok(!(bool)Parse(good.Replace("rip=00007ffd37d7f20c","rip=0000000000000001"))["module_range_matched"]);
   ok((string)Parse(good.Replace("wow_loader (", "private_name ("))["module_category"]=="other_module");
   ok((string)Parse(good.Replace("first chance","second chance"))["exception_chance"]=="second");
   ok(!(bool)Parse(good+"WGS_BEGIN_01\nWGS_END_01\n")["rip_parsed"]);
   ok(Quote("x\\")=="\"x\\\\\"");ok(Quote("a\"b")=="\"a\\\"b\"");ok(Quote(@"C:\has space\Wow.exe")=="\"C:\\has space\\Wow.exe\"");
   ok(!Boot.Contains("bu ")&&!Boot.Contains("bp ")&&!Boot.Contains("gN")&&!Boot.Contains("gh")&&!Boot.Contains("sxe"));ok(!Capture.Contains("; g")&&!Capture.Contains(".dump")&&!Capture.Contains("kv"));
   return n;
  }
 }
}
