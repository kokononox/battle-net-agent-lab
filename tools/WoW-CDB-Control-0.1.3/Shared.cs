using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
namespace CdbControl {
 public static class Shared {
  public const int Size=64,Magic=0x57434350,Version=1;
  // CONTEXT.Rip is at 0xf8 in the Windows AMD64 CONTEXT layout; this fixture is x64 only.
  public const int RipOffset=248;
  public static int IpCase(ulong rip,ulong expected){return rip==expected?1:rip==expected+1?2:3;}
  public static bool Allowed(uint code,ulong address,ulong expected,byte opcode,int count,bool armed){return armed&&count==0&&code==0x80000003&&address==expected&&opcode==0xcc;}
  public static bool ProofOK(int[] p){return p!=null&&p.Length==16&&p[0]==Magic&&p[1]==Version&&p[2]==9&&p[3]==1&&unchecked((uint)p[4])==0x80000003&&p[5]==1&&(p[6]==1||p[6]==2)&&p[7]==(p[6]==1?1:0)&&p[8]==1&&p[9]==0&&p[10]==0;}
  public static string Commands(){return "sxn ld\r\n.echo WCC_READY_01\r\nbu /1 kernelbase!GetCurrentProcessId \".echo WCC_API_01; gh\"\r\n"+
   "bu /1 kernel32!GetCurrentProcessId \".echo WCC_API_01; gh\"\r\n"+
   "bu /1 ntdll!DbgBreakPoint \".echo WCC_DISPATCH_01; gN\"\r\ng\r\n";}
  public static Dictionary<string,bool> Markers(string text){var d=new Dictionary<string,bool>{{"WCC_READY_01",false},{"WCC_API_01",false},{"WCC_DISPATCH_01",false}};using(var r=new StringReader(text)){string line;while((line=r.ReadLine())!=null){string s=line.Trim();if(d.ContainsKey(s))d[s]=true;}}return d;}
  public static string Quote(string v){var b=new StringBuilder("\"");int n=0;foreach(char c in v){if(c=='\\'){n++;continue;}b.Append('\\',c=='"'?2*n+1:n);b.Append(c);n=0;}b.Append('\\',2*n);return b.Append('"').ToString();}
  public static int Tests(){int n=0;Action<bool> ok=delegate(bool b){n++;if(!b)throw new Exception("test_"+n);};
   ok(IpCase(100,100)==1);ok(IpCase(101,100)==2);ok(IpCase(102,100)==3);
   ok(Allowed(0x80000003,100,100,0xcc,0,true));ok(!Allowed(0x80000004,100,100,0xcc,0,true));
   ok(!Allowed(0x80000003,101,100,0xcc,0,true));ok(!Allowed(0x80000003,100,100,0x90,0,true));
   ok(!Allowed(0x80000003,100,100,0xcc,1,true));ok(!Allowed(0x80000003,100,100,0xcc,0,false));
   var p=new int[16];p[0]=Magic;p[1]=Version;p[2]=9;p[3]=1;p[4]=unchecked((int)0x80000003);p[5]=1;p[6]=1;p[7]=1;p[8]=1;p[9]=0;
   ok(ProofOK(p));p[6]=2;p[7]=0;ok(ProofOK(p));p[3]=2;ok(!ProofOK(p));p[3]=1;p[8]=0;ok(!ProofOK(p));
   p[8]=1;p[6]=1;p[7]=0;ok(!ProofOK(p));p[7]=1;p[10]=31;ok(!ProofOK(p));
   ok(!ProofOK(null));ok(!ProofOK(new int[4]));ok(!ProofOK(new int[16]));
   ok(Markers("WCC_API_01\n")["WCC_API_01"]);ok(!Markers(".echo WCC_API_01")["WCC_API_01"]);
   ok(!Markers("WCC_API_01 suffix")["WCC_API_01"]);ok(!Markers("bu x \".echo WCC_DISPATCH_01;gN\"")["WCC_DISPATCH_01"]);
   ok(!Commands().Contains("wow_loader"));ok(!Commands().Contains("sxd bpe"));ok(!Commands().Contains("$$><"));
   ok(Quote(@"C:\has space\x.exe")=="\"C:\\has space\\x.exe\"");ok(Quote("x\\")=="\"x\\\\\"");return n;
  }
 }
}
