// Fixed canary: us.version.battle.net:1119/agent/versions only. No installer or login.
using System;using System.IO;using System.Text;using System.Threading;using System.Diagnostics;using System.Runtime.InteropServices;using System.ServiceProcess;using System.Net;using System.Net.Sockets;using System.Web.Script.Serialization;
public class ExternalProbe {
 public class Config {public string root,token,service_name,task_name,watchdog_name,job_name,exe,service_command,task_arguments,source_commit,run_id,rule_name,canary_ip;public long expires_ticks;}
 [StructLayout(LayoutKind.Sequential)]struct Limit{public long ProcessTime,JobTime;public uint Flags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
 [StructLayout(LayoutKind.Sequential)]struct Io{public ulong A,B,C,D,E,F;}
 [StructLayout(LayoutKind.Sequential)]struct Extended{public Limit Basic;public Io Io;public UIntPtr A,B,C,D;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenJobObject(uint access,bool inherit,string name);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetInformationJobObject(IntPtr h,int kind,ref Extended data,uint size);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool IsProcessInJob(IntPtr p,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long created,out long exited,out long kernel,out long user);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 static string Env(string n){return Environment.GetEnvironmentVariable(n)??"";}
 static bool Hosted(){return Environment.OSVersion.Platform==PlatformID.Win32NT&&Env("GITHUB_ACTIONS")=="true"&&Env("RUNNER_ENVIRONMENT")=="github-hosted"&&Env("RUNNER_OS")=="Windows"&&Env("GITHUB_REF")=="refs/heads/research/battlenet-minimal-install-isolation-2026-10-25"&&Env("GITHUB_EVENT_NAME")=="push"&&Env("GITHUB_RUN_ATTEMPT")=="1"&&Env("BNET_EXTERNAL_G11")=="lab: approved external-components qualification G11 20261025";}
 static Config Load(string path,string token){
  string prefix=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"BNetExternalG11")+"\\";path=Path.GetFullPath(path);
  if(!path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)||Path.GetFileName(path)!="config.json"||new FileInfo(path).Length>16384)throw new Exception();
  for(DirectoryInfo d=new FileInfo(path).Directory;d!=null&&d.FullName.StartsWith(prefix,StringComparison.OrdinalIgnoreCase);d=d.Parent)if((d.Attributes&FileAttributes.ReparsePoint)!=0)throw new Exception();
  if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new Exception();
  Config c=Json.Deserialize<Config>(File.ReadAllText(path));
  string self=Process.GetCurrentProcess().MainModule.FileName;
  if(c.token!=token||!String.Equals(Path.GetDirectoryName(path),Path.GetFullPath(c.root),StringComparison.OrdinalIgnoreCase)||!String.Equals(Path.GetFullPath(c.exe),Path.GetFullPath(self),StringComparison.OrdinalIgnoreCase)||c.expires_ticks<=DateTime.UtcNow.Ticks||c.expires_ticks>DateTime.UtcNow.AddMinutes(10).Ticks||!c.service_name.StartsWith("BNetLabG11_")||!c.task_name.StartsWith("BNetLabG11_"))throw new Exception();
  return c;
 }
 static void Ready(Config c,string mode,bool? member){
  var p=Process.GetCurrentProcess();long created,e,k,u;if(!GetProcessTimes(p.Handle,out created,out e,out k,out u))throw new Exception();
  string text=Json.Serialize(new {mode=mode,pid=p.Id,created=created,job_member=member});string path=Path.Combine(c.root,mode+".json");File.WriteAllText(path+".tmp",text,new UTF8Encoding(false));File.Move(path+".tmp",path);
 }
 static bool Membership(Config c){IntPtr job=OpenJobObject(4,false,c.job_name);if(job==IntPtr.Zero)throw new Exception();try{bool member;if(!IsProcessInJob(Process.GetCurrentProcess().Handle,job,out member))throw new Exception();return member;}finally{CloseHandle(job);}}
 class ProbeService:ServiceBase{
  Config C;Timer timer;public ProbeService(Config c){C=c;ServiceName=c.service_name;CanStop=true;AutoLog=false;}
  protected override void OnStart(string[] args){Ready(C,"service",Membership(C));timer=new Timer(delegate(object ignored){try{Stop();}catch{}},null,75000,Timeout.Infinite);}
  protected override void OnStop(){if(timer!=null)timer.Dispose();}
 }
 static int Canary(Config c){
  bool connected=false,http200=false;string error=null;
  try{
   IPAddress ip;if(!IPAddress.TryParse(c.canary_ip,out ip)||ip.AddressFamily!=AddressFamily.InterNetwork||IPAddress.IsLoopback(ip))throw new Exception();
   using(var tcp=new TcpClient(AddressFamily.InterNetwork)){
    var pending=tcp.ConnectAsync(ip,1119);if(!pending.Wait(3000)){error="connect_timeout";}else{
     connected=tcp.Connected;if(connected){
      tcp.ReceiveTimeout=3000;tcp.SendTimeout=3000;var stream=tcp.GetStream();byte[] request=Encoding.ASCII.GetBytes("GET /agent/versions HTTP/1.1\r\nHost: us.version.battle.net:1119\r\nConnection: close\r\n\r\n");stream.Write(request,0,request.Length);
      byte[] buffer=new byte[128];int count=0;while(count<buffer.Length){int n=stream.Read(buffer,count,1);if(n==0)break;count+=n;if(count>=2&&buffer[count-2]==13&&buffer[count-1]==10)break;}
      string status=Encoding.ASCII.GetString(buffer,0,count);http200=status.StartsWith("HTTP/1.1 200 ")||status.StartsWith("HTTP/1.0 200 ");
     }
    }
   }
  }catch{error="socket_operation_failed";}
  Console.WriteLine(Json.Serialize(new{connected=connected,http200=http200,error_code=error}));return 0;
 }
 static int Main(string[] args){
  try{
   if(args.Length!=3)return 4;string mode=args[0];if(mode!="service"&&mode!="task"&&mode!="owner"&&mode!="canary")return 4;
   if((mode=="owner"||mode=="canary")&&!Hosted())return 4;Config c=Load(args[1],args[2]);if(mode=="canary")return Canary(c);
   if(mode=="owner"){
    IntPtr job=CreateJobObject(IntPtr.Zero,c.job_name);if(job==IntPtr.Zero)return 3;
    try{Extended limit=new Extended();limit.Basic.Flags=0x2000;if(!SetInformationJobObject(job,9,ref limit,(uint)Marshal.SizeOf(typeof(Extended))))return 3;Ready(c,"owner",null);Thread.Sleep(120000);return 0;}finally{CloseHandle(job);}
   }
   if(mode=="service"){ServiceBase.Run(new ProbeService(c));return 0;}
   Ready(c,"task",Membership(c));var sw=Stopwatch.StartNew();while(sw.ElapsedMilliseconds<75000&&!File.Exists(Path.Combine(c.root,"stop-task")))Thread.Sleep(100);return 0;
  }catch{return 3;}
 }
}
