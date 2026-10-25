// Fixed canary: us.version.battle.net:1119/agent/versions only. No installer or login.
using System;using System.IO;using System.Text;using System.Threading;using System.Diagnostics;using System.Runtime.InteropServices;using System.ServiceProcess;using System.Net;using System.Net.Sockets;using System.Web.Script.Serialization;
public class ExternalProbe {
 public class Config {public string outside_exe,outside_receipt,root,token,service_name,task_name,watchdog_name,job_name,exe,service_command,task_arguments,source_commit,run_id,rule_name,canary_ip,mutex_name,supervisor_script,proxy_exe,watchdog_script;public long expires_ticks;public bool pause_owner_receipt;}
 [StructLayout(LayoutKind.Sequential)]struct Limit{public long ProcessTime,JobTime;public uint Flags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
 [StructLayout(LayoutKind.Sequential)]struct Io{public ulong A,B,C,D,E,F;}
 [StructLayout(LayoutKind.Sequential)]struct Extended{public Limit Basic;public Io Io;public UIntPtr A,B,C,D;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenJobObject(uint access,bool inherit,string name);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetInformationJobObject(IntPtr h,int kind,ref Extended data,uint size);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool IsProcessInJob(IntPtr p,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr h,out long created,out long exited,out long kernel,out long user);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct Startup{public uint Size;public string Reserved,Desktop,Title;public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;public ushort Show,ReservedSize;public IntPtr ReservedBytes,StdIn,StdOut,StdErr;}
 [StructLayout(LayoutKind.Sequential)]struct ProcessInfo{public IntPtr Process,Thread;public uint Pid,Tid;}
 [StructLayout(LayoutKind.Sequential)]struct Accounting{public long UserTime,KernelTime,PeriodUser,PeriodKernel;public uint Faults,Total,Active,Terminated;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool CreateProcess(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string cwd,ref Startup startup,out ProcessInfo info);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)]static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool TerminateProcess(IntPtr process,uint code);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)]static extern bool QueryRaw(IntPtr job,int kind,IntPtr data,uint size,IntPtr length);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting data,uint size,IntPtr length);
 public class Member{public int pid;public long created;public string image;public string kind;}
 public static IntPtr OpenOwnedJob(string name){return OpenJobObject(12,false,name);}
 public static void CloseOwnedJob(IntPtr h){if(h!=IntPtr.Zero)CloseHandle(h);}
 public static uint JobActive(IntPtr h){Accounting a;if(!QueryInformationJobObject(h,1,out a,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero))throw new Exception("job_query_failed");return a.Active;}
 public static Member[] JobMembers(IntPtr h,string exe){Member[] a=InspectJobMembers(h,exe);foreach(var m in a)if(m.kind=="unknown")throw new Exception("unclassified_job_member");return a;}
 public static Member[] InspectJobMembers(IntPtr h,string exe){
  IntPtr b=Marshal.AllocHGlobal(8+64*IntPtr.Size);
  try{
   if(!QueryRaw(h,3,b,(uint)(8+64*IntPtr.Size),IntPtr.Zero))throw new Exception("members_query_failed");int n=Marshal.ReadInt32(b,4);if(n<1||n>16||Marshal.ReadInt32(b)!=n)throw new Exception("members_count_refused");
   var list=new System.Collections.Generic.List<Member>();for(int i=0;i<n;i++){
    int pid=checked((int)Marshal.ReadIntPtr(b,8+i*IntPtr.Size).ToInt64());using(var process=Process.GetProcessById(pid)){
     IntPtr ph=process.Handle;bool member;if(!IsProcessInJob(ph,h,out member)||!member)throw new Exception("member_changed");long created,e,k,u;if(!GetProcessTimes(ph,out created,out e,out k,out u))throw new Exception("member_identity_failed");string image=process.MainModule.FileName;
     string kind=String.Equals(image,exe,StringComparison.OrdinalIgnoreCase)?"fixture":String.Equals(image,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","conhost.exe"),StringComparison.OrdinalIgnoreCase)?"console":"unknown";
     list.Add(new Member{pid=pid,created=created,image=image,kind=kind});
    }
   }return list.ToArray();
  }finally{Marshal.FreeHGlobal(b);}
 }
 public static bool EndOwnedJob(IntPtr h){if(!TerminateJobObject(h,13))return false;var watch=Stopwatch.StartNew();while(JobActive(h)!=0&&watch.ElapsedMilliseconds<10000)Thread.Sleep(50);return JobActive(h)==0;}
 static string Q(string text){if(text.Contains("\"")||text.Contains("\r")||text.Contains("\n"))throw new Exception();return "\""+text+"\"";}
 static string Args(string mode,string path,string token){return mode+" "+Q(path)+" "+token;}
 static bool WaitFile(string path){var watch=Stopwatch.StartNew();while(!File.Exists(path)&&watch.ElapsedMilliseconds<15000)Thread.Sleep(50);return File.Exists(path);}
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 static string Env(string n){return Environment.GetEnvironmentVariable(n)??"";}
 static bool Hosted(){return Environment.OSVersion.Platform==PlatformID.Win32NT&&Env("GITHUB_ACTIONS")=="true"&&Env("RUNNER_ENVIRONMENT")=="github-hosted"&&Env("RUNNER_OS")=="Windows"&&Env("GITHUB_REF")=="refs/heads/research/battlenet-minimal-install-isolation-2026-10-25"&&Env("GITHUB_EVENT_NAME")=="push"&&Env("GITHUB_RUN_ATTEMPT")=="1"&&Env("BNET_INTEGRATED_G16")=="lab: approved peer firewall integration G16a 20261025";}
 static Config Load(string path,string token){
  string prefix=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"BNetIntegratedG16")+"\\";path=Path.GetFullPath(path);
  if(!path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)||Path.GetFileName(path)!="config.json"||new FileInfo(path).Length>16384)throw new Exception();
  for(DirectoryInfo d=new FileInfo(path).Directory;d!=null&&d.FullName.StartsWith(prefix,StringComparison.OrdinalIgnoreCase);d=d.Parent)if((d.Attributes&FileAttributes.ReparsePoint)!=0)throw new Exception();
  if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new Exception();
  Config c=Json.Deserialize<Config>(File.ReadAllText(path));
  string self=Process.GetCurrentProcess().MainModule.FileName;
  if(c.token!=token||!String.Equals(Path.GetDirectoryName(path),Path.GetFullPath(c.root),StringComparison.OrdinalIgnoreCase)||!String.Equals(Path.GetFullPath(c.exe),Path.GetFullPath(self),StringComparison.OrdinalIgnoreCase)||c.expires_ticks<=DateTime.UtcNow.Ticks||c.expires_ticks>DateTime.UtcNow.AddMinutes(10).Ticks||!c.service_name.StartsWith("BNetLabG16_")||!c.task_name.StartsWith("BNetLabG16_"))throw new Exception();
  return c;
 }
 static void Ready(Config c,string mode,bool? member){
  var p=Process.GetCurrentProcess();long created,e,k,u;if(!GetProcessTimes(p.Handle,out created,out e,out k,out u))throw new Exception();
  string text=Json.Serialize(new {mode=mode,pid=p.Id,created=created,job_member=member});string path=Path.Combine(c.root,mode+".json");File.WriteAllText(path+".tmp",text,new UTF8Encoding(false));File.Move(path+".tmp",path);
 }
 public static bool CheckMembership(IntPtr process,string name){IntPtr h=OpenJobObject(4,false,name);if(h==IntPtr.Zero)throw new Exception();try{bool member;if(!IsProcessInJob(process,h,out member))throw new Exception();return member;}finally{CloseHandle(h);}}
 static bool Membership(Config c){IntPtr job=OpenJobObject(4,false,c.job_name);if(job==IntPtr.Zero)throw new Exception();try{bool member;if(!IsProcessInJob(Process.GetCurrentProcess().Handle,job,out member))throw new Exception();return member;}finally{CloseHandle(job);}}
 public class ProbeResult{public bool connected,http200,system_identity;public string error_code;}
 static ProbeResult Probe(Config c,bool viaGate){
  var result=new ProbeResult{system_identity=System.Security.Principal.WindowsIdentity.GetCurrent().User.Value=="S-1-5-18"};
  try{
   IPAddress ip;if(!IPAddress.TryParse(c.canary_ip,out ip)||ip.AddressFamily!=AddressFamily.InterNetwork||IPAddress.IsLoopback(ip))throw new Exception();
   using(var tcp=new TcpClient(AddressFamily.InterNetwork)){
    var pending=tcp.ConnectAsync(viaGate?IPAddress.Loopback:ip,1119);if(!pending.Wait(3000)){result.error_code="connect_timeout";}else{
     result.connected=tcp.Connected;if(result.connected){
      tcp.ReceiveTimeout=3000;tcp.SendTimeout=3000;var stream=tcp.GetStream();byte[] request=Encoding.ASCII.GetBytes("GET /agent/versions HTTP/1.1\r\nHost: us.version.battle.net:1119\r\nConnection: close\r\n\r\n");stream.Write(request,0,request.Length);
      byte[] buffer=new byte[128];int count=0;while(count<buffer.Length){int n=stream.Read(buffer,count,1);if(n==0)break;count+=n;if(count>=2&&buffer[count-2]==13&&buffer[count-1]==10)break;}
      string status=Encoding.ASCII.GetString(buffer,0,count);result.http200=status.StartsWith("HTTP/1.1 200 ")||status.StartsWith("HTTP/1.0 200 ");
     }
    }
   }
  }catch{result.error_code="socket_operation_failed";}return result;
 }
 static int Canary(Config c,bool viaGate){Console.WriteLine(Json.Serialize(Probe(c,viaGate)));return 0;}
 static void Commands(Config c,string kind,Func<bool> stopped){
  var timer=Stopwatch.StartNew();bool[] done=new bool[17];
  while(timer.ElapsedMilliseconds<420000&&!stopped()){
   for(int i=1;i<=16;i++){
    string command=Path.Combine(c.root,"command-"+kind+"-"+i);
    if(!done[i]&&File.Exists(command)){
     string mode=File.ReadAllText(command);if(mode!="direct"&&mode!="via_gate")throw new Exception();done[i]=true;
     var result=Probe(c,mode=="via_gate");string path=Path.Combine(c.root,"result-"+kind+"-"+i+".json");
     File.WriteAllText(path+".tmp",Json.Serialize(result),new UTF8Encoding(false));File.Move(path+".tmp",path);
    }
   }Thread.Sleep(50);
  }
 }
 class ProbeService:ServiceBase{
  Config C;Thread worker;volatile bool stopped;public ProbeService(Config c){C=c;ServiceName=c.service_name;CanStop=true;AutoLog=false;}
  protected override void OnStart(string[] args){Ready(C,"service",Membership(C));worker=new Thread(delegate(){try{Commands(C,"service",()=>stopped);}finally{try{Stop();}catch{}}});worker.IsBackground=true;worker.Start();}
  protected override void OnStop(){stopped=true;if(worker!=null&&Thread.CurrentThread!=worker)worker.Join(5000);}
 }
 static int Main(string[] args){
  try{
   if(args.Length!=3)return 4;string mode=args[0];if(mode!="service"&&mode!="task"&&mode!="owner"&&mode!="canary"&&mode!="via_gate"&&mode!="root"&&mode!="leaf"&&mode!="unlisted")return 4;
   if((mode=="owner"||mode=="canary")&&!Hosted())return 4;Config c=Load(args[1],args[2]);if(mode=="canary"||mode=="via_gate")return Canary(c,mode=="via_gate");
   if(mode=="unlisted"){Ready(c,"unlisted",Membership(c));Thread.Sleep(420000);return 0;}
   if(mode=="leaf"){Ready(c,"leaf",Membership(c));Commands(c,"leaf",()=>false);return 0;}
   if(mode=="root"){
    using(var child=Process.Start(new ProcessStartInfo(c.exe,Args("leaf",args[1],args[2])){UseShellExecute=false,CreateNoWindow=true})){Ready(c,"root",Membership(c));Commands(c,"root",()=>false);}return 0;
   }
   if(mode=="owner"){
    IntPtr job=CreateJobObject(IntPtr.Zero,c.job_name);if(job==IntPtr.Zero)return 3;ProcessInfo pi=new ProcessInfo();bool assigned=false;
    try{
     Extended limit=new Extended();limit.Basic.Flags=0x2000;if(!SetInformationJobObject(job,9,ref limit,(uint)Marshal.SizeOf(typeof(Extended))))return 3;
     var startup=new Startup{Size=(uint)Marshal.SizeOf(typeof(Startup))};if(!CreateProcess(c.exe,new StringBuilder(Q(c.exe)+" "+Args("root",args[1],args[2])),IntPtr.Zero,IntPtr.Zero,false,4|0x08000000,IntPtr.Zero,c.root,ref startup,out pi))return 3;
     if(!AssignProcessToJobObject(job,pi.Process))return 3;assigned=true;bool member;if(!IsProcessInJob(pi.Process,job,out member)||!member)return 3;
     if(ResumeThread(pi.Thread)==0xffffffff)return 3;CloseHandle(pi.Thread);pi.Thread=IntPtr.Zero;
     if(!WaitFile(Path.Combine(c.root,"root.json"))||!WaitFile(Path.Combine(c.root,"leaf.json")))return 3;
     Thread.Sleep(250);Member[] members=JobMembers(job,c.exe);if(c.pause_owner_receipt){Ready(c,"owner_pause",null);Thread.Sleep(420000);return 0;}var process=Process.GetCurrentProcess();long created,e,k,u;if(!GetProcessTimes(process.Handle,out created,out e,out k,out u))return 3;
     File.WriteAllText(Path.Combine(c.root,"owner.json.tmp"),Json.Serialize(new{mode="owner",pid=process.Id,created=created,assigned_before_resume=true,members=members}),new UTF8Encoding(false));File.Move(Path.Combine(c.root,"owner.json.tmp"),Path.Combine(c.root,"owner.json"));
     Thread.Sleep(450000);return 0;
    }finally{if(pi.Process!=IntPtr.Zero){if(!assigned)TerminateProcess(pi.Process,9);CloseHandle(pi.Process);}if(pi.Thread!=IntPtr.Zero)CloseHandle(pi.Thread);CloseHandle(job);}
   }
   if(mode=="service"){ServiceBase.Run(new ProbeService(c));return 0;}
   Ready(c,"task",Membership(c));Commands(c,"task",()=>File.Exists(Path.Combine(c.root,"stop-task")));return 0;
  }catch{return 3;}
 }
}
