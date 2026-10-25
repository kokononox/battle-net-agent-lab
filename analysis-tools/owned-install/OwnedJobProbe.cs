// Synthetic process-containment qualification only. Never launches Battle.net.
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using System.Collections.Generic;
using System.Security.Cryptography;
class OwnedJobProbe {
 const uint CREATE_SUSPENDED=4, CREATE_NO_WINDOW=0x08000000, BREAKAWAY=0x01000000, KILL_ON_CLOSE=0x2000, SYNCHRONIZE=0x00100000, QUERY_LIMITED=0x1000;
 static readonly string Self=Process.GetCurrentProcess().MainModule.FileName;
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 [StructLayout(LayoutKind.Sequential)] struct BasicLimit {public long ProcessTime,JobTime;public uint Flags;public UIntPtr MinWorking,MaxWorking;public uint ActiveLimit;public UIntPtr Affinity;public uint Priority,Scheduling;}
 [StructLayout(LayoutKind.Sequential)] struct IoCounters {public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes;}
 [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {public BasicLimit Basic;public IoCounters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory;}
 [StructLayout(LayoutKind.Sequential)] struct Accounting {public long UserTime,KernelTime,PeriodUser,PeriodKernel;public uint PageFaults,TotalProcesses,ActiveProcesses,TerminatedProcesses;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {public uint Size;public string Reserved,Desktop,Title;public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags;public ushort Show,ReservedSize;public IntPtr ReservedBytes,StdIn,StdOut,StdErr;}
 [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {public IntPtr Process,Thread;public uint Pid,Tid;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimit data,uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out Accounting data,uint size,IntPtr length);
 [DllImport("kernel32.dll",EntryPoint="QueryInformationJobObject",SetLastError=true)] static extern bool QueryJobRaw(IntPtr job,int kind,IntPtr data,uint size,IntPtr length);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string directory,ref Startup startup,out ProcessInfo info);
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,uint pid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr process,out long created,out long exited,out long kernel,out long user);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr process,uint flags,StringBuilder buffer,ref uint size);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
 public class Identity {public uint pid;public long created;public string kind;public string image_hash;}
 public class State {public Identity root;public Identity leaf;public bool assigned_before_resume;public bool breakaway_denied;public uint active;public Identity[] members;}
 public class CaseResult {public string mode;public bool ready,assigned_before_resume,root_member,leaf_member,breakaway_denied,root_exited,leaf_exited,owner_exited,active_zero_before_release;public uint active_at_ready;public int observed_members,owned_probe_members,console_host_members,unclassified_members;public bool all_observed_members_exited;public string error_code;}
 static string Env(string k){return Environment.GetEnvironmentVariable(k)??"";}
 static bool Authorized(){return Environment.OSVersion.Platform==PlatformID.Win32NT && Env("GITHUB_ACTIONS")=="true" && Env("RUNNER_ENVIRONMENT")=="github-hosted" && Env("RUNNER_OS")=="Windows" && Env("GITHUB_REF")=="refs/heads/research/battlenet-minimal-install-isolation-2026-10-25" && Env("GITHUB_EVENT_NAME")=="push" && Env("GITHUB_RUN_ATTEMPT")=="1" && Env("BNET_OWNED_G9")=="lab: approved owned-job qualification G9b 20261025";}
 static string Quote(string s){if(s.IndexOf('"')>=0 || s.IndexOf('\r')>=0 || s.IndexOf('\n')>=0)throw new Exception("path_refused");return "\""+s+"\"";}
 static string PrivatePath(string p){string full=Path.GetFullPath(p);string root=Path.GetFullPath(Env("RUNNER_TEMP")).TrimEnd('\\')+"\\";if(!full.StartsWith(root,StringComparison.OrdinalIgnoreCase)||Path.GetFileName(Path.GetDirectoryName(full)).IndexOf("bnet-owned-g9-",StringComparison.Ordinal)!=0)throw new Exception("private_path_refused");return full;}
 static void Save(string p,object value){p=PrivatePath(p);string tmp=p+".tmp";File.WriteAllText(tmp,Json.Serialize(value),new UTF8Encoding(false));File.Move(tmp,p);}
 static T Read<T>(string p){p=PrivatePath(p);if(new FileInfo(p).Length>8192)throw new Exception("private_state_limit");return Json.Deserialize<T>(File.ReadAllText(p));}
 static Identity Identify(IntPtr h,uint pid){
  long c,e,k,u;if(!GetProcessTimes(h,out c,out e,out k,out u))throw new Exception("process_identity_unavailable");
  var name=new StringBuilder(32768);uint size=32768;if(!QueryFullProcessImageName(h,0,name,ref size))throw new Exception("process_image_unavailable");
  string image=Path.GetFullPath(name.ToString());string kind="other";
  if(String.Equals(image,Path.GetFullPath(Self),StringComparison.OrdinalIgnoreCase))kind="owned_probe";
  else if(String.Equals(image,Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","conhost.exe"),StringComparison.OrdinalIgnoreCase))kind="windows_console_host";
  string hash;using(var sha=SHA256.Create())hash=BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(image.ToUpperInvariant()))).Replace("-","");
  return new Identity{pid=pid,created=c,kind=kind,image_hash=hash};
 }
 static IntPtr OpenVerified(Identity id){IntPtr h=OpenProcess(SYNCHRONIZE|QUERY_LIMITED,false,id.pid);if(h==IntPtr.Zero)throw new Exception("process_open_failed");try{Identity actual=Identify(h,id.pid);if(actual.created!=id.created||actual.image_hash!=id.image_hash||actual.kind!=id.kind)throw new Exception("process_identity_mismatch");return h;}catch{CloseHandle(h);throw;}}
 static Identity[] Members(IntPtr job){
  int capacity=64;IntPtr buffer=Marshal.AllocHGlobal(8+capacity*IntPtr.Size);
  try{
   if(!QueryJobRaw(job,3,buffer,(uint)(8+capacity*IntPtr.Size),IntPtr.Zero))throw new Exception("job_members_query_failed");
   int assigned=Marshal.ReadInt32(buffer),count=Marshal.ReadInt32(buffer,4);if(count<2||count>16||assigned!=count)throw new Exception("job_members_count_refused");
   var result=new List<Identity>();
   for(int i=0;i<count;i++){
    uint pid=checked((uint)Marshal.ReadIntPtr(buffer,8+i*IntPtr.Size).ToInt64());IntPtr h=OpenProcess(SYNCHRONIZE|QUERY_LIMITED,false,pid);if(h==IntPtr.Zero)throw new Exception("job_member_open_failed");
    try{bool member;if(!IsProcessInJob(h,job,out member)||!member)throw new Exception("job_member_changed");result.Add(Identify(h,pid));}finally{CloseHandle(h);}
   }return result.ToArray();
  }finally{Marshal.FreeHGlobal(buffer);}
 }
 static uint Active(IntPtr job){Accounting a;if(!QueryInformationJobObject(job,1,out a,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero))throw new Exception("job_query_failed");return a.ActiveProcesses;}
 static Process StartMode(string args){return Process.Start(new ProcessStartInfo(Self,args){UseShellExecute=false,CreateNoWindow=true});}
 static bool AwaitFile(string p,Process owner,int ms){var sw=Stopwatch.StartNew();while(sw.ElapsedMilliseconds<ms){if(File.Exists(p))return true;if(owner!=null&&owner.HasExited)return false;Thread.Sleep(30);}return false;}
 static int Worker(string statePath){
  bool denied=false;Process escaped=null,leaf=null;
  try{
   // A breakaway attempt must be denied by the owned job, not silently allowed.
   Startup si=new Startup{Size=(uint)Marshal.SizeOf(typeof(Startup))};ProcessInfo pi;
   if(CreateProcess(Self,new StringBuilder(Quote(Self)+" leaf"),IntPtr.Zero,IntPtr.Zero,false,BREAKAWAY|CREATE_NO_WINDOW,IntPtr.Zero,Path.GetDirectoryName(Self),ref si,out pi)){
    try{TerminateProcess(pi.Process,7);WaitForSingleObject(pi.Process,5000);}finally{CloseHandle(pi.Thread);CloseHandle(pi.Process);}
   }else{denied=Marshal.GetLastWin32Error()==5;}
   leaf=StartMode("leaf");if(leaf==null)throw new Exception("leaf_launch_failed");
   var me=Process.GetCurrentProcess();Save(statePath,new State{root=Identify(me.Handle,(uint)me.Id),leaf=Identify(leaf.Handle,(uint)leaf.Id),breakaway_denied=denied});
   Thread.Sleep(60000);return 0;
  }finally{if(escaped!=null)escaped.Dispose();if(leaf!=null)leaf.Dispose();}
 }
 static int Owner(string directory){
  directory=Path.GetDirectoryName(PrivatePath(Path.Combine(directory,"guard")));IntPtr job=IntPtr.Zero;ProcessInfo pi=new ProcessInfo();bool assigned=false;
  try{
   job=CreateJobObject(IntPtr.Zero,null);if(job==IntPtr.Zero)throw new Exception("job_create_failed");
   var limits=new ExtendedLimit();limits.Basic.Flags=KILL_ON_CLOSE;
   if(!SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(ExtendedLimit))))throw new Exception("job_limits_failed");
   var si=new Startup{Size=(uint)Marshal.SizeOf(typeof(Startup))};string worker=Path.Combine(directory,"worker.json");
   if(!CreateProcess(Self,new StringBuilder(Quote(Self)+" worker "+Quote(worker)),IntPtr.Zero,IntPtr.Zero,false,CREATE_SUSPENDED|CREATE_NO_WINDOW,IntPtr.Zero,Path.GetDirectoryName(Self),ref si,out pi))throw new Exception("suspended_launch_failed");
   if(!AssignProcessToJobObject(job,pi.Process))throw new Exception("job_assign_failed");assigned=true;
   bool member;if(!IsProcessInJob(pi.Process,job,out member)||!member)throw new Exception("root_membership_failed");
   if(ResumeThread(pi.Thread)==0xffffffff)throw new Exception("resume_failed");CloseHandle(pi.Thread);pi.Thread=IntPtr.Zero;
   if(!AwaitFile(worker,null,12000))throw new Exception("worker_ready_timeout");
   State state=Read<State>(worker);IntPtr leaf=OpenVerified(state.leaf);
   try{bool leafMember;if(!IsProcessInJob(leaf,job,out leafMember)||!leafMember)throw new Exception("leaf_membership_failed");}finally{CloseHandle(leaf);}
   state.assigned_before_resume=true;Thread.Sleep(250);state.members=Members(job);state.active=Active(job);if(state.active!=state.members.Length)throw new Exception("job_member_snapshot_unstable");Save(Path.Combine(directory,"ready.json"),state);
   if(!AwaitFile(Path.Combine(directory,"terminate"),null,30000))return 3;
   if(!TerminateJobObject(job,9))throw new Exception("job_terminate_failed");
   var sw=Stopwatch.StartNew();while(Active(job)!=0&&sw.ElapsedMilliseconds<5000)Thread.Sleep(25);
   Save(Path.Combine(directory,"done.json"),new State{active=Active(job)});return 0;
  }finally{
   // Covers assignment/resume failures too; never leave a suspended root behind.
   if(pi.Process!=IntPtr.Zero){if(!assigned){TerminateProcess(pi.Process,8);WaitForSingleObject(pi.Process,5000);}CloseHandle(pi.Process);}
   if(pi.Thread!=IntPtr.Zero)CloseHandle(pi.Thread);if(job!=IntPtr.Zero)CloseHandle(job);
  }
 }
 static CaseResult RunCase(string mode){
  var r=new CaseResult{mode=mode};string dir=Path.Combine(Env("RUNNER_TEMP"),"bnet-owned-g9-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(dir);Process owner=null;IntPtr root=IntPtr.Zero,leaf=IntPtr.Zero;var observedHandles=new List<IntPtr>();
  try{
   owner=StartMode("owner "+Quote(dir));if(owner==null||!AwaitFile(Path.Combine(dir,"ready.json"),owner,18000))throw new Exception("owner_ready_failed");
   State state=Read<State>(Path.Combine(dir,"ready.json"));root=OpenVerified(state.root);leaf=OpenVerified(state.leaf);
   bool rootMember,leafMember;if(!IsProcessInJob(root,IntPtr.Zero,out rootMember)||!IsProcessInJob(leaf,IntPtr.Zero,out leafMember))throw new Exception("membership_query_failed");
   if(state.members==null)throw new Exception("member_identities_missing");
   foreach(Identity id in state.members){observedHandles.Add(OpenVerified(id));if(id.kind=="owned_probe")r.owned_probe_members++;else if(id.kind=="windows_console_host")r.console_host_members++;else r.unclassified_members++;}
   r.observed_members=observedHandles.Count;
   r.ready=true;r.assigned_before_resume=state.assigned_before_resume;r.root_member=rootMember;r.leaf_member=leafMember;r.breakaway_denied=state.breakaway_denied;r.active_at_ready=state.active;
   if(mode=="owner_crash")owner.Kill();else File.WriteAllText(Path.Combine(dir,"terminate"),"terminate");
   r.owner_exited=owner.WaitForExit(10000);r.root_exited=WaitForSingleObject(root,5000)==0;r.leaf_exited=WaitForSingleObject(leaf,5000)==0;
   r.all_observed_members_exited=observedHandles.Count>0;foreach(IntPtr h in observedHandles)if(WaitForSingleObject(h,5000)!=0)r.all_observed_members_exited=false;
   if(mode=="explicit_terminate"&&File.Exists(Path.Combine(dir,"done.json")))r.active_zero_before_release=Read<State>(Path.Combine(dir,"done.json")).active==0;
  }catch(Exception ex){string code=ex.Message;r.error_code=System.Text.RegularExpressions.Regex.IsMatch(code,"^[a-z_]{1,64}$")?code:"owned_job_operation_failed";}
  finally{
   if(owner!=null){try{if(!owner.HasExited){owner.Kill();owner.WaitForExit(5000);}}catch{}owner.Dispose();}
   foreach(IntPtr h in observedHandles){WaitForSingleObject(h,5000);CloseHandle(h);}
   if(root!=IntPtr.Zero){WaitForSingleObject(root,5000);CloseHandle(root);}if(leaf!=IntPtr.Zero){WaitForSingleObject(leaf,5000);CloseHandle(leaf);}
   try{Directory.Delete(dir,true);}catch{}
  }return r;
 }
 static bool Pass(CaseResult r){return r.error_code==null&&r.ready&&r.assigned_before_resume&&r.root_member&&r.leaf_member&&r.breakaway_denied&&r.active_at_ready==r.observed_members&&r.owned_probe_members==2&&r.unclassified_members==0&&r.all_observed_members_exited&&r.owner_exited&&r.root_exited&&r.leaf_exited&&(r.mode!="explicit_terminate"||r.active_zero_before_release);}
 static int Main(string[] args){
  if(!Authorized())return 4;
  try{
   if(args.Length==1&&args[0]=="leaf"){Thread.Sleep(60000);return 0;}
   if(args.Length==2&&args[0]=="worker")return Worker(PrivatePath(args[1]));
   if(args.Length==2&&args[0]=="owner")return Owner(args[1]);
   if(args.Length!=0)return 4;
   CaseResult normal=RunCase("explicit_terminate"),crash=RunCase("owner_crash");bool passed=Pass(normal)&&Pass(crash);
   var result=new Dictionary<string,object>{{"schema","bnet-owned-job-g9b-1"},{"source_commit",Env("GITHUB_SHA")},{"run_id",Env("GITHUB_RUN_ID")},{"architecture",IntPtr.Size==8?"x64":"x86"},{"status",passed?"qualified_synthetic_owned_descendants":"stopped"},{"installer_launched",false},{"network_policy_changed",false},{"services_changed",false},{"service_containment_proven",false},{"network_release_order_tested",false},{"cases",new[]{normal,crash}}};
   Console.WriteLine(Json.Serialize(result));return passed?0:2;
  }catch{Console.WriteLine("{\"schema\":\"bnet-owned-job-g9-1\",\"status\":\"stopped\",\"error_code\":\"harness_failed\",\"installer_launched\":false}");return 2;}
 }
}
