// Control helper: signature/canary and Job cleanup only. No process-creation route.
using System;using System.IO;using System.Text;using System.Diagnostics;using System.Runtime.InteropServices;using System.Web.Script.Serialization;using System.Collections.Generic;using System.Security.Cryptography;using System.Net;using System.Net.Sockets;
public class OfflineLauncher {
 const string Pin="f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6";
 static JavaScriptSerializer J=new JavaScriptSerializer(); static string Stage="entry";
 public class Config{public string root,setup,job_name,canary_ip;public bool signature_accepted;public Dictionary<string,string> child_environment;}
 public class Identity{public int pid;public long created;public string image;}
 [StructLayout(LayoutKind.Sequential)]struct Limit{public long A,B;public uint Flags;public UIntPtr Min,Max;public uint Active;public UIntPtr Affinity;public uint Priority,Scheduling;}
 [StructLayout(LayoutKind.Sequential)]struct Io{public ulong A,B,C,D,E,F;}
 [StructLayout(LayoutKind.Sequential)]struct Extended{public Limit Basic;public Io Io;public UIntPtr A,B,C,D;}
 [StructLayout(LayoutKind.Sequential)]struct Accounting{public long A,B,C,D;public uint Faults,Total,Active,Terminated;}
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct Startup{public uint Size;public string Reserved,Desktop,Title;public uint X,Y,XS,YS,XC,YC,Fill,Flags;public ushort Show,ReservedSize;public IntPtr ReservedBytes,StdIn,StdOut,StdErr;}
 [StructLayout(LayoutKind.Sequential)]struct PI{public IntPtr Process,Thread;public uint Pid,Tid;}
 [StructLayout(LayoutKind.Sequential)]struct Association{public IntPtr Key,Port;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr CreateJobObject(IntPtr a,string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr OpenJobObject(uint access,bool inherit,string name);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool SetInformationJobObject(IntPtr h,int kind,ref Extended data,uint size);
 [DllImport("kernel32.dll",EntryPoint="SetInformationJobObject",SetLastError=true)]static extern bool SetAssociation(IntPtr h,int kind,ref Association data,uint size);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool QueryInformationJobObject(IntPtr h,int kind,out Accounting data,uint size,IntPtr len);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool AssignProcessToJobObject(IntPtr h,IntPtr p);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool IsProcessInJob(IntPtr p,IntPtr h,out bool member);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool TerminateJobObject(IntPtr h,uint code);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool TerminateProcess(IntPtr h,uint code);
 [DllImport("kernel32.dll",SetLastError=true)]static extern uint ResumeThread(IntPtr thread);

 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr CreateIoCompletionPort(IntPtr file,IntPtr existing,UIntPtr key,uint threads);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetQueuedCompletionStatus(IntPtr port,out uint code,out UIntPtr key,out IntPtr data,uint wait);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetProcessTimes(IntPtr p,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder path,ref uint size);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll")]static extern uint WaitForSingleObject(IntPtr h,uint wait);
 static string Env(string name){return Environment.GetEnvironmentVariable(name)??"";}
 static void Authorized(){if(Env("GITHUB_ACTIONS")!="true"||Env("RUNNER_ENVIRONMENT")!="github-hosted"||Env("RUNNER_OS")!="Windows"||Env("GITHUB_EVENT_NAME")!="push"||Env("GITHUB_RUN_ATTEMPT")!="1"||Env("GITHUB_REF")!="refs/heads/research/battlenet-minimal-install-isolation-2026-10-25"||Env("BNET_ONLINE_G34")!="lab: approved ambient no Setup control G34 20261025")throw new Exception("fresh_hosted_required");}
 public static string PrivateRoot(string path){path=Path.GetFullPath(path);string prefix=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"BNetOnlineG34")+"\\";if(!path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)||Path.GetFileName(path).Length!=32)throw new Exception("private_root_refused");for(var d=new DirectoryInfo(path);d!=null&&d.FullName.StartsWith(prefix,StringComparison.OrdinalIgnoreCase);d=d.Parent)if((d.Attributes&FileAttributes.ReparsePoint)!=0)throw new Exception("reparse_refused");return path;}
 static Config Load(string path){string root=PrivateRoot(Path.GetDirectoryName(path));if(Path.GetFileName(path)!="config.json"||new FileInfo(path).Length>32768)throw new Exception("context_refused");var c=J.Deserialize<Config>(File.ReadAllText(path));if(c.root!=root||c.setup!=Path.Combine(root,"Battle.net-Setup.exe")||c.job_name!="Global\\BNetOnlineG34_"+Path.GetFileName(root))throw new Exception("context_identity_refused");return c;}
 static void Save(string path,object value){string t=path+".tmp";File.WriteAllText(t,J.Serialize(value),new UTF8Encoding(false));if(File.Exists(path))File.Delete(path);File.Move(t,path);}
 public static IntPtr OpenOwnedJob(string name){if(!System.Text.RegularExpressions.Regex.IsMatch(name,@"^Global\\BNetOnlineG34_[a-f0-9]{32}$"))throw new Exception("job_scope_refused");return OpenJobObject(12,false,name);}
 public static uint Active(IntPtr job){Accounting a;if(!QueryInformationJobObject(job,1,out a,(uint)Marshal.SizeOf(typeof(Accounting)),IntPtr.Zero))throw new Exception("job_query_failed");return a.Active;}
 public static bool EndJob(IntPtr h){if(!TerminateJobObject(h,17))throw new Exception("job_termination_failed");var w=Stopwatch.StartNew();while(Active(h)!=0&&w.ElapsedMilliseconds<10000)System.Threading.Thread.Sleep(50);return Active(h)==0;}
 public static void CloseJob(IntPtr h){if(h!=IntPtr.Zero)CloseHandle(h);}
 static Identity Identify(IntPtr h,int pid){long c,e,k,u;if(!GetProcessTimes(h,out c,out e,out k,out u))throw new Exception("identity_failed");var name=new StringBuilder(32768);uint size=(uint)name.Capacity;if(!QueryFullProcessImageName(h,0,name,ref size))throw new Exception("image_query_failed");return new Identity{pid=pid,created=c,image=name.ToString()};}
 static IntPtr EnvironmentBlock(Config c){
  var allow=new HashSet<string>(StringComparer.OrdinalIgnoreCase){"SystemRoot","windir","SystemDrive","ProgramFiles","ProgramFiles(x86)","ProgramW6432","ProgramData","LOCALAPPDATA","APPDATA","USERPROFILE","TEMP","TMP","COMSPEC","PATH"};
  if(c.child_environment==null||c.child_environment.Count<8||c.child_environment.Count>allow.Count)throw new Exception("child_environment_refused");var keys=new List<string>(c.child_environment.Keys);keys.Sort(StringComparer.OrdinalIgnoreCase);var b=new StringBuilder();foreach(string k in keys){string v=c.child_environment[k];if(!allow.Contains(k)||v==null||v.IndexOf('\0')>=0)throw new Exception("child_environment_refused");b.Append(k).Append('=').Append(v).Append('\0');}b.Append('\0');return Marshal.StringToHGlobalUni(b.ToString());
 }
 static void VerifyBlock(){object fw=Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));try{foreach(int profile in new[]{1,2,4}){object enabled=fw.GetType().InvokeMember("FirewallEnabled",System.Reflection.BindingFlags.GetProperty,null,fw,new object[]{profile});object action=fw.GetType().InvokeMember("DefaultOutboundAction",System.Reflection.BindingFlags.GetProperty,null,fw,new object[]{profile});if(!(bool)enabled||Convert.ToInt32(action)!=0)throw new Exception("offline_profile_not_enforced");}}finally{Marshal.FinalReleaseComObject(fw);}}
 static int Main(string[] args){try{
  if(args.Length!=2)return 4;if(args[0]=="verify"){Authorized();Console.WriteLine(J.Serialize(AuthenticodeNative.Verify(Path.GetFullPath(args[1]))));return 0;}
  var c=Load(args[1]);if(args[0]=="run")throw new Exception("installer_execution_disabled_in_control");
  if(args[0]=="canary"){Authorized();IPAddress ip;if(!IPAddress.TryParse(c.canary_ip,out ip)||ip.AddressFamily!=AddressFamily.InterNetwork||IPAddress.IsLoopback(ip))return 4;bool connected=false;try{using(var tcp=new TcpClient(AddressFamily.InterNetwork)){if(tcp.ConnectAsync(ip,1119).Wait(3000))connected=tcp.Connected;}}catch{}Console.WriteLine(J.Serialize(new{connected=connected}));return 0;}return 4;
 }catch(Exception e){string m=e.Message;if(!System.Text.RegularExpressions.Regex.IsMatch(m,"^[a-z_]{1,80}$"))m="launcher_operation_failed";Console.WriteLine(J.Serialize(new{error_code=m,failure_stage=Stage,error_type=e.GetType().Name,error_hresult=e.HResult}));return 2;}}
}
