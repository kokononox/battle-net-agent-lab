// Read-only lifecycle/role receipts. No permission decisions use command line or diagnostics.
using System;using System.IO;using System.Runtime.InteropServices;using System.Collections.Generic;using System.Management;using System.Text.RegularExpressions;using System.Web.Script.Serialization;
public static class ProcessDiagnostics {
 [DllImport("kernel32.dll",SetLastError=true)]static extern IntPtr OpenProcess(uint a,bool i,int p);
 [DllImport("kernel32.dll")]static extern bool CloseHandle(IntPtr p);
 [DllImport("kernel32.dll")]static extern bool GetProcessTimes(IntPtr p,out long c,out long e,out long k,out long u);
 [DllImport("kernel32.dll")]static extern bool GetExitCodeProcess(IntPtr p,out uint code);
 [DllImport("kernel32.dll")]static extern uint WaitForSingleObject(IntPtr p,uint ms);
 [DllImport("kernel32.dll")]static extern bool IsProcessInJob(IntPtr p,IntPtr j,out bool yes);
 class Item {public int Index,Pid,Parent;public long Created,Start,ExitAt=-1;public IntPtr Handle;public string Name,Role="unavailable";public bool Abnormal;}
 static List<Item> Items=new List<Item>();static int Failed;
 public static string Role(string command){if(command==null)return "unavailable";var m=Regex.Match(command,@"(?:^|\s)--type=""?([a-z-]+)(?:""|\s|$)");if(!m.Success)return "no_type_switch";switch(m.Groups[1].Value){case "renderer":case "gpu-process":case "utility":case "zygote":case "crashpad-handler":return m.Groups[1].Value.Replace('-','_');default:return "other_type_switch";}}
 static string Name(string image){switch(Path.GetFileName(image).ToLowerInvariant()){case "battle.net-setup.exe":return "setup";case "battle.net.exe":return "client";case "battle.net launcher.exe":return "launcher";case "agent.exe":return "agent";case "conhost.exe":return "conhost";default:return "other_executable";}}
 public static void New(int pid,long created,string image,IntPtr job,long ms){
  IntPtr h=IntPtr.Zero;try{
   if(Items.Count>=128){Failed++;return;}h=OpenProcess(0x101000,false,pid);long c,e,k,u;bool own;
   if(h==IntPtr.Zero||!GetProcessTimes(h,out c,out e,out k,out u)||c!=created||!IsProcessInJob(h,job,out own)||!own)throw new Exception();
   var item=new Item{Index=Items.Count+1,Pid=pid,Created=created,Name=Name(image),Start=ms,Handle=h};h=IntPtr.Zero;Items.Add(item);
   try{
    var options=new EnumerationOptions{ReturnImmediately=false,Timeout=TimeSpan.FromSeconds(2)};
    using(var query=new ManagementObjectSearcher("root\\cimv2","SELECT CommandLine,ParentProcessId,CreationDate FROM Win32_Process WHERE ProcessId="+pid,options))using(var found=query.Get())foreach(ManagementObject row in found){using(row){string date=row["CreationDate"] as string;if(date==null||Math.Abs(ManagementDateTimeConverter.ToDateTime(date).ToUniversalTime().ToFileTimeUtc()-created)>10000000)continue;item.Parent=Convert.ToInt32(row["ParentProcessId"]);item.Role=Role(row["CommandLine"] as string);break;}}
   }catch{} // Missing role is uncertainty, not an ownership bypass.
  }catch{Failed++;}finally{if(h!=IntPtr.Zero)CloseHandle(h);}
 }
 public static void Exit(int pid,long ms,bool abnormal){for(int n=Items.Count-1;n>=0;n--)if(Items[n].Pid==pid&&Items[n].ExitAt<0){Items[n].ExitAt=ms;Items[n].Abnormal=abnormal;break;}}
 public static void Finish(string root,long ms){
  var rows=new List<object>();try{foreach(var item in Items){bool exited=WaitForSingleObject(item.Handle,0)==0;uint code=0;bool got=exited&&GetExitCodeProcess(item.Handle,out code);int? parent=null;foreach(var candidate in Items)if(candidate.Pid==item.Parent&&candidate.Created<item.Created)parent=candidate.Index;
   rows.Add(new{record=item.Index,parent_record=parent,kind=item.Name,role=item.Role,observed_start_ms=item.Start,exit_event_ms=item.ExitAt<0?(long?)null:item.ExitAt,alive_before_controller_termination=!exited,observed_lifetime_ms=Math.Max(0,(item.ExitAt<0?ms:item.ExitAt)-item.Start),exit_code=got?"0x"+code.ToString("x8"):null,job_abnormal_exit_message=item.Abnormal,terminated_by_controller_if_alive=!exited});
  }
  File.WriteAllText(Path.Combine(root,"process-diagnostics.json"),new JavaScriptSerializer().Serialize(new{schema="job_process_diagnostics_v1",phase="before_controller_job_termination",role_source="bounded_wmi_same_identity_best_effort",roles_are_not_authorization=true,observation_ms=ms,identity_capture_failures=Failed,records=rows}));
  }finally{foreach(var item in Items)if(item.Handle!=IntPtr.Zero){CloseHandle(item.Handle);item.Handle=IntPtr.Zero;}}
 }
 public static int SelfTest(){int n=0;foreach(var value in new[]{"renderer","gpu-process","utility","zygote","crashpad-handler"}){if(Role("x.exe --type="+value+" --x")!=value.Replace('-','_'))throw new Exception("role_parser_failed");n++;}if(Role("x.exe --type=unknown")!="other_type_switch"||Role("x.exe")!="no_type_switch"||Role(null)!="unavailable"||Role("x.exe --type=\"renderer\"")!="renderer")throw new Exception("role_parser_failed");n+=4;Console.WriteLine(new JavaScriptSerializer().Serialize(new{schema="process_role_selftests_v1",all_passed=true,cases=n}));return 0;}
}
