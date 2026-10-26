// Wrapper for the existing strictly-scoped repository LanguageAdvance guard.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Web.Script.Serialization;
public static class LanguageOnce {
 delegate bool CB(IntPtr h,IntPtr p);
 [DllImport("user32.dll")]static extern bool EnumWindows(CB cb,IntPtr p);
 [DllImport("user32.dll")]static extern bool IsWindowVisible(IntPtr h);
 [DllImport("user32.dll")]static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
 static void Fail(string status){Console.WriteLine(new JavaScriptSerializer().Serialize(new{status=status,authorized=true,helper_started=true,selection_attempted=false,selection_confirmed=false,continue_attempted=false,continue_returned=false,outcome_uncertain=false}));}
 public static int Main(string[] args){
  try{
   if(Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT")!="github-hosted"||Environment.GetEnvironmentVariable("BNET_G67")!="approved-live-startup-two-hosts-g67"){Fail("approval_required");return 2;}
   int pid;long birth;
   if(args.Length!=2||!Int32.TryParse(args[0],out pid)||!Int64.TryParse(args[1],out birth)||pid<=0){Fail("arguments_rejected");return 2;}
   string root=Path.GetFullPath(Path.Combine(Environment.GetEnvironmentVariable("RUNNER_TEMP"),"g67-private"));
   string setup=Path.Combine(root,"Battle.net-Setup.exe");
   using(var file=File.Open(setup,FileMode.Open,FileAccess.Read,FileShare.Read))using(var sha=SHA256.Create()){
    if(file.Length!=4700880||BitConverter.ToString(sha.ComputeHash(file)).Replace("-","").ToLowerInvariant()!="f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6"){Fail("identity_hash_rejected");return 2;}
   }
   using(var process=Process.GetProcessById(pid)){
    if(process.HasExited||process.StartTime.ToUniversalTime().ToFileTimeUtc()!=birth||!String.Equals(Path.GetFullPath(process.MainModule.FileName),setup,StringComparison.OrdinalIgnoreCase)){Fail("process_identity_rejected");return 2;}
    var targets=new List<IntPtr>();
    EnumWindows(delegate(IntPtr h,IntPtr _){uint owner;GetWindowThreadProcessId(h,out owner);if(owner==pid&&IsWindowVisible(h))targets.Add(h);return true;},IntPtr.Zero);
    if(targets.Count!=1){Fail("visible_window_ambiguous");return 2;}
    // Consume exactly one action ticket even if later strict page guards refuse.
    using(var ticket=new FileStream(Path.Combine(root,"language-once.ticket"),FileMode.CreateNew,FileAccess.Write,FileShare.None)){ticket.WriteByte(1);ticket.Flush(true);}
    var cfg=new{target=new{pid=pid,hwnd=targets[0].ToInt64()},setup=setup,journal=Path.Combine(root,"language-action.PRIVATE.json")};
    Environment.SetEnvironmentVariable("BNET_LAB_LANGUAGE_CONFIG",new JavaScriptSerializer().Serialize(cfg));
    LanguageAdvance.Run();
   }
   return 0;
  }catch{Fail("wrapper_failed_no_retry");return 2;}
 }
}
