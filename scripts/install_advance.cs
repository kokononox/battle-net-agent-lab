// Exactly one approved setup-options Continue; never a general wizard driver.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Automation;
public static class InstallAdvance {
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    static JavaScriptSerializer json=new JavaScriptSerializer{MaxJsonLength=4096};
    sealed class Stop:Exception {public string Code;public Stop(string c){Code=c;}}
    static Dictionary<string,object> r;static string journal;
    static string Name(AutomationElement e){var c=e.Current;if(c.IsPassword||c.IsOffscreen)throw new Stop("page_mismatch");string n=c.Name??"";if(n.Length>512)throw new Stop("page_mismatch");return Regex.Replace(n.Replace("&","").Trim(),@"\s+"," ").ToLowerInvariant();}
    static bool Owner(IntPtr h,int pid,string setup){uint p;GetWindowThreadProcessId(h,out p);if(p!=(uint)pid||!IsWindowVisible(h))return false;using(var proc=Process.GetProcessById(pid))return string.Equals(Path.GetFullPath(proc.MainModule.FileName),setup,StringComparison.OrdinalIgnoreCase);}
    static bool SameImage(string a,string b){
        // A relocated child must be byte-for-byte the already trusted download.
        var x=new FileInfo(a);var y=new FileInfo(b);
        if(x.Length<=0||x.Length>128L*1024*1024||x.Length!=y.Length)return false;
        using(var sha=SHA256.Create()){
            byte[] first,second;
            using(var f=File.Open(a,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete))first=sha.ComputeHash(f);
            using(var f=File.Open(b,FileMode.Open,FileAccess.Read,FileShare.Read|FileShare.Delete))second=sha.ComputeHash(f);
            for(int i=0;i<first.Length;i++)if(first[i]!=second[i])return false;
        }
        return true;
    }
    static string VerifiedPath(IntPtr h,int pid,string setup){
        uint owner;GetWindowThreadProcessId(h,out owner);
        if(owner!=(uint)pid||!IsWindowVisible(h))throw new Stop("process_mismatch");
        string actual;using(var p=Process.GetProcessById(pid))actual=Path.GetFullPath(p.MainModule.FileName);
        if(!string.Equals(actual,setup,StringComparison.OrdinalIgnoreCase)&&!SameImage(actual,setup))throw new Stop("executable_identity_refused");
        var signed=AuthenticodeNative.Verify(actual);
        if((int)signed["trust_status"]!=0||!(bool)signed["expected_blizzard_publisher"])throw new Stop("signature_refused");
        return actual;
    }
    static void Save(){try{byte[] b=new UTF8Encoding(false).GetBytes(json.Serialize(r));string tmp=journal+".tmp";using(var f=new FileStream(tmp,FileMode.Create,FileAccess.Write,FileShare.None)){f.Write(b,0,b.Length);f.Flush(true);}if(File.Exists(journal))File.Replace(tmp,journal,null);else File.Move(tmp,journal);}catch{throw new Stop("journal_failed");}}
    static AutomationElement Page(AutomationElement root,int pid){
        var stack=new Stack<AutomationElement>();stack.Push(root);var watch=Stopwatch.StartNew();
        int count=0,buttons=0,changes=0,boxes=0,texts=0;AutomationElement button=null;
        while(stack.Count>0){
            if(++count>16||watch.ElapsedMilliseconds>2000)throw new Stop("page_mismatch");
            var e=stack.Pop();var c=e.Current;
            if(c.ProcessId!=pid||!c.IsEnabled||c.IsPassword||c.IsOffscreen)throw new Stop("page_mismatch");
            var t=c.ControlType;
            // Unknown roles, account fields, agreements and extra controls fail closed.
            if(t!=ControlType.Window&&t!=ControlType.Text&&t!=ControlType.Button&&t!=ControlType.Hyperlink&&t!=ControlType.CheckBox)throw new Stop("page_mismatch");
            string name=Name(e);
            if(Regex.IsMatch(name,@"\b(license|licence|agreement|terms|eula|privacy|login|log[ -]?in|sign[ -]?in|password|error)\b"))throw new Stop("forbidden_text");
            if(t==ControlType.Window){if(!Automation.Compare(e,root)||name!="battle.net setup")throw new Stop("page_mismatch");}
            else if(t==ControlType.Text){texts++;}
            else if(t==ControlType.Button){if(name!="continue")throw new Stop("page_mismatch");buttons++;button=e;}
            else if(t==ControlType.Hyperlink){if(name!="change")throw new Stop("page_mismatch");changes++;}
            else if(t==ControlType.CheckBox){if(name!="launch battle.net when you start your computer")throw new Stop("page_mismatch");boxes++;}
            var child=TreeWalker.RawViewWalker.GetFirstChild(e);int siblings=0;
            while(child!=null){if(++siblings>8||stack.Count>=16)throw new Stop("page_mismatch");stack.Push(child);child=TreeWalker.RawViewWalker.GetNextSibling(child);}
        }
        if(count!=6||buttons!=1||changes!=1||boxes!=1||texts!=2)throw new Stop("page_mismatch");
        return button;
    }
    public static void Run(){
        r=new Dictionary<string,object>{{"status","pending"},{"authorized",true},{"helper_started",true},{"page_confirmed",false},{"continue_attempted",false},{"continue_returned",false},{"journal_recovered",false},{"outcome_uncertain",false}};
        try{
            var cfg=(Dictionary<string,object>)json.DeserializeObject(Environment.GetEnvironmentVariable("BNET_LAB_INSTALL_CONFIG"));
            var target=(Dictionary<string,object>)cfg["target"];int pid=Convert.ToInt32(target["pid"]);var hwnd=new IntPtr(Convert.ToInt64(target["hwnd"]));string setup=Path.GetFullPath((string)cfg["setup"]);journal=(string)cfg["journal"];
            string verified=VerifiedPath(hwnd,pid,setup);
            var root=AutomationElement.FromHandle(hwnd);var button=Page(root,pid);object pattern;
            if(!button.TryGetCurrentPattern(InvokePattern.Pattern,out pattern))throw new Stop("pattern_unavailable");
            r["page_confirmed"]=true;r["status"]="page_confirmed";Save();
            if(!Owner(hwnd,pid,verified))throw new Stop("process_mismatch");
            if(!Automation.Compare(button,Page(AutomationElement.FromHandle(hwnd),pid)))throw new Stop("page_changed");
            r["continue_attempted"]=true;r["status"]="continue_attempted";Save();
            ((InvokePattern)pattern).Invoke();
            r["continue_returned"]=true;r["status"]="continued";Save();
        }catch(Stop e){r["status"]=e.Code;if((bool)r["continue_attempted"])r["outcome_uncertain"]=true;}
        catch{r["status"]="native_exception";if((bool)r["continue_attempted"])r["outcome_uncertain"]=true;}
        Console.WriteLine(json.Serialize(r));
    }
}
