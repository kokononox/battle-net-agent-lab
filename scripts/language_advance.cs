// Only the specifically approved English (US) radio and language-page Continue.
// No coordinates, mouse/keyboard events, install/legal/account actions or retries.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Automation;

public static class LanguageAdvance {
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    static JavaScriptSerializer json=new JavaScriptSerializer {MaxJsonLength=4096};
    sealed class Stop:Exception {public string Code;public Stop(string c){Code=c;}}
    sealed class Node {public AutomationElement E;public int D;public Node(AutomationElement e,int d){E=e;D=d;}}
    static Dictionary<string,object> r;
    static string journal;
    static string Name(AutomationElement e) {var c=e.Current;if(c.IsPassword||c.IsOffscreen)throw new Stop("page_not_language");string n=c.Name??"";if(n.Length>512)throw new Stop("page_not_language");return Regex.Replace(n.Replace("&","").Trim(),@"\s+"," ").ToLowerInvariant();}
    static bool Ready(AutomationElement e,int pid,ControlType t) {var c=e.Current;return c.ProcessId==pid&&c.ControlType==t&&c.IsEnabled&&!c.IsOffscreen&&!c.IsPassword;}
    static void Save() {
        try {
            byte[] data=new UTF8Encoding(false).GetBytes(json.Serialize(r));
            string temp=journal+".tmp";
            using(var f=new FileStream(temp,FileMode.Create,FileAccess.Write,FileShare.None)){f.Write(data,0,data.Length);f.Flush(true);}
            if(File.Exists(journal))File.Replace(temp,journal,null);else File.Move(temp,journal);
        }catch{throw new Stop("journal_failed");}
    }
    static bool Owner(IntPtr h,int pid,string setup) {
        uint owner;GetWindowThreadProcessId(h,out owner);
        if(owner!=pid||!IsWindowVisible(h))return false;
        using(var p=Process.GetProcessById(pid))return string.Equals(Path.GetFullPath(p.MainModule.FileName),setup,StringComparison.OrdinalIgnoreCase);
    }
    static List<AutomationElement> Tree(AutomationElement root,int pid) {
        var result=new List<AutomationElement>();var seen=new HashSet<string>();var stack=new Stack<Node>();stack.Push(new Node(root,0));var watch=Stopwatch.StartNew();var walk=TreeWalker.RawViewWalker;
        while(stack.Count>0){
            if(result.Count>=64||watch.ElapsedMilliseconds>3000)throw new Stop("control_ambiguous");
            var n=stack.Pop();var c=n.E.Current;if(c.ProcessId!=pid)throw new Stop("process_mismatch");
            string id=string.Join(",",Array.ConvertAll(n.E.GetRuntimeId(),x=>x.ToString()));if(!seen.Add(id))continue;
            result.Add(n.E);
            if(n.D>=6){if(walk.GetFirstChild(n.E)!=null)throw new Stop("control_ambiguous");continue;}
            var child=walk.GetFirstChild(n.E);int count=0;
            while(child!=null){if(++count>64||stack.Count>=64||watch.ElapsedMilliseconds>3000)throw new Stop("control_ambiguous");stack.Push(new Node(child,n.D+1));child=walk.GetNextSibling(child);}
        }return result;
    }
    static AutomationElement[] Controls(AutomationElement root,int pid) {
        var groups=new List<AutomationElement>();var buttons=new List<AutomationElement>();
        foreach(var e in Tree(root,pid)){
            var c=e.Current;if(c.IsOffscreen)continue;
            if(c.IsPassword||c.ControlType==ControlType.Edit||c.ControlType==ControlType.Document)throw new Stop("page_not_language");
            // Do not read Custom/ListItem/unknown provider text.
            if(c.ControlType!=ControlType.Window&&c.ControlType!=ControlType.Group&&c.ControlType!=ControlType.Text&&c.ControlType!=ControlType.Button&&c.ControlType!=ControlType.RadioButton&&c.ControlType!=ControlType.Pane)continue;
            string n=Name(e);
            if(Regex.IsMatch(n,@"\b(license|licence|agreement|terms|eula|privacy|login|log[ -]?in|sign[ -]?in|password|error)\b"))throw new Stop("page_not_language");
            if(Ready(e,pid,ControlType.Group)&&n=="select a language")groups.Add(e);
            if(Ready(e,pid,ControlType.Button)&&n=="continue")buttons.Add(e);
        }
        if(groups.Count!=1||buttons.Count!=1)throw new Stop("page_not_language");
        var radios=new List<AutomationElement>();var seen=new HashSet<string>();var walker=TreeWalker.RawViewWalker;var radio=walker.GetFirstChild(groups[0]);int limit=0;
        while(radio!=null){
            if(++limit>32)throw new Stop("control_ambiguous");
            if(Ready(radio,pid,ControlType.RadioButton)&&(Name(radio)=="english (us)"||Name(radio)=="english (united states)")){
                string id=string.Join(",",Array.ConvertAll(radio.GetRuntimeId(),x=>x.ToString()));if(seen.Add(id))radios.Add(radio);
            }radio=walker.GetNextSibling(radio);
        }
        if(radios.Count!=1)throw new Stop("control_ambiguous");
        return new[]{radios[0],buttons[0]};
    }
    public static void Run() {
        r=new Dictionary<string,object>{{"status","pending"},{"authorized",true},{"helper_started",true},{"selection_already_set",null},{"selection_attempted",false},{"selection_confirmed",false},{"continue_attempted",false},{"continue_returned",false},{"journal_recovered",false},{"outcome_uncertain",false}};
        try{
            var cfg=(Dictionary<string,object>)json.DeserializeObject(Environment.GetEnvironmentVariable("BNET_LAB_LANGUAGE_CONFIG"));
            var target=(Dictionary<string,object>)cfg["target"];int pid=Convert.ToInt32(target["pid"]);var hwnd=new IntPtr(Convert.ToInt64(target["hwnd"]));string setup=Path.GetFullPath((string)cfg["setup"]);journal=(string)cfg["journal"];
            if(!Owner(hwnd,pid,setup))throw new Stop("process_mismatch");
            var root=AutomationElement.FromHandle(hwnd);
            if(!Ready(root,pid,ControlType.Window)||Name(root)!="battle.net setup")throw new Stop("window_mismatch");
            var controls=Controls(root,pid);object selectObject,invokeObject;
            if(!controls[0].TryGetCurrentPattern(SelectionItemPattern.Pattern,out selectObject)||!controls[1].TryGetCurrentPattern(InvokePattern.Pattern,out invokeObject))throw new Stop("pattern_unavailable");
            var select=(SelectionItemPattern)selectObject;var invoke=(InvokePattern)invokeObject;
            bool selected=select.Current.IsSelected;r["selection_already_set"]=selected;
            if(!selected){r["selection_attempted"]=true;r["status"]="selection_attempted";Save();select.Select();}
            if(!select.Current.IsSelected)throw new Stop("selection_failed");r["selection_confirmed"]=true;r["status"]="selection_confirmed";Save();
            // Recheck page/owner and the exact same controls after selection, never a next-page Continue.
            if(!Owner(hwnd,pid,setup)||!Ready(root,pid,ControlType.Window)||Name(root)!="battle.net setup")throw new Stop("window_mismatch");
            var again=Controls(root,pid);
            if(!Automation.Compare(controls[0],again[0])||!Automation.Compare(controls[1],again[1])||!select.Current.IsSelected)throw new Stop("page_not_language");
            r["continue_attempted"]=true;r["status"]="continue_attempted";Save();invoke.Invoke();
            r["continue_returned"]=true;r["status"]="continued";Save();
        }catch(Stop e){r["status"]=e.Code;if((bool)r["selection_attempted"]||(bool)r["continue_attempted"])r["outcome_uncertain"]=true;}
        catch{r["status"]="native_exception";if((bool)r["selection_attempted"]||(bool)r["continue_attempted"])r["outcome_uncertain"]=true;}
        Console.WriteLine(json.Serialize(r));
    }
}
