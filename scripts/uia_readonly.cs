// Read-only UI Automation for explicitly supplied HWND/PID pairs. No UI actions.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Automation;

public static class UiaReadOnly {
    static JavaScriptSerializer json = new JavaScriptSerializer { MaxJsonLength = 65536 };
    sealed class Node { public AutomationElement Element; public int Depth;
        public Node(AutomationElement e,int depth) { Element=e; Depth=depth; } }
    static Dictionary<string,object> Report(int n) {
        return new Dictionary<string,object> { {"status","ok"},{"elements",new List<object>()},
            {"truncated",false},{"errors",0},{"top_windows_requested",n} }; }
    [STAThread]
    public static int Main(string[] args) {
        try {
            if(args.Length==1 && args[0]=="signature") {
                Console.WriteLine(json.Serialize(AuthenticodeNative.Verify(Environment.GetEnvironmentVariable("BNET_LAB_VERIFY_PATH")))); return 0;
            }
            if(args.Length==1 && args[0]=="signature-abi") { Console.WriteLine(json.Serialize(AuthenticodeNative.Abi())); return 0; }
            if(args.Length==1 && args[0]=="advance-language") { LanguageAdvance.Run(); return 0; }
            if(args.Length!=0) return 2;
            var cfg=(Dictionary<string,object>)json.DeserializeObject(Environment.GetEnvironmentVariable("BNET_LAB_UIA_CONFIG"));
            var targets=(object[])cfg["targets"];
            if(targets.Length>8) return 2;
            var report=Report(targets.Length);
            // Empty-scope smoke test loads the runtime/serializer without any desktop traversal.
            if(targets.Length==0) { Console.WriteLine(json.Serialize(report)); return 0; }
            Probe(cfg,targets,report);
            Console.WriteLine(json.Serialize(report)); return 0;
        } catch { return 3; } // No raw provider exceptions/paths/configuration leave the helper.
    }
    static void Probe(Dictionary<string,object> cfg,object[] targets,Dictionary<string,object> report) {
        var allowed=new HashSet<string>(); foreach(var v in (object[])cfg["types"]) allowed.Add((string)v);
        var readable=new HashSet<string>(); foreach(var v in (object[])cfg["readable_types"]) readable.Add((string)v);
        var labels=(Dictionary<string,object>)cfg["labels"];
        var markerList=(object[])cfg["markers"];
        var items=(List<object>)report["elements"];
        var watch=Stopwatch.StartNew(); var walker=TreeWalker.RawViewWalker; int errors=0; bool truncated=false;
        foreach(var value in targets) {
            if(watch.ElapsedMilliseconds>3000 || items.Count>=64) { truncated=true; break; }
            var target=(Dictionary<string,object>)value;
            int pid=Convert.ToInt32(target["pid"]); long hwnd=Convert.ToInt64(target["hwnd"]);
            try {
                var stack=new Stack<Node>(); stack.Push(new Node(AutomationElement.FromHandle(new IntPtr(hwnd)),0));
                while(stack.Count>0) {
                    if(watch.ElapsedMilliseconds>3000 || items.Count>=64) { truncated=true; break; }
                    var node=stack.Pop();
                    try {
                        var current=node.Element.Current;
                        if(current.ProcessId!=pid) continue;
                        string kind=current.ControlType.ProgrammaticName;
                        if(kind.StartsWith("ControlType.")) kind=kind.Substring(12);
                        if(!allowed.Contains(kind)) kind="Other";
                        bool password=current.IsPassword, offscreen=current.IsOffscreen, enabled=current.IsEnabled;
                        string label="not_read"; var markers=new List<string>();
                        if(!password && !offscreen && readable.Contains(kind)) {
                            string name=current.Name ?? "";
                            if(name.Length>512) name=name.Substring(0,512);
                            name=Regex.Replace(name.Replace("&","").Trim(),@"\s+"," ").ToLowerInvariant();
                            object mapped; label=labels.TryGetValue(name,out mapped)?(string)mapped:"unrecognized";
                            foreach(var v in markerList) {
                                string m=(string)v; string pattern=m=="sign_in"?@"\bsign[ _-]?in\b":@"\b"+Regex.Escape(m)+@"\b";
                                if(Regex.IsMatch(name,pattern)) markers.Add(m);
                            }
                        }
                        items.Add(new Dictionary<string,object> { {"pid",pid},{"depth",node.Depth},{"control_type",kind},
                            {"enabled",enabled},{"offscreen",offscreen},{"password",password},{"label",label},{"markers",markers} });
                        if(node.Depth>=6) { truncated=true; continue; }
                        var child=walker.GetFirstChild(node.Element); int siblings=0;
                        while(child!=null) {
                            if(watch.ElapsedMilliseconds>3000 || stack.Count>=64 || siblings>=64) { truncated=true; break; }
                            stack.Push(new Node(child,node.Depth+1)); child=walker.GetNextSibling(child); siblings++;
                        }
                    } catch { errors++; }
                }
            } catch { errors++; }
        }
        report["truncated"]=truncated; report["errors"]=errors;
    }
}
