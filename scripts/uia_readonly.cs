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

    const string CaptionWords="install installation location folder directory destination choose select path change battle.net start launch run startup automatically when windows computer desktop shortcut create account login sign log agreement license terms privacy accept agree continue update updating download downloading error failed retry network required space available disk recommended options additional open application";
    static Dictionary<string,object> Caption(string raw) {
        bool cut=raw.Length>512;string text=cut?raw.Substring(0,512):raw;
        bool path=Regex.IsMatch(text,@"\b[a-z]:[\\/]|\\\\",RegexOptions.IgnoreCase);
        text=Regex.Replace(text,@"\b[a-z]:[\\/][^\r\n]*|\\\\[^\r\n]*"," ",RegexOptions.IgnoreCase);
        text=Regex.Replace(text,@"(?:https?|file)://\S+|[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}"," ",RegexOptions.IgnoreCase);
        var allowed=new HashSet<string>(CaptionWords.Split(' '));var tokens=new List<string>();bool unknown=false;
        foreach(Match m in Regex.Matches(text.ToLowerInvariant(),@"[a-z]+(?:\.[a-z]+)?")) {
            if(allowed.Contains(m.Value)){if(!tokens.Contains(m.Value))tokens.Add(m.Value);}else unknown=true;
        }
        return new Dictionary<string,object>{{"tokens",tokens},{"has_path",path},{"has_unknown_words",unknown},{"truncated",cut},{"toggle_state","not_applicable"}};
    }
    static Dictionary<string,object> CaptionSelfTest() {
        var path=Caption(@"Install Location: C:\Users\PRIVATE\Battle.net");
        var words=(List<string>)path["tokens"];
        var checkbox=Caption("Launch Battle.net when you start your computer.");
        var hidden=Caption("private@example.invalid https://private.invalid/SECRET");
        var longText=Caption(new string('x',600));
        return new Dictionary<string,object>{
            {"path_redacted",(bool)path["has_path"]&&words.Count==2&&words[0]=="install"&&words[1]=="location"},
            {"startup_words",((List<string>)checkbox["tokens"]).Contains("launch")&&((List<string>)checkbox["tokens"]).Contains("computer")},
            {"addresses_redacted",((List<string>)hidden["tokens"]).Count==0},
            {"length_bounded",(bool)longText["truncated"]&&((List<string>)longText["tokens"]).Count==0}};
    }
    [STAThread]
    public static int Main(string[] args) {
        try {
            if(args.Length==1 && args[0]=="caption-selftest") { Console.WriteLine(json.Serialize(CaptionSelfTest())); return 0; }
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
                        string label="not_read"; var markers=new List<string>();Dictionary<string,object> caption=null;
                        if(!password && !offscreen && readable.Contains(kind)) {
                            string name=current.Name ?? "";
                            if(kind=="Text"||kind=="CheckBox") {
                                caption=Caption(name);
                                // Static Text only: values can hold the rendered directory/caption
                                // when its accessible Name is empty or a provider identifier.
                                // Never query input/edit/document/password/hidden control values.
                                if(kind=="Text"&&((List<string>)caption["tokens"]).Count==0&&!(bool)caption["has_path"]) {
                                    object textValue;
                                    if(node.Element.TryGetCurrentPattern(ValuePattern.Pattern,out textValue)) {
                                        var staticValue=(ValuePattern)textValue;
                                        caption=Caption(staticValue.Current.Value??"");
                                    }
                                    if(((List<string>)caption["tokens"]).Count==0&&!(bool)caption["has_path"]&&node.Element.TryGetCurrentPattern(TextPattern.Pattern,out textValue)) {
                                        var text=(TextPattern)textValue;
                                        caption=Caption(text.DocumentRange.GetText(512)??"");
                                    }
                                }
                                if(kind=="CheckBox") {
                                    caption["toggle_state"]="unavailable";object toggleObject;
                                    if(node.Element.TryGetCurrentPattern(TogglePattern.Pattern,out toggleObject)) {
                                        var toggle=(TogglePattern)toggleObject;
                                        caption["toggle_state"]=toggle.Current.ToggleState.ToString().ToLowerInvariant();
                                    }
                                }
                            }
                            if(name.Length>512) name=name.Substring(0,512);
                            name=Regex.Replace(name.Replace("&","").Trim(),@"\s+"," ").ToLowerInvariant();
                            object mapped; label=labels.TryGetValue(name,out mapped)?(string)mapped:"unrecognized";
                            foreach(var v in markerList) {
                                string m=(string)v; string pattern=m=="sign_in"?@"\bsign[ _-]?in\b":@"\b"+Regex.Escape(m)+@"\b";
                                if(Regex.IsMatch(name,pattern)) markers.Add(m);
                            }
                        }
                        items.Add(new Dictionary<string,object> { {"pid",pid},{"depth",node.Depth},{"control_type",kind},
                            {"enabled",enabled},{"offscreen",offscreen},{"password",password},{"label",label},{"markers",markers},{"caption_features",caption} });
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
