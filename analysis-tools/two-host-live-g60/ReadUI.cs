using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;
using System.Windows.Automation;
public class ReadUI {
 delegate bool CB(IntPtr hwnd,IntPtr param);
 [DllImport("user32.dll")]static extern bool EnumWindows(CB cb,IntPtr p);
 [DllImport("user32.dll")]static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
 [DllImport("user32.dll")]static extern bool IsWindowVisible(IntPtr h);
 static HashSet<int> pids=new HashSet<int>();static List<object> rows=new List<object>();static int errors=0,nodes=0,windows=0;static bool truncated=false;
 static Stopwatch watch=new Stopwatch();
 static HashSet<string> labels=new HashSet<string>{"ok","continue","cancel","install","next","back","close","language","select a language","english (us)","english","battle.net setup","setup","updating battle.net","installing battle.net"};
 static string[] marks={"language","error","install","update","login","network","initializing","connecting","download","failed","language selection","english","connection","retry"};
 static void Visit(AutomationElement e,int depth){
  if(e==null||depth>6)return;
  if(nodes>=128||watch.ElapsedMilliseconds>3500){truncated=true;return;}nodes++;
  try{
   var c=e.Current;if(!pids.Contains(c.ProcessId))return;
   string type=c.ControlType.ProgrammaticName.Replace("ControlType.","");
   if(!c.IsOffscreen&&!c.IsPassword&&type!="Edit"&&type!="Document"){
    string name="";bool readable=type=="Hyperlink"||type=="Window"||type=="Text"||type=="Button"||type=="ComboBox"||type=="CheckBox"||type=="RadioButton";
    if(readable){name=c.Name??"";if(name.Length>512)name="";name=Regex.Replace(name.Replace("&"," ").ToLowerInvariant(),@"\s+"," ").Trim();}
    var found=new List<string>();foreach(var marker in marks){if(readable&&Regex.IsMatch(name,@"\b"+Regex.Escape(marker)+@"\b"))found.Add(marker);}
    var codes=new List<string>();foreach(Match hit in Regex.Matches(name,@"\bblz[a-z0-9]{4,40}\b",RegexOptions.IgnoreCase)){codes.Add(hit.Value.ToUpperInvariant());}
    var messageClasses=new List<string>();foreach(var phrase in new[]{"whoops","something broke","can't connect","cannot connect","patch service","internet connection","unable to","try again"}){if(name.Contains(phrase))messageClasses.Add(phrase);}
    rows.Add(new{error_codes=codes,message_classes=messageClasses,type=type,label=!readable?"not_read":labels.Contains(name)?name:"unrecognized",markers=found,enabled=c.IsEnabled});
   }
   var child=TreeWalker.ControlViewWalker.GetFirstChild(e);
   while(child!=null){Visit(child,depth+1);if(truncated)return;child=TreeWalker.ControlViewWalker.GetNextSibling(child);}
  }catch{errors++;}
 }
 public static int Main(string[] args){
  foreach(string s in args){int p;if(!Int32.TryParse(s,out p)||p<=0||pids.Count>=24)return 2;pids.Add(p);}
  if(pids.Count==0)return 3;
  watch.Start();
  EnumWindows(delegate(IntPtr h,IntPtr _){uint p;GetWindowThreadProcessId(h,out p);if(pids.Contains((int)p)&&IsWindowVisible(h)){windows++;try{Visit(AutomationElement.FromHandle(h),0);}catch{errors++;}}return !truncated;},IntPtr.Zero);
  Console.WriteLine(new JavaScriptSerializer().Serialize(new{status="completed_bounded_read",windows=windows,nodes=nodes,rows=rows,errors=errors,truncated=truncated,raw_text_exported=false,actions_performed=false,coverage_complete=false}));return 0;
 }
}
