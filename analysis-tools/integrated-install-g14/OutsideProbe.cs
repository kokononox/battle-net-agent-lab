// Inert bounded fixture: no sockets, installer, account, persistence beyond test-owned SCM/task.
using System;using System.IO;using System.Text;using System.Diagnostics;using System.Threading;using System.ServiceProcess;using System.Web.Script.Serialization;
public class OutsideProbe {
 static readonly JavaScriptSerializer Json=new JavaScriptSerializer();
 static string Receipt(string path){
  path=Path.GetFullPath(path);string prefix=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"BNetOutsideG14")+"\\";
  if(!path.StartsWith(prefix,StringComparison.OrdinalIgnoreCase)||Path.GetFileName(path)!="outside-ready.json"||!Directory.Exists(Path.GetDirectoryName(path)))throw new Exception();return path;
 }
 static void Ready(string path){using(var p=Process.GetCurrentProcess()){var o=new{pid=p.Id,created=p.StartTime.ToFileTimeUtc(),image=p.MainModule.FileName};File.WriteAllText(path,Json.Serialize(o),new UTF8Encoding(false));}}
 class FixtureService:ServiceBase {string PathValue;Timer timer;public FixtureService(string name,string path){if(!name.StartsWith("BNetOutsideG14_"))throw new Exception();ServiceName=name;PathValue=path;CanStop=true;AutoLog=false;}
 protected override void OnStart(string[] args){Ready(PathValue);timer=new Timer(delegate(object o){try{Stop();}catch{}},null,360000,Timeout.Infinite);}
 protected override void OnStop(){if(timer!=null)timer.Dispose();}}
 static int Main(string[] args){try{
  if(args.Length==3&&args[0]=="service"){ServiceBase.Run(new FixtureService(args[1],Receipt(args[2])));return 0;}
  if(args.Length!=2||(args[0]!="task"&&args[0]!="child"))return 4;
  Ready(Receipt(args[1]));Thread.Sleep(360000);return 0;
 }catch{return 3;}}
}
