// Read-only PrintWindow capture of one verified setup options window, never desktop.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;
using System.Web.Script.Serialization;
using System.Windows.Automation;
public static class SetupVisual {
    [StructLayout(LayoutKind.Sequential)] struct Rect {public int L,T,R,B;}
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h,out Rect r);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h,out uint p);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags);
    static JavaScriptSerializer json=new JavaScriptSerializer{MaxJsonLength=100000};
    static bool Page(AutomationElement root,int pid) {
        var stack=new Stack<AutomationElement>();stack.Push(root);var watch=Stopwatch.StartNew();int count=0,buttons=0,changes=0,boxes=0,texts=0;
        while(stack.Count>0){
            if(++count>16||watch.ElapsedMilliseconds>2000)return false;
            var e=stack.Pop();var c=e.Current;
            if(c.ProcessId!=pid||!c.IsEnabled||c.IsPassword||c.IsOffscreen)return false;
            var t=c.ControlType;
            if(t==ControlType.Window){if(!Automation.Compare(e,root)||c.Name!="Battle.net Setup")return false;}
            else if(t==ControlType.Text){texts++;}
            else if(t==ControlType.CheckBox){boxes++;}
            else if(t==ControlType.Button){if(c.Name!="Continue")return false;buttons++;}
            else if(t==ControlType.Hyperlink){if(c.Name!="Change")return false;changes++;}
            else return false;
            var child=TreeWalker.RawViewWalker.GetFirstChild(e);int siblings=0;
            while(child!=null){if(++siblings>8||stack.Count>=16)return false;stack.Push(child);child=TreeWalker.RawViewWalker.GetNextSibling(child);}
        }
        return buttons==1&&changes==1&&boxes==1&&texts==2;
    }
    public static void Run(){
        var result=new Dictionary<string,object>{{"status","refused"},{"width",0},{"height",0},{"image_png_base64",null}};
        try{
            var cfg=(Dictionary<string,object>)json.DeserializeObject(Environment.GetEnvironmentVariable("BNET_LAB_VISUAL_CONFIG"));
            int pid=Convert.ToInt32(cfg["pid"]);var hwnd=new IntPtr(Convert.ToInt64(cfg["hwnd"]));uint owner;
            GetWindowThreadProcessId(hwnd,out owner);
            if(owner!=(uint)pid||!IsWindowVisible(hwnd))throw new Exception();
            using(var p=Process.GetProcessById(pid)){
                string name=p.ProcessName.ToLowerInvariant().Replace(" ","");
                if(name!="battle.netsetup"&&name!="battle.net-setup")throw new Exception();
                var signed=AuthenticodeNative.Verify(p.MainModule.FileName);
                if((int)signed["trust_status"]!=0||!(bool)signed["expected_blizzard_publisher"])throw new Exception();
            }
            var root=AutomationElement.FromHandle(hwnd);if(!Page(root,pid))throw new Exception();
            Rect rect;if(!GetWindowRect(hwnd,out rect))throw new Exception();int w=rect.R-rect.L,h=rect.B-rect.T;
            if(w<100||h<100||w>1024||h>768)throw new Exception();
            using(var bitmap=new Bitmap(w,h)){
                using(var graphics=Graphics.FromImage(bitmap)){
                    IntPtr dc=graphics.GetHdc();bool printed;
                    try{printed=PrintWindow(hwnd,dc,2);}finally{graphics.ReleaseHdc(dc);}
                    if(!printed)throw new Exception();
                }
                // Refuse any window transition during capture; no whole-screen fallback.
                if(!Page(AutomationElement.FromHandle(hwnd),pid))throw new Exception();
                using(var stream=new MemoryStream()){
                    bitmap.Save(stream,ImageFormat.Png);byte[] bytes=stream.ToArray();if(bytes.Length>65536)throw new Exception();
                    result["status"]="captured";result["width"]=w;result["height"]=h;result["image_png_base64"]=Convert.ToBase64String(bytes);
                }
            }
        }catch{result["status"]="refused";}
        Console.WriteLine(json.Serialize(result));
    }
}
