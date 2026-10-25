using System;using System.IO;using System.Text;using System.Linq;using System.Collections.Generic;using System.Threading;using System.Security.AccessControl;using System.Security.Principal;using System.Runtime.InteropServices;using System.Web.Script.Serialization;using Microsoft.Win32.SafeHandles;
// Local private capture helper only. No network, installer, firewall or task API.
public static class PrivateCaptureStore {
 static readonly JavaScriptSerializer J=new JavaScriptSerializer();
 static readonly SecurityIdentifier Admin=new SecurityIdentifier("S-1-5-32-544"),SystemSid=new SecurityIdentifier("S-1-5-18");
 const int MaxRecord=262144,MaxStore=1048576,MaxRecords=16;
 const uint ReadControl=0x20000,ReadAttributes=0x80,ReadData=1,OpenExisting=3,OpenReparse=0x200000,BackupSemantics=0x2000000;
 [StructLayout(LayoutKind.Sequential)]struct Info {public uint Attributes;public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write;public uint Volume,SizeHigh,SizeLow,Links,IndexHigh,IndexLow;}
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr sa,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)]static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder path,uint size,uint flags);
 [DllImport("advapi32.dll")]static extern uint GetSecurityInfo(SafeFileHandle h,int type,uint information,out IntPtr owner,out IntPtr group,out IntPtr dacl,out IntPtr sacl,out IntPtr descriptor);
 [DllImport("advapi32.dll")]static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
 [DllImport("kernel32.dll")]static extern IntPtr LocalFree(IntPtr memory);
 static void Demand(bool ok){if(!ok)throw new InvalidOperationException("private_store_rejected");}
 static bool Id(string s){return s!=null&&System.Text.RegularExpressions.Regex.IsMatch(s,"^[0-9a-f]{32}$");}
 static void VerifyDescriptor(RawSecurityDescriptor sd,bool dir,int mask){
  Demand(sd.Owner!=null&&(sd.Owner.Equals(Admin)||sd.Owner.Equals(SystemSid)));
  Demand((sd.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0&&sd.DiscretionaryAcl!=null&&sd.DiscretionaryAcl.Count==2);
  var seen=new HashSet<string>();
  foreach(GenericAce ga in sd.DiscretionaryAcl){var ace=ga as CommonAce;Demand(ace!=null&&ace.AceQualifier==AceQualifier.AccessAllowed&&!ace.IsCallback&&ace.AccessMask==mask);Demand(ace.AceFlags==(dir?(AceFlags.ContainerInherit|AceFlags.ObjectInherit):AceFlags.None));string sid=ace.SecurityIdentifier.Value;Demand((sid==Admin.Value||sid==SystemSid.Value)&&seen.Add(sid));}
 }
 static Info VerifyHandle(SafeFileHandle h,string expected,bool dir){
  Demand(!h.IsInvalid);Info i;Demand(GetFileInformationByHandle(h,out i));Demand((i.Attributes&0x400)==0&&((i.Attributes&0x10)!=0)==dir);if(!dir)Demand(i.Links==1&&i.SizeHigh==0&&i.SizeLow<=MaxRecord);
  var path=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(h,path,(uint)path.Capacity,0);Demand(n>0&&n<path.Capacity);string full=path.ToString();if(full.StartsWith(@"\\?\"))full=full.Substring(4);Demand(String.Equals(full,expected,StringComparison.OrdinalIgnoreCase));
  IntPtr owner,group,dacl,sacl,sd;Demand(GetSecurityInfo(h,1,1|4,out owner,out group,out dacl,out sacl,out sd)==0);
  try{uint len=GetSecurityDescriptorLength(sd);Demand(len>0&&len<65536);var bytes=new byte[len];Marshal.Copy(sd,bytes,0,(int)len);VerifyDescriptor(new RawSecurityDescriptor(bytes,0),dir,0x1f01ff);}finally{LocalFree(sd);}return i;
 }
 static DirectorySecurity DirectoryAcl(){var s=new DirectorySecurity();s.SetOwner(Admin);s.SetAccessRuleProtection(true,false);foreach(var sid in new[]{Admin,SystemSid})s.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));return s;}
 static FileSecurity FileAcl(){var s=new FileSecurity();s.SetOwner(Admin);s.SetAccessRuleProtection(true,false);foreach(var sid in new[]{Admin,SystemSid})s.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,AccessControlType.Allow));return s;}
 static MutexSecurity MutexAcl(){var s=new MutexSecurity();s.SetOwner(Admin);s.SetAccessRuleProtection(true,false);foreach(var sid in new[]{Admin,SystemSid})s.AddAccessRule(new MutexAccessRule(sid,MutexRights.FullControl,AccessControlType.Allow));return s;}
 static SafeFileHandle Open(string path,bool dir){var h=CreateFileW(path,ReadControl|ReadAttributes|(dir?0:ReadData),dir?3u:1u,IntPtr.Zero,OpenExisting,OpenReparse|(dir?BackupSemantics:0),IntPtr.Zero);try{VerifyHandle(h,path,dir);return h;}catch{h.Dispose();throw;}}
 static List<SafeFileHandle> Roots(string root,bool init){
  string b=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"BNetOnlineG40");root=Path.GetFullPath(root);string session=Path.GetDirectoryName(root);Demand(Id(Path.GetFileName(session))&&String.Equals(Path.GetDirectoryName(session),b,StringComparison.OrdinalIgnoreCase)&&Path.GetFileName(root)=="quarantine");
  var holds=new List<SafeFileHandle>();try{foreach(string p in new[]{b,session,root}){if(init&&!Directory.Exists(p))Directory.CreateDirectory(p,DirectoryAcl());holds.Add(Open(p,true));}return holds;}catch{foreach(var h in holds)h.Dispose();throw;}
 }
 static Tuple<int,long> Inventory(string root){int count=0;long bytes=0;foreach(string p in Directory.GetFileSystemEntries(root)){Demand(Path.GetExtension(p)==".json"&&Id(Path.GetFileNameWithoutExtension(p)));using(var h=Open(p,false)){Info i=VerifyHandle(h,p,false);count++;bytes+=i.SizeLow;}}Demand(count<=MaxRecords&&bytes<=MaxStore);return Tuple.Create(count,bytes);}
 static string Input(){var b=new StringBuilder();char[] c=new char[4096];int n;while((n=Console.In.Read(c,0,c.Length))>0){b.Append(c,0,n);Demand(b.Length<=MaxRecord);}return b.ToString();}
 static int Main(string[] args){
  try{
   Demand(args.Length==2||args.Length==3);string action=args[0],root=Path.GetFullPath(args[1]);Demand(action=="init"||action=="write"||action=="read");Demand(args.Length==(action=="read"?3:2));
   var holds=Roots(root,action=="init");try{
    bool created;string mutexName="Global\\BNetPrivateG40_"+Path.GetFileName(Path.GetDirectoryName(root));using(var mutex=new Mutex(false,mutexName,out created,MutexAcl())){
     VerifyDescriptor(new RawSecurityDescriptor(mutex.GetAccessControl().GetSecurityDescriptorBinaryForm(),0),false,0x1f0001);bool held=false;
     try{held=mutex.WaitOne(10000);Demand(held);var inventory=Inventory(root);
      if(action=="init"){Console.WriteLine(J.Serialize(new{ok=true}));return 0;}
      if(action=="read"){
       Demand(Id(args[2]));string p=Path.Combine(root,args[2]+".json");byte[] bytes;
       using(var h=Open(p,false))using(var f=new FileStream(h,FileAccess.Read)){Demand(f.Length<=MaxRecord);bytes=new byte[(int)f.Length];int pos=0,n;while(pos<bytes.Length&&(n=f.Read(bytes,pos,bytes.Length-pos))>0)pos+=n;Demand(pos==bytes.Length);}
       object record=J.DeserializeObject(Encoding.UTF8.GetString(bytes));Console.WriteLine(J.Serialize(new{ok=true,record=record}));return 0;
      }
      string text=Input();byte[] data=new UTF8Encoding(false,true).GetBytes(text);Demand(data.Length<=MaxRecord&&inventory.Item1<MaxRecords&&inventory.Item2+data.Length<=MaxStore);
      var recordObject=J.DeserializeObject(text) as Dictionary<string,object>;Demand(recordObject!=null&&recordObject.ContainsKey("approval_granted")&&Object.Equals(recordObject["approval_granted"],false));
      string id=Guid.NewGuid().ToString("N"),file=Path.Combine(root,id+".json");bool made=false;
      try{using(var f=new FileStream(file,FileMode.CreateNew,FileSystemRights.FullControl,FileShare.None,4096,FileOptions.WriteThrough,FileAcl())){made=true;VerifyHandle(f.SafeFileHandle,file,false);f.Write(data,0,data.Length);f.Flush(true);VerifyHandle(f.SafeFileHandle,file,false);}}
      catch{if(made)File.Delete(file);throw;}
      Console.WriteLine(J.Serialize(new{ok=true,capture_id=id}));return 0;
     }finally{if(held)mutex.ReleaseMutex();}
    }
   }finally{foreach(var h in holds)h.Dispose();}
  }catch{Console.WriteLine("{\"ok\":false,\"error\":\"private_store_rejected\"}");return 2;}
 }
}
