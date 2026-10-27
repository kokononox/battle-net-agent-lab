// Native audit masks and DOS-device mapping only. No program launcher or firewall writer.
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace UfwRuntime01 {
 [StructLayout(LayoutKind.Sequential)] public struct AuditInfo { public Guid Subcategory; public uint Flags; public Guid Category; }
 [StructLayout(LayoutKind.Sequential)] internal struct Luid {public uint Low; public int High;}
 [StructLayout(LayoutKind.Sequential)] internal struct TokenPrivileges {public uint Count;public Luid Id;public uint Attributes;}
 public sealed class SecurityPrivilege : IDisposable {
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid id);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref TokenPrivileges state,int length,out TokenPrivileges previous,out int returned);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  IntPtr handle;TokenPrivileges old;bool enabled;
  public SecurityPrivilege() {
   if(Environment.OSVersion.Platform!=PlatformID.Win32NT)throw new InvalidOperationException("ufw_runtime_windows_required");
   if(!OpenProcessToken(GetCurrentProcess(),0x28,out handle))throw new InvalidOperationException("ufw_runtime_security_privilege_unavailable");
   try {
    Luid id;if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out id))throw new InvalidOperationException("ufw_runtime_security_privilege_unavailable");
    TokenPrivileges next=new TokenPrivileges{Count=1,Id=id,Attributes=2};int returned;
    if(!AdjustTokenPrivileges(handle,false,ref next,Marshal.SizeOf(typeof(TokenPrivileges)),out old,out returned)||Marshal.GetLastWin32Error()!=0)throw new InvalidOperationException("ufw_runtime_security_privilege_unavailable");
    enabled=true;
   }catch{CloseHandle(handle);handle=IntPtr.Zero;throw;}
  }
  public void Dispose(){if(handle==IntPtr.Zero)return;bool ok=true;try{if(enabled){TokenPrivileges ignored;int n;ok=AdjustTokenPrivileges(handle,false,ref old,Marshal.SizeOf(typeof(TokenPrivileges)),out ignored,out n)&&Marshal.GetLastWin32Error()==0;}}finally{CloseHandle(handle);handle=IntPtr.Zero;}if(!ok)throw new InvalidOperationException("ufw_runtime_privilege_restore_failed");}
 }
 public static class Audit {
  [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.U1)] static extern bool AuditQuerySystemPolicy([In] Guid[] ids,uint count,out IntPtr data);
  [DllImport("advapi32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.U1)] static extern bool AuditSetSystemPolicy([In] AuditInfo[] values,uint count);
  [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr p);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint QueryDosDevice(string name,StringBuilder target,int length);
  public static uint Query(string id){IntPtr p;if(!AuditQuerySystemPolicy(new[]{new Guid(id)},1,out p))throw new InvalidOperationException("ufw_runtime_audit_query_failed");try{AuditInfo x=(AuditInfo)Marshal.PtrToStructure(p,typeof(AuditInfo));if(x.Subcategory!=new Guid(id)||(x.Flags&~7u)!=0)throw new InvalidOperationException("ufw_runtime_audit_query_shape");return x.Flags&3u;}finally{AuditFree(p);}}
  public static void Set(string id,uint flags){if(flags>3)throw new InvalidOperationException("ufw_runtime_audit_mask");AuditInfo[] v={new AuditInfo{Subcategory=new Guid(id),Flags=flags==0?4u:flags,Category=Guid.Empty}};if(!AuditSetSystemPolicy(v,1))throw new InvalidOperationException("ufw_runtime_audit_set_failed");}
  public static string Device(string drive){StringBuilder b=new StringBuilder(32768);if(QueryDosDevice(drive,b,b.Capacity)==0)throw new InvalidOperationException("ufw_runtime_device_mapping_failed");string s=b.ToString();int nul=s.IndexOf('\0');if(nul>=0)s=s.Substring(0,nul);if(!s.StartsWith(@"\Device\",StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("ufw_runtime_device_mapping_invalid");return s;}
 }
}
