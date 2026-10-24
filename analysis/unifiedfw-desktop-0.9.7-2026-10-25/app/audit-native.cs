// Fixed subcategory only. No firewall APIs. Compilable with Windows PowerShell 5.1 Add-Type.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace UnifiedAudit096 {
 public static class Native {
  public static readonly Guid Subcategory=new Guid("0CCE9226-69AE-11D9-BED3-505054503030");
  [StructLayout(LayoutKind.Sequential)] public struct Policy { public Guid Subcategory; public uint Flags; public Guid Category; }
  [StructLayout(LayoutKind.Sequential)] struct Luid { public uint Low; public int High; }
  [StructLayout(LayoutKind.Sequential)] struct Privileges { public uint Count; public Luid Luid; public uint Attributes; }
  [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditQuerySystemPolicy(ref Guid ids,uint count,out IntPtr policy);
  [DllImport("advapi32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.U1)] static extern bool AuditSetSystemPolicy(ref Policy policy,uint count);
  [DllImport("advapi32.dll")] static extern void AuditFree(IntPtr buffer);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint rights,out IntPtr token);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeValue(string system,string name,out Luid luid);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token,bool disable,ref Privileges state,uint length,IntPtr previous,IntPtr returned);
  [DllImport("kernel32.dll")] static extern void SetLastError(uint error);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint QueryDosDevice(string device,StringBuilder target,int size);
  public static void EnableSecurityPrivilege(){
   IntPtr token; if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Win32Exception(Marshal.GetLastWin32Error());
   try { Luid luid;if(!LookupPrivilegeValue(null,"SeSecurityPrivilege",out luid))throw new Win32Exception(Marshal.GetLastWin32Error());
    Privileges p=new Privileges{Count=1,Luid=luid,Attributes=2};SetLastError(0);bool ok=AdjustTokenPrivileges(token,false,ref p,0,IntPtr.Zero,IntPtr.Zero);int error=Marshal.GetLastWin32Error();if(!ok||error!=0)throw new Win32Exception(error);
   }finally{CloseHandle(token);}
  }
  public static uint Read(){Guid id=Subcategory;IntPtr p;if(!AuditQuerySystemPolicy(ref id,1,out p))throw new Win32Exception(Marshal.GetLastWin32Error());
   try {Policy policy=(Policy)Marshal.PtrToStructure(p,typeof(Policy));if(policy.Subcategory!=Subcategory)throw new InvalidOperationException("audit_subcategory_mismatch");return policy.Flags;}finally{AuditFree(p);}
  }
  public static void Write(uint flags){if(flags!=1&&flags!=2&&flags!=3&&flags!=4)throw new ArgumentException("audit_flags");Policy p=new Policy{Subcategory=Subcategory,Flags=flags};if(!AuditSetSystemPolicy(ref p,1))throw new Win32Exception(Marshal.GetLastWin32Error());}
  public static string DevicePath(string path){if(path==null||path.Length<3||path[1]!=':')return "";StringBuilder b=new StringBuilder(32768);return QueryDosDevice(path.Substring(0,2),b,b.Capacity)==0?"":b.ToString()+path.Substring(2);}
 }
}
