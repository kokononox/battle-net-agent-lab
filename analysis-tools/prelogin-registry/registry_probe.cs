using System;using System.Runtime.InteropServices;using Microsoft.Win32;
public class RegistryProbe {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegOpenKeyExW(IntPtr h,string s,uint o,uint a,out IntPtr k);
 [DllImport("advapi32.dll",CharSet=CharSet.Ansi,ExactSpelling=true)] static extern int RegOpenKeyExA(IntPtr h,string s,uint o,uint a,out IntPtr k);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegSetValueExW(IntPtr h,string n,uint z,uint t,byte[] b,uint l);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegQueryValueExW(IntPtr h,string n,IntPtr z,out uint t,byte[] b,ref uint l);
 [DllImport("advapi32.dll",CharSet=CharSet.Ansi,ExactSpelling=true)] static extern int RegQueryValueExA(IntPtr h,string n,IntPtr z,out uint t,byte[] b,ref uint l);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)] static extern int RegGetValueW(IntPtr h,string s,string n,uint f,out uint t,byte[] b,ref uint l);
 [DllImport("advapi32.dll",ExactSpelling=true)] static extern int RegCloseKey(IntPtr h);
 public static int Main(){const string path=@"Software\BattleNetAgentLab\RegistryProbe";IntPtr k=IntPtr.Zero;int rc=1;
 try{using(var x=Registry.CurrentUser.CreateSubKey(path)){};
 if(RegOpenKeyExW(new IntPtr(unchecked((int)0x80000001)),path,0,0x2001f,out k)!=0)return 2;
 byte[] v=System.Text.Encoding.Unicode.GetBytes("abcdefab-abcd-4abc-abcd-abcdefabcdef\0");if(RegSetValueExW(k,"UserUUID",0,1,v,(uint)v.Length)!=0)return 3;
 uint t,n=256;byte[] b=new byte[256];if(RegQueryValueExW(k,"UserUUID",IntPtr.Zero,out t,b,ref n)!=0)return 4;
 n=256;if(RegQueryValueExA(k,"UserUUID",IntPtr.Zero,out t,b,ref n)!=0)return 5;
 n=256;if(RegGetValueW(k,null,"UserUUID",2,out t,b,ref n)!=0)return 6;
 n=256;if(RegQueryValueExW(k,"Missing",IntPtr.Zero,out t,b,ref n)!=2)return 7;
 // A size-only success is not a value witness. Wrong-path/name must not match.
 n=0;if(RegQueryValueExW(k,"UserUUID",IntPtr.Zero,out t,null,ref n)!=0)return 8;
 RegCloseKey(k);k=IntPtr.Zero;
 if(RegOpenKeyExA(new IntPtr(unchecked((int)0x80000001)),path,0,0x20019,out k)!=0)return 9;
 n=256;if(RegQueryValueExW(k,"UserUUID",IntPtr.Zero,out t,b,ref n)!=0)return 10;rc=0;
 }catch{rc=20;}finally{if(k!=IntPtr.Zero)RegCloseKey(k);Registry.CurrentUser.DeleteSubKeyTree(path,false);}return rc;
 }
}
