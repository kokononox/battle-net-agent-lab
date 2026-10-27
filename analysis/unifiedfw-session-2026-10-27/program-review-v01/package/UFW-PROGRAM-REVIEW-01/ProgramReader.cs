// Read-only Windows file observation. No execution, network, trust verification or policy writes.
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace UfwProgramReview01 {
 public sealed class Observation {
  public string Path;
  public string Sha256;
  public string FileId;
  public string VolumeId;
  public string Architecture;
  public long Length;
  public bool SameHandleDoubleHashMatched;
  public bool NativeIdentityObserved;
  public bool AuthenticodeVerified;
  public bool ProgramTrusted;
  public bool ExecutionAuthorized;
 }
 public static class Reader {
  [StructLayout(LayoutKind.Sequential)] private struct Time {public uint Low;public uint High;}
  [StructLayout(LayoutKind.Sequential)] private struct Info {
   public uint Attributes;public Time Created;public Time Accessed;public Time Written;
   public uint Volume;public uint SizeHigh;public uint SizeLow;public uint Links;public uint IndexHigh;public uint IndexLow;
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern SafeFileHandle CreateFileW(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] [return:MarshalAs(UnmanagedType.Bool)] private static extern bool GetFileInformationByHandle(SafeFileHandle handle,out Info info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle,StringBuilder text,uint length,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] private static extern uint GetDriveTypeW(string root);
  private static void Fail(string code){throw new InvalidOperationException(code);}
  public static string ValidatePathText(string value) {
   if(value==null || value.Length<8 || value.Length>260 || !Regex.IsMatch(value,@"^[A-Z]:\\") || value.IndexOfAny(new char[]{'/','*','?','%','"','<','>','|'})>=0 || value.Substring(2).Contains(":")) Fail("ufw_program_exact_local_exe_path");
   foreach(char c in value) if(c<32) Fail("ufw_program_exact_local_exe_path");
   string[] parts=value.Substring(3).Split('\\');
   foreach(string p in parts){if(p.Length==0 || p=="." || p==".." || p.EndsWith(".") || p.EndsWith(" ") || Regex.IsMatch(p.Split('.')[0],@"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$",RegexOptions.IgnoreCase)) Fail("ufw_program_exact_local_exe_path");}
   string leaf=parts[parts.Length-1];
   if(!leaf.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)) Fail("ufw_program_exact_local_exe_path");
   if(leaf.Equals("svchost.exe",StringComparison.OrdinalIgnoreCase) || leaf.Equals("rundll32.exe",StringComparison.OrdinalIgnoreCase) || leaf.Equals("dllhost.exe",StringComparison.OrdinalIgnoreCase)) Fail("ufw_program_shared_host_requires_service_design");
   return value;
  }
  private static void PinParents(string path,System.Collections.Generic.List<SafeFileHandle> pins) {
   string full=System.IO.Path.GetFullPath(path);if(!String.Equals(full,path,StringComparison.OrdinalIgnoreCase)) Fail("ufw_program_noncanonical_path");
   string current=path.Substring(0,3);string[] parts=path.Substring(3).Split('\\');
   // Root-to-leaf, open final directory component itself, reject reparse before descending.
   // Hold parent handles without write/delete sharing until file observation completes.
   for(int i=0;i<parts.Length;i++) {
    SafeFileHandle h=CreateFileW(current,0x80,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
    pins.Add(h);if(h.IsInvalid) Fail("ufw_program_parent_pin_unavailable");
    Info info=GetInfo(h);
    if((info.Attributes & (uint)FileAttributes.Directory)==0 || (info.Attributes & (uint)FileAttributes.ReparsePoint)!=0) Fail("ufw_program_parent_reparse_or_not_directory");
    if(!String.Equals(FinalName(h).TrimEnd('\\'),current.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase)) Fail("ufw_program_parent_final_path_mismatch");
    if(i<parts.Length-1) current=System.IO.Path.Combine(current,parts[i]);
   }
  }
  private static Info GetInfo(SafeFileHandle h){Info v;if(!GetFileInformationByHandle(h,out v)) Fail("ufw_program_native_info_unavailable");return v;}
  private static long Size(Info i){return ((long)i.SizeHigh<<32)|i.SizeLow;}
  private static bool Stable(Info a,Info b){return a.Volume==b.Volume && a.IndexHigh==b.IndexHigh && a.IndexLow==b.IndexLow && a.SizeHigh==b.SizeHigh && a.SizeLow==b.SizeLow && a.Written.High==b.Written.High && a.Written.Low==b.Written.Low && a.Created.High==b.Created.High && a.Created.Low==b.Created.Low && a.Attributes==b.Attributes && a.Links==b.Links;}
  private static string FinalName(SafeFileHandle h) {
   StringBuilder b=new StringBuilder(1024);uint n=GetFinalPathNameByHandleW(h,b,(uint)b.Capacity,0);
   if(n==0 || n>=b.Capacity) Fail("ufw_program_final_path_unavailable");
   string p=b.ToString();if(p.StartsWith(@"\\?\",StringComparison.Ordinal)) p=p.Substring(4);
   return p;
  }
  private static string Hash(Stream s){s.Position=0;using(SHA256 h=SHA256.Create()){return BitConverter.ToString(h.ComputeHash(s)).Replace("-","").ToLowerInvariant();}}
  // Public only to permit pure PE-header fixtures. Does not prove code safety/signature.
  public static string InspectPe(Stream stream) {
   if(stream==null || !stream.CanRead || !stream.CanSeek || stream.Length<96) Fail("ufw_program_pe_header");
   BinaryReader r=new BinaryReader(stream,Encoding.UTF8,true);stream.Position=0;
   if(r.ReadUInt16()!=0x5a4d) Fail("ufw_program_pe_header");stream.Position=0x3c;int offset=r.ReadInt32();
   if(offset<64 || offset>1048576 || offset>stream.Length-96) Fail("ufw_program_pe_header");
   stream.Position=offset;if(r.ReadUInt32()!=0x00004550) Fail("ufw_program_pe_header");
   ushort machine=r.ReadUInt16();ushort sections=r.ReadUInt16();stream.Position=offset+20;
   ushort optionalSize=r.ReadUInt16();ushort flags=r.ReadUInt16();
   if(sections==0 || sections>96 || (flags & 2)==0 || (flags & 0x2000)!=0) Fail("ufw_program_pe_not_application");
   if(optionalSize<96 || offset+24L+optionalSize+40L*sections>stream.Length) Fail("ufw_program_pe_header");
   ushort magic=r.ReadUInt16();string arch=null;
   if(machine==0x14c && magic==0x10b) arch="x86";
   else if(machine==0x8664 && magic==0x20b && optionalSize>=112) arch="x64";
   else Fail("ufw_program_pe_architecture_unsupported");
   stream.Position=offset+24+68;ushort subsystem=r.ReadUInt16();if(subsystem!=2 && subsystem!=3) Fail("ufw_program_pe_subsystem_unsupported");
   return arch;
  }
  public static Observation Observe(string requested) {
   if(Environment.OSVersion.Platform!=PlatformID.Win32NT) Fail("ufw_program_windows_required");
   ValidatePathText(requested);
   if(GetDriveTypeW(requested.Substring(0,3))!=3) Fail("ufw_program_fixed_local_drive_required");
   System.Collections.Generic.List<SafeFileHandle> parents=new System.Collections.Generic.List<SafeFileHandle>();
   try {
   PinParents(requested,parents);
   // GENERIC_READ, share READ only (no write/delete sharing), OPEN_EXISTING,
   // OPEN_REPARSE_POINT prevents silently following a swapped final component.
   using(SafeFileHandle handle=CreateFileW(requested,0x80000000,1,IntPtr.Zero,3,0x08200000,IntPtr.Zero)) {
    if(handle.IsInvalid) Fail("ufw_program_open_unavailable_or_file_busy");
    Info before=GetInfo(handle);
    if((before.Attributes & (uint)(FileAttributes.Directory|FileAttributes.ReparsePoint))!=0) Fail("ufw_program_not_regular_file");
    if(before.Links!=1) Fail("ufw_program_hardlinks_not_supported");
    if(Size(before)<96 || Size(before)>536870912) Fail("ufw_program_size_limit");
    string path=FinalName(handle);ValidatePathText(path);if(!String.Equals(path,requested,StringComparison.OrdinalIgnoreCase)) Fail("ufw_program_final_path_mismatch");
    using(FileStream stream=new FileStream(handle,FileAccess.Read,65536,false)) {
     string architecture=InspectPe(stream);string first=Hash(stream);Info middle=GetInfo(handle);string second=Hash(stream);Info after=GetInfo(handle);
     if(!Stable(before,middle) || !Stable(before,after) || first!=second) Fail("ufw_program_changed_during_observation");
     if(!String.Equals(FinalName(handle),path,StringComparison.OrdinalIgnoreCase)) Fail("ufw_program_final_path_changed");

     return new Observation{Path=path,Sha256=first,FileId=before.IndexHigh.ToString("x8")+before.IndexLow.ToString("x8"),VolumeId=before.Volume.ToString("x8"),Length=Size(before),Architecture=architecture,SameHandleDoubleHashMatched=true,NativeIdentityObserved=true,AuthenticodeVerified=false,ProgramTrusted=false,ExecutionAuthorized=false};
    }
   }
   } finally {for(int i=parents.Count-1;i>=0;i--) parents[i].Dispose();}
  }
 }
}
