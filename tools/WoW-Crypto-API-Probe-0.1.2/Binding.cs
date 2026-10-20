using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
namespace WowCryptoProbe {
 sealed class Binding {
  public string Module,FileHash;public uint Rva;
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern IntPtr LoadLibraryEx(string file,IntPtr reserved,uint flags);
  [DllImport("kernel32.dll",CharSet=CharSet.Ansi,ExactSpelling=true,SetLastError=true)]static extern IntPtr GetProcAddress(IntPtr module,string name);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern bool GetModuleHandleEx(uint flags,IntPtr address,out IntPtr module);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern uint GetModuleFileName(IntPtr module,StringBuilder path,uint size);
  [DllImport("kernel32.dll")]static extern bool FreeLibrary(IntPtr module);
  public static Binding Resolve(){
   string sys=Path.GetFullPath(Environment.SystemDirectory).TrimEnd('\\');
   IntPtr wrapper=LoadLibraryEx(Path.Combine(sys,"secur32.dll"),IntPtr.Zero,0x800);if(wrapper==IntPtr.Zero)throw new InvalidOperationException("sspi_library_unavailable");
   try{IntPtr entry=GetProcAddress(wrapper,"EncryptMessage");IntPtr owner;
    if(entry==IntPtr.Zero||!GetModuleHandleEx(6,entry,out owner))throw new InvalidOperationException("sspi_entry_unavailable");
    var b=new StringBuilder(32768);uint n=GetModuleFileName(owner,b,(uint)b.Capacity);if(n==0||n>=b.Capacity)throw new InvalidOperationException("sspi_owner_unavailable");
    string path=Path.GetFullPath(b.ToString());if(!String.Equals(Path.GetDirectoryName(path),sys,StringComparison.OrdinalIgnoreCase))throw new InvalidOperationException("sspi_owner_not_system32");
    string module=Path.GetFileNameWithoutExtension(path);if(!Core.ModuleOK(module))throw new InvalidOperationException("sspi_module_name_unsupported");
    long offset=entry.ToInt64()-owner.ToInt64();if(offset<=0||offset>0x7fffffff)throw new InvalidOperationException("sspi_offset_out_of_bounds");
    // Bound to this mapped module's actual SizeOfImage, not its forwarder symbol name.
    int pe=Marshal.ReadInt32(owner,0x3c);if(pe<0x40||pe>0x100000)throw new InvalidOperationException("sspi_image_invalid");
    if(Marshal.ReadInt32(owner,pe)!=0x4550)throw new InvalidOperationException("sspi_image_invalid");
    uint imageSize=unchecked((uint)Marshal.ReadInt32(owner,pe+24+56));if(offset>=imageSize)throw new InvalidOperationException("sspi_offset_outside_image");
    return new Binding{Module=module,Rva=(uint)offset,FileHash=Core.Sha(path)};
   }finally{FreeLibrary(wrapper);}
  }
 }
}
