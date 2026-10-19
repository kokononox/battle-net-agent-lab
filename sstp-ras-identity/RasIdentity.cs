using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
namespace SstpIdentityV1 {
 [StructLayout(LayoutKind.Sequential, Pack=4, CharSet=CharSet.Unicode)]
 public struct RasConnW {
  public uint Size; public IntPtr Handle;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string EntryName;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=17)] public string DeviceType;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=129)] public string DeviceName;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string Phonebook;
  public uint SubEntry; public Guid EntryGuid; public uint Flags;
  // This is a LOGON SESSION LUID, NOT a NET_LUID. Never pass it to IP Helper.
  public uint LogonLuidLow; public int LogonLuidHigh; public Guid CorrelationGuid;
 }
 [StructLayout(LayoutKind.Sequential,Pack=4,CharSet=CharSet.Unicode)]
 public struct RasPppIpW {
  public uint Size; public uint Error;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=16)] public string ClientAddress;
  [MarshalAs(UnmanagedType.ByValTStr,SizeConst=16)] public string ServerAddress;
  public uint Options; public uint ServerOptions;
 }
 public sealed class RasRecord {
  public IntPtr Handle; public Guid EntryGuid; public Guid CorrelationGuid;
  public string EntryName; public string DeviceType; public bool AllUsers;
 }
 public sealed class NicRecord {
  public Guid Guid; public uint Index; public string Name; public int Type; public bool Up; public string[] IPv4;
 }
 public sealed class InterfaceIdentity { public uint Index; public ulong NetLuid; public Guid Guid; }
 public static class Native {
  public const uint AllUsersMask=1; public const uint ProjectionKind=0x8021; public const int PppIfType=23;
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("rasapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
  private static extern uint RasEnumConnectionsW(IntPtr records,ref uint bytes,out uint count);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("rasapi32.dll",CharSet=CharSet.Unicode,ExactSpelling=true)]
  private static extern uint RasGetProjectionInfoW(IntPtr handle,uint projection,ref RasPppIpW value,ref uint bytes);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("iphlpapi.dll",ExactSpelling=true)]
  private static extern uint ConvertInterfaceIndexToLuid(uint index,out ulong luid);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("iphlpapi.dll",ExactSpelling=true)]
  private static extern uint ConvertInterfaceLuidToIndex(ref ulong luid,out uint index);
  [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
  [DllImport("iphlpapi.dll",ExactSpelling=true)]
  private static extern uint ConvertInterfaceLuidToGuid(ref ulong luid,out Guid guid);
  public static int RasSize { get { return Marshal.SizeOf(typeof(RasConnW)); } }
  public static int ProjectionSize { get { return Marshal.SizeOf(typeof(RasPppIpW)); } }
  public static int Offset(string member) { return Marshal.OffsetOf(typeof(RasConnW),member).ToInt32(); }
  public static RasRecord[] Enumerate() {
   int size=RasSize;
   if (size!=(IntPtr.Size==8?1388:1384) || ProjectionSize!=80) throw new InvalidOperationException("binding_abi_unexpected");
   const int cap=128;int total=checked(size*cap);IntPtr p=Marshal.AllocHGlobal(total);
   try {
    Marshal.Copy(new byte[total],0,p,total);Marshal.WriteInt32(p,size);
    uint bytes=(uint)total,count;uint code=RasEnumConnectionsW(p,ref bytes,out count);
    if (code!=0) throw new InvalidOperationException("ras_enum_api_"+code);
    if (count>cap || bytes>total || (ulong)count*(uint)size>(uint)total) throw new InvalidOperationException("binding_ras_bounds");
    List<RasRecord> rows=new List<RasRecord>();
    for(int i=0;i<count;i++) {
     RasConnW r=(RasConnW)Marshal.PtrToStructure(IntPtr.Add(p,checked(i*size)),typeof(RasConnW));
     if(r.Size!=(uint)size) throw new InvalidOperationException("binding_ras_record_size");
     rows.Add(new RasRecord {Handle=r.Handle,EntryGuid=r.EntryGuid,CorrelationGuid=r.CorrelationGuid,EntryName=r.EntryName,DeviceType=r.DeviceType,AllUsers=((r.Flags&AllUsersMask)!=0)});
    }
    return rows.ToArray();
   } finally { Marshal.FreeHGlobal(p); }
  }
  public static string ProjectionIPv4(IntPtr handle) {
   if(handle==IntPtr.Zero) throw new InvalidOperationException("binding_zero_ras_handle");
   RasPppIpW v=new RasPppIpW();v.Size=(uint)ProjectionSize;uint bytes=v.Size;
   uint code=RasGetProjectionInfoW(handle,ProjectionKind,ref v,ref bytes);
   if(code!=0) throw new InvalidOperationException("ras_projection_api_"+code);
   if(v.Error!=0) throw new InvalidOperationException("ras_projection_negotiation_"+v.Error);
   if(v.Size!=(uint)ProjectionSize || bytes>(uint)ProjectionSize) throw new InvalidOperationException("binding_projection_size");
   IPAddress ip;if(!IPAddress.TryParse(v.ClientAddress,out ip) || ip.AddressFamily!=AddressFamily.InterNetwork || IPAddress.IsLoopback(ip)) throw new InvalidOperationException("binding_projection_address");
   byte[] b=ip.GetAddressBytes();if(b[0]==0 || b[0]>=224 || (b[0]==169 && b[1]==254)) throw new InvalidOperationException("binding_projection_address");
   return ip.ToString();
  }
  public static NicRecord[] Adapters() {
   List<NicRecord> rows=new List<NicRecord>();
   foreach(NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces()) {
    IPInterfaceProperties props=n.GetIPProperties();List<string> ips=new List<string>();
    foreach(UnicastIPAddressInformation a in props.UnicastAddresses) if(a.Address.AddressFamily==AddressFamily.InterNetwork) ips.Add(a.Address.ToString());
    if(ips.Count==0) continue;
    Guid guid;if(!Guid.TryParse(n.Id,out guid) || guid==Guid.Empty) throw new InvalidOperationException("binding_nic_guid_unavailable");
    IPv4InterfaceProperties v4=props.GetIPv4Properties();if(v4==null || v4.Index<=0) throw new InvalidOperationException("binding_nic_index_unavailable");
    rows.Add(new NicRecord {Guid=guid,Index=(uint)v4.Index,Name=n.Name,Type=(int)n.NetworkInterfaceType,Up=(n.OperationalStatus==OperationalStatus.Up),IPv4=ips.ToArray()});
   }
   return rows.ToArray();
  }
  public static InterfaceIdentity InterfaceFromIndex(uint index) {
   if(index==0) throw new InvalidOperationException("binding_zero_interface_index");
   ulong luid;uint code=ConvertInterfaceIndexToLuid(index,out luid);
   if(code!=0) throw new InvalidOperationException("binding_index_luid_api_"+code);
   uint back;code=ConvertInterfaceLuidToIndex(ref luid,out back);
   if(code!=0 || back!=index || luid==0) throw new InvalidOperationException("binding_index_roundtrip");
   Guid guid;code=ConvertInterfaceLuidToGuid(ref luid,out guid);
   if(code!=0 || guid==Guid.Empty) throw new InvalidOperationException("binding_luid_guid_api_"+code);
   return new InterfaceIdentity {Index=index,NetLuid=luid,Guid=guid};
  }
 }
}
