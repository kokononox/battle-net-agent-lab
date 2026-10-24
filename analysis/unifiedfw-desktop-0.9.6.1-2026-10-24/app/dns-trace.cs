// Windows x64 DNS-Client real-time ETW. No packet capture, channel/audit edits or DNS queries.
// Only query events for exact selected executable paths are queued; all other data is discarded.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
namespace UnifiedDns {
 [StructLayout(LayoutKind.Sequential)] public struct Wnode { public uint BufferSize,ProviderId; public ulong HistoricalContext; public long TimeStamp; public Guid Guid; public uint ClientContext,Flags; }
 [StructLayout(LayoutKind.Sequential)] public struct Properties { public Wnode Wnode; public uint BufferSize,MinimumBuffers,MaximumBuffers,MaximumFileSize,LogFileMode,FlushTimer,EnableFlags; public int AgeLimit; public uint NumberOfBuffers,FreeBuffers,EventsLost,BuffersWritten,LogBuffersLost,RealTimeBuffersLost; public IntPtr LoggerThreadId; public uint LogFileNameOffset,LoggerNameOffset; }
 [StructLayout(LayoutKind.Sequential)] public struct Descriptor { public ushort Id; public byte Version,Channel,Level,Opcode; public ushort Task; public ulong Keyword; }
 [StructLayout(LayoutKind.Sequential)] public struct Header { public ushort Size,HeaderType,Flags,EventProperty; public uint ThreadId,ProcessId; public long TimeStamp; public Guid ProviderId; public Descriptor EventDescriptor; public ulong ProcessorTime; public Guid ActivityId; }
 [StructLayout(LayoutKind.Sequential)] public struct Record { public Header EventHeader; public uint BufferContext; public ushort ExtendedDataCount,UserDataLength; public IntPtr ExtendedData,UserData,UserContext; }
 [StructLayout(LayoutKind.Sequential)] public struct TraceHeader { public ushort Size,FieldTypeFlags; public uint Version,ThreadId,ProcessId; public long TimeStamp; public Guid Guid; public ulong ProcessorTime; }
 [StructLayout(LayoutKind.Sequential)] public struct Trace { public TraceHeader Header; public uint InstanceId,ParentInstanceId; public Guid ParentGuid; public IntPtr MofData; public uint MofLength,ClientContext; }
 [StructLayout(LayoutKind.Sequential)] public struct SystemTime { public ushort Year,Month,DayOfWeek,Day,Hour,Minute,Second,Milliseconds; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct Zone { public int Bias; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string StandardName; public SystemTime StandardDate; public int StandardBias; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)] public string DaylightName; public SystemTime DaylightDate; public int DaylightBias; }
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct LogHeader { public uint BufferSize,Version,ProviderVersion,NumberOfProcessors; public long EndTime; public uint TimerResolution,MaximumFileSize,LogFileMode,BuffersWritten; public Guid LogInstanceGuid; public IntPtr LoggerName,LogFileName; public Zone TimeZone; public long BootTime,PerfFreq,StartTime; public uint ReservedFlags,BuffersLost; }
 [UnmanagedFunctionPointer(CallingConvention.Winapi)] public delegate void EventCallback(IntPtr record);
 [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] public struct LogFile { [MarshalAs(UnmanagedType.LPWStr)] public string LogFileName; [MarshalAs(UnmanagedType.LPWStr)] public string LoggerName; public long CurrentTime; public uint BuffersRead,ProcessTraceMode; public Trace CurrentEvent; public LogHeader LogfileHeader; public IntPtr BufferCallback; public uint BufferSize,Filled,EventsLost; public EventCallback EventRecordCallback; public uint IsKernelTrace; public IntPtr Context; }
 [StructLayout(LayoutKind.Sequential)] public struct PropertyDescriptor { public ulong PropertyName; public uint ArrayIndex,Reserved; }
 public class Query { public string domain,results,status,program_id,program_path,observed_utc,process_start_ticks; public uint pid; public ushort event_id; public long sequence; }
 public sealed class Collector : IDisposable {
  static readonly Guid Provider=new Guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d");
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern uint StartTraceW(out ulong handle,string name,IntPtr props);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern uint ControlTraceW(ulong handle,string name,IntPtr props,uint code);
  [DllImport("advapi32.dll")] static extern uint EnableTraceEx2(ulong handle,ref Guid provider,uint control,byte level,ulong any,ulong all,uint timeout,IntPtr parameters);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern ulong OpenTraceW(ref LogFile log);
  [DllImport("advapi32.dll")] static extern uint ProcessTrace([In] ulong[] handles,uint count,IntPtr start,IntPtr end);
  [DllImport("advapi32.dll")] static extern uint CloseTrace(ulong handle);
  [DllImport("tdh.dll")] static extern uint TdhGetPropertySize(IntPtr record,uint contextCount,IntPtr context,uint count,[In] PropertyDescriptor[] properties,out uint size);
  [DllImport("tdh.dll")] static extern uint TdhGetProperty(IntPtr record,uint contextCount,IntPtr context,uint count,[In] PropertyDescriptor[] properties,uint size,[Out] byte[] data);
  readonly ConcurrentQueue<Query> queue=new ConcurrentQueue<Query>(); readonly Dictionary<string,string> targets=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
  readonly string name; readonly Guid sessionGuid; bool baselineMode; long baselineCutoff; ulong session,consumer=ulong.MaxValue; IntPtr props=IntPtr.Zero; EventCallback callback; Thread worker; volatile bool disposed; long queued,sequence,errors,unattributed,dropped,seen; uint processStatus; public uint StopStatus {get;private set;} public uint LostEvents {get;private set;}
  public string SessionName {get{return name;}} public string SessionGuid {get{return sessionGuid.ToString();}} public long Errors {get{return Interlocked.Read(ref errors);}} public long Unattributed {get{return Interlocked.Read(ref unattributed);}} public long Dropped {get{return Interlocked.Read(ref dropped);}} public long Seen {get{return Interlocked.Read(ref seen);}} public bool Running {get{return !disposed && worker!=null && worker.IsAlive;}} public uint ProcessStatus {get{return processStatus;}}
  public static int[] Layout(){return new int[]{Marshal.SizeOf(typeof(Wnode)),Marshal.SizeOf(typeof(Properties)),Marshal.SizeOf(typeof(Header)),Marshal.SizeOf(typeof(Record)),Marshal.SizeOf(typeof(Trace)),Marshal.SizeOf(typeof(LogHeader)),Marshal.SizeOf(typeof(LogFile)),Marshal.OffsetOf(typeof(LogFile),"EventRecordCallback").ToInt32()};}
  public Collector(string captureId,string owner,string guid,string[] paths,string[] ids){
   if(IntPtr.Size!=8)throw new InvalidOperationException("DNS_ETW_requires_x64");
   Guid c,o,g;if(!Guid.TryParseExact(captureId,"N",out c)||!Guid.TryParseExact(owner,"N",out o)||!Guid.TryParse(guid,out g)||paths.Length!=ids.Length||paths.Length<1||paths.Length>32)throw new ArgumentException("DNS_ETW_scope");
   name="UnifiedFW-DNS-"+owner+"-"+captureId;sessionGuid=g;
   for(int i=0;i<paths.Length;i++)targets.Add(paths[i],ids[i]);
  }
  public static bool IsNewProcess(long birth,long cutoff){return cutoff>0&&birth>cutoff;}
  public Collector(string captureId,string owner,string guid,long cutoff) : this(captureId,owner,guid,new string[]{@"C:\__baseline_scope_placeholder__.exe"},new string[]{"baseline"}) {
   if(cutoff<=0)throw new ArgumentException("baseline_cutoff");baselineMode=true;baselineCutoff=cutoff;targets.Clear();
  }
  static IntPtr Allocate(string name,Guid guid){
   int n=Marshal.SizeOf(typeof(Properties)),total=n+(name.Length+1)*2;IntPtr p=Marshal.AllocHGlobal(total);Marshal.Copy(new byte[total],0,p,total);
   Properties v=new Properties();v.Wnode.BufferSize=(uint)total;v.Wnode.Guid=guid;v.Wnode.ClientContext=2;v.Wnode.Flags=0x00020000;v.BufferSize=64;v.MinimumBuffers=2;v.MaximumBuffers=8;v.LogFileMode=0x100;v.FlushTimer=1;v.LoggerNameOffset=(uint)n;
   Marshal.StructureToPtr(v,p,false);byte[] text=System.Text.Encoding.Unicode.GetBytes(name+"\0");Marshal.Copy(text,0,IntPtr.Add(p,n),text.Length);return p;
  }
  public void Start(){
   if(props!=IntPtr.Zero||disposed)throw new InvalidOperationException("DNS_ETW_already_started");
   props=Allocate(name,sessionGuid);
   try{
    uint code=StartTraceW(out session,name,props);if(code!=0){session=0;throw new InvalidOperationException("DNS_ETW_StartTrace_"+code);}
    callback=OnEvent;LogFile log=new LogFile();log.LoggerName=name;log.ProcessTraceMode=0x100|0x10000000;log.EventRecordCallback=callback;
    consumer=OpenTraceW(ref log);if(consumer==ulong.MaxValue)throw new InvalidOperationException("DNS_ETW_OpenTrace_"+Marshal.GetLastWin32Error());
    ulong readHandle=consumer;worker=new Thread(delegate(){try{processStatus=ProcessTrace(new ulong[]{readHandle},1,IntPtr.Zero,IntPtr.Zero);}finally{GC.KeepAlive(callback);}});worker.IsBackground=true;worker.Start();
    Guid provider=Provider;code=EnableTraceEx2(session,ref provider,1,5,ulong.MaxValue,0,0,IntPtr.Zero);if(code!=0)throw new InvalidOperationException("DNS_ETW_EnableTrace_"+code);
   }catch{Dispose();throw;}
  }
  static byte[] Property(IntPtr r,string name){
   IntPtr text=Marshal.StringToHGlobalUni(name);try{
    PropertyDescriptor p=new PropertyDescriptor();p.PropertyName=(ulong)text.ToInt64();p.ArrayIndex=uint.MaxValue;uint size;PropertyDescriptor[] descriptors=new PropertyDescriptor[]{p};
    if(TdhGetPropertySize(r,0,IntPtr.Zero,1,descriptors,out size)!=0||size==0||size>8192)return null;
    byte[] bytes=new byte[size];return TdhGetProperty(r,0,IntPtr.Zero,1,descriptors,size,bytes)==0?bytes:null;
   }finally{Marshal.FreeHGlobal(text);}
  }
  static string Text(byte[] v){return v==null||v.Length%2!=0?"":System.Text.Encoding.Unicode.GetString(v).TrimEnd('\0');}
  static uint Number(byte[] v){return v!=null&&v.Length==4?BitConverter.ToUInt32(v,0):0;}
  public static bool Eligible(int eventId,Guid provider){return provider==Provider&&(eventId==3006||eventId==3008);}
  void OnEvent(IntPtr ptr){
   try{
    if(disposed)return;Record record=(Record)Marshal.PtrToStructure(ptr,typeof(Record));int id=record.EventHeader.EventDescriptor.Id;if(!Eligible(id,record.EventHeader.ProviderId))return;Interlocked.Increment(ref seen);
    DateTime time=DateTime.FromFileTimeUtc(record.EventHeader.TimeStamp);
    uint pid=Number(Property(ptr,"ClientPID"));if(pid==0)pid=Number(Property(ptr,"ClientProcessId"));if(pid==0)pid=record.EventHeader.ProcessId;
    string path,program;long birth;
    try{using(Process p=Process.GetProcessById(checked((int)pid))){path=p.MainModule.FileName;birth=p.StartTime.ToUniversalTime().Ticks;if(birth>time.Ticks){Interlocked.Increment(ref unattributed);return;}if(baselineMode){if(!IsNewProcess(birth,baselineCutoff)){Interlocked.Increment(ref unattributed);return;}program="";}else if(!targets.TryGetValue(path,out program)){Interlocked.Increment(ref unattributed);return;}}}catch{Interlocked.Increment(ref unattributed);return;}
    string domain=Text(Property(ptr,"QueryName")).TrimEnd('.').ToLowerInvariant();if(domain.Length<1||domain.Length>253){Interlocked.Increment(ref errors);return;}
    string results=Text(Property(ptr,"QueryResults"));if(results.Length>2000)results=results.Substring(0,2000);byte[] status=Property(ptr,"QueryStatus");
    Query q=new Query();q.domain=domain;q.results=results;q.status=status==null?"pending":Number(status).ToString(System.Globalization.CultureInfo.InvariantCulture);q.pid=pid;q.program_id=program;q.program_path=path;q.observed_utc=time.ToString("o");q.process_start_ticks=birth.ToString(System.Globalization.CultureInfo.InvariantCulture);q.event_id=(ushort)id;q.sequence=Interlocked.Increment(ref sequence);
    if(Interlocked.Increment(ref queued)>1000){Interlocked.Decrement(ref queued);Interlocked.Increment(ref dropped);return;}queue.Enqueue(q);
   }catch{Interlocked.Increment(ref errors);}
  }
  public Query[] Drain(){List<Query> list=new List<Query>();Query q;while(list.Count<1000&&queue.TryDequeue(out q)){Interlocked.Decrement(ref queued);list.Add(q);}return list.ToArray();}
  public void Dispose(){
   if(disposed)return;
   if(session!=0&&props!=IntPtr.Zero){StopStatus=ControlTraceW(session,name,props,1);Properties v=(Properties)Marshal.PtrToStructure(props,typeof(Properties));LostEvents=v.EventsLost+v.RealTimeBuffersLost;session=0;}
   if(worker!=null)worker.Join(3000);
   if(consumer!=ulong.MaxValue){CloseTrace(consumer);consumer=ulong.MaxValue;}
   if(worker!=null&&worker.IsAlive)worker.Join(1000);
   disposed=true;
   // Keep delegate rooted if the consumer has not unwound; this object lives until worker exit.
   if(props!=IntPtr.Zero){Marshal.FreeHGlobal(props);props=IntPtr.Zero;}
  }
  // Recovery only for an exact recorded session name and random session GUID; never wildcard-stop.
  public static uint Cleanup(string name,string expectedGuid){
   Guid guid;if(!Guid.TryParse(expectedGuid,out guid)||!System.Text.RegularExpressions.Regex.IsMatch(name,@"^UnifiedFW-DNS-[a-f0-9]{32}-[a-f0-9]{32}$"))throw new ArgumentException("DNS_cleanup_scope");
   IntPtr p=Allocate(name,guid);try{uint code=ControlTraceW(0,name,p,0);if(code==4201)return code;if(code!=0)return code;Properties value=(Properties)Marshal.PtrToStructure(p,typeof(Properties));if(value.Wnode.Guid!=guid)throw new InvalidOperationException("DNS_cleanup_GUID_mismatch");return ControlTraceW(0,name,p,1);}finally{Marshal.FreeHGlobal(p);}
  }
 }
}
