"""Read-only process/TCP snapshots with Windows APIs, no WMI or PowerShell startup."""
import ctypes
from ctypes import wintypes as w
import socket
import struct
import sys


def snapshot(names):
    if sys.platform!='win32':raise OSError('windows_api_required')
    class Entry(ctypes.Structure):
        _fields_=[('dwSize',w.DWORD),('cntUsage',w.DWORD),('th32ProcessID',w.DWORD),
            ('th32DefaultHeapID',ctypes.c_size_t),('th32ModuleID',w.DWORD),
            ('cntThreads',w.DWORD),('th32ParentProcessID',w.DWORD),
            ('pcPriClassBase',w.LONG),('dwFlags',w.DWORD),('szExeFile',w.WCHAR*260)]
    expected=568 if ctypes.sizeof(ctypes.c_void_p)==8 else 556
    if ctypes.sizeof(Entry)!=expected:raise OSError('unexpected_windows_process_structure_layout')
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes=[w.DWORD,w.DWORD];kernel.CreateToolhelp32Snapshot.restype=w.HANDLE
    kernel.Process32FirstW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)];kernel.Process32FirstW.restype=w.BOOL
    kernel.Process32NextW.argtypes=[w.HANDLE,ctypes.POINTER(Entry)];kernel.Process32NextW.restype=w.BOOL
    kernel.CloseHandle.argtypes=[w.HANDLE];kernel.CloseHandle.restype=w.BOOL
    handle=kernel.CreateToolhelp32Snapshot(2,0)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    processes=[]
    try:
        row=Entry();row.dwSize=ctypes.sizeof(row)
        good=kernel.Process32FirstW(handle,ctypes.byref(row))
        if not good:raise ctypes.WinError(ctypes.get_last_error())
        while good:
            if row.szExeFile.lower() in names:
                processes.append({'Name':row.szExeFile,'ProcessId':int(row.th32ProcessID),
                                  'ParentProcessId':int(row.th32ParentProcessID)})
            good=kernel.Process32NextW(handle,ctypes.byref(row))
        if ctypes.get_last_error() not in (0,18):raise ctypes.WinError(ctypes.get_last_error())
    finally:kernel.CloseHandle(handle)
    ids={p['ProcessId'] for p in processes}
    return {'processes':processes,'connections':tcp_connections(ids) if ids else []}


def tcp_connections(ids):
    iphlp=ctypes.WinDLL('iphlpapi',use_last_error=True)
    api=iphlp.GetExtendedTcpTable
    api.argtypes=[ctypes.c_void_p,ctypes.POINTER(w.DWORD),w.BOOL,w.ULONG,ctypes.c_int,w.ULONG]
    api.restype=w.DWORD
    class Row4(ctypes.Structure):
        _fields_=[('state',w.DWORD),('local_addr',w.DWORD),('local_port',w.DWORD),
                  ('remote_addr',w.DWORD),('remote_port',w.DWORD),('pid',w.DWORD)]
    class Row6(ctypes.Structure):
        _fields_=[('local_addr',w.BYTE*16),('local_scope',w.DWORD),('local_port',w.DWORD),
                  ('remote_addr',w.BYTE*16),('remote_scope',w.DWORD),('remote_port',w.DWORD),
                  ('state',w.DWORD),('pid',w.DWORD)]
    states={1:'Closed',2:'Listen',3:'SynSent',4:'SynReceived',5:'Established',6:'FinWait1',
            7:'FinWait2',8:'CloseWait',9:'Closing',10:'LastAck',11:'TimeWait',12:'DeleteTCB'}
    result=[]
    for family,row_type in ((socket.AF_INET,Row4),(socket.AF_INET6,Row6)):
        size=w.DWORD(0);code=api(None,ctypes.byref(size),False,family,5,0)
        if code not in (0,122):raise ctypes.WinError(code)
        if not 4<=size.value<=16*1024**2:raise OSError('windows_tcp_table_size_limit')
        # TCP tables can grow between the size query and the read. Bound retries.
        for _ in range(3):
            allocated=size.value;buf=ctypes.create_string_buffer(allocated)
            code=api(buf,ctypes.byref(size),False,family,5,0)
            if code==0:break
            if code!=122 or not 4<=size.value<=16*1024**2:raise ctypes.WinError(code)
        if code:raise ctypes.WinError(code)
        count=struct.unpack_from('<I',buf.raw,0)[0];width=ctypes.sizeof(row_type)
        if count>100000 or 4+count*width>allocated:raise OSError('windows_tcp_table_bounds')
        for i in range(count):
            row=row_type.from_buffer_copy(buf,4+i*width)
            if row.pid not in ids:continue
            addr=struct.pack('=I',row.remote_addr) if family==socket.AF_INET else bytes(row.remote_addr)
            result.append({'OwningProcess':int(row.pid),'RemoteAddress':socket.inet_ntop(family,addr),
                           'RemotePort':socket.ntohs(row.remote_port&65535),
                           'LocalAddress':socket.inet_ntop(family,struct.pack('=I',row.local_addr) if family==socket.AF_INET else bytes(row.local_addr)),
                           'LocalPort':socket.ntohs(row.local_port&65535),
                           'State':states.get(row.state,'other')})
    return result
