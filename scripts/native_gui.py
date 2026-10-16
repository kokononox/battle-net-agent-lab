"""Read-only, bounded GUI inspection of explicitly observed setup/Agent PIDs.
No screenshots, raw text export, edits, clicks, keyboard events or login inputs.
"""
import ctypes
from ctypes import wintypes as w
import os
import re
import sys
import time

LABELS={'ok':'ok','continue':'continue','cancel':'cancel','install':'install','next':'next',
        'back':'back','close':'close','yes':'yes','no':'no','i agree':'agree','agree':'agree',
        'english (us)':'english_us','english (united states)':'english_us','english':'english',
        'language':'language','select a language':'select_language','battle.net':'battle_net',
        'battle.net setup':'battle_net_setup','setup':'setup'}
MARKERS=('language','license','agreement','terms','privacy','error','install','update',
         'permission','administrator','network','login','sign_in')
CLASS_NAMES={'#32770':'dialog','button':'button','static':'static','combobox':'combobox',
             'combolbox':'combo_list','edit':'edit','richedit20w':'rich_edit',
             'richedit50w':'rich_edit','syslink':'link','msctls_progress32':'progress'}
READABLE_CLASSES={'dialog','button','static','combobox'}


def classify_class(name):
    name=name.lower()
    if name.startswith('chrome_widgetwin_') or name=='cefbrowserwindow':return 'chromium'
    return CLASS_NAMES.get(name,'other')


def safe_text(text, class_kind, visible):
    # Unknown/edit/password/hidden control contents are never even requested by
    # the native inspector. This second guard also prevents accidental export.
    if not visible or class_kind not in READABLE_CLASSES:
        return {'label':'not_read','markers':[]}
    normalized=' '.join(text.replace('&','').strip().casefold().split())
    label=LABELS.get(normalized,'unrecognized')
    markers=[]
    for marker in MARKERS:
        pattern=r'\bsign[ _-]?in\b' if marker=='sign_in' else r'\b'+marker+r'\b'
        if re.search(pattern,normalized):markers.append(marker)
    return {'label':label,'markers':markers}


def inspect(pids,elapsed):
    if sys.platform!='win32':raise OSError('windows_gui_api_required')
    pids={pid for pid in pids if type(pid) is int and 0<pid<2**32}
    pids=set(sorted(pids)[:24])
    result={'elapsed_seconds':elapsed,'observer_session_id':None,'process_sessions':[],
            'window_station_visible':None,'input_desktop_accessible':False,
            'input_desktop_error':None,'windows':[],'enumeration_truncated':False,'probe_errors':0}
    user=ctypes.WinDLL('user32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    enum_callback=ctypes.WINFUNCTYPE(w.BOOL,w.HWND,w.LPARAM)
    user.EnumWindows.argtypes=[enum_callback,w.LPARAM];user.EnumWindows.restype=w.BOOL
    user.EnumChildWindows.argtypes=[w.HWND,enum_callback,w.LPARAM];user.EnumChildWindows.restype=w.BOOL
    user.GetWindowThreadProcessId.argtypes=[w.HWND,ctypes.POINTER(w.DWORD)];user.GetWindowThreadProcessId.restype=w.DWORD
    user.GetClassNameW.argtypes=[w.HWND,w.LPWSTR,ctypes.c_int];user.GetClassNameW.restype=ctypes.c_int
    user.IsWindowVisible.argtypes=[w.HWND];user.IsWindowVisible.restype=w.BOOL
    user.IsWindowEnabled.argtypes=[w.HWND];user.IsWindowEnabled.restype=w.BOOL
    user.SendMessageTimeoutW.argtypes=[w.HWND,w.UINT,w.WPARAM,w.LPARAM,w.UINT,w.UINT,ctypes.POINTER(ctypes.c_size_t)]
    user.SendMessageTimeoutW.restype=w.LPARAM
    kernel.ProcessIdToSessionId.argtypes=[w.DWORD,ctypes.POINTER(w.DWORD)];kernel.ProcessIdToSessionId.restype=w.BOOL
    user.GetProcessWindowStation.argtypes=[];user.GetProcessWindowStation.restype=w.HANDLE
    user.GetUserObjectInformationW.argtypes=[w.HANDLE,ctypes.c_int,ctypes.c_void_p,w.DWORD,ctypes.POINTER(w.DWORD)]
    user.GetUserObjectInformationW.restype=w.BOOL
    user.OpenInputDesktop.argtypes=[w.DWORD,w.BOOL,w.DWORD];user.OpenInputDesktop.restype=w.HANDLE
    user.CloseDesktop.argtypes=[w.HANDLE];user.CloseDesktop.restype=w.BOOL
    def session(pid):
        sid=w.DWORD()
        return int(sid.value) if kernel.ProcessIdToSessionId(pid,ctypes.byref(sid)) else None
    result['observer_session_id']=session(os.getpid())
    result['process_sessions']=[{'pid':pid,'session_id':session(pid)} for pid in sorted(pids)]
    class Flags(ctypes.Structure):
        _fields_=[('inherit',w.BOOL),('reserved',w.BOOL),('flags',w.DWORD)]
    flags=Flags();length=w.DWORD()
    if user.GetUserObjectInformationW(user.GetProcessWindowStation(),1,ctypes.byref(flags),ctypes.sizeof(flags),ctypes.byref(length)):
        result['window_station_visible']=bool(flags.flags&1)
    else:result['probe_errors']+=1
    desktop=user.OpenInputDesktop(0,False,1)
    if desktop:
        result['input_desktop_accessible']=True;user.CloseDesktop(desktop)
    else:result['input_desktop_error']=int(ctypes.get_last_error())
    deadline=time.monotonic()+4;control_count=0
    def owned(hwnd):
        pid=w.DWORD();user.GetWindowThreadProcessId(hwnd,ctypes.byref(pid));return int(pid.value) in pids
    def item(hwnd):
        cls=ctypes.create_unicode_buffer(256);user.GetClassNameW(hwnd,cls,len(cls));kind=classify_class(cls.value)
        visible=bool(user.IsWindowVisible(hwnd));enabled=bool(user.IsWindowEnabled(hwnd))
        text=''
        if visible and kind in READABLE_CLASSES:
            buf=ctypes.create_unicode_buffer(513);written=ctypes.c_size_t()
            # Only WM_GETTEXT (0x000D), never a mutating message. 50 ms deadline
            # bounds hung setup controls. No edit/rich-edit text is requested.
            if user.SendMessageTimeoutW(hwnd,0x000D,len(buf),ctypes.addressof(buf),3,50,ctypes.byref(written)):
                text=buf.value
            else:result['probe_errors']+=1
        return {'class':kind,'visible':visible,'enabled':enabled,**safe_text(text,kind,visible)}
    @enum_callback
    def top(hwnd,param):
        nonlocal control_count
        try:
            if time.monotonic()>deadline or len(result['windows'])>=8:
                result['enumeration_truncated']=True;return False
            if not owned(hwnd):return True
            window=item(hwnd);window['controls']=[]
            @enum_callback
            def child(child_hwnd,child_param):
                nonlocal control_count
                try:
                    if time.monotonic()>deadline or control_count>=32:
                        result['enumeration_truncated']=True;return False
                    if owned(child_hwnd):
                        window['controls'].append(item(child_hwnd));control_count+=1
                except Exception:result['probe_errors']+=1
                return True
            user.EnumChildWindows(hwnd,child,0)
            result['windows'].append(window)
        except Exception:result['probe_errors']+=1
        return True
    user.EnumWindows(top,0)
    return result
