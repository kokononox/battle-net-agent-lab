"""Read only numeric VS_FIXEDFILEINFO; never localized/free-form resource strings."""
import sys

def fixed_version(ms,ls,signature):
 if any(type(x) is not int or not 0<=x<=0xffffffff for x in (ms,ls,signature)) or signature!=0xfeef04bd:return None
 parts=(ms>>16,ms&65535,ls>>16,ls&65535)
 return '.'.join(map(str,parts)) if any(parts) else None

def query(path):
 if sys.platform!='win32':return '', 'native_error'
 try:
  import ctypes as c
  from ctypes import wintypes as w
  class Fixed(c.Structure):
   _fields_=[(name,w.DWORD) for name in ('signature','struct_version','file_ms','file_ls','product_ms','product_ls','flags_mask','flags','file_os','file_type','subtype','date_ms','date_ls')]
  lib=c.WinDLL('version',use_last_error=True)
  lib.GetFileVersionInfoSizeW.argtypes=[w.LPCWSTR,c.POINTER(w.DWORD)];lib.GetFileVersionInfoSizeW.restype=w.DWORD
  lib.GetFileVersionInfoW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,c.c_void_p];lib.GetFileVersionInfoW.restype=w.BOOL
  lib.VerQueryValueW.argtypes=[c.c_void_p,w.LPCWSTR,c.POINTER(c.c_void_p),c.POINTER(w.UINT)];lib.VerQueryValueW.restype=w.BOOL
  ignored=w.DWORD();size=lib.GetFileVersionInfoSizeW(str(path),c.byref(ignored))
  if not size:return '', 'no_resource'
  if size>1048576:return '', 'invalid_fixed_info'
  data=c.create_string_buffer(size)
  if not lib.GetFileVersionInfoW(str(path),0,size,data):return '', 'native_error'
  ptr=c.c_void_p();length=w.UINT()
  if not lib.VerQueryValueW(data,'\\',c.byref(ptr),c.byref(length)) or not ptr or length.value<c.sizeof(Fixed):return '', 'invalid_fixed_info'
  info=c.cast(ptr,c.POINTER(Fixed)).contents;version=fixed_version(info.file_ms,info.file_ls,info.signature)
  return (version,'accepted') if version else ('','invalid_fixed_info')
 except Exception:return '', 'native_error'
