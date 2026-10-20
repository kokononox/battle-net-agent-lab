"""Integrity and single-instance helpers for the standalone passive package."""

import ctypes,hashlib,json,re

from pathlib import Path

from safepaths import safe_path

BASE=Path(__file__).resolve().parents[1]

def integrity():
 m=json.loads((BASE/'MANIFEST-SHA256.json').read_text())
 if not isinstance(m,dict) or len(m)>4096:raise ValueError('manifest_invalid')
 for name,h in m.items():
  if not re.fullmatch(r'[A-Za-z0-9_./-]{1,220}',name) or '..' in name.split('/') or name.startswith('/'):raise ValueError('manifest_path')
  p=safe_path(BASE/name)
  if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=h:raise ValueError('package_integrity_failed')

def mutex():
 k=ctypes.WinDLL('kernel32',use_last_error=True)
 k.CreateMutexW.argtypes=[ctypes.c_void_p,ctypes.c_int,ctypes.c_wchar_p];k.CreateMutexW.restype=ctypes.c_void_p
 h=k.CreateMutexW(None,False,'Global\\LocalRetailPrivacyObserverU1')
 if not h or ctypes.get_last_error()==183:raise ValueError('another_observer_running')
 return h
