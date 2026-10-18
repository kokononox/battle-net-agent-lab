"""Native mapped-writer counterexamples on NEW synthetic owned trees only.
Never maps user control/index files. Demonstrates sharing is not an OS snapshot.
"""
import ctypes,unittest
from ctypes import wintypes as w
import windows_generation_cases as generation_cases
from windows_generation_view import WindowsGenerationView
class MappingCases(unittest.TestCase):
 # Borrow only fixture setup; do not inherit the previous test methods/count.
 def setUp(self):
  generation_cases.GenerationViewCases.setUp(self);self.unmaps=[]
 def tearDown(self):
  try:
   for k,address in reversed(self.unmaps):self.assertTrue(k.UnmapViewOfFile(address))
  finally:self.t.cleanup()
 write=generation_cases.GenerationViewCases.write
 def mapping(self):
  k=ctypes.WinDLL('kernel32',use_last_error=True)
  k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,w.LPVOID,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
  k.CreateFileMappingW.argtypes=[w.HANDLE,w.LPVOID,w.DWORD,w.DWORD,w.DWORD,w.LPCWSTR];k.CreateFileMappingW.restype=w.HANDLE
  k.MapViewOfFile.argtypes=[w.HANDLE,w.DWORD,w.DWORD,w.DWORD,ctypes.c_size_t];k.MapViewOfFile.restype=w.LPVOID
  k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
  k.UnmapViewOfFile.argtypes=[w.LPCVOID];k.UnmapViewOfFile.restype=w.BOOL
  h=k.CreateFileW(str(self.d/'shmem'),0xc0000000,3,None,3,0x80,None)
  if h==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
  try:
   section=k.CreateFileMappingW(h,None,4,0,0,None)
   if not section:raise ctypes.WinError(ctypes.get_last_error())
   try:
    address=k.MapViewOfFile(section,2,0,0,0)
    if not address:raise ctypes.WinError(ctypes.get_last_error())
   finally:k.CloseHandle(section)
  finally:k.CloseHandle(h)
  self.unmaps.append((k,address))
  return ctypes.c_ubyte.from_address(address+len(self.build.control)-1)
 def test_mapped_write_detected_if_not_restored(self):
  mapped=self.mapping();touched=[]
  # Native streams are fdopen objects; f.name is an integer. Use stream identity.
  class Inject(WindowsGenerationView):
   def _read(view,f,n):
    raw=super()._read(f,n)
    if len(view.streams)==19 and f is view.streams[3][0]and not touched:mapped.value=1;touched.append(True)
    return raw
  from release_core import InvalidRelease
  with Inject(self.root)as view:
   with self.assertRaisesRegex(InvalidRelease,'control_changed'):view.observe()
  self.assertEqual(touched,[True]);mapped.value=0
 def test_mapped_ABA_is_not_proven_absent_by_equal_rounds(self):
  mapped=self.mapping();transitions=[]
  class Inject(WindowsGenerationView):
   def _read(view,f,n):
    raw=super()._read(f,n)
    if len(view.streams)==19 and f is view.streams[3][0]and not transitions:
     mapped.value=1;transitions.append(mapped.value);mapped.value=0;transitions.append(mapped.value)
    return raw
  with Inject(self.root)as view:r=view.observe()
  self.assertEqual(transitions,[1,0]);self.assertTrue(r['both_rounds_bytes_equal']);self.assertFalse(r['no_change_between_rounds_proven']);self.assertFalse(r['coherent_live_snapshot_proven'])
