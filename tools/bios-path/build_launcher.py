"""Build the GUI-subsystem Windows x64 launcher with Zig 0.14.1."""
import json,os,subprocess
from pathlib import Path
root=Path(__file__).resolve().parent
zig=os.environ.get('ZIG','zig');env=json.loads(subprocess.check_output([zig,'env'],text=True))
subprocess.run([zig,'cc','-target','x86_64-windows-gnu','-Os','-nostdlib','-isystem',str(Path(env['lib_dir'])/'libc/include/any-windows-any'),'-fno-stack-protector','-fno-builtin','-Wl,--subsystem,windows','-Wl,--entry,entry',str(root/'launcher.c'),'-lkernel32','-luser32','-o',str(root/'WLab-BIOS-Path.exe')],check=True)
