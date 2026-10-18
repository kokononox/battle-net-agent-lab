"""Copy the runner's installed CPython + only hash-pinned Frida dependencies."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import sysconfig
import zipfile

def build():
    if sys.platform!='win32' or sys.maxsize<2**32:raise SystemExit('windows_x64_required')
    root=Path(__file__).resolve().parent;dest=root/'release'/'Local-Retail-Privacy-Monitor-U1'
    if dest.exists():raise SystemExit('fresh_build_destination_required')
    runtime=dest/'runtime';runtime.mkdir(parents=True);source=Path(sys.base_prefix)
    for f in source.glob('*'):
        if f.is_file() and (f.suffix.lower()=='.dll' or f.name in ('python.exe','LICENSE.txt')):shutil.copy2(f,runtime/f.name)
    shutil.copytree(source/'DLLs',runtime/'DLLs',ignore=shutil.ignore_patterns('_tkinter.pyd','tcl*','tk*','__pycache__'))
    version=f'python{sys.version_info.major}{sys.version_info.minor}'
    with zipfile.ZipFile(runtime/(version+'.zip'),'w',compression=zipfile.ZIP_DEFLATED) as z:
        for f in (source/'Lib').rglob('*'):
            rel=f.relative_to(source/'Lib')
            if any(x in {'site-packages','test','tests','__pycache__','ensurepip','idlelib','tkinter','turtledemo','venv'} for x in rel.parts):continue
            if f.is_file() and f.suffix not in ('.pyc','.pyo'):z.write(f,rel.as_posix())
    sites=runtime/'Lib'/'site-packages';sites.mkdir(parents=True)
    import frida,typing_extensions
    if frida.__version__!='17.24.2':raise SystemExit('frida_version')
    installed=Path(frida.__file__).parent.parent
    shutil.copytree(installed/'frida',sites/'frida',ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(Path(typing_extensions.__file__),sites/'typing_extensions.py')
    for pattern in ('frida-*.dist-info','typing_extensions-*.dist-info'):
        matches=list(installed.glob(pattern))
        if len(matches)!=1:raise SystemExit('dependency_metadata')
        shutil.copytree(matches[0],sites/matches[0].name)
    (runtime/(version+'._pth')).write_text(f'{version}.zip\n.\nDLLs\nLib/site-packages\n../app\n',encoding='utf-8')
    shutil.copytree(root/'app',dest/'app',ignore=shutil.ignore_patterns('__pycache__'))
    for name in ('Start-Monitor.cmd','SelfTest-Only.cmd','Restore-Hosts-Only.cmd','README-fa.md','THIRD-PARTY-NOTICES.txt'):
        shutil.copy2(root/name,dest/name)
    (dest/'BUILD-INFO.json').write_text(json.dumps({'source_commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'python_version':sys.version.split()[0],'frida_version':frida.__version__,'runner_image_version':os.environ.get('ImageVersion'),'native_selftest_scheduled_after_build':True,'not_user_pc_observed':True},indent=2)+'\n')
    manifest={f.relative_to(dest).as_posix():hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(dest.rglob('*')) if f.is_file()}
    (dest/'MANIFEST-SHA256.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'package_files':len(manifest),'package_bytes':sum(f.stat().st_size for f in dest.rglob('*') if f.is_file()),'python_version':sys.version.split()[0]}))
if __name__=='__main__':build()
