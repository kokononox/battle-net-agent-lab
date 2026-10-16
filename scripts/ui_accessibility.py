"""Bounded read-only UIA helper. Sanitized enums only; never acts on a control."""
import json
import tempfile
import os
import re
from pathlib import Path
import subprocess
import sys
from native_gui import LABELS, MARKERS

TYPES={'Window','Pane','Text','Button','ComboBox','Edit','Document','Group','CheckBox',
       'RadioButton','List','ListItem','Hyperlink','ProgressBar','Custom','Other'}
READABLE={'Window','Pane','Text','Button','ComboBox','Group','CheckBox','RadioButton','Hyperlink'}
STATUSES={'ok','no_targets','timeout','probe_failed','output_rejected','not_windows'}
MAX_OUTPUT=65536

def blank(status,n=0):
    return {'status':status,'elements':[],'truncated':False,'errors':0,'top_windows_requested':n}

def validate(report,targets,requested_count=None):
    if type(report) is not dict or set(report)!={'status','elements','truncated','errors','top_windows_requested'}:raise ValueError('uia_schema')
    if report['status'] not in STATUSES:raise ValueError('uia_status')
    if type(report['truncated']) is not bool:raise ValueError('uia_flag')
    if type(report['errors']) is not int or not 0<=report['errors']<=1024:raise ValueError('uia_errors')
    n=report['top_windows_requested']
    if type(n) is not int or not 0<=n<=8 or n!=(len(targets) if requested_count is None else requested_count):raise ValueError('uia_targets')
    if report['status']=='no_targets' and n!=0:raise ValueError('uia_empty_targets')
    if type(report['elements']) is not list or len(report['elements'])>64:raise ValueError('uia_limit')
    pids={x['pid'] for x in targets}
    for e in report['elements']:
        base={'pid','depth','control_type','enabled','offscreen','password','label','markers'}
        if type(e) is not dict or set(e) not in (base,base|{'caption_features'}):raise ValueError('uia_element')
        if type(e['pid']) is not int or e['pid'] not in pids:raise ValueError('uia_pid')
        if type(e['depth']) is not int or not 0<=e['depth']<=6:raise ValueError('uia_depth')
        if e['control_type'] not in TYPES:raise ValueError('uia_control_type')
        for f in ('enabled','offscreen','password'):
            if type(e[f]) is not bool:raise ValueError('uia_boolean')
        if e['label'] not in set(LABELS.values())|{'unrecognized','not_read'}:raise ValueError('uia_label')
        if type(e['markers']) is not list or len(e['markers'])>len(MARKERS) or any(type(m) is not str or m not in MARKERS for m in e['markers']):raise ValueError('uia_marker')
        from caption_features import validate as validate_caption
        validate_caption(e.get('caption_features'),e)
        if e['password'] or e['offscreen'] or e['control_type'] not in READABLE:
            if e['label']!='not_read' or e['markers']:raise ValueError('uia_sensitive_name')
    if n==0 and report['elements']:raise ValueError('uia_zero_scope')
    if report['status']!='ok' and (report['elements'] or report['truncated'] or report['errors']):raise ValueError('uia_error_payload')
    return report

class ToolchainError(RuntimeError):
    def __init__(self,code,compiler_codes=()):
        super().__init__(code);self.code=code
        self.compiler_codes=sorted({c for c in compiler_codes if type(c) is str and re.fullmatch(r'CS[0-9]{4}',c)})[:8]

TOOLCHAIN_CODES={'uia_compiler_missing','uia_references_missing','uia_compile_timeout','uia_compile_failed','uia_runtime_timeout','uia_runtime_failed','uia_runtime_output_rejected'}

def native_helper(env):
    # Compile only trusted repository C# with the installed .NET Framework compiler.
    # No package install/download, PowerShell, generated source or provider input.
    source=Path(__file__).with_name('uia_readonly.cs').resolve()
    base=Path(os.environ.get('SystemRoot','C:/Windows'))/'Microsoft.NET'/'Framework64'/'v4.0.30319'
    compiler=base/'csc.exe'
    if not compiler.is_file():raise ToolchainError('uia_compiler_missing')
    refs=[base/'System.Web.Extensions.dll',base/'WPF'/'UIAutomationClient.dll',base/'WPF'/'UIAutomationTypes.dll',base/'WPF'/'WindowsBase.dll']
    if not all(p.is_file() for p in refs):raise ToolchainError('uia_references_missing')
    # An existing EXE is never trusted/reused across Python processes.
    with tempfile.TemporaryDirectory(prefix='uia-readonly-build-') as tmp:
        dest=Path(tmp)/'UiaReadOnly.exe'
        command=[str(compiler),'/nologo','/warn:0','/target:exe','/out:'+str(dest),*[('/reference:'+str(p)) for p in refs],str(source),str(source.with_name('authenticode_native.cs')),str(source.with_name('language_advance.cs'))]
        try:compiled=subprocess.run(command,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,check=False)
        except subprocess.TimeoutExpired:raise ToolchainError('uia_compile_timeout') from None
        except OSError:raise ToolchainError('uia_compile_failed') from None
        if compiled.returncode or not dest.is_file():
            codes=re.findall(r'\bCS[0-9]{4}\b',compiled.stdout[:65536].decode('ascii',errors='ignore'))
            raise ToolchainError('uia_compile_failed',codes)
        executable=dest.read_bytes()
    # Keep the executable in a live private temporary directory for this process only.
    work=tempfile.TemporaryDirectory(prefix='uia-readonly-run-')
    output=Path(work.name)/'UiaReadOnly.exe';output.write_bytes(executable)
    return output,work

_HELPER=None

def launch(targets):
    global _HELPER
    from observe_agent import clean_environment
    env=clean_environment(os.environ)
    config={'targets':targets,'labels':LABELS,'markers':MARKERS,'types':sorted(TYPES),'readable_types':sorted(READABLE)}
    if _HELPER is None:_HELPER=native_helper(env)
    env['BNET_LAB_UIA_CONFIG']=json.dumps(config,separators=(',',':'))
    return subprocess.run([str(_HELPER[0])],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=False)

def inspect(targets):
    # HWNDs were collected by native_gui solely for observed allowed setup/Agent PIDs.
    if type(targets) is not list:raise ValueError('uia_input')
    for t in targets:
        if type(t) is not dict or set(t)!={'hwnd','pid'}:raise ValueError('uia_input')
        if any(type(t[f]) is not int for f in ('hwnd','pid')) or not 0<t['hwnd']<2**64 or not 0<t['pid']<2**32:raise ValueError('uia_input')
    if len(targets)>8:raise ValueError('uia_input')
    n=len(targets)
    if not targets:return blank('no_targets')
    if sys.platform!='win32':return blank('not_windows',n)
    try:
        response=launch(targets)
        if response.returncode:return blank('probe_failed',n)
        if len(response.stdout)>MAX_OUTPUT:return blank('output_rejected',n)
        def pairs(items):
            result={}
            for k,v in items:
                if k in result:raise ValueError('duplicate_key')
                result[k]=v
            return result
        def constant(_):raise ValueError('nonfinite')
        report=json.loads(response.stdout.decode('utf-8-sig'),object_pairs_hook=pairs,parse_constant=constant)
        return validate(report,targets)
    except ToolchainError:return blank('probe_failed',n)
    except subprocess.TimeoutExpired:return blank('timeout',n)
    except (ValueError,UnicodeError,TypeError,KeyError):return blank('output_rejected',n)
    except OSError:return blank('probe_failed',n)

def smoke_check():
    """Required native Windows integration check. Failure is NOT treated as pass."""
    try:response=launch([])
    except subprocess.TimeoutExpired:raise ToolchainError('uia_runtime_timeout') from None
    if response.returncode:raise ToolchainError('uia_runtime_failed')
    try:
        if len(response.stdout)>MAX_OUTPUT:raise ValueError('size')
        report=json.loads(response.stdout.decode('utf-8-sig'));validate(report,[])
        if report['status']!='ok':raise ValueError('status')
    except (ValueError,UnicodeError,TypeError,KeyError):raise ToolchainError('uia_runtime_output_rejected') from None
    return report
