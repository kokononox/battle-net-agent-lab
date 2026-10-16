"""Reject unrecognized fields, arbitrary strings, raw logs and credential output."""
import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import re
import shutil
from native_gui import LABELS, MARKERS as GUI_MARKERS, CLASS_NAMES
from observe_agent import initial_report, NAMES, MARKERS, ROOT_KEYS, MAX_SETUP, MAX_REPORT

class ReportError(ValueError):pass

def need(value):
    if not value:raise ReportError('report_schema_rejected')
def keys(obj,expected):need(type(obj) is dict and set(obj)==set(expected))
def integer(value,cap=2**63-1):need(type(value) is int and 0<=value<=cap)
def boolean(value):need(type(value) is bool)
def hashval(value):need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None)
def sig(obj,base=()):
    standard=(*base,'authenticode_valid','expected_blizzard_publisher','accepted_for_execution')
    need(set(obj) in (set(standard),set(standard)|{'winverifytrust_status'}))
    if 'winverifytrust_status' in obj:
        need(type(obj['winverifytrust_status']) is int and -2**31<=obj['winverifytrust_status']<2**31)
        need(obj['authenticode_valid']==(obj['winverifytrust_status']==0))
        need(not obj['expected_blizzard_publisher'] or obj['winverifytrust_status']==0)
    for k in ('authenticode_valid','expected_blizzard_publisher','accepted_for_execution'):boolean(obj[k])
    need(obj['accepted_for_execution']==(obj['authenticode_valid'] and obj['expected_blizzard_publisher']))

def validate(r):
    template=initial_report();keys(r,template)
    need(r['schema']==template['schema'] and r['scope']==template['scope'])
    need(r['signature_backend']==template['signature_backend'])
    need(r['status'] in ('not_started','stopped','agent_process_observed','bootstrapper_observed_agent_not_observed'))
    need(type(r['utc']) is str and len(r['utc'])<40)
    datetime.datetime.fromisoformat(r['utc'])
    need(r['error_code'] is None or (type(r['error_code']) is str and re.fullmatch('[a-z0-9_]{1,100}',r['error_code'])))
    need(r['phase'] in {'environment_check','directory_prepare','baseline_snapshot','installer_download','installer_signature','bootstrapper_launch','sampling','gui_inspection','filesystem_observation','agent_binary_signature','cleanup','complete','safety_tests'})
    for field in ('error_type','underlying_error_type'):
        need(r[field] is None or (type(r[field]) is str and re.fullmatch('[A-Za-z0-9_]{1,64}',r[field])))
    need(r['numeric_error_code'] is None or (type(r['numeric_error_code']) is int and -2**31<=r['numeric_error_code']<2**31))
    boolean(r['cleanup_attempted']);need(r['safety']==template['safety'] and r['interpretation']==template['interpretation'])
    keys(r['limits'],template['limits'])
    integer(r['limits']['observation_seconds'],150);need(r['limits']['observation_seconds']>=30)
    need(r['limits']['installer_body_bytes']==MAX_SETUP and r['limits']['bootstrapper_child_network_hard_byte_cap'] is False)
    need(r['source_commit'] is None or (type(r['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',r['source_commit'])))
    for field in ('run_id','run_attempt'):
        need(r[field] is None or (type(r[field]) is str and re.fullmatch('[0-9]{1,24}',r[field])))
    need(type(r['gui_observations']) is list and len(r['gui_observations'])<=2)
    for gui in r['gui_observations']:validate_gui(gui)
    if r['safety_test_result']:
        from run_safety_tests import validate_summary
        try:validate_summary(r['safety_test_result'])
        except (ValueError,TypeError,KeyError):raise ReportError('report_schema_rejected') from None
    if r['installer']:
        need(set(r['installer']) in ({'bytes','sha256','redirects'}, {'bytes','sha256','redirects','authenticode_valid','expected_blizzard_publisher','accepted_for_execution'}, {'bytes','sha256','redirects','authenticode_valid','expected_blizzard_publisher','accepted_for_execution','winverifytrust_status'}))
        integer(r['installer']['bytes'],MAX_SETUP);hashval(r['installer']['sha256']);integer(r['installer']['redirects'],6)
        if 'accepted_for_execution' in r['installer']:sig(r['installer'],('bytes','sha256','redirects'))
    need(type(r['samples']) is list and len(r['samples'])<=30)
    for sample in r['samples']:
        keys(sample,('elapsed_seconds','processes','connections'))
        need(type(sample['elapsed_seconds']) in (int,float) and 0<=sample['elapsed_seconds']<=300)
        need(type(sample['processes']) is list and len(sample['processes'])<=24)
        ids=set()
        for p in sample['processes']:
            keys(p,('name','pid','parent_pid'));need(p['name'] in NAMES);integer(p['pid'],2**32-1);integer(p['parent_pid'],2**32-1);ids.add(p['pid'])
        need(type(sample['connections']) is list and len(sample['connections'])<=24)
        for c in sample['connections']:
            keys(c,('pid','remote_address','remote_port','state'));need(c['pid'] in ids);integer(c['remote_port'],65535)
            if c['remote_address']!='nonpublic':need(ipaddress.ip_address(c['remote_address']).is_global)
            need(c['state'] in {'Closed','Listen','SynSent','SynReceived','Established','FinWait1','FinWait2','CloseWait','Closing','LastAck','TimeWait','DeleteTCB','Bound','other'})
    need(type(r['file_observations']) is dict and set(r['file_observations'])<=set(ROOT_KEYS))
    for group in r['file_observations'].values():
        keys(group,('files_observed','bytes_on_disk_observed','skipped_files','extensions'))
        integer(group['files_observed'],10000);integer(group['bytes_on_disk_observed']);integer(group['skipped_files'])
        need(type(group['extensions']) is dict and len(group['extensions'])<=32)
        for ext,n in group['extensions'].items():
            need(ext=='other' or re.fullmatch(r'\.[a-z0-9]{1,10}',ext));integer(n,10000)
    need(type(r['agent_binaries']) is list and len(r['agent_binaries'])<=4)
    for binary in r['agent_binaries']:
        sig(binary,('name','bytes','sha256'));need(binary['name']=='agent.exe');integer(binary['bytes'],128*1024**2);hashval(binary['sha256'])
    if r['log_markers']:
        keys(r['log_markers'],('bytes_read','keyword_occurrences_only','raw_log_content_exported'))
        integer(r['log_markers']['bytes_read'],32*1024**2);need(r['log_markers']['raw_log_content_exported'] is False)
        keys(r['log_markers']['keyword_occurrences_only'],MARKERS)
        for n in r['log_markers']['keyword_occurrences_only'].values():integer(n,32*1024**2)
    return r


def validate_gui(g):
    keys(g,('elapsed_seconds','observer_session_id','process_sessions','window_station_visible',
            'input_desktop_accessible','input_desktop_error','windows','enumeration_truncated','probe_errors','accessibility'))
    need(type(g['elapsed_seconds']) in (int,float) and 0<=g['elapsed_seconds']<=300)
    if g['observer_session_id'] is not None:integer(g['observer_session_id'],2**32-1)
    need(type(g['process_sessions']) is list and len(g['process_sessions'])<=24)
    for p in g['process_sessions']:
        keys(p,('pid','session_id'));integer(p['pid'],2**32-1)
        if p['session_id'] is not None:integer(p['session_id'],2**32-1)
    need(g['window_station_visible'] is None or type(g['window_station_visible']) is bool)
    boolean(g['input_desktop_accessible']);boolean(g['enumeration_truncated']);integer(g['probe_errors'])
    if g['input_desktop_error'] is not None:integer(g['input_desktop_error'],2**32-1)
    need(type(g['windows']) is list and len(g['windows'])<=8)
    count=0
    def item(i,top=False):
        fields=('class','visible','enabled','label','markers')
        keys(i,fields+('controls',) if top else fields)
        need(i['class'] in set(CLASS_NAMES.values())|{'chromium','other'})
        boolean(i['visible']);boolean(i['enabled'])
        need(i['label'] in set(LABELS.values())|{'unrecognized','not_read'})
        need(type(i['markers']) is list and len(i['markers'])<=len(GUI_MARKERS) and set(i['markers'])<=set(GUI_MARKERS))
        if i['class'] not in ('dialog','button','static','combobox') or i['visible'] is False:
            need(i['label']=='not_read' and i['markers']==[])
    for window in g['windows']:
        item(window,True);need(type(window['controls']) is list)
        for control in window['controls']:item(control);count+=1
    need(count<=32)
    from ui_accessibility import validate as validate_accessibility
    # UIA report does not export HWNDs; validate PID ownership against scoped native sample.
    n=g['accessibility'].get('top_windows_requested') if type(g['accessibility']) is dict else None
    need(type(n) is int and 0<=n<=8)
    need(n<=sum(1 for w in g['windows'] if w['visible']))
    targets=[{'pid':p['pid']} for p in g['process_sessions']]
    # Exact HWND target count is enforced by the launcher; writer can check native PIDs and bounds.
    need(not g['accessibility'].get('elements') or targets)
    if n and not targets:raise ReportError('report_schema_rejected')
    synthetic_targets=[{'pid':p['pid']} for p in g['process_sessions']]
    try:
        # validate accepts count separately when checking the sanitized publication schema.
        validate_accessibility(g['accessibility'],synthetic_targets,requested_count=n)
    except (ValueError,TypeError,KeyError):raise ReportError('report_schema_rejected') from None


def load(path):
    if path.stat().st_size>MAX_REPORT:raise ReportError('report_size_limit')
    def unique(pairs):
        r={}
        for k,v in pairs:
            if k in r:raise ReportError('duplicate_json_key')
            r[k]=v
        return r
    def constant(_):raise ReportError('nonfinite_json')
    return validate(json.loads(path.read_text(encoding='utf-8'),object_pairs_hook=unique,parse_constant=constant))

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();r=load(a.input);a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':r['status'],'sanitized_report_validated':True}))
