"""Reject unrecognized fields, arbitrary strings, raw logs and credential output."""
import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import re
import shutil
from observe_agent import initial_report, NAMES, MARKERS, ROOT_KEYS, MAX_SETUP, MAX_REPORT

class ReportError(ValueError):pass

def need(value):
    if not value:raise ReportError('report_schema_rejected')
def keys(obj,expected):need(type(obj) is dict and set(obj)==set(expected))
def integer(value,cap=2**63-1):need(type(value) is int and 0<=value<=cap)
def boolean(value):need(type(value) is bool)
def hashval(value):need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None)
def sig(obj,base=()):
    keys(obj,(*base,'authenticode_valid','expected_blizzard_publisher','accepted_for_execution'))
    for k in ('authenticode_valid','expected_blizzard_publisher','accepted_for_execution'):boolean(obj[k])
    need(obj['accepted_for_execution']==(obj['authenticode_valid'] and obj['expected_blizzard_publisher']))

def validate(r):
    template=initial_report();keys(r,template)
    need(r['schema']==template['schema'] and r['scope']==template['scope'])
    need(r['status'] in ('not_started','stopped','agent_process_observed','bootstrapper_observed_agent_not_observed'))
    need(type(r['utc']) is str and len(r['utc'])<40)
    datetime.datetime.fromisoformat(r['utc'])
    need(r['error_code'] is None or (type(r['error_code']) is str and re.fullmatch('[a-z0-9_]{1,100}',r['error_code'])))
    boolean(r['cleanup_attempted']);need(r['safety']==template['safety'] and r['interpretation']==template['interpretation'])
    need(r['limits']==template['limits'])
    if r['installer']:
        need(set(r['installer']) in ({'bytes','sha256','redirects'}, {'bytes','sha256','redirects','authenticode_valid','expected_blizzard_publisher','accepted_for_execution'}))
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
