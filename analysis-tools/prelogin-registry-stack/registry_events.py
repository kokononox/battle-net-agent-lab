"""Private bytes remain only in process memory; public records are boolean/counters."""
import re
APIS={a+b for a in ('RegOpenKeyEx','RegCreateKeyEx','RegQueryValueEx','RegGetValue','RegSetValueEx') for b in ('A','W')}|{'RegCloseKey'}
UUID=re.compile(rb'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}')
def decode(raw):
    for enc in ('ascii','utf-16-le'):
        try:
            x=raw.decode(enc).rstrip('\0').encode('ascii')
            if UUID.fullmatch(x):return x
        except (UnicodeError,ValueError):pass
    return None
class Events:
    def __init__(self):self.ready=set();self.installed={};self.values=[];self.errors=0;self.limits=0
    def accept(self,row,e,raw):
        try:
            k=e['kind'];pid=row['pid']
            if k=='reg_ready':
                if set(e)!={'kind','pointer_bits'} or e['pointer_bits'] not in (32,64):raise ValueError()
                self.ready.add(pid)
            elif k=='reg_installed':
                if set(e)!={'kind','api'} or e['api'] not in APIS:raise ValueError()
                self.installed.setdefault(pid,set()).add(e['api'])
            elif k=='reg_error':self.errors+=1
            elif k=='reg_limit':self.limits+=1
            elif k=='reg_value':
                if set(e)!={'kind','api','operation','label','status','value_type','caller_rva','stack_status','main_module_stack_rvas'}:raise ValueError()
                if e['api'] not in APIS or e['operation'] not in ('read','write') or e['label'] not in ('target','probe'):raise ValueError()
                if type(e['status']) is not int or not 0<=e['status']<=65535:raise ValueError()
                for x in ('value_type','caller_rva'):
                    if e[x] is not None and (type(e[x]) is not int or not 0<=e[x]<=0xffffffff):raise ValueError()
                if e['stack_status'] not in ('captured','failed') or type(e['main_module_stack_rvas']) is not list or len(e['main_module_stack_rvas'])>16:raise ValueError()
                if any(type(v) is not int or not 0<=v<=0xffffffff for v in e['main_module_stack_rvas']) or len(set(e['main_module_stack_rvas']))!=len(e['main_module_stack_rvas']) or (e['stack_status']=='failed' and e['main_module_stack_rvas']):raise ValueError()
                raw=bytes(raw or b'')
                if len(raw)>256 or (e['status']!=0 and raw) or len(self.values)>=256:raise ValueError()
                self.values.append(dict(e,pid=pid,process_sha256=row['sha256'],value=decode(raw) if e['status']==0 and e['value_type']==1 else None))
            else:raise ValueError()
        except (ValueError,KeyError,TypeError):self.errors+=1
    def summary(self,values):
        records=[]
        for x in self.values:
            if x['label']!='target':continue
            records.append({k:x[k] for k in ('api','operation','status','value_type','caller_rva','process_sha256','stack_status','main_module_stack_rvas')}|{'valid_uuid':x['value'] is not None,'equals_wire_host_id':len(values)==1 and x['value'] in values})
        return dict(ready_processes=len(self.ready),installed_apis=sorted(set.union(set(),*self.installed.values())),errors=self.errors,limits=self.limits,records=records)
