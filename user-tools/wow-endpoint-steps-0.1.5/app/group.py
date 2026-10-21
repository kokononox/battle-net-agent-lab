"""Fixed five-target experiment. Separate owned journals; shared deadline, all-or-stop."""
import json,os,time,uuid
from core import Session,ENDPOINTS,LEASE,atomic,digest
from observer import signal_stop
GROUP_ENDPOINTS=[dict(ip=ip,port=port,protocol='TCP') for ip,port in (
 ('3.124.215.108',443),('3.75.62.211',443),('35.204.95.176',1119),
 ('37.244.29.93',3724),('37.244.62.205',3724))]
assert all(e in ENDPOINTS for e in GROUP_ENDPOINTS)

class GroupSession(Session):
 def __init__(self,*args,**kwargs):
  super().__init__(*args,**kwargs);self.members=[];self.group_started=None;self.group_active=None;self.group_monitor_result=None
 def start_group(self,consent):
  if self.phase!='idle' or self.current is not None:raise RuntimeError('restore_previous_first')
  if consent is not True:raise RuntimeError('explicit_group_consent_required')
  if not self.program or digest(self.program)!=self.hash:raise RuntimeError('selected_exe_changed')
  self.phase='arming';self.group_started=time.time();expires=self.group_started+LEASE
  self.group_active=None;self.group_monitor_result=None
  try:
   # Persist every intent before any rule is added. Each has exact independent ownership.
   for e in GROUP_ENDPOINTS:
    i=uuid.uuid4().hex;j={'id':i,'name':'WoWEndpointSteps-'+i,'group':'WoWEndpointStepsOwner-'+i,'program':str(self.program),**e,'expires':expires,'parent_pid':os.getpid()}
    if not self.members:j.update(monitor_targets=GROUP_ENDPOINTS,monitor_seconds=LEASE)
    p=self.private/('session-'+i+'.json');atomic(p,j);self.members.append((p,j,ENDPOINTS.index(e)))
    self.current=self.members[0]
   for p,j,index in self.members:self.fw('probe',p)
   if not self.guard:raise RuntimeError('watchdog_unavailable')
   for p,j,index in self.members:self.guard(p)
   for p,j,index in self.members:
    # Reserve more than the 60-second add timeout before watchdog expiry.
    if time.time()>=expires-90:raise RuntimeError('group_setup_too_slow_restore_required')
    try:self.fw('add',p)
    except Exception:
     j['add_outcome_uncertain']=True;atomic(p,j);raise
   if any(p.with_suffix('.restored').exists() for p,j,index in self.members) or time.time()>=expires-30:raise RuntimeError('group_deadline_or_guard_restore')
   if not self.monitor:raise RuntimeError('group_monitor_required')
   self.monitor(self.members[0][0])
   if time.time()>=expires-30 or any(p.with_suffix('.restored').exists() for p,j,index in self.members):raise RuntimeError('group_deadline_or_guard_restore')
   self.group_active=time.time();self.phase='blocked';self.error=None
  except Exception:
   if self.members:
    try:self.restore('setup_failed')
    except Exception:self.phase='recovery_required'
   else:self.phase='idle'
   raise
 def restore(self,why='manual'):
  if not self.members:return super().restore(why)
  self.phase='recovery_required';primary=self.members[0][0]
  # Signal the sampling boundary before cleanup. Never wait on monitoring to remove rules.
  try:signal_stop(primary)
  except Exception:pass
  failures=[];verified=[]
  for p,j,index in self.members:
   try:
    self.fw('remove',p)
    if j.get('add_outcome_uncertain') and time.time()<j['expires'] and not p.with_suffix('.restored').exists():raise RuntimeError('add_uncertain_wait_for_watchdog_lease')
    verified.append(p)
   except Exception:failures.append(p)
  if failures:
   self.error='restore_failed_use_restore_cmd'
   # All journals stay, including verified ones; no group-wide success claim.
   self.save();raise RuntimeError('group_restore_incomplete_run_Restore')
  restored=time.time()
  if self.group_monitor_result is None:
   try:self.group_monitor_result=self.monitor_stop(primary) if self.monitor_stop else {'status':'not_collected'}
   except Exception:self.group_monitor_result={'status':'monitor_inconclusive'}
  self.records.append({'mode':'group','endpoints':GROUP_ENDPOINTS,'selected_exe_sha256':self.hash,
   'started_utc_epoch':self.group_started,'all_rules_active_utc_epoch':self.group_active,
   'restored_utc_epoch':restored,'reason':why,'connection_monitor':self.group_monitor_result,
   'rule_absence_verified':True,'rule_absence_verified_count':len(verified),
   'packet_block_verified':False,'observation':None,'baseline_restored':None})
  for p,j,index in self.members:
   p.unlink(missing_ok=True);p.with_suffix('.ready').unlink(missing_ok=True);p.with_suffix('.restored').unlink(missing_ok=True)
  self.members=[];self.current=None;self.phase='baseline';self.error=None;self.save()
 def status(self):
  if not self.members:return {**super().status(),'mode':'single','group_endpoints':GROUP_ENDPOINTS}
  expires=min(j['expires'] for p,j,index in self.members);remaining=max(0,int(expires-time.time()))
  if remaining==0 or any(p.with_suffix('.restored').exists() for p,j,index in self.members):
   try:self.restore('watchdog_or_lease_expired')
   except Exception:self.phase='recovery_required';self.error='restore_failed_use_restore_cmd'
  return {'phase':self.phase,'remaining':remaining,'endpoint':None,'mode':'group','group_endpoints':GROUP_ENDPOINTS,'records':self.records,'error':self.error,'program_selected':self.program is not None}
