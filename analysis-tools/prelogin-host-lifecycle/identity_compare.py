"""Private equality only; never export a UUID, its hash, or computer-name candidate."""
import re
PINNED_AGENT='b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5'
UUID4=re.compile(rb'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}')
class Tracking:
    def __init__(self,delegate):
        self.delegate=delegate;self.values=set();self.observations=0;self.invalid=0
    def __call__(self,request,sha):
        result=self.delegate(request,sha)
        if sha!=PINNED_AGENT or request['host']!='telemetry-in.battle.net' or request['method']!='POST' or not result['hardware_payload_verified']:return result
        from decode_startup import parts,wire,one_bytes
        try:
            for chunk in parts(request['body'],request['content_type']):
                envelope=wire(chunk)
                if one_bytes(envelope,2)!=b'Blizzard.Telemetry.Distribution.Agent' or one_bytes(envelope,3)!=b'StartAgent':continue
                value=one_bytes(wire(one_bytes(wire(one_bytes(envelope,1)),4)),1)
                if not UUID4.fullmatch(value):self.invalid+=1;continue
                self.observations+=1;self.values.add(value)
        except (ValueError,TypeError,KeyError):self.invalid+=1
        return result
    def summary(self):
        return {'host_id_observations':self.observations,'host_id_unique':len(self.values),'invalid_host_id_events':self.invalid}

def eligible(p):
    return (p['completed'] and p['launched'] and p['bootstrap_pin_match'] and p['all_processes_instrumented']
            and p['instrumented_processes']>0 and p['collector_errors']==0 and p['dropped_events']==0
            and not p['collector_fatal'] and p['hardware_requests']>0 and p['host_id_observations']>0
            and p['host_id_unique']==1 and p['invalid_host_id_events']==0)

def compare(a,b,phases):
    if len(phases)!=2 or not all(eligible(x) for x in phases) or len(a.values)!=1 or len(b.values)!=1:return None
    return a.values==b.values
