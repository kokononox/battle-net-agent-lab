"""Account only observed accepted Winsock writes; TLS framing isn't decryption.

No ciphertext, payload, socket or peer identifier is serialized. No attempt to
call TLS ciphertext 'safe' or claim all API paths are observed.
"""
import re
from collections import Counter

class TransportAudit:
    def __init__(self):
        self.streams={}
        self.counts=Counter()
        self.total=0
        self.capped=False

    def feed(self,key,data):
        self.total+=len(data)
        if self.total>16777216 or (key not in self.streams and len(self.streams)>=1000):
            self.capped=True
            self.counts['cap_unclassified_bytes']+=len(data)
            return
        s=self.streams.setdefault(key,{'mode':'detect','buf':b''})
        if s['mode']=='HTTP1_candidate':
            self.counts['HTTP1_candidate_bytes']+=len(data)
            return
        if s['mode']=='opaque':
            self.counts['opaque_bytes']+=len(data)
            return
        s['buf']+=data
        if s['mode']=='detect':
            if len(s['buf'])<8:
                return
            if re.match(rb'(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) ',s['buf']):
                s['mode']='HTTP1_candidate'
                self.counts['HTTP1_candidate_bytes']+=len(s['buf'])
                s['buf']=b''
                return
            if s['buf'][0] in (20,21,22,23,24) and s['buf'][1]==3:
                s['mode']='TLS_candidate'
            else:
                s['mode']='opaque'
                self.counts['opaque_bytes']+=len(s['buf'])
                s['buf']=b''
                return
        while len(s['buf'])>=5:
            b=s['buf'];kind=b[0];size=int.from_bytes(b[3:5],'big')
            if kind not in (20,21,22,23,24) or b[1]!=3 or b[2]>4 or size>18432:
                self.counts['invalid_TLS_framing_bytes']+=len(b)
                s['mode']='opaque';s['buf']=b''
                return
            end=5+size
            if len(b)<end:
                break
            name={20:'change_cipher_spec',21:'alert',22:'handshake',
                  23:'application_data',24:'heartbeat'}[kind]
            self.counts['TLS_'+name+'_record_bytes']+=end
            self.counts['TLS_'+name+'_records']+=1
            s['buf']=b[end:]

    def close(self,key):
        s=self.streams.pop(key,None)
        if s and s['buf']:
            self.counts['incomplete_at_observed_close_bytes']+=len(s['buf'])

    def report(self):
        buffered=sum(len(s['buf']) for s in self.streams.values())
        accounted=sum(v for k,v in self.counts.items() if k.endswith('_bytes'))+buffered
        return {'accepted_API_input_bytes':self.total,'counts':dict(self.counts),
                'buffered_unclassified_bytes':buffered,
                'accounting_reconciles':accounted==self.total,
                'cap_hit':self.capped,
                'TLS_record_type_does_not_reveal_plaintext':True,
                'HTTP_candidate_bytes_require_separate_HTTP_audit':True,
                'ciphertext_to_SSPI_plaintext_one_to_one_mapping_proven':False,
                'all_processes_and_APIs_covered':False,
                'raw_values_exported':False,'fingerprinting_absence_proven':False}