import struct
import unittest
import packets
import packet_diagnostics

def block(k,b):
    b+=b'\0'*((-len(b))%4);n=len(b)+12
    return struct.pack('<II',k,n)+b+struct.pack('<I',n)
def pcap(segments):
    out=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))+block(1,struct.pack('<HHI',1,0,65535))
    for seq,payload,invalid in segments:
        tcp=struct.pack('!HHIIBBHHH',12345,443,seq,0,0x50,0x18,65535,0,0)+payload
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,0 if invalid else 20+len(tcp),1,0,64,6,0,b'\1'*4,b'\2'*4)
        f=b'\0'*12+b'\x08\x00'+ip+tcp;out+=block(6,struct.pack('<5I',0,0,0,len(f),len(f))+f)
    return out
class ParserAudit(unittest.TestCase):
    def review(self,segments):
        raw=pcap(segments);a=packets.tcp_runs(raw);b=packet_diagnostics.tcp_runs(raw)
        self.assertEqual(a,{k:v for k,v in b.items() if not k.startswith('_private_')});return b
    def test_valid_retransmissions(self):
        b=self.review([(1,b'ABCDE',False),(1,b'ABCDE',False)]);self.assertEqual(len(b['_private_valid_segments']),2)
    def test_ip_rejected_stays_rejected(self):
        b=self.review([(1,b'SYNTHETIC_PRIVATE',True)]);self.assertEqual(b['runs'],[]);self.assertEqual(len(b['_private_rejected_ip_frames']),1)
    def test_conflicted_flow_stays_rejected(self):
        b=self.review([(1,b'ABCDE',False),(1,b'AXXXX',False)]);self.assertEqual(b['runs'],[]);self.assertEqual(len(b['_private_conflicted_segments']),2)
    def test_gap_stays_gap(self):
        b=self.review([(1,b'ABCDE',False),(9,b'FGHIJ',False)]);self.assertEqual(len(b['runs'][0]['chunks']),2)
if __name__=='__main__':unittest.main()
