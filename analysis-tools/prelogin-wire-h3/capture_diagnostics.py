"""Same frozen H2 capture, additionally report allowlisted file-size counters."""
from capture import Capture as Original
class Capture(Original):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.diagnostics=None
    def finish(self):
        result=super().finish()
        etl=self.work/'capture.etl';pcap=self.work/'capture.pcapng'
        if etl.exists() and pcap.exists():
            a=etl.stat().st_size;b=pcap.stat().st_size
            if not 0<a<=80*1024*1024 or not 0<b<=128*1024*1024:raise ValueError('capture_diagnostic_size')
            self.diagnostics={'etl_bytes':a,'pcap_bytes':b,'etl_at_configured_capacity':a>=64*1024*1024}
        return result
