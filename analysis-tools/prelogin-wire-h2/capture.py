"""Private, bounded pktmon capture. No raw capture is ever an artifact."""
import os
from pathlib import Path
import subprocess
from packets import tcp_runs

class Capture:
    def __init__(self,work,env):
        self.work=Path(work);self.env=env;self.active=False
        self.exe=Path(os.environ['SystemRoot'])/'System32'/'pktmon.exe'
        self.meta={'start_code':None,'stop_code':None,'convert_code':None,'packets':0,'issues':{}}
        self.parsed={'packets':0,'issues':{},'runs':[]}
    def command(self,args,timeout=30):
        p=subprocess.run([str(self.exe),*map(str,args)],env=self.env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout,check=False)
        return p.returncode
    def start(self):
        self.meta['start_code']=self.command(['start','--capture','--comp','nics','--pkt-size','0','--file-size','64','--log-mode','circular','--file-name',self.work/'capture.etl'])
        if self.meta['start_code']!=0:raise RuntimeError('capture_start_failed')
        self.active=True
    def finish(self):
        if not self.active:return self.parsed
        self.active=False;self.meta['stop_code']=self.command(['stop'])
        etl=self.work/'capture.etl';pcap=self.work/'capture.pcapng'
        if self.meta['stop_code']!=0 or not etl.exists() or not 0<etl.stat().st_size<=80*1024*1024:raise RuntimeError('capture_stop_or_size_failed')
        self.meta['convert_code']=self.command(['etl2pcap',etl,'--out',pcap],90)
        if self.meta['convert_code']!=0 or not pcap.exists() or not 0<pcap.stat().st_size<=128*1024*1024:raise RuntimeError('capture_convert_failed')
        self.parsed=tcp_runs(pcap.read_bytes())
        self.meta.update(packets=self.parsed['packets'],issues=self.parsed['issues'])
        return self.parsed
