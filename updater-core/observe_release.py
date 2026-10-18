"""Observe only the two official release tables. No CDN configs/assets or game IO."""
from pathlib import Path
import argparse,json,datetime
from release_core import *

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--info',type=Path,required=True,help='Uploaded/offline .build.info copy, not a game directory');ap.add_argument('--config',type=Path,required=True,help='Uploaded/offline selected build config');ap.add_argument('--region',choices=sorted(REGIONS),default='eu');ap.add_argument('--out',type=Path,required=True);args=ap.parse_args();need(not args.out.exists(),'output_exists')
 def bounded(p,limit):
  need(p.is_file() and not p.is_symlink() and p.stat().st_size<=limit,'input_bounds')
  with p.open('rb') as f:r=f.read(limit+1)
  need(len(r)<=limit,'input_limit');return r
 baseline=read_baseline_bytes(bounded(args.info,1048576),bounded(args.config,CAP),Scope(region=args.region));transport=OfficialTableTransport();v=transport.fetch(VERSIONS_URL);d=transport.fetch(CDNS_URL);target=resolve(v,d,baseline.scope);report=metadata_report(baseline,target,'live_official_https_release_tables');report.update(observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),release_table_requests=transport.requests,release_table_bytes=transport.bytes_read,release_urls=[VERSIONS_URL,CDNS_URL],latest_claim_scope='single advertised region row at observation time; not a timeless latest-version guarantee')
 with args.out.open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
 print(json.dumps({'status':report['decision'],'installed_version':baseline.version,'advertised_version':target.version,'region':target.scope.region,'requests':transport.requests,'bytes':transport.bytes_read,'game_assets_fetched':0,'installation_ready':False}))
if __name__=='__main__':
 try:main()
 except Exception as e:
  print('Stopped:',str(e) if isinstance(e,InvalidRelease) else type(e).__name__);raise SystemExit(2)
