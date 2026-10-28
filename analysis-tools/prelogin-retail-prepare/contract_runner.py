"""Expose bounded test IDs/format booleans, never exception messages or values."""
import hashlib,json,os,re,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
def notice(label,value):
 print('::notice title=bounded_contract_diagnostic::'+label+'='+str(value),flush=True)
def main(suite):
 folders={'retail':ROOT/'analysis-tools/prelogin-retail-prepare','attribution':ROOT/'analysis-tools/prelogin-tcp-attribution'}
 if suite not in folders:raise ValueError('suite')
 if suite=='retail':
  raw=(folders[suite]/'content_reference.json').read_bytes()
  notice('reference_has_crlf',b'\r\n'in raw)
  sys.path.insert(0,str(folders[suite]));import content_probe
  notice('reference_exact_sha_matches',hashlib.sha256(raw).hexdigest()==content_probe.REFERENCE_SHA)
  manifest=json.loads((folders[suite]/'testdata/attribution/manifest.json').read_text())
  notice('frozen_exact_sha_match_count',sum(hashlib.sha256((folders[suite]/'testdata/attribution'/v['file']).read_bytes()).hexdigest()==v['sha256']for v in manifest.values()))
 tests=unittest.defaultTestLoader.discover(str(folders[suite]),pattern='test_*.py')
 result=unittest.TextTestRunner(verbosity=2).run(tests)
 notice('suite',suite);notice('executed',result.testsRun);notice('failures',len(result.failures));notice('errors',len(result.errors))
 for test,_ in (result.failures+result.errors)[:32]:
  name=test.id()
  if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{1,220}',name):notice('failed_test',name)
 return 0 if result.wasSuccessful()else 1
if __name__=='__main__':raise SystemExit(main(sys.argv[1]))
