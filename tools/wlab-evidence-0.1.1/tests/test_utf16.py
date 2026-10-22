"""Regression against retained control DNS strings, plus strict Unicode/capacity checks."""
import pathlib,subprocess,tempfile,json
r=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as d:
 exe=pathlib.Path(d)/'utf16-test'
 subprocess.run(['gcc','-std=c11','-O2',str(r/'tests/utf16_test.c'),'-o',str(exe)],check=True)
 cases=['','example.com','172.66.147.243;104.20.23.154;','::ffff:104.20.23.154;::ffff:172.66.147.243;','سلام','🌍','"\\\t\n']
 for s in cases:
  v=subprocess.run([str(exe),(s+'\0').encode('utf-16le').hex(),'24577'],capture_output=True,check=True)
  assert json.loads(v.stdout.decode())==s
 for raw,cap in [('6500',99),('65',99),('00d80000',99),('00dc0000',99),('000061000000',99),('65000000',1),('65000000',0)]:
  assert subprocess.run([str(exe),raw,str(cap)],capture_output=True).returncode==2
 # Exact non-formatted QueryName bytes observed in user control evidence, no private domains.
 raw='6500780061006d0070006c0065002e0063006f006d000000'
 assert json.loads(subprocess.check_output([str(exe),raw,'256']))=='example.com'
 # Boundary / reproducible broad round trip; no invalid surrogate code points.
 for cp in [1,31,32,127,128,2047,2048,0xd7ff,0xe000,0xffff,0x10000,0x10ffff]:
  s=chr(cp);assert json.loads(subprocess.check_output([str(exe),(s+'\0').encode('utf-16le').hex(),'16']))==s
print('UTF-16LE regression, Persian, surrogate pairs, malformed input, JSON and bounds: passed.')
