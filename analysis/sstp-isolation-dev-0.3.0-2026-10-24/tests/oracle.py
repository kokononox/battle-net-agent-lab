"""Independent Python integer/ipaddress oracle for PowerShell interval output."""
import ipaddress as ip, json, pathlib, random, subprocess, sys
root=pathlib.Path(__file__).resolve().parents[1]
pwsh=sys.argv[1] if len(sys.argv)>1 else 'pwsh'
rng=random.Random(20261024)
cases=[]
for bits in (32,128):
 for _ in range(24):
  allowed=[]
  for __ in range(rng.randrange(1,5)):
   lo=rng.randrange(1<<bits); hi=min((1<<bits)-1,lo+rng.randrange(1<<rng.randrange(1,bits+1)))
   addr=ip.IPv4Address if bits==32 else ip.IPv6Address
   allowed.append(f'{addr(lo)}-{addr(hi)}')
  cases.append({'bits':bits,'allowed':allowed})
(root/'evidence/random-inputs.json').write_text(json.dumps(cases))
script=r'''
param([string]$Root)
$ErrorActionPreference='Stop'
. (Join-Path $Root 'src/Ranges.ps1')
$cases=ConvertFrom-Json ([IO.File]::ReadAllText((Join-Path $Root 'evidence/random-inputs.json')))
$out=@();foreach($c in $cases){$out+=,[pscustomobject]@{bits=$c.bits;allowed=@($c.allowed);blocked_cidrs=@(IntervalsToCidrs (ComplementAddresses @($c.allowed) $c.bits))}}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/random-output.json'),(ConvertTo-Json -InputObject $out -Depth 8))
'''
(root/'tests/Oracle-Vectors.ps1').write_text(script)
subprocess.run([pwsh,'-NoProfile','-File',str(root/'tests/Oracle-Vectors.ps1'),str(root)],check=True)
def intervals(texts,bits):
 result=[]
 for text in texts:
  if '-' in text:
   a,b=text.split('-');a,b=ip.ip_address(a),ip.ip_address(b)
  elif '/' in text:
   n=ip.ip_network(text,strict=False);a,b=n.network_address,n.broadcast_address
  else:a=b=ip.ip_address(text)
  if a.max_prefixlen!=bits:continue
  result.append((int(a),int(b)))
 return merge(result)
def merge(values):
 out=[]
 for a,b in sorted(values):
  if out and a<=out[-1][1]+1:out[-1]=(out[-1][0],max(out[-1][1],b))
  else:out.append((a,b))
 return out
def complement(allowed,bits):
 cursor=0;out=[]
 for a,b in allowed:
  if cursor<a:out.append((cursor,a-1))
  cursor=b+1
 if cursor<(1<<bits):out.append((cursor,(1<<bits)-1))
 return out
vectors=json.loads((root/'evidence/range-vectors.json').read_text())+json.loads((root/'evidence/random-output.json').read_text())
for i,c in enumerate(vectors):
 bits=c['bits'];expected=complement(intervals(c['allowed'],bits),bits)
 nets=[ip.ip_network(n,strict=True) for n in c['blocked_cidrs']]
 assert all(n.max_prefixlen==bits for n in nets),i
 assert intervals(c['blocked_cidrs'],bits)==expected,(i,'complement mismatch')
 assert sum(n.num_addresses for n in nets)==sum(b-a+1 for a,b in expected),(i,'overlapping CIDRs')
 # Exact address cardinality, including 2**128, without enumerating any IPs.
 assert sum(b-a+1 for a,b in intervals(c['allowed'],bits))+sum(n.num_addresses for n in nets)==1<<bits,i
result={'suite':'independent-python-oracle','passed':True,'cases':len(vectors),'random_seed':20261024,'method':'Python ipaddress + integer complement; no IP-by-IP expansion','netsecurity_executed':False}
(root/'evidence/oracle-tests.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result))
