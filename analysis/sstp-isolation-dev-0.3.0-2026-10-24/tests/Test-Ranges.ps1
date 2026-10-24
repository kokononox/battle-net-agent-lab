param([string]$OutputDirectory=(Join-Path $PSScriptRoot '../evidence'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '../src/Preview.ps1')
$script:Checks=0
function Check([bool]$Condition,[string]$Name){if(-not $Condition){throw ('test_failed: '+$Name)};$script:Checks++}
function Reject([scriptblock]$Body,[string]$Name){$threw=$false;try{& $Body|Out-Null}catch{$threw=$true};Check $threw $Name}
Check ((AssertPublicInterval '8.8.8.8') -ceq '8.8.8.8') 'single-v4'
Check ((AssertPublicInterval '8.8.8.0/24') -ceq '8.8.8.0-8.8.8.255') 'cidr-v4'
Check ((AssertPublicInterval '2606:4700::/32') -ceq '2606:4700::-2606:4700:ffff:ffff:ffff:ffff:ffff:ffff') 'cidr-v6'
foreach($v in @('8.8.8.9/24','2606:4700::1/32','8.8.8.1-8.8.8.0','8.8.8.8-2606:4700::1','008.8.8.8','8.8.8','0x08080808','8.8.8.8%1','8.8.8.8/33','2606:4700::/129','8.8.8.0/024','8.8.8.0/255.255.255.0','8.8.8.8/24/1','8.8.8.8 - 8.8.8.9','::ffff:8.8.8.8','1.1.1.1-11.0.0.1','9.0.0.0-11.0.0.0','::/0','0.0.0.0/0','fc00::/7','192.168.1.0/24','224.0.0.0/4','fe80::/10')){
 Reject {AssertPublicInterval $v} ('reject-'+$v)
}
Check ((AssertPublicInterval ' 8.8.8.0/24 ') -ceq '8.8.8.0-8.8.8.255') 'outer-whitespace'
$c=ConfigFromLines @('8.8.8.0/24','8.8.8.128-8.8.9.0','cloudflare-dns.com','2606:4700:4700::1111')
Check ($c.schema -ceq 'sstp-allowlist-config-2' -and $c.domains[0] -ceq 'cloudflare-dns.com') 'config-domains-and-ranges'
$p=NewDestinationPlan $c @{'cloudflare-dns.com'=@('1.1.1.1')}
Check (-not $p.activation_allowed -and -not $p.firewall_changed -and -not $p.dns_queried) 'pure-preview-gated'
Reject {NewDestinationPlan $c} 'unresolved-domain'
Reject {NewDestinationPlan $c @{'cloudflare-dns.com'=@('1.1.1.0/24')}} 'dns-answer-must-be-single'
Check ((IntervalSignature @('8.8.8.0/24')) -cne (IntervalSignature @('8.8.9.0/24'))) 'different-signatures'
Check ((IntervalSignature @('8.8.8.8','8.8.8.10')) -cne (IntervalSignature @('1.1.1.1','1.1.1.3'))) 'baseline-multielement-signature-regression'
Check ((IntervalSignature @('8.8.8.8','8.8.8.9')) -ceq (IntervalSignature @('8.8.8.8-8.8.8.9'))) 'same-signatures'
$merged=@(CanonicalIntervals @('8.8.8.0/24','8.8.8.128-8.8.9.0'))
Check ($merged.Count -eq 1 -and (FormatInterval $merged[0].low $merged[0].high 32) -ceq '8.8.8.0-8.8.9.0') 'merge-overlap-adjacent'
foreach($bits in @(32,128)){
 Check ((IntervalSignature (ComplementAddresses @() $bits)) -ceq ($bits.ToString()+':0:'+([Numerics.BigInteger]::Pow(2,$bits)-1).ToString())) ('empty-allow-'+$bits)
 $all='0.0.0.0/0';if($bits -eq 128){$all='::/0'}
 Check (@(ComplementAddresses @($all) $bits).Count -eq 0) ('full-allow-'+$bits)
 Check ((IntervalSignature (IntervalsToCidrs @($all))) -ceq (IntervalSignature @($all))) ('zero-prefix-split-'+$bits)
}
# Small exhaustive oracle: evaluate every offset in a /24 with mixed overlaps.
$allow=@('8.8.8.3-8.8.8.7','8.8.8.6-8.8.8.12','8.8.8.64/27','8.8.8.255')
$blocked=@(CanonicalIntervals (IntervalsToCidrs (ComplementAddresses $allow 32)))
$allowed=@(CanonicalIntervals $allow);$base=(AddressNumber '8.8.8.0').number
for($i=0;$i -lt 256;$i++){
 $n=$base+$i;$yes=$false;$no=$false
 foreach($r in $allowed){if($n -ge $r.low -and $n -le $r.high){$yes=$true}}
 foreach($r in $blocked){if($n -ge $r.low -and $n -le $r.high){$no=$true}}
 Check ($yes -ne $no) ('partition-'+$i)
}
# Export independent-oracle vectors, including IPv6 and almost-full spaces.
$vectors=@()
foreach($case in @(@('8.8.8.0/24','8.8.8.128-8.8.9.0'),@('2606:4700::/32','2001:4860:4860::8888'),@('0.0.0.0/1','128.0.0.0/2'),@('::/1','8000::/2'),@('0.0.0.0','255.255.255.255'),@('::','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'))){
 foreach($bits in @(32,128)){$vectors+=,[pscustomobject]@{allowed=@($case);bits=$bits;blocked_cidrs=@(IntervalsToCidrs (ComplementAddresses $case $bits))}}
}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'range-vectors.json'),(ConvertTo-Json -InputObject $vectors -Depth 8))
$result=[pscustomobject]@{suite='range-preview';assertions=$script:Checks;passed=$true;runtime=$PSVersionTable.PSVersion.ToString();netsecurity_executed=$false}
[IO.File]::WriteAllText((Join-Path $OutputDirectory 'range-tests.json'),(ConvertTo-Json $result))
$result|ConvertTo-Json -Compress
