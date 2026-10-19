param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Ranges.ps1')
$script:checks=0
function Check($Value){if(-not $Value){throw 'overlay_ranges_failed'};$script:checks++}
function Reject([scriptblock]$Code){$bad=$false;try{& $Code|Out-Null}catch{$bad=$true};Check $bad}
function Member([string]$Ip,[string[]]$Intervals){$a=AddressNumber $Ip;foreach($t in $Intervals){$r=ParseAddressInterval $t;if($a.bits -eq $r.bits -and $a.number -ge $r.low -and $a.number -le $r.high){return $true}};return $false}
$r=[ordered]@{schema='sstp-overlay-ranges-1';passed=$false;checks=0;error_code=$null;network_changed=$false}
try{
 foreach($t in @('0.0.0.0','0.0.0.1','127.0.0.1','255.255.255.255','::','::1','2001:db8::1','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')){$a=AddressNumber $t;Check ((NumberAddress $a.number $a.bits) -ceq $a.canonical)}
 Check ((IntervalSignature @('10.0.0.0/24')) -ceq (IntervalSignature @('10.0.0.0-10.0.0.255')))
 Check ((IntervalSignature @('::/127')) -ceq (IntervalSignature @('::','::1')))
 foreach($bits in @(32,128)){
  $max=[Numerics.BigInteger]::Pow(2,$bits)-1
  $allowed=@((NumberAddress 0 $bits),(NumberAddress 1 $bits),(NumberAddress 2 $bits),(NumberAddress ($max-1) $bits),(NumberAddress $max $bits))
  $complement=ComplementAddresses $allowed $bits
  Check ($complement.Count -eq 1)
  foreach($ip in $allowed){Check (-not (Member $ip $complement))}
  foreach($n in @([Numerics.BigInteger]3,([Numerics.BigInteger]::Pow(2,($bits-1))),($max-2))){Check (Member (NumberAddress $n $bits) $complement)}
  $empty=ComplementAddresses @() $bits;Check ($empty.Count -eq 1);Check (Member (NumberAddress $max $bits) $empty)
 }
 $random=New-Object Random(20261019)
 for($trial=0;$trial -lt 40;$trial++){
  $allowed=@();$numbers=@{}
  for($n=0;$n -lt 15;$n++){$value=$random.Next(0,1024);$numbers[[string]$value]=$true;$allowed+=,(NumberAddress ([Numerics.BigInteger]$value) 32)}
  $comp=ComplementAddresses $allowed 32
  foreach($point in @(0,1,1023,1024,($random.Next(0,1024)))){Check ((Member (NumberAddress ([Numerics.BigInteger]$point) 32) $comp) -ne $numbers.ContainsKey([string]$point))}
 }
 foreach($bad in @('127.0.0.1','10.1.1.1','172.16.0.1','192.168.1.1','100.64.0.1','fe80::1','fc00::1','ff02::1','::1')){Reject {AssertPublicTarget $bad}}
 foreach($bad in @('Any','::ffff:192.0.2.1','fe80::1%4','10.0.0.0/8')){Reject {AddressNumber $bad}}
 Reject {ParseAddressInterval '::/129'};Reject {ParseAddressInterval '1.1.1.2-1.1.1.1'}
 $r.passed=$true
}catch{$r.error_code='overlay_ranges_failed'}finally{$r.checks=$script:checks;if($OutputPath){[IO.File]::WriteAllText($OutputPath,($r|ConvertTo-Json -Depth 4),(New-Object Text.UTF8Encoding($false)))}}
$r|ConvertTo-Json -Depth 4
if(-not $r.passed){exit 1}
