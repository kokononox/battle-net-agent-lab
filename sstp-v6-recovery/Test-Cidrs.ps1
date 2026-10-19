param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Ranges.ps1')
$script:checks=0
function Check($Value){if(-not $Value){throw 'cidr_check_failed'};$script:checks++}
function Reject([scriptblock]$Code){$bad=$false;try{& $Code|Out-Null}catch{$bad=$true};Check $bad}
$r=[ordered]@{schema='sstp-cidr-test-1';passed=$false;checks=0;error_code=$null;network_changed=$false}
try{
 foreach($bits in @(32,128)){
  $full=ComplementAddresses @() $bits;$prefix=IntervalsToCidrs $full
  Check ($prefix.Count -eq 1);Check ((IntervalSignature $prefix) -ceq (IntervalSignature $full))
  $point='192.0.2.1';if($bits -eq 128){$point='2001:db8::1'}
  $old=ComplementAddresses @($point) $bits;$new=IntervalsToCidrs $old
  Check ($new.Count -eq $bits);Check ((IntervalSignature $old) -ceq (IntervalSignature $new))
  Check (@($new|Where-Object{$_ -match '-'}).Count -eq 0)
  Reject {IntervalsToCidrs $old 1}
 }
 $rnd=New-Object Random(1202)
 for($trial=0;$trial -lt 16;$trial++){
  $points=@()
  for($n=0;$n -lt 5;$n++){$value=[Numerics.BigInteger]::Pow(2,125)+$rnd.Next(1,1000000);$points+=,(NumberAddress $value 128)}
  $old=ComplementAddresses $points 128;$new=IntervalsToCidrs $old
  Check ((IntervalSignature $old) -ceq (IntervalSignature $new))
 }
 $r.passed=$true
}catch{$r.error_code='cidr_test_failed'}finally{$r.checks=$script:checks;if($OutputPath){[IO.File]::WriteAllText($OutputPath,($r|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))}}
$r|ConvertTo-Json
if(-not $r.passed){exit 1};exit 0
