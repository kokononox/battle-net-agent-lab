# Pure integer interval operations. No DNS/network/firewall calls.
Set-StrictMode -Version 2.0
Add-Type -AssemblyName System.Numerics
function AddressNumber([string]$Text) {
 if($Text -match '[%\s]'){throw 'overlay_address'}
 $ip=$null;if(-not [Net.IPAddress]::TryParse($Text,[ref]$ip) -or $ip.IsIPv4MappedToIPv6){throw 'overlay_address'}
 $bytes=$ip.GetAddressBytes();[Array]::Reverse($bytes)
 $unsigned=New-Object byte[] ($bytes.Length+1);[Array]::Copy($bytes,$unsigned,$bytes.Length)
 $n=New-Object Numerics.BigInteger (,$unsigned)
 [pscustomobject]@{bits=($bytes.Length*8);number=$n;canonical=$ip.ToString()}
}
function NumberAddress([Numerics.BigInteger]$Value,[int]$Bits) {
 if($Bits -notin @(32,128) -or $Value -lt 0 -or $Value -ge [Numerics.BigInteger]::Pow(2,$Bits)){throw 'overlay_number'}
 $little=$Value.ToByteArray();$bytes=New-Object byte[] ($Bits/8)
 [Array]::Copy($little,$bytes,[Math]::Min($little.Length,$bytes.Length));[Array]::Reverse($bytes)
 (New-Object Net.IPAddress (,$bytes)).ToString()
}
function ParseAddressInterval([string]$Text) {
 if($Text.Contains('/')) {
  $parts=$Text.Split('/');if($parts.Length -ne 2 -or $parts[1] -cnotmatch '^\d{1,3}$'){throw 'overlay_interval'}
  $a=AddressNumber $parts[0];$prefix=[int]$parts[1]
  if($prefix -gt $a.bits){throw 'overlay_interval'}
  $size=[Numerics.BigInteger]::Pow(2,($a.bits-$prefix))
  $lo=[Numerics.BigInteger]::Divide($a.number,$size)*$size
  return [pscustomobject]@{bits=$a.bits;low=$lo;high=($lo+$size-1)}
 }
 $parts=$Text.Split('-');if($parts.Length -gt 2){throw 'overlay_interval'}
 $a=AddressNumber $parts[0];$b=$a;if($parts.Length -eq 2){$b=AddressNumber $parts[1]}
 if($a.bits -ne $b.bits -or $a.number -gt $b.number){throw 'overlay_interval'}
 [pscustomobject]@{bits=$a.bits;low=$a.number;high=$b.number}
}
function CanonicalIntervals([string[]]$Texts) {
 $items=@($Texts|ForEach-Object{ParseAddressInterval $_}|Sort-Object bits,low,high)
 $merged=New-Object Collections.ArrayList
 foreach($x in $items) {
  if($merged.Count -gt 0) {
   $prev=$merged[$merged.Count-1]
   if($prev.bits -eq $x.bits -and $x.low -le ($prev.high+1)){if($x.high -gt $prev.high){$prev.high=$x.high};continue}
  }
  $null=$merged.Add($x)
 }
 return ,@($merged.ToArray())
}
function IntervalSignature([string[]]$Texts) {
 (@(CanonicalIntervals $Texts)|ForEach-Object{[string]$_.bits+':'+$_.low.ToString()+':'+$_.high.ToString()}) -join '|'
}
function FormatInterval([Numerics.BigInteger]$Low,[Numerics.BigInteger]$High,[int]$Bits) {
 if($Low -eq $High){return (NumberAddress $Low $Bits)}
 if($Low -eq 0 -and $High -eq ([Numerics.BigInteger]::Pow(2,$Bits)-1)){if($Bits -eq 32){return '0.0.0.0/0'};return '::/0'}
 (NumberAddress $Low $Bits)+'-'+(NumberAddress $High $Bits)
}
function ComplementAddresses([string[]]$Allowed,[int]$Bits) {
 if($Bits -notin @(32,128) -or $Allowed.Count -gt 512){throw 'overlay_allow_size'}
 $points=@($Allowed|ForEach-Object{AddressNumber $_}|Where-Object{$_.bits -eq $Bits}|Sort-Object number -Unique)
 $cursor=[Numerics.BigInteger]::Zero;$limit=[Numerics.BigInteger]::Pow(2,$Bits)-1;$out=@()
 foreach($p in $points){if($p.number -gt $cursor){$out+=,(FormatInterval $cursor ($p.number-1) $Bits)};$cursor=$p.number+1}
 if($cursor -le $limit){$out+=,(FormatInterval $cursor $limit $Bits)}
 return ,$out
}
function AssertPublicTarget([string]$Text) {
 $a=AddressNumber $Text;$n=$a.number
 if($a.bits -eq 32){
  $forbidden=@('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.168.0.0/16','224.0.0.0/3')
 }else{$forbidden=@('::/96','::1','fc00::/7','fe80::/10','fec0::/10','ff00::/8')}
 foreach($r in $forbidden){$x=ParseAddressInterval $r;if($n -ge $x.low -and $n -le $x.high){throw 'overlay_non_public_target'}}
 return $a.canonical
}
# MSFT_NetFirewallRule: aggregate status can be Full=1 plus InactiveProfile=5
# for a rule scoped to Any profiles. Never accept inactive-only or error states.
function QualifiedOverlayEnforcement([int[]]$Status,[int]$Primary){
 if($null -eq $Status -or $Status.Count -lt 1 -or $Status.Count -gt 2 -or $Primary -ne 1){return $false}
 $unique=@($Status|Sort-Object -Unique)
 if($unique.Count -ne $Status.Count -or $Status -notcontains 1){return $false}
 foreach($v in $Status){if($v -notin @(1,5)){return $false}}
 return $true
}
# Exact CIDR decomposition; only the representation changes, never coverage.
function IntervalsToCidrs([string[]]$Intervals,[int]$Limit=2048){
 $result=New-Object Collections.ArrayList
 foreach($r in (CanonicalIntervals $Intervals)){
  $cursor=[Numerics.BigInteger]$r.low
  while($cursor -le $r.high){
   $block=[Numerics.BigInteger]::One;$prefix=[int]$r.bits
   $room=$r.high-$cursor+1
   while($prefix -gt 0){
    $next=$block*2
    if($next -gt $room -or ($cursor % $next) -ne 0){break}
    $block=$next;$prefix--
   }
   if($result.Count -ge $Limit){throw 'overlay_cidr_limit'}
   $null=$result.Add(((NumberAddress $cursor $r.bits)+'/'+[string]$prefix))
   $cursor+=$block
  }
 }
 $out=@($result.ToArray())
 if((IntervalSignature $out) -cne (IntervalSignature $Intervals)){throw 'overlay_cidr_coverage'}
 return ,$out
}
