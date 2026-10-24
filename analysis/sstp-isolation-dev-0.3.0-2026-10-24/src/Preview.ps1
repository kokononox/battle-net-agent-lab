# Pure configuration-to-rule-plan pipeline. No DNS/firewall/VPN operations.
Set-StrictMode -Version 2.0
. (Join-Path $PSScriptRoot 'Policy.ps1')
function ConfigFromLines([string[]]$Lines){
 $domains=@();$ips=@()
 foreach($line in $Lines){
  $v=$line.Trim();if(-not $v){continue}
  if($v -match '[/:]' -or $v -match '^[0-9.]+-' -or $v -match '^[0-9.]+$'){$ips+=,(PolicyIp $v)}
  else{try{$ips+=,(PolicyIp $v)}catch{$domains+=,(PolicyDomain $v)}}
 }
 PolicyConfig ([pscustomobject]@{schema='sstp-allowlist-config-2';domains=$domains;ip_addresses=$ips})
}
function NewDestinationPlan($Config,[hashtable]$DomainAnswers=@{}){
 $c=PolicyConfig $Config;$ips=@($c.ip_addresses)
 foreach($key in $DomainAnswers.Keys){if($key -cnotin $c.domains){throw 'plan_unexpected_domain_answer'}}
 foreach($domain in $c.domains){
  if(-not $DomainAnswers.ContainsKey($domain)){throw 'plan_unresolved_domain'}
  $answers=@($DomainAnswers[$domain]);if($answers.Count -lt 1 -or $answers.Count -gt 32){throw 'plan_domain_answers'}
  foreach($value in $answers){
   if($value -isnot [string] -or $value -match '[/\-]'){throw 'plan_domain_answer_not_single_ip'}
   $a=UserAddress $value;$ips+=,(AssertPublicInterval $a.canonical)
  }
 }
 if($ips.Count -lt 1 -or $ips.Count -gt 512){throw 'plan_size'}
 $merged=@(CanonicalIntervals $ips);$allowed=@($merged|ForEach-Object{FormatInterval $_.low $_.high $_.bits})
 $v4=@(IntervalsToCidrs (ComplementAddresses $allowed 32));$v6=@(IntervalsToCidrs (ComplementAddresses $allowed 128))
 [pscustomobject]@{schema='sstp-destination-plan-1';version='0.3.0-dev';allowed_intervals=$allowed;blocked_ipv4_cidrs=$v4;blocked_ipv6_cidrs=$v6;dns_queried=$false;firewall_changed=$false;activation_allowed=$false;outside_vpn_protection_installed=$false;domain_identity='caller_supplied_ip_snapshot_not_hostname_identity'}
}
