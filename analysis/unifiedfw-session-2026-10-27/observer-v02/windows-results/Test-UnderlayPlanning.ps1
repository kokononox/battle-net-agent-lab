$ErrorActionPreference='Stop';Set-StrictMode -Version 2.0
$root='/data/ufd-hf122-prepare/candidate'
. (Join-Path $root 'lab/session-core.ps1');. (Join-Path $root 'lab/native.ps1');. (Join-Path $root 'app/isolation-native.ps1')
$script:n=0;function Check($b,$m){$script:n++;if(-not $b){throw $m}}
function IsoAssertNoOtherEngine{param($s)[pscustomobject]@{physical_alias=$script:physicalAlias;physical_index=$script:physicalIndex}}
function IsoDetectSstp{[pscustomobject]@{name='SSTP fixture';svchost='C:\Windows\System32\svchost.exe';server_ips=@('192.0.2.11');dns_servers=@('192.0.2.53');interface_index=$script:vpnIndex}}
function IsoPrepareForeignAllows{param($s)return ,@()}
function IsoProfileRead{param($n)[pscustomobject]@{name=$n;enabled='True';default_outbound='Allow';allow_local_rules='True'}}
function Get-NetFirewallSecurityFilter{param($PolicyStore,$ErrorAction)return @()}
$policy=[pscustomobject]@{schema='unified-isolation-policy-1';owner=('a'*32);connection='vpn';whitelist=@([pscustomobject]@{remote_addresses=@('192.0.2.22');protocol='TCP';remote_port='443'})}
$script:physicalAlias='USB Wi-Fi fixture';$script:physicalIndex=7;$script:vpnIndex=42;$wifi=IsoPrepare $policy $null
$script:physicalAlias='Ethernet fixture';$script:physicalIndex=19;$ethernet=IsoPrepare $policy $null
Check (UEqual $wifi.rules $ethernet.rules) 'physical adapter alias/index does not enter compiled rules'
$transport=@($ethernet.rules|Where-Object{$_.spec.service -ceq 'SstpSvc'})
Check ($transport.Count -eq 1) 'one transport rule'
Check ($transport[0].spec.interface_alias -ceq 'Any' -and $transport[0].spec.interface_type -ceq 'Any') 'transport is not bound to old WiFi'
Check ($transport[0].spec.program -cne 'Any' -and $transport[0].spec.protocol -ceq 'TCP' -and $transport[0].spec.port -ceq '443' -and $transport[0].spec.remote_addresses[0] -ceq '192.0.2.11') 'physical agnosticism is not general 443 access'
$data=@($ethernet.rules|Where-Object{$_.spec.service -cne 'SstpSvc'})
foreach($r in $data){Check ($r.spec.interface_alias -ceq 'SSTP fixture' -and $r.spec.interface_type -ceq 'RemoteAccess') 'data and DNS bound only to tunnel'}
$script:vpnIndex=77;$afterReconnect=IsoPrepare $policy $null
Check ($afterReconnect.vpn.interface_index -eq 77) 'new VPN index observed separately from compiled alias rule'
Check (UEqual $afterReconnect.rules $ethernet.rules) 'same alias can hide a new connection; identity observer/rebind still required'
Check (-not $afterReconnect.no_leak_certified) 'no packet qualification invented'
@{schema='underlay-independent-rule-planning-model-1';passed=$true;assertions=$script:n;Windows_API_executed=$false;actual_WiFi_to_Ethernet_switch_tested=$false;DHCP_DNS_route_bootstrap_tested=$false;firewall_changed=$false}|ConvertTo-Json|Set-Content '/data/sstp-observer-v02/windows-results/underlay-planning-model.json'
Write-Host ('Passed '+$script:n+' planning checks; real adapter switch NOT tested.')
