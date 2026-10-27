param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1');. (Join-Path $Root 'lab/native.ps1');. (Join-Path $Root 'app/isolation-core.ps1');. (Join-Path $Root 'app/isolation-native.ps1')
$script:checks=0
function Assert($b,$m){$script:checks++;if(-not $b){throw $m}}
$script:rules=@();$script:active=@();$script:reads=@();$script:profileDefault='Block'
function Get-NetFirewallRule{param($PolicyStore,$ErrorAction)if($PolicyStore -ceq 'ActiveStore'){return $script:active}else{return $script:rules}}
function Get-NetFirewallProfile{param($PolicyStore,$ErrorAction)foreach($n in @('Domain','Private','Public')){[pscustomobject]@{Name=$n;Enabled='True';DefaultOutboundAction=$script:profileDefault;AllowLocalFirewallRules='True';DisabledInterfaceAliases=@('NotConfigured')}}}
function Get-NetFirewallSecurityFilter{param($PolicyStore,$ErrorAction)return @()}
function UReadNative{param($Name,$Store='PersistentStore')$script:reads+=,$Name;[pscustomobject]@{rule=[pscustomobject]@{Name=$Name;Enabled='1'};filters='all-seven'}}
function IsoValidateNative{param($Image,$Rule,$Session,$Store='PersistentStore',$Enabled='False')}
$session=[pscustomobject]@{id='i';entries=@();foreign=@()}
$foreign=IsoForeignAllows $session;Assert ($foreign.Count -eq 0) 'empty list';IsoVerify $session;Assert $true 'empty list should verify'
$local=[pscustomobject]@{Name='local';Enabled='True';Direction='Outbound';Action='Allow';PolicyStoreSourceType='Local'}
$script:rules=@($local);$script:active=@();$foreign=IsoForeignAllows $session;Assert ($foreign.Count -eq 1) 'non-applicable persistent Allow must also quarantine';Assert ($foreign[0].image.filters -ceq 'all-seven') 'full before image'
$caught=$false;try{IsoVerify $session}catch{$caught=$_.Exception.Message -ceq 'iso_unquarantined_effective_allow'};Assert $caught 'unquarantined Allow detected'
$script:active=@([pscustomobject]@{Name='GPO';Enabled='True';Direction='Outbound';Action='Allow';PolicyStoreSourceType='GroupPolicy'})
$caught=$false;try{$null=IsoForeignAllows $session}catch{$caught=$_.Exception.Message -ceq 'iso_nonlocal_allow_cannot_quarantine_review_GPO'};Assert $caught 'GPO gate'
$script:active=@($local);$script:rules=@();$caught=$false;try{$null=IsoForeignAllows $session}catch{$caught=$_.Exception.Message -ceq 'iso_effective_allow_not_mutable_locally'};Assert $caught 'effective-only Allow gate'
$script:rules=@($local);$session.entries=@([pscustomobject]@{name='local';removed=$false});$foreign=IsoForeignAllows $session;Assert ($foreign.Count -eq 0) 'exact current owned rule excluded';$session.entries=@()
$script:active=@();$script:rules=@();$script:profileDefault='Allow';$caught=$false;try{IsoVerify $session}catch{$caught=$true};Assert $caught 'default Allow rejected';$script:profileDefault='Block'
# Test actual rule compiler using detected interface fixture, never hardcoded VPN name/address.
function IsoAssertNoOtherEngine{param($S)@{read_only=$true}}
function IsoDetectSstp{[pscustomobject]@{name='Synthetic SSTP';server='vpn.fixture.invalid';scope='current_user';interface_index=42;server_ips=@('8.8.4.4');dns_servers=@('1.1.1.1');svchost='C:\Windows\System32\svchost.exe';svchost_sha256=('a'*64)}}
$policy=[pscustomobject]@{schema='unified-isolation-policy-1';owner=('a'*32);generation=1;whitelist=@([pscustomobject]@{remote_addresses=@('8.8.8.0/24');protocol='TCP';remote_port='4000-5000'});overlaps=@()}
function IsoPrepareForeignAllows{param($s)return ,@()}
$plan=IsoPrepare $policy $null;Assert ($plan.rules.Count -eq 4) 'whitelist + transport + two DNS rules';Assert ($plan.foreign.Count -eq 0) 'no fake foreign'
$white=@($plan.rules|Where-Object{$_.spec.program -ceq 'Any'});Assert ($white.Count -eq 1) 'global whitelist';Assert ($white[0].spec.interface_alias -ceq 'Synthetic SSTP') 'exact detected VPN';Assert ($white[0].spec.interface_type -ceq 'RemoteAccess') 'VPN interface type';Assert ($white[0].spec.port -ceq '4000-5000') 'native port range'
$transport=@($plan.rules|Where-Object{$_.spec.service -ceq 'SstpSvc'});Assert ($transport.Count -eq 1) 'transport only once';Assert ($transport[0].spec.program -cne 'Any') 'transport not all apps';Assert ($transport[0].spec.port -ceq '443') 'transport port';Assert ($transport[0].spec.remote_addresses[0] -ceq '8.8.4.4') 'detected server'
$dns=@($plan.rules|Where-Object{$_.spec.service -ceq 'Dnscache'});Assert ($dns.Count -eq 2) 'DNS TCPUDP';foreach($d in $dns){Assert ($d.spec.interface_alias -ceq 'Synthetic SSTP') 'DNS cannot use physical alias';Assert ($d.spec.interface_type -ceq 'RemoteAccess') 'DNS tunnel type';Assert ($d.spec.remote_addresses[0] -ceq '1.1.1.1') 'VPN DNS only'}
Assert (@($plan.rules|Where-Object{$_.spec.service -ceq 'Any' -and $_.spec.interface_alias -ceq 'Any'}).Count -eq 0) 'no unrestricted direct exception';Assert (-not $plan.no_leak_certified) 'not falsely certified'
# Journal written and read back with checksum in a real temporary physical directory (no ACL claim on Linux).
$script:IsoRoot=Join-Path ([IO.Path]::GetTempPath()) ('iso-fixture-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($script:IsoRoot)
try{
 $s=[pscustomobject]@{schema='unified-isolation-session-1';owner=('a'*32);id=('b'*32);entries=@();foreign=@();profiles=@(@{name='Domain'},@{name='Private'},@{name='Public'});phase='prepared'}
 IsoSave $s;$round=IsoLoad;Assert (UEqual $s $round) 'journal roundtrip'
 $path=Join-Path $script:IsoRoot 'session.json';$envelope=ConvertFrom-Json ([IO.File]::ReadAllText($path));$envelope.payload+='x';[IO.File]::WriteAllText($path,(UJson $envelope));$caught=$false;try{$null=IsoLoad}catch{$caught=$_.Exception.Message -ceq 'iso_journal_checksum'};Assert $caught 'checksum corruption refused'
}finally{Remove-Item -LiteralPath $script:IsoRoot -Recurse -Force}
$result=@{suite='isolation-native-adapter-mock-model';assertions=$script:checks;passed=$true;Windows_API_executed=$false;Windows_ACL_executed=$false;packet_leak_tested=$false};[IO.File]::WriteAllText((Join-Path $Root 'evidence/isolation-native-model-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
