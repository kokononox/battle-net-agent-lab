param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0;$ErrorActionPreference='Stop'
. (Join-Path $Root 'lab/session-core.ps1');. (Join-Path $Root 'lab/native.ps1');. (Join-Path $Root 'app/isolation-native.ps1')
$script:checks=0;$env:SystemRoot='C:\Windows'
# Map a synthetic Windows path only for Join-Path in the detector; no Windows API or network used.
New-PSDrive -Name C -PSProvider FileSystem -Root ([IO.Path]::GetTempPath())|Out-Null
function Assert($b,$m){$script:checks++;if(-not $b){throw $m}}
function Reset-Fixture{
 $script:vpn=@([pscustomobject]@{status='Connected';tunnel='Sstp';split_tunneling=$false;name='Dynamic SSTP fixture';server='fixture.invalid';scope='current_user'})
 $script:errors=@();$script:binary='C:/Windows/System32/svchost.exe';$script:server='8.8.4.4';$script:cache=$true;$script:servicePID=123;$script:tcpPID=123;$script:tcpPort=443;$script:tcpIP='8.8.4.4';$script:signature='Valid';$script:dns=@('1.1.1.1')
}
function UReadEnvironment{[pscustomobject]@{vpn=$script:vpn;vpn_query_errors=$script:errors}}
function Get-NetIPInterface{param($ErrorAction)[pscustomobject]@{InterfaceAlias='Dynamic SSTP fixture';ConnectionState='Connected';InterfaceIndex=42}}
function Get-CimInstance{param($ClassName,$Filter,$ErrorAction)if($ClassName -ceq 'Win32_Service'){[pscustomobject]@{State='Running';ProcessId=$script:servicePID}}else{[pscustomobject]@{ExecutablePath=$script:binary}}}
function Get-AuthenticodeSignature{param($LiteralPath,$ErrorAction)[pscustomobject]@{Status=$script:signature;SignerCertificate=[pscustomobject]@{Subject='CN=Microsoft Windows'}}}
function Get-DnsClientCache{param($ErrorAction)if($script:cache){[pscustomobject]@{Entry='fixture.invalid';Data=$script:server}}}
function Get-NetTCPConnection{param($State,$ErrorAction)[pscustomobject]@{OwningProcess=$script:tcpPID;RemotePort=$script:tcpPort;RemoteAddress=$script:tcpIP}}
function Get-DnsClientServerAddress{param($InterfaceIndex,$ErrorAction)[pscustomobject]@{ServerAddresses=$script:dns}}
function Get-FileHash{param($LiteralPath,$Algorithm)[pscustomobject]@{Hash=('A'*64)}}
Reset-Fixture;$v=IsoDetectSstp;Assert ($v.name -ceq 'Dynamic SSTP fixture') 'dynamic name';Assert ($v.server_ips[0] -ceq '8.8.4.4') 'server qualification';Assert ($v.dns_servers[0] -ceq '1.1.1.1') 'VPN DNS';Assert ($v.interface_index -eq 42) 'dynamic index'
foreach($case in @('none','two','nonSstp','split','queryError','servicePID','binary','signature','cacheMiss','wrongIP','wrongPID','wrongPort')){
 Reset-Fixture
 switch($case){
 'none'{$script:vpn=@()};'two'{$script:vpn+=,$script:vpn[0]};'nonSstp'{$script:vpn[0].tunnel='Ikev2'};'split'{$script:vpn[0].split_tunneling=$true};'queryError'{$script:errors=@('all_users')};'servicePID'{$script:servicePID=0};'binary'{$script:binary='C:/Other/app.exe'};'signature'{$script:signature='NotSigned'};'cacheMiss'{$script:cache=$false};'wrongIP'{$script:tcpIP='9.9.9.9'};'wrongPID'{$script:tcpPID=999};'wrongPort'{$script:tcpPort=8443}
 }
 $caught=$false;try{$null=IsoDetectSstp}catch{$caught=$true};Assert $caught ('unsafe detection accepted '+$case)
}
Reset-Fixture;$script:vpn[0].server='8.8.4.4';$script:cache=$false;$v=IsoDetectSstp;Assert ($v.server_ips[0] -ceq '8.8.4.4') 'numeric server no DNS cache required'
Remove-PSDrive C
$result=@{suite='SSTP-detection-fake-Windows';assertions=$script:checks;passed=$true;Windows_API_executed=$false;DNS_query_performed=$false;no_leak_certified=$false};[IO.File]::WriteAllText((Join-Path $Root 'evidence/isolation-sstp-detection-tests.json'),(ConvertTo-Json $result));$result|ConvertTo-Json -Compress
