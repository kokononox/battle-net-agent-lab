$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$parsed=0
foreach($file in Get-ChildItem -LiteralPath (Join-Path $root 'diag') -Filter '*.ps1'){
 $tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
 if($errors.Count -gt 0){throw ($errors|Out-String)};$parsed++
}
$source=[IO.File]::ReadAllText((Join-Path $root 'diag/reference.ps1'))
$prefix=$source.Substring($source.IndexOf('function SafePath'),$source.IndexOf('$root=')-$source.IndexOf('function SafePath'))
. ([scriptblock]::Create($prefix))
. (Join-Path $root 'diag/https-tools.ps1')
$assertions=0
foreach($ip in @('9.9.9.9','8.8.8.8','1.1.1.1')){TAssertPublicIPv4 $ip;$assertions++}
foreach($ip in @('0.0.0.0','10.1.1.1','100.64.0.1','127.0.0.1','169.254.1.1','172.16.1.1','192.168.1.1','192.0.2.1','198.18.0.1','198.51.100.1','203.0.113.1','224.0.0.1','255.255.255.255','::1')){
 $rejected=$false;try{TAssertPublicIPv4 $ip}catch{$rejected=$true};if(-not $rejected){throw ('gate accepted '+$ip)};$assertions++
}
$valid=HValidateEndpoint 'https://ufw-test.example/probe.php' '9.9.9.9';if($valid.port -ne 443){throw 'port'};$assertions++
foreach($url in @('http://ufw-test.example/probe.php','https://ufw-test.example:443/probe.php','https://ufw-test.example/probe.php?a=1','https://ufw-test.example/probe.php#x','https://9.9.9.9/probe.php')){
 $rejected=$false;try{$null=HValidateEndpoint $url '9.9.9.9'}catch{$rejected=$true};if(-not $rejected){throw 'URL accepted'};$assertions++
}
@{parsed=$parsed;assertions=$assertions;passed=$true;Windows_executed=$false}|ConvertTo-Json -Compress
