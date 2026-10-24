param([string]$Root=(Join-Path $PSScriptRoot '..'))
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
foreach($file in @('session-core.ps1','native.ps1','traffic-tools.ps1','https-tools.ps1')){. (Join-Path $Root ('lab/'+$file))}
$script:checks=0
function Check([bool]$OK,[string]$Why){$script:checks++;if(-not $OK){throw ('https_assertion:'+ $Why)}}
function Throws([scriptblock]$Body){$caught=$false;try{& $Body|Out-Null}catch{$caught=$true};Check $caught 'expected_rejection'}
Add-Type -TypeDefinition @'
public class UnifiedHttpsMemoryStream : System.IO.MemoryStream {
 public UnifiedHttpsMemoryStream(byte[] bytes) : base(bytes) {}
 public override bool CanTimeout { get { return true; } }
 public override int ReadTimeout { get; set; }
}
'@
$challenge=[pscustomobject]@{kind='unifiedfw-traffic-1';nonce=('a'*64);request_id=('b'*32);role='REF'}
$body=UJson ([ordered]@{kind=$challenge.kind;nonce=$challenge.nonce;request_id=$challenge.request_id;role=$challenge.role;observed_peer='127.0.0.1'})
function ReadReply([string]$Text){$stream=[UnifiedHttpsMemoryStream]::new([Text.Encoding]::UTF8.GetBytes($Text));$clock=[Diagnostics.Stopwatch]::StartNew();try{HReadResponse $stream @{bytes=0;clock=$clock} $challenge}finally{$stream.Dispose();$clock.Stop()}}
$cfg=HValidateEndpoint 'https://ufw-test.example/probe.php' '9.9.9.9';Check ($cfg.port -eq 443 -and $cfg.host -ceq 'ufw-test.example') 'fixed_HTTPS_endpoint'
foreach($url in @('http://ufw-test.example/probe.php','https://9.9.9.9/probe.php','https://user:pass@ufw-test.example/probe.php','https://ufw-test.example:443/probe.php','https://ufw-test.example:4443/probe.php','https://ufw-test.example/probe.php?x=1','https://ufw-test.example/probe.php#x','https://ufw-test.example/../probe.php','https://ufw-test.example/a%2fprobe.php','https://ufw-test.example/index.html')){Throws {HValidateEndpoint $url '9.9.9.9'}}
Throws {HValidateEndpoint 'https://ufw-test.example/probe.php' '127.0.0.1'}
$raw='HTTP/1.1 200 OK'+"`r`n"+'Content-Type: application/json'+"`r`n"+'Content-Length: '+$body.Length+"`r`n`r`n"+$body
Check ((ReadReply $raw) -ceq '127.0.0.1') 'bounded_content_length_response'
$chunk='HTTP/1.1 200 OK'+"`r`n"+'Content-Type: application/json'+"`r`n"+'Transfer-Encoding: chunked'+"`r`n`r`n"+$body.Length.ToString('x')+"`r`n"+$body+"`r`n0`r`n`r`n"
Check ((ReadReply $chunk) -ceq '127.0.0.1') 'bounded_chunked_response'
foreach($case in @('redirect','html','compressed','duplicate_length','large_body','wrong_nonce','missing_peer','truncated','ambiguous','large_header')){
 $bad=$raw
 switch($case){
  'redirect' {$bad=$raw.Replace('200 OK','302 Found')}
  'html' {$bad=$raw.Replace('application/json','text/html')}
  'compressed' {$bad=$raw.Replace('Content-Type:',('Content-Encoding: gzip'+"`r`n"+'Content-Type:'))}
  'duplicate_length' {$bad=$raw.Replace('Content-Type:',('Content-Length: 1'+"`r`n"+'Content-Type:'))}
  'large_body' {$bad=$raw.Replace(('Content-Length: '+$body.Length),'Content-Length: 99999')}
  'wrong_nonce' {$bad=$raw.Replace(('a'*64),('c'*64))}
  'missing_peer' {$bad=$raw.Replace('observed_peer','unexpected_peer')}
  'truncated' {$bad=$raw.Substring(0,$raw.Length-5)}
  'ambiguous' {$bad=$chunk.Replace('Transfer-Encoding:',('Content-Length: 1'+"`r`n"+'Transfer-Encoding:'))}
  'large_header' {$bad='HTTP/1.1 200 OK'+"`r`n"+'X: '+('a'*33000)+"`r`n`r`n"}
 }
 Throws {ReadReply $bad}
}
$report=[ordered]@{passed=$true;assertions=$script:checks;windows_executed=$false;backend='URL admission and bounded HTTP parsing over in-memory streams';TLS_certificate_validation_executed=$false}
[IO.File]::WriteAllText((Join-Path $Root 'evidence/https-tools-tests.json'),(UJson $report));$report|ConvertTo-Json -Compress
