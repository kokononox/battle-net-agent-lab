function SafePath([string]$Path){
 $p=[IO.Path]::GetFullPath($Path)
 for($v=$p;$v;$v=[IO.Path]::GetDirectoryName($v)){
  if(Test-Path -LiteralPath $v){if(((Get-Item -LiteralPath $v -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'reparse_path_rejected'}}
 }
 return $p
}
function UJson($x){return (ConvertTo-Json -InputObject $x -Depth 12 -Compress)}
function TAssertPublicIPv4([string]$Text){
 $ip=[Net.IPAddress]::Parse($Text)
 if($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $ip.ToString() -cne $Text){throw 'literal_ipv4_required'}
 function N($a){$v=[long]0;foreach($b in $a.GetAddressBytes()){$v=$v*256+[long]$b};return $v}
 $number=N $ip
 foreach($cidr in @('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/3')){
  $s=$cidr.Split('/');$low=N ([Net.IPAddress]::Parse($s[0]));$size=[Math]::Pow(2,32-[int]$s[1]);if($number -ge $low -and $number -lt ($low+$size)){throw 'special_use_ipv4_rejected'}
 }
}

function UAssertPath([string]$Path){$null=SafePath $Path}
function TSave([string]$Path,$Object){
 UAssertPath $Path;$tmp=$Path+'.next-'+[guid]::NewGuid().ToString('N')
 try{[IO.File]::WriteAllText($tmp,(ConvertTo-Json -InputObject $Object -Depth 20),(New-Object Text.UTF8Encoding($false)));if([IO.File]::Exists($Path)){[IO.File]::Replace($tmp,$Path,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$Path)}}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}
function TChallenge([string]$Role){[pscustomobject][ordered]@{kind='unifiedfw-traffic-1';nonce=([guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N'));request_id=[guid]::NewGuid().ToString('N');role=$Role}}
function TRunProcess([string]$Exe,[string]$Script,[string]$Request,[string]$Output){
 foreach($p in @($Exe,$Script,$Request,$Output)){UAssertPath $p;if($p.Contains('"')){throw 'invalid_process_path'}}
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$Exe;$info.Arguments='-I "'+$Script+'" --request "'+$Request+'" --output "'+$Output+'"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $process=New-Object Diagnostics.Process;$process.StartInfo=$info
 try{if(-not $process.Start()){throw 'probe_start_failed'};if(-not $process.WaitForExit(12000)){$process.Kill();$process.WaitForExit();throw 'probe_process_timeout_not_block_evidence'};if($process.ExitCode -ne 0 -or -not [IO.File]::Exists($Output)){throw 'probe_process_failed_not_block_evidence'};if((Get-Item -LiteralPath $Output).Length -gt 4194304){throw 'probe_output_limit'}}finally{$process.Dispose()}
 return (ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Output)))
}
# Fixed HTTPS pacing applies across TMatrix calls and Restore boundaries.
# Stopwatch is monotonic; no wall-clock changes can shorten the minimum gap.
$script:THttpsLastFinished=$null
$script:THttpsSequence=0
function TMonotonicMilliseconds(){return ([double][Diagnostics.Stopwatch]::GetTimestamp()*1000.0/[Diagnostics.Stopwatch]::Frequency)}
function TDelayMilliseconds([int]$Milliseconds){Start-Sleep -Milliseconds $Milliseconds}
function TWaitHTTPSProbeGap(){
 if($null -eq $script:THttpsLastFinished){return $null}
 while($true){
  $elapsed=(TMonotonicMilliseconds)-$script:THttpsLastFinished
  if($elapsed -ge 4000.0){return $elapsed}
  TDelayMilliseconds ([int][Math]::Ceiling(4000.0-$elapsed))
 }
}
function TMatrix($Q,[string]$Job,[string]$Root,[scriptblock]$RouteGuard=$null){
 $records=@();$isHttps=$false
 if($null -ne $Q.PSObject.Properties['transport']){
  if($Q.transport -cne 'https_php' -or $Q.schema -cne 'unifiedfw-coexistence-request-1'){throw 'unsupported_matrix_transport'}
  $isHttps=$true
 }
 for($round=0;$round -lt 3;$round++){
  if($null -ne $RouteGuard){& $RouteGuard|Out-Null}
  # Reference probes bracket the two image probes across alternating round order.
  $order=@('REF','A','B');if($round -eq 1){$order=@('B','A','REF')}
  foreach($role in $order){
   $pacingGap=$null
   if($isHttps){
    $pacingGap=TWaitHTTPSProbeGap
    # Re-check after any wait, immediately before each HTTPS attempt.
    if($null -ne $RouteGuard){& $RouteGuard|Out-Null}
   }
   $probeStarted=[datetime]::UtcNow.ToString('o')
   $challenge=TChallenge $role
   if($role -ceq 'REF'){if($isHttps){$r=HReference $Q.https_url $Q.address $challenge}else{$r=TReference $Q.address $Q.port $challenge}}
   else{
    $p=@($Q.programs|Where-Object{$_.role -ceq $role})[0]
    $request=Join-Path $Job ($challenge.request_id+'-request.json');$output=Join-Path $Job ($challenge.request_id+'-probe.json')
    $probeRequest=[ordered]@{address=$Q.address;port=$Q.port;challenge=$challenge};$probeScript='traffic-probe.py'
    if($isHttps){$probeRequest=[ordered]@{url=$Q.https_url;address=$Q.address;challenge=$challenge};$probeScript='probe.py'}
    TSave $request $probeRequest
    try{
     if((Get-FileHash -LiteralPath $p.path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $p.sha256){throw 'probe_binary_changed'}
     $r=TRunProcess $p.path (Join-Path $Root ('control126/'+$probeScript)) $request $output
     if($r.request_id -cne $challenge.request_id -or $r.role -cne $role){throw 'probe_response_identity'}
    }catch{$r=[pscustomobject]@{schema='unifiedfw-tcp-probe-1';probe_valid=$false;request_id=$challenge.request_id;role=$role;connected=$false;handshake_ok=$false;error=$_.Exception.Message}}
   }
   if($isHttps){
    $script:THttpsLastFinished=TMonotonicMilliseconds
    Add-Member -InputObject $r -NotePropertyName pacing_sequence -NotePropertyValue $script:THttpsSequence
    Add-Member -InputObject $r -NotePropertyName gap_since_previous_probe_ms -NotePropertyValue $pacingGap
    Add-Member -InputObject $r -NotePropertyName started_utc -NotePropertyValue $probeStarted
    Add-Member -InputObject $r -NotePropertyName ended_utc -NotePropertyValue ([datetime]::UtcNow.ToString('o'))
    $script:THttpsSequence++
   }
   Add-Member -InputObject $r -NotePropertyName round -NotePropertyValue $round
   $records+=,$r
   SaveControlRow $r
  }
  if($null -ne $RouteGuard){& $RouteGuard|Out-Null}
 }
 return ,$records
}
