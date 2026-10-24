# Only probe process I/O and .NET TCP challenge; no firewall mutations here.
function TSave([string]$Path,$Object){
 if($Object -is [System.Collections.IDictionary] -and $Object.Contains('instrumentation')){$Object.instrumentation=XSummary}
 UAssertPath $Path;$tmp=$Path+'.next-'+[guid]::NewGuid().ToString('N')
 try{[IO.File]::WriteAllText($tmp,(UJson $Object),(New-Object Text.UTF8Encoding($false)));if([IO.File]::Exists($Path)){[IO.File]::Replace($tmp,$Path,[Management.Automation.Language.NullString]::Value)}else{[IO.File]::Move($tmp,$Path)}}finally{if([IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)}}
}
function TChallenge([string]$Role){[pscustomobject][ordered]@{kind='unifiedfw-traffic-1';nonce=([guid]::NewGuid().ToString('N')+[guid]::NewGuid().ToString('N'));request_id=[guid]::NewGuid().ToString('N');role=$Role}}
function TRunProcess([string]$Exe,[string]$Script,[string]$Request,[string]$Output){
 foreach($p in @($Exe,$Script,$Request,$Output)){UAssertPath $p;if($p.Contains('"')){throw 'invalid_process_path'}}
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$Exe;$info.Arguments='-I "'+$Script+'" --request "'+$Request+'" --output "'+$Output+'"';$info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $process=New-Object Diagnostics.Process;$process.StartInfo=$info
 try{if(-not $process.Start()){throw 'probe_start_failed'};if(-not $process.WaitForExit(12000)){$process.Kill();$process.WaitForExit();throw 'probe_process_timeout_not_block_evidence'};if($process.ExitCode -ne 0 -or -not [IO.File]::Exists($Output)){throw 'probe_process_failed_not_block_evidence'};if((Get-Item -LiteralPath $Output).Length -gt 4194304){throw 'probe_output_limit'}}finally{$process.Dispose()}
 return (ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($Output)))
}
function TReference([string]$Address,[int]$Port,$Challenge){
 $result=[ordered]@{schema='unifiedfw-tcp-probe-1';probe_valid=$true;request_id=$Challenge.request_id;role='REF';connected=$false;handshake_ok=$false;local_address=$null;server_observed_peer=$null;error=$null;error_code=$null;elapsed_ms=0}
 $clock=[Diagnostics.Stopwatch]::StartNew();$client=New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetwork);$async=$null
 try{
  $async=$client.BeginConnect(([Net.IPAddress]::Parse($Address)),$Port,$null,$null)
  if(-not $async.AsyncWaitHandle.WaitOne(2500)){throw 'reference_connect_timeout'}
  $client.EndConnect($async);$result.connected=$true;$result.local_address=$client.Client.LocalEndPoint.Address.ToString();$client.ReceiveTimeout=2500;$client.SendTimeout=2500
  $stream=$client.GetStream();$bytes=[Text.Encoding]::ASCII.GetBytes((UJson $Challenge)+"`n");$stream.Write($bytes,0,$bytes.Length)
  $buffer=New-Object Collections.Generic.List[byte];$newline=$false
  while($buffer.Count -lt 2048){$b=$stream.ReadByte();if($b -lt 0){throw 'reference_peer_closed'};if($b -eq 10){$newline=$true;break};$buffer.Add([byte]$b)}
  if(-not $newline){throw 'reference_response_too_large'}
  $response=ConvertFrom-Json -InputObject ([Text.Encoding]::UTF8.GetString($buffer.ToArray()))
  foreach($key in @('kind','nonce','request_id','role')){if($response.$key -cne $Challenge.$key){throw 'reference_challenge_mismatch'}}
  $peer=[Net.IPAddress]::Parse([string]$response.observed_peer);if($peer.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){throw 'reference_peer_not_ipv4'}
  $result.handshake_ok=$true;$result.server_observed_peer=$peer.ToString()
 }catch{$result.error=$_.Exception.Message;if($_.Exception -is [Net.Sockets.SocketException]){$result.error_code=$_.Exception.NativeErrorCode}}
 finally{$client.Close();if($null -ne $async){$async.AsyncWaitHandle.Close()};$clock.Stop();$result.elapsed_ms=$clock.ElapsedMilliseconds}
 return [pscustomobject]$result
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
   if($isHttps){$xProbe=XProbeStart $challenge}
   if($role -ceq 'REF'){if($isHttps){$r=HReference $Q.https_url $Q.address $challenge}else{$r=TReference $Q.address $Q.port $challenge}}
   else{
    $p=@($Q.programs|Where-Object{$_.role -ceq $role})[0]
    $request=Join-Path $Job ($challenge.request_id+'-request.json');$output=Join-Path $Job ($challenge.request_id+'-probe.json')
    $probeRequest=[ordered]@{address=$Q.address;port=$Q.port;challenge=$challenge};$probeScript='traffic-probe.py'
    if($isHttps){$probeRequest.https_url=$Q.https_url;$probeScript='https-probe.py'}
    TSave $request $probeRequest
    try{
     if((Get-FileHash -LiteralPath $p.path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -cne $p.sha256){throw 'probe_binary_changed'}
     $r=TRunProcess $p.path (Join-Path $Root ('lab/'+$probeScript)) $request $output
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
   if($isHttps){XProbeEnd $xProbe $r}
   $records+=,$r
  }
  if($null -ne $RouteGuard){& $RouteGuard|Out-Null}
 }
 return ,$records
}
function TBaselineGood($Rows){return (@($Rows).Count -eq 9 -and @($Rows|Where-Object{-not $_.probe_valid -or -not $_.connected -or -not $_.handshake_ok}).Count -eq 0)}
function TAssertPublicIPv4([string]$Text){
 $a=[Net.IPAddress]::Parse($Text)
 if($a.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $a.ToString() -cne $Text){throw 'literal_public_ipv4_required'}
 $number=UIPNumber $a
 foreach($cidr in @('0.0.0.0/8','10.0.0.0/8','100.64.0.0/10','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/3')){
  $parts=$cidr.Split('/');$low=UIPNumber ([Net.IPAddress]::Parse($parts[0]));$size=[Numerics.BigInteger]::Pow(2,(32-[int]$parts[1]))
  if($number -ge $low -and $number -lt ($low+$size)){throw 'special_use_endpoint_not_supported'}
 }
}
function TValidateRequest($Q,[string]$Root){
 if($Q.schema -cne 'unifiedfw-traffic-request-1' -or $Q.programs -isnot [array] -or $Q.programs.Count -ne 2 -or $Q.phases -isnot [array] -or $Q.phases.Count -ne 3){throw 'traffic_request_schema'}
 TAssertPublicIPv4 ([string]$Q.address)
 $address=[Net.IPAddress]::Parse([string]$Q.address);if($address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or $address.ToString() -cne $Q.address -or ($Q.port -isnot [int] -and $Q.port -isnot [long]) -or $Q.port -lt 1024 -or $Q.port -gt 65535){throw 'traffic_endpoint'}
 $expectedPaths=@((Join-Path $Root 'runtime/python.exe'),(Join-Path $Root 'runtime/pythonw.exe'));$ids=@{};$names=@('only_A','only_B','both');$counts=@(1,1,2)
 for($i=0;$i -lt 2;$i++){$p=$Q.programs[$i];if($p.role -cne @('A','B')[$i] -or -not (UStringEqual $p.path $expectedPaths[$i])){throw 'traffic_only_bundled_executables'};$ids[$p.role]=$p.id}
 $owner=$Q.phases[0].request.plan.owner
 for($i=0;$i -lt 3;$i++){
  $phase=$Q.phases[$i];$phaseRequest=$phase.request;UValidateRequest $phaseRequest
  if($phase.name -cne $names[$i] -or $phaseRequest.mode -cne 'blacklist_only' -or $phaseRequest.legacy_imports.Count -ne 0 -or $phaseRequest.programs.Count -ne 2 -or $phaseRequest.plan.rules.Count -ne $counts[$i] -or $phaseRequest.plan.owner -cne $owner){throw 'traffic_phase_scope'}
  foreach($p in $phaseRequest.programs){$same=@($Q.programs|Where-Object{$_.id -ceq $p.id -and $_.path -ceq $p.path -and $_.sha256 -ceq $p.sha256});if($same.Count -ne 1){throw 'traffic_phase_program_mismatch'}}
  $seen=@{};foreach($r in $phaseRequest.plan.rules){$s=$r.spec
   if($r.component -cne 'blacklist' -or $s.interface_type -cne 'Any' -or $s.protocol -cne 'TCP' -or $s.port -ne $Q.port -or $s.remote_addresses.Count -ne 1 -or $s.remote_addresses[0] -cne ($Q.address+'/32') -or $seen.ContainsKey($s.program_id)){throw 'traffic_rule_scope'};$seen[$s.program_id]=$true
  }
  if(($i -eq 0 -and -not $seen.ContainsKey($ids.A)) -or ($i -eq 1 -and -not $seen.ContainsKey($ids.B)) -or ($i -eq 2 -and (-not $seen.ContainsKey($ids.A) -or -not $seen.ContainsKey($ids.B)))){throw 'traffic_matrix_scope'}
 }
}
