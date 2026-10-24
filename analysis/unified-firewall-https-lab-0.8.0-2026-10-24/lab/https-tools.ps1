# Independent .NET HTTPS reference. No certificate-validation callback/bypass.
function HValidateEndpoint([string]$URL,[string]$Address){
 TAssertPublicIPv4 $Address
 if($URL.Length -gt 512){throw 'https_url_size'}
 $uri=[uri]$URL;$hostName=$uri.DnsSafeHost;$path=$uri.AbsolutePath
 if(-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https' -or $uri.Port -ne 443 -or $URL -cne ('https://'+$hostName+$path) -or $hostName -cnotmatch '^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' -or $path -cnotmatch '^/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.php$'){throw 'canonical_https_dns_hostname_and_simple_php_path_required'}
 return [pscustomobject]@{url=$URL;host=$hostName;path=$path;address=$Address;port=443}
}
function HReadByte($Stream,$Budget){
 $remaining=8000-$Budget.clock.ElapsedMilliseconds
 if($remaining -le 0){throw 'https_total_deadline'};if($Budget.bytes -ge 32768){throw 'https_wire_size_limit'}
 $Stream.ReadTimeout=[int][Math]::Min(2500,$remaining);$b=$Stream.ReadByte();if($b -ge 0){$Budget.bytes++};return $b
}
function HReadLine($Stream,$Budget){
 $bytes=New-Object Collections.Generic.List[byte]
 while($bytes.Count -lt 8192){$b=HReadByte $Stream $Budget;if($b -lt 0){throw 'https_truncated_headers'};if($b -eq 10){if($bytes.Count -lt 1 -or $bytes[$bytes.Count-1] -ne 13){throw 'https_CRLF_required'};$bytes.RemoveAt($bytes.Count-1);return [Text.Encoding]::ASCII.GetString($bytes.ToArray())};$bytes.Add([byte]$b)}
 throw 'https_header_line_limit'
}
function HReadResponse($Stream,$Budget,$Challenge){
 $status=HReadLine $Stream $Budget
 if($status -cnotmatch '^HTTP/1\.[01] 200(?: .*)?$'){throw 'https_status_not_200_no_redirect_followed'}
 $headers=@{}
 while($true){$line=HReadLine $Stream $Budget;if($line.Length -eq 0){break};$index=$line.IndexOf(':');if($index -lt 1){throw 'https_invalid_header'};$name=$line.Substring(0,$index).ToLowerInvariant();$value=$line.Substring($index+1).Trim()
  if($name -cnotmatch '^[a-z0-9-]+$'){throw 'https_invalid_header_name'}
  if($headers.ContainsKey($name) -and $name -cin @('content-length','transfer-encoding','content-type','content-encoding')){throw 'https_duplicate_header'};$headers[$name]=$value
 }
 if(-not $headers.ContainsKey('content-type') -or $headers['content-type'].Split(';')[0].Trim().ToLowerInvariant() -cne 'application/json'){throw 'https_json_content_type_required'}
 if($headers.ContainsKey('content-encoding') -and $headers['content-encoding'].ToLowerInvariant() -cne 'identity'){throw 'https_compression_not_supported'}
 if($headers.ContainsKey('content-length') -and $headers.ContainsKey('transfer-encoding')){throw 'https_ambiguous_framing'}
 $body=New-Object Collections.Generic.List[byte]
 if($headers.ContainsKey('content-length')){
  $length=$headers['content-length'];if($length -cnotmatch '^\d{1,5}$' -or [int]$length -gt 2048){throw 'https_body_size_limit'}
  for($i=0;$i -lt [int]$length;$i++){$b=HReadByte $Stream $Budget;if($b -lt 0){throw 'https_truncated_body'};$body.Add([byte]$b)}
 }elseif($headers.ContainsKey('transfer-encoding')){
  if($headers['transfer-encoding'].ToLowerInvariant() -cne 'chunked'){throw 'https_transfer_encoding_not_supported'}
  while($true){
   $sizeText=(HReadLine $Stream $Budget).Split(';')[0];if($sizeText -cnotmatch '^[0-9a-fA-F]{1,6}$'){throw 'https_invalid_chunk'};$size=[Convert]::ToInt32($sizeText,16)
   if($size -eq 0){while((HReadLine $Stream $Budget).Length -gt 0){};break}
   if(($body.Count+$size) -gt 2048){throw 'https_body_size_limit'}
   for($i=0;$i -lt $size;$i++){$b=HReadByte $Stream $Budget;if($b -lt 0){throw 'https_truncated_chunk'};$body.Add([byte]$b)}
   if((HReadLine $Stream $Budget).Length -ne 0){throw 'https_chunk_CRLF_required'}
  }
 }else{
  while($true){$b=HReadByte $Stream $Budget;if($b -lt 0){break};if($body.Count -ge 2048){throw 'https_body_size_limit'};$body.Add([byte]$b)}
 }
 $utf8=New-Object Text.UTF8Encoding($false,$true);$response=ConvertFrom-Json -InputObject ($utf8.GetString($body.ToArray()))
 if((@($response.PSObject.Properties.Name|Sort-Object)-join ',') -cne 'kind,nonce,observed_peer,request_id,role'){throw 'https_response_schema'}
 foreach($key in @('kind','nonce','request_id','role')){if($response.$key -cne $Challenge.$key){throw 'https_challenge_mismatch'}}
 $peer=[Net.IPAddress]::Parse([string]$response.observed_peer);return $peer.ToString()
}
function HReference([string]$URL,[string]$Address,$Challenge){
 $cfg=HValidateEndpoint $URL $Address
 $result=[ordered]@{schema='unifiedfw-https-probe-1';transport='https_php';probe_valid=$true;request_id=$Challenge.request_id;role='REF';connected=$false;tls_verified=$false;http_status=$null;handshake_ok=$false;local_address=$null;server_observed_peer=$null;error=$null;error_code=$null;elapsed_ms=0}
 $clock=[Diagnostics.Stopwatch]::StartNew();$budget=@{clock=$clock;bytes=0};$client=New-Object Net.Sockets.TcpClient([Net.Sockets.AddressFamily]::InterNetwork);$connect=$null;$auth=$null;$tls=$null
 try{
  $connect=$client.BeginConnect(([Net.IPAddress]::Parse($Address)),443,$null,$null)
  if(-not $connect.AsyncWaitHandle.WaitOne(3000)){throw 'https_connect_timeout'};$client.EndConnect($connect);$result.connected=$true;$result.local_address=$client.Client.LocalEndPoint.Address.ToString()
  $stream=$client.GetStream();$tls=New-Object Net.Security.SslStream($stream,$false)
  # Default .NET chain/name validation; never supply an accept-all callback.
  $auth=$tls.BeginAuthenticateAsClient($cfg.host,$null,$null)
  $left=8000-$clock.ElapsedMilliseconds;if($left -le 0 -or -not $auth.AsyncWaitHandle.WaitOne([int][Math]::Min(4000,$left))){throw 'https_TLS_timeout'};$tls.EndAuthenticateAsClient($auth)
  if(-not $tls.IsAuthenticated -or -not $tls.IsEncrypted -or [string]$tls.SslProtocol -cnotin @('Tls12','Tls13')){throw 'https_TLS_1_2_or_newer_required'};$result.tls_verified=$true
  $body=[Text.Encoding]::ASCII.GetBytes((UJson $Challenge));$headers='POST '+$cfg.path+' HTTP/1.1'+"`r`n"+'Host: '+$cfg.host+"`r`n"+'Content-Type: application/json'+"`r`n"+'Accept: application/json'+"`r`n"+'Accept-Encoding: identity'+"`r`n"+'Cache-Control: no-store'+"`r`n"+'Connection: close'+"`r`n"+'Content-Length: '+$body.Length+"`r`n`r`n"
  $headerBytes=[Text.Encoding]::ASCII.GetBytes($headers);$tls.WriteTimeout=2500;$tls.Write($headerBytes,0,$headerBytes.Length);$tls.Write($body,0,$body.Length)
  $result.server_observed_peer=HReadResponse $tls $budget $Challenge;$result.http_status=200;$result.handshake_ok=$true
 }catch{
  $result.error=$_.Exception.Message;$exception=$_.Exception
  while($null -ne $exception){if($exception -is [Net.Sockets.SocketException]){$result.error_code=$exception.NativeErrorCode;break};$exception=$exception.InnerException}
 }finally{
  if($null -ne $tls){$tls.Dispose()};$client.Close();foreach($operation in @($connect,$auth)){if($null -ne $operation){$operation.AsyncWaitHandle.Close()}};$clock.Stop();$result.elapsed_ms=$clock.ElapsedMilliseconds
 }
 return [pscustomobject]$result
}
