$ErrorActionPreference='Stop'
# Static verification only: never invoke, load or install the downloaded PE.
Add-Type -AssemblyName System.Net.Http
$r=@{schema='static_signature_g42_v1';source_commit=$env:GITHUB_SHA;run_id=$env:GITHUB_RUN_ID;installer_executed=$false;firewall_changed=$false;catalog_entries_approved=0;signature_status='not_checked';error_code=$null}
$path=Join-Path $env:RUNNER_TEMP ('bnet-static-g42-'+[guid]::NewGuid().ToString('N')+'.exe')
$handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseCookies=$false;$handler.UseProxy=$false
$client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds(30);$client.MaxResponseContentBufferSize=8MB
try{
 $url='https://downloader.battle.net/download/installer/win/1.0.68/Battle.net-Setup.exe'
 $client.DefaultRequestHeaders.UserAgent.ParseAdd('BattleNetStaticSignatureReview/0.1')
 $response=$client.GetAsync($url).GetAwaiter().GetResult()
 if([int]$response.StatusCode -ne 200){throw 'download_status_rejected'}
 $bytes=$response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
 if($bytes.Length -ne 4700880){throw 'size_rejected'}
 [IO.File]::WriteAllBytes($path,$bytes)
 $sha=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
 $r.bytes=$bytes.Length;$r.sha256=$sha;$r.url=$url
 if($sha -ne 'f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'){throw 'hash_rejected'}
 # Default Windows chain/trust behavior; no revocation/TLS bypass or imported CA.
 $sig=Get-AuthenticodeSignature -LiteralPath $path
 $r.signature_status=[string]$sig.Status
 if($sig.SignerCertificate){$r.signer_subject=$sig.SignerCertificate.Subject;$r.signer_thumbprint=$sig.SignerCertificate.Thumbprint;$r.signer_issuer=$sig.SignerCertificate.Issuer}
 if($sig.TimeStamperCertificate){$r.timestamp_subject=$sig.TimeStamperCertificate.Subject}
 if($sig.Status -ne 'Valid'){throw 'signature_not_valid'}
 $r.accepted=$true
}catch{
 $m=$_.Exception.Message;if($m -notmatch '^[a-z_]{1,80}$'){$m='static_verification_failed'}
 $r.error_code=$m;$r.accepted=$false
}finally{
 $client.Dispose();$handler.Dispose()
 if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}
 $j=$r|ConvertTo-Json -Depth 6 -Compress
 'G42_SIGNATURE_B64='+[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($j))
}
if(-not $r.accepted){throw 'static_signature_rejected'}
