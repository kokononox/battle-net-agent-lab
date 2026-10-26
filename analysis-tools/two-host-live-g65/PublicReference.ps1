param([string]$Root)
$ErrorActionPreference='Stop'
if($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:BNET_G65 -ne 'approved-live-startup-two-hosts-g65'){throw 'fresh_hosted_required'}
if([IO.Path]::GetFullPath($Root) -ne [IO.Path]::GetFullPath((Join-Path $env:RUNNER_TEMP 'g65-private'))){throw 'root_rejected'}
Add-Type -AssemblyName System.Net.Http
$handler=[Net.Http.HttpClientHandler]::new();$handler.AllowAutoRedirect=$false;$handler.UseProxy=$false;$handler.UseCookies=$false;$handler.CheckCertificateRevocationList=$true
$client=[Net.Http.HttpClient]::new($handler);$client.Timeout=[TimeSpan]::FromSeconds(8);$client.MaxResponseContentBufferSize=128KB
$rows=@()
try{
 try{
  $r=$client.GetAsync('https://us.version.battle.net/v2/summary').GetAwaiter().GetResult()
  if([int]$r.StatusCode -eq 200){$text=$r.Content.ReadAsStringAsync().GetAwaiter().GetResult();$rows+=@{route='/v2/summary';status=200;text=$text}}else{$rows+=@{route='/v2/summary';status=[int]$r.StatusCode;text=''}}
  $r.Dispose()
 }catch{$rows+=@{route='/v2/summary';status=0;text=''}}
 foreach($product in @('agent','bna','bnt')){foreach($kind in @('versions','cdns')){
  $route='/v2/products/'+$product+'/'+$kind
  try{
   $r=$client.GetAsync('https://us.version.battle.net'+$route).GetAwaiter().GetResult()
   if([int]$r.StatusCode -eq 200){$text=$r.Content.ReadAsStringAsync().GetAwaiter().GetResult();$rows+=@{route=$route;status=200;text=$text}}else{$rows+=@{route=$route;status=[int]$r.StatusCode;text=''}}
   $r.Dispose()
  }catch{$rows+=@{route=$route;status=0;text=''}}
 }}
 @{fixed_public_requests_only=$true;rows=$rows}|ConvertTo-Json -Depth 6 -Compress|Set-Content -LiteralPath (Join-Path $Root 'public-reference.PRIVATE.json') -Encoding UTF8
}finally{$client.Dispose();$handler.Dispose()}
