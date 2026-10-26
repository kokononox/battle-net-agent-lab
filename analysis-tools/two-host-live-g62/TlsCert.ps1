param([ValidateSet('Prepare','Cleanup')][string]$Action)
$ErrorActionPreference='Stop'
if($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:BNET_G62 -ne 'approved-live-startup-two-hosts-g62'){throw 'fresh_hosted_required'}
$state=Join-Path $env:RUNNER_TEMP 'g62-tls-cert.PRIVATE.json'
$der=Join-Path $env:RUNNER_TEMP 'g62-tls-public.cer'
$phase=Join-Path $env:RUNNER_TEMP 'g62-tls-phase'
function Phase([string]$p){Set-Content -LiteralPath $phase -Value $p -Encoding ASCII}
if($Action -eq 'Prepare'){
 if(Test-Path $state){throw 'fixture_cert_state_exists'}
 Phase 'create-localhost-certificate'
 $cert=New-SelfSignedCertificate -DnsName 'localhost' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -HashAlgorithm SHA256 -Type SSLServerAuthentication -NotAfter (Get-Date).AddHours(2)
 @{thumbprint=$cert.Thumbprint}|ConvertTo-Json -Compress|Set-Content -LiteralPath $state -Encoding UTF8
 Phase 'fixture-certificate-ready-no-root-trust'
 Write-Output $cert.Thumbprint
}else{
 if(-not(Test-Path $state)){throw 'fixture_cert_state_missing'}
 $thumb=(Get-Content -LiteralPath $state -Raw|ConvertFrom-Json).thumbprint
 if($thumb -notmatch '^[0-9A-F]{40}$'){throw 'fixture_cert_identity_invalid'}
 foreach($store in @('My')){
  $path='Cert:\CurrentUser\'+$store+'\'+$thumb
  if(Test-Path -LiteralPath $path){Remove-Item -LiteralPath $path -Force}
  if(Test-Path -LiteralPath $path){throw 'fixture_certificate_removal_unverified'}
 }
 Remove-Item -LiteralPath $state
 if(Test-Path -LiteralPath $der){Remove-Item -LiteralPath $der -Force}
 Write-Output 'fixture_trust_removed'
}
