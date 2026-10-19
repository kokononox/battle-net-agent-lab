param([string]$OutputPath)
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Resume.ps1')
$script:checks=0
function Check($Value){if(-not $Value){throw 'diagnostic_check_failed'};$script:checks++}
$r=[ordered]@{schema='sstp-resume-diagnostic-test-1';passed=$false;checks=0;network_changed=$false;user_device_tested=$false}
try{
 Check ((ResumeSafeMessage 'The address is invalid.' @()) -ceq 'The address is invalid.')
 $private=@('secret_user','SstpDestinationOverlay-0123456789abcdef0123456789abcdef-v6','secret-machine')
 $text=ResumeSafeMessage 'Failed secret_user secret-machine SstpDestinationOverlay-0123456789abcdef0123456789abcdef-v6 8.8.8.8/32 2001:db8::1/128 abc.example.org 01234567-89ab-cdef-0123-456789abcdef https://private.example/path' $private
 foreach($bad in @('secret_user','secret-machine','0123456789abcdef0123456789abcdef','8.8.8.8','2001:db8','abc.example.org','01234567-89ab-cdef-0123-456789abcdef','https://private')){Check (-not $text.Contains($bad))}
 Check ((ResumeSafeMessage 'C:\Users\private\data.txt' @()) -ceq '[path]')
 Check ((ResumeSafeMessage ('x'*5000) @()).Length -le 2012)
 Check ((ResumeSafeMessage "error`ncode" @()) -ceq "error`ncode")
 Check ((ResumeSafeMessage "x$([char]1)y" @()) -ceq 'x y')
 Check ((ResumeSafeMessage 'HOSTPRIV bad' @('hostpriv')) -ceq '[private] bad')
 $r.passed=$true
}finally{
 $r.checks=$script:checks
 if($OutputPath){[IO.File]::WriteAllText($OutputPath,($r|ConvertTo-Json),(New-Object Text.UTF8Encoding($false)))}
}
$r|ConvertTo-Json
if(-not $r.passed){exit 1};exit 0
