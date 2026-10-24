# Explicit repair for the exact disabled orphan identified in the user's two reports.
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'session-core.ps1')
. (Join-Path $PSScriptRoot 'native.ps1')
. (Join-Path $PSScriptRoot 'recovery-core.ps1')
$root=Split-Path $PSScriptRoot -Parent
$dir=Join-Path $root ('private-state/recovery-jobs/'+[guid]::NewGuid().ToString('N'));UAssertPath $dir;$null=[IO.Directory]::CreateDirectory($dir)
$out=Join-Path $dir 'result.json';$lock=$null;$attempted=$false;$result=$null;$exitCode=0
try{
 UAdmin;Import-Module NetSecurity -ErrorAction Stop
 $file=Join-Path $PSScriptRoot 'recovery-expected.json';UAssertPath $file
 if((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'caff4996ce9d27725fa41fd488a1a4d23508786321102a785df95bc15913587c'){throw 'recovery_expected_file_integrity'}
 $expected=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($file))
 if($expected.schema -cne 'unifiedfw-known-disabled-recovery-1' -or $expected.owner -cne 'ebc12e15e9144e3e850e869eaf067f2c' -or $expected.session_id -cne 'e38f9e9dd64f41b3bc30f99f8ea509d2'){throw 'unexpected_recovery_target'}
 $journalRoot=USecureRoot $false;if(-not [IO.Directory]::Exists($journalRoot)){throw 'known_journal_missing'}
 $lock=UOpenPrivateFile (Join-Path $journalRoot 'session.lock') ([IO.FileMode]::OpenOrCreate)
 $session=ULoad $journalRoot;AssertKnownSession $session $expected
 Write-Host 'This repair removes ONLY the exact unchanged DISABLED selftest orphan.'
 Write-Host ('Target: '+$expected.target_name)
 Write-Host 'It then finishes the failed session journal. No Apply or SELFTEST is run.'
 Write-Host 'If anything differs from the observed rule, repair stops without force.'
 if((Read-Host 'Type REMOVE KNOWN DISABLED TEST RULE to confirm') -cne 'REMOVE KNOWN DISABLED TEST RULE'){throw 'cancelled_no_rule_mutation'}
 $attempted=$true
 $r=InvokeKnownDisabledRecovery $journalRoot $expected {param($name,$store) UReadNative $name $store} {param($name) URemoveNative $name}
 $result=[ordered]@{schema='unifiedfw-known-recovery-result-1';action='recover_known_disabled_orphan';ok=$r.ok;recovery=$r;packet_enforcement_tested=$false;protection_verified=$false}
 Write-Host 'Recovery completed. This is NOT an Apply or protection certification.' -ForegroundColor Green
}catch{
 $exitCode=1;$result=[ordered]@{schema='unifiedfw-known-recovery-result-1';action='recover_known_disabled_orphan';ok=$false;error=$_.Exception.Message;repair_attempted=$attempted;change_status=$(if($attempted){'inspect_result_or_rerun_same_repair; no_blind_cleanup'}else{'no_rule_mutation_attempted'});protection_verified=$false}
 Write-Host ('STOP: '+$_.Exception.Message) -ForegroundColor Yellow
}finally{if($null -ne $lock){$lock.Dispose()}}
[IO.File]::WriteAllText($out,(ConvertTo-Json -InputObject $result -Depth 32),(New-Object Text.UTF8Encoding($false)))
Write-Host ('Result file: '+$out)
exit $exitCode
