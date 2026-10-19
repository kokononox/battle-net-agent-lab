param([string]$Root,[ValidateSet('Hold','Release')][string]$Action,[ValidateSet('None','BeforeMutation','AfterMutation')][string]$Fault='None')
try{. "$PSScriptRoot/Guard.ps1";InvokeTransitionGuard -Root $Root -Action $Action -Fault $Fault | Out-Null;exit 0}catch{if($_.Exception.Message -match '^(guard|journal|integrated|inventory)_[a-z_]+$'){Write-Host $_.Exception.Message};exit 1}
