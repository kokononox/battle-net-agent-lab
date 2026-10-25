$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$r=@{admin=$false;hypervisor_present=$null;firmware_virtualization=$null;slat=$null;vm_monitor_extensions=$null;hyperv_feature_installed=$null;new_vm_command=$false;vmms_present=$false;vmms_running=$false;vm_definition_created=$false;vm_definition_removed=$false;diagnostic='none'}
$r.admin=([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
try{$r.hypervisor_present=[bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent}catch{}
try{
 $cpus=@(Get-CimInstance Win32_Processor)
 if($cpus.Count -gt 0){
  $r.firmware_virtualization=(@($cpus|Where-Object{$_.VirtualizationFirmwareEnabled -eq $true}).Count -eq $cpus.Count)
  $r.slat=(@($cpus|Where-Object{$_.SecondLevelAddressTranslationExtensions -eq $true}).Count -eq $cpus.Count)
  $r.vm_monitor_extensions=(@($cpus|Where-Object{$_.VMMonitorModeExtensions -eq $true}).Count -eq $cpus.Count)
 }
}catch{}
try{$r.hyperv_feature_installed=[bool](Get-WindowsFeature -Name Hyper-V).Installed}catch{}
try{$r.new_vm_command=[bool](Get-Command New-VM -ErrorAction Stop)}catch{}
$svc=$null
try{$svc=Get-Service -Name vmms -ErrorAction Stop}catch{}
$r.vmms_present=($null -ne $svc)
$r.vmms_running=($null -ne $svc -and $svc.Status -eq 'Running')
$name=$null;$folder=$null
if($r.hyperv_feature_installed -and $r.new_vm_command -and $r.vmms_running){
 try{
  $name='owned-nested-probe-'+[Guid]::NewGuid().ToString('N')
  $folder=Join-Path $env:RUNNER_TEMP $name
  $null=New-VM -Name $name -MemoryStartupBytes 512MB -Generation 2 -NoVHD -Path $folder
  $r.vm_definition_created=$true
 }catch{$r.diagnostic='vm_definition_failed'}
 finally{
  if($r.vm_definition_created){
   try{Remove-VM -Name $name -Force;$r.vm_definition_removed=$true}catch{$r.diagnostic='vm_cleanup_failed'}
  }
  if($r.vm_definition_removed -and $null -ne $folder -and (Test-Path -LiteralPath $folder)){
   Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
  }
 }
}else{$r.diagnostic='feature_or_service_unavailable'}
$r|ConvertTo-Json -Compress
