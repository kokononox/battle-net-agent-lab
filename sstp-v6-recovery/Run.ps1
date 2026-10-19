param([ValidateSet('Window','Check','Status','Disable','UiSmoke','Resume')][string]$Action='Window')
Set-StrictMode -Version 2.0
$ErrorActionPreference='Stop'
$script:ResumeNativeError=$null
function SafeCode($ErrorRecord){
 $m=$ErrorRecord.Exception.Message
 if($m -cmatch '^(overlay|tool|policy|journal|resume)_[a-z_0-9]{1,80}$'){return $m}
 return 'overlay_operation_failed'
}
try{
 . (Join-Path $PSScriptRoot 'ConfigCore.ps1')
 . (Join-Path $PSScriptRoot 'Overlay.ps1')
 . (Join-Path $PSScriptRoot 'Preflight.ps1')
 . (Join-Path $PSScriptRoot 'Resume.ps1')
 $script:root=Join-Path $env:ProgramData 'SstpDestinationOverlayTest'
 $script:config=Join-Path $PSScriptRoot 'allowlist.json'
 if($Action -ceq 'Check'){TestOverlayPrerequisites|ConvertTo-Json -Depth 5;exit 0}
 if($Action -ceq 'Status'){InvokeOverlay $script:root Status|ConvertTo-Json -Depth 5;exit 0}
 Add-Type -AssemblyName System.Windows.Forms
 if($Action -ceq 'Resume'){
  if([Windows.Forms.MessageBox]::Show('Resume ONLY the incomplete IPv6 preparation? Existing rules must be disabled and exact. No rule will be activated, adopted or deleted.','Resume preparation','YesNo','Warning') -ne 'Yes'){
   [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'resume-result.json'),'{"schema":"sstp-v6-resume-result-1","cancelled":true,"network_changed":false}',(New-Object Text.UTF8Encoding($false)))
   exit 0
  }
  $known=OverlayLoad $script:root;if($known.state.scope -cne 'RemoteAccess'){throw 'resume_user_scope'}
  $result=ResumeOverlayPreparation $script:root
  [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'resume-result.json'),($result|ConvertTo-Json -Depth 4),(New-Object Text.UTF8Encoding($false)))
  exit 0
 }
 if($Action -ceq 'Disable'){
  if([Windows.Forms.MessageBox]::Show('Disable ONLY the destination overlay and restore its prior pass-through state? Existing kill-switch rules will not be changed.','Disable overlay','YesNo','Warning') -eq 'Yes'){InvokeOverlay $script:root Disable|Out-Null}
  exit 0
 }
 Add-Type -AssemblyName System.Drawing
 [Windows.Forms.Application]::EnableVisualStyles()
 $form=New-Object Windows.Forms.Form;$form.Text='VPN destination allowlist - TEST BUILD';$form.Size=New-Object Drawing.Size(760,650);$form.StartPosition='CenterScreen'
 $label=New-Object Windows.Forms.Label;$label.Text='Test build: restricts ALL RemoteAccess tunnels, not an independent kill switch.';$label.Location=New-Object Drawing.Point(15,15);$label.Size=New-Object Drawing.Size(715,35);$form.Controls.Add($label)
 $info=New-Object Windows.Forms.Label;$info.Text='One domain or public IP per line. Shared IPs are not exclusive hostnames.';$info.Location=New-Object Drawing.Point(15,50);$info.Size=New-Object Drawing.Size(710,25);$form.Controls.Add($info)
 $box=New-Object Windows.Forms.TextBox;$box.Multiline=$true;$box.ScrollBars='Vertical';$box.Location=New-Object Drawing.Point(15,80);$box.Size=New-Object Drawing.Size(710,200);$form.Controls.Add($box)
 $status=New-Object Windows.Forms.TextBox;$status.Multiline=$true;$status.ReadOnly=$true;$status.ScrollBars='Vertical';$status.Location=New-Object Drawing.Point(15,385);$status.Size=New-Object Drawing.Size(710,205);$form.Controls.Add($status)
 if(-not [IO.File]::Exists($script:config)){$null=EditAllowlistFile $script:config Init}
 $cfg=ReadAllowlistConfig $script:config;$box.Lines=@($cfg.domains)+@($cfg.ip_addresses)
 $script:snapshot=$null
 function SaveList {
  $domains=@();$ips=@()
  foreach($line in $box.Lines){$v=$line.Trim();if(-not $v){continue};$ip=$null;if([Net.IPAddress]::TryParse($v,[ref]$ip)){$ips+=,(AssertPublicTarget $v)}else{$domains+=,(PolicyDomain $v)}}
  $c=PolicyConfig ([pscustomobject]@{schema='sstp-allowlist-config-1';domains=$domains;ip_addresses=$ips})
  # Use the existing cooperative lock + atomic replacement, not a firewall journal.
  $full=AssertConfigPath $script:config;$lockPath=$full+'.lock'
  if([IO.File]::Exists($lockPath) -and (([IO.File]::GetAttributes($lockPath)-band [IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'tool_config_link'}
  $h=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$tmp=$null
  try{
   $tmp=Join-Path $PSScriptRoot ('.sstp-config-'+[guid]::NewGuid().ToString('N')+'.tmp')
   $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes((ConvertTo-Json -InputObject $c -Depth 5))
   $stream=[IO.File]::Open($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
   [IO.File]::Replace($tmp,$full,[Management.Automation.Language.NullString]::Value);$tmp=$null
  }finally{if($tmp -and [IO.File]::Exists($tmp)){[IO.File]::Delete($tmp)};$h.Dispose()}
  $script:snapshot=$null;$status.Text='List saved. No firewall changes. Prepare again to use an updated list.'
 }
 function Confirm([string]$Text){return [Windows.Forms.MessageBox]::Show($Text,'Experimental scope','YesNo','Warning') -eq 'Yes'}
 function ShowFailure($Err){$status.Text=(SafeCode $Err)+"`r`nNo reset/force-Allow was performed. If the VPN guard is held, try Disable in this same tool. Do not use the old EmergencyReset."}
 $actions=@(
  @('Save list',15,295,{try{SaveList}catch{ShowFailure $_}}),
  @('Check only',195,295,{try{$status.Text=(TestOverlayPrerequisites|ConvertTo-Json -Depth 5)}catch{ShowFailure $_}}),
  @('Prepare disabled',375,295,{
   try{
    if(-not (Confirm 'Prepare performs DNS lookups using the current Windows resolver; it does NOT guarantee DNS remains inside VPN. It creates only DISABLED firewall rules. Continue?')){return}
    SaveList;$script:snapshot=NewOverlaySnapshot $script:config
    $null=InitializeJournalRoot $script:root
    $old=ReadJournal $script:root
    if($old.status -ceq 'valid' -and $old.record.state.phase -cin @('prepared','inactive')){InvokeOverlay $script:root Remove|Out-Null}
    NewOverlay $script:root $script:snapshot.allowed_ips -ConfigSha256 $script:snapshot.config_sha256|Out-Null
    $status.Text='Prepared: 3 DISABLED rules. No active restriction yet. Review the test limitations before Enable.'
   }catch{ShowFailure $_}
  }),
  @('Enable + exit',15,340,{
   try{
    $null=TestOverlayPrerequisites
    if(-not (Confirm 'TEST: blocks destinations outside the prepared IP list on ALL RemoteAccess tunnels. It may stop game/DNS traffic. Outside-VPN protection is NOT certified. Existing kill switch stays unchanged. Close downloads/games first. Continue?')){return}
    $state=OverlayLoad $script:root
    if($state.state.scope -cne 'RemoteAccess'){throw 'overlay_wrong_user_scope'}
    if($state.state.config_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $state.state.config_sha256 -cne (OverlayHash (ReadAllowlistConfig $script:config))){throw 'overlay_list_changed_prepare_again'}
    InvokeOverlay $script:root Enable|Out-Null;$form.Close()
   }catch{ShowFailure $_}
  }),
  @('Disable + exit',195,340,{
   try{InvokeOverlay $script:root Disable|Out-Null;$form.Close()}catch{ShowFailure $_}
  }),
  @('Remove disabled',375,340,{
   try{InvokeOverlay $script:root Remove|Out-Null;$status.Text='Only this tool''s exact disabled rules were removed. Existing kill-switch rules were not changed.'}catch{ShowFailure $_}
  }),
  @('Close',555,340,{$form.Close()})
 )
 foreach($a in $actions){$button=New-Object Windows.Forms.Button;$button.Text=$a[0];$button.Location=New-Object Drawing.Point($a[1],$a[2]);$button.Size=New-Object Drawing.Size(165,32);$button.Add_Click($a[3]);$form.Controls.Add($button)}
 $status.Text='Start with Check only. No automatic connection, no automatic Enable, no resident component.'
 if($Action -ceq 'UiSmoke'){
  if($form.Controls.Count -ne 11){throw 'overlay_ui_control_count'}
  $form.CreateControl();$form.Dispose()
  [Console]::WriteLine('overlay_ui_smoke_ok');exit 0
 }
 [Windows.Forms.Application]::Run($form)
 exit 0
}catch{
 $code=SafeCode $_
 $file=[IO.Path]::GetFileName([string]$_.InvocationInfo.ScriptName)
 if($file -cnotin @('Run.ps1','ConfigCore.ps1','Overlay.ps1','Ranges.ps1','Policy.ps1','Journal.ps1','Inventory.ps1','Preflight.ps1','Resume.ps1')){$file='runtime'}
 $report=[pscustomobject]@{schema='sstp-startup-error-1';code=$code;exception_type=$_.Exception.GetType().Name;file=$file;line=[int]$_.InvocationInfo.ScriptLineNumber;powershell=$PSVersionTable.PSVersion.ToString();process_bits=([IntPtr]::Size*8);apartment=[Threading.Thread]::CurrentThread.GetApartmentState().ToString()}
 if($Action -ceq 'Resume' -and $null -ne $script:ResumeNativeError){$report|Add-Member -NotePropertyName native_codes -NotePropertyValue $script:ResumeNativeError}
 try{[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'startup-error.json'),($report|ConvertTo-Json -Depth 4),(New-Object Text.UTF8Encoding($false)))}catch{}
 if($Action -cin @('Window','Disable','Resume')){try{Add-Type -AssemblyName System.Windows.Forms;[Windows.Forms.MessageBox]::Show($code,'Allowlist error')|Out-Null}catch{}}
 [Console]::Error.WriteLine($code);exit 1
}
