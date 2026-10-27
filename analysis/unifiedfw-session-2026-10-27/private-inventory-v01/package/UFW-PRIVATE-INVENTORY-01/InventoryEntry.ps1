function Get-UfwInventoryRoot{return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'UnifiedFW-PrivateInventory-01'}
function Save-UfwInventoryPrivate($Data){
 $payload=Get-UfwInventoryJson $Data;$hash=Get-UfwJournalHash $payload;$bytes=[Text.Encoding]::UTF8.GetBytes((Get-UfwInventoryJson ([pscustomobject]@{payload=$payload;sha256=$hash})))
 if($bytes.Length -gt 67108864){throw 'ufw_inventory_snapshot_size'}
 $root=Get-UfwInventoryRoot
 if([IO.Directory]::Exists($root)){Assert-UfwJournalAcl $root $true}else{New-UfwPrivateJournalDirectory $root}
 $dir=Join-Path $root ('inventory-'+[guid]::NewGuid().ToString('N'));New-UfwPrivateJournalDirectory $dir
 $path=Join-Path $dir 'private-policy-snapshot.json';$file=Open-UfwPrivateJournalFile $path ([IO.FileMode]::CreateNew)
 try{$file.Write($bytes,0,$bytes.Length);$file.Flush($true)}finally{$file.Dispose()}
 Assert-UfwJournalAcl $path $false
 $file=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{if($file.Length -ne $bytes.Length){throw 'ufw_inventory_snapshot_readback'};$reader=New-Object IO.StreamReader($file,[Text.Encoding]::UTF8,$true,4096,$true);try{$text=$reader.ReadToEnd()}finally{$reader.Dispose()}}finally{$file.Dispose()}
 if($text -cne [Text.Encoding]::UTF8.GetString($bytes)){throw 'ufw_inventory_snapshot_readback'}
 $en=ConvertFrom-Json $text;if($en.sha256 -cne (Get-UfwJournalHash $en.payload) -or $en.payload -cne $payload){throw 'ufw_inventory_snapshot_checksum'}
 return [pscustomobject]@{readback_verified=$true}
}
function Confirm-UfwInventoryStorage {
 Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop;$f=New-Object System.Windows.Forms.Form
 try{
  $f.Text='Private inventory only - no firewall changes or installer launch';$f.Width=900;$f.Height=440;$f.StartPosition='CenterScreen'
  $t=New-Object System.Windows.Forms.TextBox;$t.Multiline=$true;$t.ReadOnly=$true;$t.Dock='Fill';$t.ScrollBars='Vertical'
  $t.Text='This reads PersistentStore and ActiveStore (including source tracing), all visible rules/profiles and seven associated filter types per rule. It may take several minutes; progress displays counts only. Nothing is changed in firewall, audit, DNS or VPN. No installer is launched. No candidate, old baseline or Security log is accessed. With consent, exact rule names, paths, IPs, policy sources and other private properties are stored only under the protected ProgramData UnifiedFW-PrivateInventory-01 folder, Administrators/SYSTEM only. The record is NOT yet qualified for restore or Apply and is NOT a complete WFP inventory. Header rechecks cannot prove filter stability or atomicity. Return ONLY the small public UFW-PRIVATE-INVENTORY-01 diagnostic, never the private snapshot, screenshots or transcripts. A failed write may leave a partial private folder; do not delete/repair it to force a pass. Cancel changes nothing and saves no private snapshot. This consent is storage-only, never consent to quarantine or firewall changes.'
  $panel=New-Object System.Windows.Forms.FlowLayoutPanel;$panel.Dock='Bottom';$panel.Height=55;$panel.FlowDirection='RightToLeft'
  $cancel=New-Object System.Windows.Forms.Button;$cancel.Text='Cancel';$cancel.Width=120;$cancel.DialogResult='Cancel'
  $yes=New-Object System.Windows.Forms.Button;$yes.Text='Save private inventory only';$yes.Width=280;$yes.DialogResult='OK'
  $panel.Controls.Add($cancel);$panel.Controls.Add($yes);$f.Controls.Add($t);$f.Controls.Add($panel);$f.CancelButton=$cancel;$f.ActiveControl=$cancel
  return ($f.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK)
 }finally{$f.Dispose()}
}
function Invoke-UfwInventoryNative {
 $watch=[Diagnostics.Stopwatch]::StartNew();$budget=[pscustomobject]@{nodes=0}
 $ops=@{
  Confirm={Confirm-UfwInventoryStorage}
  Actor={[Security.Principal.WindowsIdentity]::GetCurrent().User.Value}
  Clock={[datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm:ss.fffffff UTC')}
  Rules={param($store)if($store -ceq 'ActiveStore'){Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop}else{Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop}}
  Profiles={param($store)Get-NetFirewallProfile -PolicyStore $store -ErrorAction Stop}
  Filters={param($kind,$rule)switch -CaseSensitive ($kind){
   'Application'{$rule|Get-NetFirewallApplicationFilter -ErrorAction Stop}
   'Service'{$rule|Get-NetFirewallServiceFilter -ErrorAction Stop}
   'Port'{$rule|Get-NetFirewallPortFilter -ErrorAction Stop}
   'Address'{$rule|Get-NetFirewallAddressFilter -ErrorAction Stop}
   'Interface'{$rule|Get-NetFirewallInterfaceFilter -ErrorAction Stop}
   'InterfaceType'{$rule|Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop}
   'Security'{$rule|Get-NetFirewallSecurityFilter -ErrorAction Stop}
   default{throw 'ufw_inventory_filter_kind'}
  }}
  Serialize={param($v)ConvertTo-UfwInventoryValue $v 0 $budget}
  Save={param($d)Save-UfwInventoryPrivate $d}
  Progress={param($count)if($count%25 -eq 0){Write-Host ('Rules with associated filters captured: '+$count)}}
  CheckTime={if($watch.Elapsed.TotalMinutes -gt 15){throw 'ufw_inventory_time_cap'}}
 }
 try{return Invoke-UfwInventoryCapture $ops}finally{$watch.Stop()}
}
