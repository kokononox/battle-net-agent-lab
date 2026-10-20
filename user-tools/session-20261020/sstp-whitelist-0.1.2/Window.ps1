# UI is English/Persian; all policy operations are in App-Core, not event glue.
Set-StrictMode -Version 2.0
function ShowAppWindow([string]$Root){
 Add-Type -AssemblyName System.Drawing
 [Windows.Forms.Application]::EnableVisualStyles()
 $form=New-Object Windows.Forms.Form;$form.Text='SSTP Whitelist 0.1.2 — VPN destinations only';$form.Size=New-Object Drawing.Size(810,740);$form.MinimumSize=$form.Size;$form.StartPosition='CenterScreen';$form.Font=New-Object Drawing.Font('Segoe UI',10)
 $title=New-Object Windows.Forms.Label;$title.Text='فهرست مقصدهای مجاز روی VPN';$title.Font=New-Object Drawing.Font('Segoe UI',15,[Drawing.FontStyle]::Bold);$title.Location=New-Object Drawing.Point(20,15);$title.Size=New-Object Drawing.Size(750,35);$title.TextAlign='MiddleRight';$form.Controls.Add($title)
 $scope=New-Object Windows.Forms.Label;$scope.Text='فقط محدودیت مقصد روی همهٔ تونل‌های RemoteAccess؛ نه حفاظت کامل خارج VPN.';$scope.Location=New-Object Drawing.Point(20,55);$scope.Size=New-Object Drawing.Size(750,50);$scope.ForeColor=[Drawing.Color]::DarkRed;$scope.TextAlign='MiddleRight';$form.Controls.Add($scope)
 $hint=New-Object Windows.Forms.Label;$hint.Text='هر خط: یک IP عمومی یا دامنه. Preview فقط کش را می‌خواند؛ برای دریافت IP از DNS، دکمهٔ Resolve DNS را بزنید.';$hint.Location=New-Object Drawing.Point(20,108);$hint.Size=New-Object Drawing.Size(750,45);$hint.TextAlign='MiddleRight';$form.Controls.Add($hint)
 $box=New-Object Windows.Forms.TextBox;$box.Multiline=$true;$box.ScrollBars='Vertical';$box.Location=New-Object Drawing.Point(20,155);$box.Size=New-Object Drawing.Size(750,205);$box.Font=New-Object Drawing.Font('Consolas',11);$form.Controls.Add($box)
 $config=ReadAllowlistConfig (AppConfigPath $Root);$box.Lines=@($config.domains)+@($config.ip_addresses)
 $ack=New-Object Windows.Forms.CheckBox;$ack.Text='می‌پذیرم: این نسخه فقط مقصدهای VPN را محدود می‌کند و کیل‌سوییچ کامل کل ویندوز نیست.';$ack.Location=New-Object Drawing.Point(20,370);$ack.Size=New-Object Drawing.Size(750,45);$ack.RightToLeft='Yes';$form.Controls.Add($ack)
 $status=New-Object Windows.Forms.TextBox;$status.Multiline=$true;$status.ReadOnly=$true;$status.ScrollBars='Vertical';$status.Location=New-Object Drawing.Point(20,515);$status.Size=New-Object Drawing.Size(750,170);$form.Controls.Add($status)
 $status.Text="Ready. Save only makes no firewall changes.`r`nApply creates persistent VPN-only Block rules, then fully exits.`r`nRestore removes only this app's exact rules. No reset, new Allow, or background service."
 $script:AppSnapshot=$null;$script:AppWindow=$form;$script:AppEditor=$box;$script:AppStatus=$status;$script:AppAck=$ack;$script:AppUiRoot=$Root
 function SaveWindowList {
  $c=SaveAppConfig $script:AppUiRoot @($script:AppEditor.Lines)
  if($null -ne $script:AppSnapshot -and $script:AppSnapshot.config_sha256 -cne (OverlayHash $c)){$script:AppSnapshot=$null}
  return $c
 }
 function AppWindowFailure($Err){
  $code=AppSafeCode $Err
  $script:AppStatus.Text=$code+"`r`nNo reset/force-Allow was performed. Existing restrictions may remain. Restore is available in this window or Restore.cmd."
  if($Err.Exception.Data.Contains('domain')){$script:AppStatus.Text+="`r`nDomain: "+[string]$Err.Exception.Data['domain']}
  switch($code){
   'app_domain_not_cached' {$script:AppStatus.Text+="`r`nNo usable cached address. Use Resolve DNS... (requires explicit consent) or an explicit public IP. No automatic fallback was sent."}
   'app_domain_cache_lookup_failed' {$script:AppStatus.Text+="`r`nWindows cache lookup failed. Use Resolve DNS... to request an online lookup with consent, or an explicit public IP."}
   'app_domain_network_lookup_failed' {$script:AppStatus.Text+="`r`nWindows DNS lookup failed. Check the domain and existing DNS/VPN access. No firewall exception was added. Previous preview was cleared."}
   'app_domain_no_usable_addresses' {$script:AppStatus.Text+="`r`nDNS returned no usable A/AAAA answer. No IP was guessed; previous preview was cleared."}
   'app_domain_address_rejected' {$script:AppStatus.Text+="`r`nDNS returned an address outside the permitted public-IP scope. No rule was applied."}
   'app_dns_connected_sstp_required' {$script:AppStatus.Text+="`r`nConnect your SSTP VPN first. This does not certify DNS stays inside the tunnel."}
   'app_snapshot_expired' {$script:AppSnapshot=$null;$script:AppStatus.Text+="`r`nPreview expired. Preview again, or use Resolve DNS... for an online refresh."}
  }
 }
 $buttons=@(
  @('Save list',20,425,{
   try{$null=SaveWindowList;$script:AppStatus.Text='List saved. Firewall unchanged. Apply is a separate action.'}catch{AppWindowFailure $_}
  }),
  @('Preview IPs',210,425,{
   try{$script:AppSnapshot=$null;$c=SaveWindowList;$script:AppSnapshot=BuildAppSnapshot $c;$script:AppStatus.Text="IP snapshot (not exclusive hostname identity):`r`n"+($script:AppSnapshot.allowed_ips -join "`r`n")+"`r`nNo DNS query and no firewall change."}catch{AppWindowFailure $_}
  }),
  @('Resolve DNS...',590,425,{
   try{
    $text="Request IP addresses for the listed domains using Windows DNS?`r`nThis permits DNS network traffic under CURRENT Windows routing/DNS policy. Even with VPN connected, DNS may go outside the VPN; tunnel-only DNS is NOT guaranteed.`r`nNo firewall exceptions, DNS settings or VPN connection will be changed. Existing restrictions may block the lookup. Continue?"
    if([Windows.Forms.MessageBox]::Show($text,'Allow DNS lookup for this preview only?','YesNo','Warning') -ne 'Yes'){return}
    $script:AppSnapshot=$null;$c=SaveWindowList
    $script:AppStatus.Text='Resolving with Windows DNS after your confirmation. No firewall changes...';$script:AppWindow.Refresh()
    $script:AppSnapshot=BuildAppSnapshot -Config $c -DnsMode WindowsDns -NetworkDnsConfirmed $true
    $script:AppStatus.Text="DNS preview ready. Review the IPs, then Apply + exit:`r`n"+($script:AppSnapshot.allowed_ips -join "`r`n")+"`r`nNetwork DNS was permitted for this preview only; tunnel-only routing is NOT certified. No firewall change."
   }catch{AppWindowFailure $_}
  }),
  @('Apply + exit',400,425,{
   try{
    if(-not $script:AppAck.Checked){throw 'app_scope_acknowledgement_required'}
    $c=SaveWindowList;if($null -eq $script:AppSnapshot){$script:AppSnapshot=BuildAppSnapshot $c}
    $text="Apply VPN-only destination restrictions to ALL programs on ALL RemoteAccess interfaces?`r`n"+"Allowed IP snapshot: "+($script:AppSnapshot.allowed_ips -join ', ')+"`r`nDNS/game traffic to other IPs may stop. This does NOT install outside-VPN protection. Existing kill switch remains unchanged."
    if([Windows.Forms.MessageBox]::Show($text,'Confirm VPN-only scope','YesNo','Warning') -ne 'Yes'){return}
    $script:AppStatus.Text='Applying exact persistent rules. Please wait...';$script:AppWindow.Refresh()
    $report=ApplyApp $script:AppUiRoot $script:AppSnapshot ([bool]$script:AppAck.Checked);WriteAppOutcome $report
    if(-not $report.passed){throw $report.code}
    $script:AppWindow.Close()
   }catch{AppWindowFailure $_}
  }),
  @('Restore + exit',20,470,{
   try{
    if([Windows.Forms.MessageBox]::Show('Remove only this app''s VPN destination restrictions? Other rules and profiles stay unchanged.','Restore','YesNo','Warning') -ne 'Yes'){return}
    $script:AppStatus.Text='Restoring exact owned rules. Please wait...';$script:AppWindow.Refresh()
    $report=RestoreApp $script:AppUiRoot;WriteAppOutcome $report
    if(-not $report.passed){throw $report.code};$script:AppWindow.Close()
   }catch{AppWindowFailure $_}
  }),
  @('Status',210,470,{
   try{
    $h=AppLock $script:AppUiRoot
    try{$slots=ReadAppSlots $script:AppUiRoot;$script:AppStatus.Text=(@($slots|ForEach-Object{$_.slot+': '+$_.phase}) -join "`r`n")+"`r`nScope: VPN destinations only. Outside protection NOT installed."}finally{$h.Dispose()}
   }catch{AppWindowFailure $_}
  }),
  @('Close',400,470,{$script:AppWindow.Close()})
 )
 foreach($item in $buttons){$b=New-Object Windows.Forms.Button;$b.Text=$item[0];$b.Location=New-Object Drawing.Point($item[1],$item[2]);$b.Size=New-Object Drawing.Size(175,35);$b.Add_Click($item[3]);$form.Controls.Add($b);if($item[0] -ceq 'Apply + exit'){$script:AppApplyButton=$b;$b.Enabled=$false}}
 $ack.Add_CheckedChanged({$script:AppApplyButton.Enabled=$script:AppAck.Checked})
 $form.MaximizeBox=$false
 [Windows.Forms.Application]::Run($form)
 $form.Dispose()
}
