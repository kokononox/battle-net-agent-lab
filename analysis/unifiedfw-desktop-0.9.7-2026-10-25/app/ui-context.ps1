# Context transfer: blacklist stages draft rows; whitelist appends multiple unsaved values. NO save, registration, lookup or apply.
$script:observedMenus=New-Object Collections.Generic.List[object]
function Observed-PrefillOptions($Row,[string]$Kind){
 $values=New-Object Collections.Generic.List[object];$seen=@{}
 function Add-PrefillValue([string]$Value,[string]$Type){
  if(-not $Value -or $seen.ContainsKey($Type+'|'+$Value)){return};$seen[$Type+'|'+$Value]=$true
  $values.Add([pscustomobject]@{value=$Value;type=$Type;label=($Value+' / '+$(if($Type -ceq 'domain'){'دامنه'}else{'IP'}))})
 }
 if($Kind -ceq 'dns'){
  Add-PrefillValue ([string]$Row.domain) 'domain'
  foreach($ip in (Get-MonitorResultIPs ([string]$Row.query_results))){Add-PrefillValue $ip 'ip'}
 }elseif($Kind -ceq 'process'){
  foreach($r in @($script:liveFrame.endpoints|Where-Object{$_.program_id -ceq $Row.program_id -and $_.pid -eq $Row.pid -and $_.process_start_ticks -ceq $Row.process_start_ticks})){Add-PrefillValue ([string]$r.remote_ip) 'ip'}
  foreach($r in @($script:liveFrame.event_evidence.events|Where-Object{$_.PSObject.Properties.Name -contains 'process_start_ticks' -and $_.program_id -ceq $Row.program_id -and $_.pid -eq $Row.pid -and $_.process_start_ticks -ceq $Row.process_start_ticks})){
   if($r.kind -ceq 'dns_query'){Add-PrefillValue ([string]$r.domain) 'domain'}
   elseif($r.kind -ceq 'wfp_connection_block'){Add-PrefillValue ([string]$r.ip) 'ip'}
  }
 }else{
  $ip=if($Row.PSObject.Properties.Name -contains 'remote_ip'){$Row.remote_ip}else{$Row.ip};Add-PrefillValue ([string]$ip) 'ip'
 }
 return $values.ToArray()
}
# Pure bounded merge; preserve existing text, do not overwrite or persist settings.
function Merge-WhitelistDraft([string]$Existing,$Choices){
 $seen=@{};foreach($line in @($Existing -split '\r?\n')){if($line.Trim()){$seen[$line.Trim().ToLowerInvariant()]=$true}}
 $added=New-Object Collections.Generic.List[string]
 foreach($c in @($Choices)){
  $v=([string]$c.value).Trim();if(-not $v -or $v.Length -gt 253 -or $v -match '[\r\n]'){throw 'مقدار انتقال معتبر نیست؛ پیش‌نویس تغییر نکرد.'}
  $key=$v.ToLowerInvariant();if(-not $seen.ContainsKey($key)){$seen[$key]=$true;$added.Add($v)}
 }
 if($seen.Count -gt 1024){throw 'حداکثر ۱۰۲۴ مقدار در پیش‌نویس انتقال؛ هیچ موردی ناقص منتقل نشد.'}
 if($added.Count -eq 0){return $Existing}
 return $Existing+$(if($Existing.Length -gt 0 -and -not $Existing.EndsWith("`n")){"`r`n"}else{''})+($added.ToArray() -join "`r`n")
}
function Get-ObservedChoices($Rows,[string]$Kind){
 $all=New-Object Collections.Generic.List[object];$seen=@{}
 foreach($r in @($Rows)){
  foreach($o in @(Observed-PrefillOptions $r.Tag $Kind)){
   $key=$o.type+'|'+$o.value.ToLowerInvariant();if($seen.ContainsKey($key)){continue}
   $seen[$key]=$true;$all.Add($o)
   if($all.Count -gt 1024){throw 'بیش از ۱۰۲۴ مقصد؛ انتخاب را محدود کنید. انتقال ناقص انجام نشد.'}
  }
 };return $all.ToArray()
}
function Select-WhitelistChoices($Options,$Owner){
 if(@($Options).Count -eq 1){return ,@($Options)}
 $dialog=New-Object Windows.Forms.Form;$dialog.Text='انتخاب چند دامنه / IP برای پیش‌نویس وایت‌لیست';$dialog.Font=$form.Font;$dialog.AutoScaleMode='Dpi';$dialog.StartPosition='CenterParent';$dialog.Size=New-Object Drawing.Size(780,540);$dialog.MinimumSize=New-Object Drawing.Size(560,360);$dialog.RightToLeft='Yes';$dialog.RightToLeftLayout=$true
 $layout=Stack $dialog 3;$layout.RowStyles[0].SizeType='AutoSize';$layout.RowStyles[1].SizeType='Percent';$layout.RowStyles[1].Height=100;$layout.RowStyles[2].SizeType='AutoSize'
 $note=Label 'چند مورد را تیک بزنید؛ به متن قبلی اضافه می‌شوند، نه جایگزین. دامنه فقط پیش‌نویس است؛ ذخیرهٔ فعلی فقط IP/CIDR/بازه می‌پذیرد. هیچ DNS lookup یا ذخیره/Apply انجام نمی‌شود.';$layout.Controls.Add($note,0,0)
 $pick=New-Object Windows.Forms.CheckedListBox;$pick.Dock='Fill';$pick.CheckOnClick=$true;$pick.RightToLeft='No';$pick.HorizontalScrollbar=$true
 foreach($o in @($Options)){[void]$pick.Items.Add($o.label,$false)};$layout.Controls.Add($pick,0,1)
 $buttons=Flow;$all=Button 'انتخاب همه';$none=Button 'پاک‌کردن انتخاب';$ok=Button 'انتقال موارد تیک‌خورده';$cancel=Button 'لغو'
 $all.Add_Click({for($i=0;$i -lt $pick.Items.Count;$i++){$pick.SetItemChecked($i,$true)}})
 $none.Add_Click({for($i=0;$i -lt $pick.Items.Count;$i++){$pick.SetItemChecked($i,$false)}})
 $ok.DialogResult='OK';$cancel.DialogResult='Cancel';foreach($b in @($all,$none,$ok,$cancel)){$buttons.Controls.Add($b)};$layout.Controls.Add($buttons,0,2);$dialog.AcceptButton=$ok;$dialog.CancelButton=$cancel
 Prepare-Dialog $dialog
 try{
  if($dialog.ShowDialog($Owner) -ne 'OK'){return ,@()}
  $chosen=@();foreach($i in $pick.CheckedIndices){$chosen+=,$Options[[int]$i]};return ,$chosen
 }finally{$dialog.Dispose()}
}
function Prefill-Observed($Grid,[string]$Kind,[string]$Destination){
 if($Grid.SelectedRows.Count -eq 0){throw 'یک یا چند ردیف را انتخاب کنید.'}
 if($Destination -ceq 'whitelist'){
  $options=@(Get-ObservedChoices @($Grid.SelectedRows) $Kind)
  if($options.Count -eq 0){throw 'IP یا دامنه‌ای ثبت نشده؛ مقداری حدس زده نمی‌شود.'}
  $choices=Select-WhitelistChoices $options ($Grid.FindForm())
  if(@($choices).Count -eq 0){return}
  $text=Merge-WhitelistDraft ([string]$whitelist.Text) $choices
  $whitelist.Text=$text;$tabs.SelectedTab=$policyTab;$form.BringToFront();$whitelist.Focus()
  $status.Text='انتخاب چندتایی به پیش‌نویس وایت‌لیست افزوده شد؛ موارد تکراری حذف شدند. ذخیره نشده و Apply انجام نشد. دامنه فقط پیش‌نویس است: ذخیرهٔ فعلی IP/CIDR/بازه می‌پذیرد؛ تبدیل DNS خودکار نداریم.'
  return
 }
 if($Grid.SelectedRows.Count -ne 1){throw 'برای بلک‌لیست یک ردیف را انتخاب کنید؛ وایت‌لیست چندانتخابی است.'}
 $row=$Grid.SelectedRows[0].Tag;$options=@(Observed-PrefillOptions $row $Kind)
 if($options.Count -eq 0){throw 'برای این فرایند هنوز IP یا دامنه‌ای ثبت نشده است؛ مقداری حدس زده نمی‌شود.'}
 $chosen=$options[0]
 if($options.Count -gt 1){
  $dialog=New-Object Windows.Forms.Form;$dialog.Text='انتخاب مقدار برای انتقال — بدون ذخیره';$dialog.Font=$form.Font;$dialog.AutoScaleMode='Dpi';$dialog.StartPosition='CenterParent';$dialog.Size=New-Object Drawing.Size(690,280);$dialog.MinimumSize=New-Object Drawing.Size(560,240);$dialog.RightToLeft='Yes';$dialog.RightToLeftLayout=$true
  $layout=Stack $dialog 3;$note=Label 'فقط یک دامنه یا IP را انتخاب کنید؛ هیچ ذخیره، ثبت EXE یا Apply انجام نمی‌شود.';$layout.Controls.Add($note,0,0)
  $pick=New-Object Windows.Forms.ComboBox;$pick.DropDownStyle='DropDownList';$pick.Dock='Top';$pick.RightToLeft='No';foreach($o in $options){[void]$pick.Items.Add($o.label)};$pick.SelectedIndex=0;$layout.Controls.Add($pick,0,1)
  $buttons=Flow;$ok=Button 'فقط انتقال به فیلد';$cancel=Button 'لغو';$ok.DialogResult='OK';$cancel.DialogResult='Cancel';$buttons.Controls.Add($ok);$buttons.Controls.Add($cancel);$layout.Controls.Add($buttons,0,2);$dialog.AcceptButton=$ok;$dialog.CancelButton=$cancel
  Prepare-Dialog $dialog
  try{if($dialog.ShowDialog($Grid.FindForm()) -ne 'OK'){return};$chosen=$options[$pick.SelectedIndex]}finally{$dialog.Dispose()}
 }
 if($Destination -ceq 'blacklist'){Stage-ObservedDraft $row $chosen;return}

}
foreach($pair in @(@($liveGrid,'endpoint'),@($popupGrid,'endpoint'),@($domainMain,'dns'),@($domainPopup,'dns'),@($processGrid,'process'),@($popupProcessGrid,'process'))){
 $grid=$pair[0];$observedContextMenu=New-Object Windows.Forms.ContextMenuStrip;$observedContextMenu.RightToLeft='Yes';$observedContextMenu.ShowItemToolTips=$true;$observedContextMenu.Tag=[pscustomobject]@{grid=$grid;kind=[string]$pair[1]}
 foreach($entry in @(@('افزودن به بلک‌لیست — فقط انتقال به فیلد','blacklist'),@('وایت‌لیست — انتقال چند دامنه/IP به پیش‌نویس','whitelist'))){
  $item=New-Object Windows.Forms.ToolStripMenuItem;$item.Text=$entry[0];$item.Tag=$entry[1];$item.ToolTipText='صرفاً پرکردن فیلد؛ ذخیره بعداً با اقدام خودتان است.';[void]$observedContextMenu.Items.Add($item)
  $item.Add_Click({param($sender,$e)TryOp {$info=$sender.Owner.Tag;Prefill-Observed $info.grid $info.kind ([string]$sender.Tag)}})
 }
 $grid.ContextMenuStrip=$observedContextMenu;$script:observedMenus.Add($observedContextMenu)
 $grid.Add_CellMouseDown({param($sender,$e)if($e.Button -eq [Windows.Forms.MouseButtons]::Right){
  if($e.RowIndex -lt 0 -or $e.ColumnIndex -lt 0){$sender.ClearSelection();return}
  if(-not $sender.Rows[$e.RowIndex].Selected){$sender.ClearSelection();$sender.CurrentCell=$sender.Rows[$e.RowIndex].Cells[$e.ColumnIndex];$sender.Rows[$e.RowIndex].Selected=$true}
 }})
 $observedContextMenu.Add_Opening({param($sender,$e)if($sender.Tag.grid.SelectedRows.Count -eq 0){$e.Cancel=$true;return};$sender.Items[0].Enabled=($sender.Tag.grid.SelectedRows.Count -eq 1)})
}
$stageObserved.Text='انتقال مقصد انتخابی به فیلد بلک‌لیست'
