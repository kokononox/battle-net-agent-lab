# Context transfer: blacklist stages draft rows; whitelist prefills text. NO save, registration, lookup or apply.
$script:observedMenus=New-Object Collections.Generic.List[object]
function Observed-PrefillOptions($Row,[string]$Kind){
 $values=New-Object Collections.Generic.List[object];$seen=@{}
 function Add-PrefillValue([string]$Value,[string]$Type){
  if(-not $Value -or $seen.ContainsKey($Type+'|'+$Value)){return};$seen[$Type+'|'+$Value]=$true
  $values.Add([pscustomobject]@{value=$Value;type=$Type;label=($Value+' / '+$(if($Type -ceq 'domain'){'دامنه'}else{'IP'}))})
 }
 if($Kind -ceq 'dns'){
  Add-PrefillValue ([string]$Row.domain) 'domain'
  foreach($ip in @(Get-MonitorResultIPs ([string]$Row.query_results))){Add-PrefillValue $ip 'ip'}
 }elseif($Kind -ceq 'process'){
  foreach($r in @($script:liveFrame.endpoints|Where-Object{$_.program_id -ceq $Row.program_id -and $_.pid -eq $Row.pid -and $_.process_start_ticks -ceq $Row.process_start_ticks})){Add-PrefillValue ([string]$r.remote_ip) 'ip'}
  foreach($r in @($script:liveFrame.event_evidence.events|Where-Object{$_.kind -ceq 'dns_query' -and $_.program_id -ceq $Row.program_id -and $_.pid -eq $Row.pid -and $_.process_start_ticks -ceq $Row.process_start_ticks})){Add-PrefillValue ([string]$r.domain) 'domain'}
 }else{
  $ip=if($Row.PSObject.Properties.Name -contains 'remote_ip'){$Row.remote_ip}else{$Row.ip};Add-PrefillValue ([string]$ip) 'ip'
 }
 return $values.ToArray()
}
function Prefill-Observed($Grid,[string]$Kind,[string]$Destination){
 if($Grid.SelectedRows.Count -ne 1){throw 'فقط یک ردیف را انتخاب کنید.'}
 $row=$Grid.SelectedRows[0].Tag;$options=@(Observed-PrefillOptions $row $Kind)
 if($options.Count -eq 0){throw 'برای این فرایند هنوز IP یا دامنه‌ای ثبت نشده است؛ مقداری حدس زده نمی‌شود.'}
 $chosen=$options[0]
 if($options.Count -gt 1){
  $dialog=New-Object Windows.Forms.Form;$dialog.Text='انتخاب مقدار برای انتقال — بدون ذخیره';$dialog.Font=$form.Font;$dialog.AutoScaleMode='Dpi';$dialog.StartPosition='CenterParent';$dialog.Size=New-Object Drawing.Size(690,280);$dialog.MinimumSize=New-Object Drawing.Size(560,240);$dialog.RightToLeft='Yes';$dialog.RightToLeftLayout=$true
  $layout=Stack $dialog 3;$note=Label 'فقط یک دامنه یا IP را انتخاب کنید؛ هیچ ذخیره، ثبت EXE یا Apply انجام نمی‌شود.';$layout.Controls.Add($note,0,0)
  $pick=New-Object Windows.Forms.ComboBox;$pick.DropDownStyle='DropDownList';$pick.Dock='Top';$pick.RightToLeft='No';foreach($o in $options){[void]$pick.Items.Add($o.label)};$pick.SelectedIndex=0;$layout.Controls.Add($pick,0,1)
  $buttons=Flow;$ok=Button 'فقط انتقال به فیلد';$cancel=Button 'لغو';$ok.DialogResult='OK';$cancel.DialogResult='Cancel';$buttons.Controls.Add($ok);$buttons.Controls.Add($cancel);$layout.Controls.Add($buttons,0,2);$dialog.AcceptButton=$ok;$dialog.CancelButton=$cancel
  try{if($dialog.ShowDialog($Grid.FindForm()) -ne 'OK'){return};$chosen=$options[$pick.SelectedIndex]}finally{$dialog.Dispose()}
 }
 if($Destination -ceq 'blacklist'){Stage-ObservedDraft $row $chosen;return}
 # Do not overwrite an existing draft without consent. Existing save/preview/apply buttons remain untouched.
 $field=$whitelist;$page=$policyTab
 if($field.Text.Trim() -and $field.Text.Trim() -cne $chosen.value -and [Windows.Forms.MessageBox]::Show('مقدار قبلی این کادر با مقدار انتخابی جایگزین شود؟ هیچ ذخیره‌ای انجام نمی‌شود.','جایگزینی پیش‌نویس','YesNo','Question') -ne 'Yes'){return}
 $field.Text=$chosen.value;$tabs.SelectedTab=$page;$form.BringToFront();$field.Focus()
 $message='فقط فیلد پر شد؛ هنوز ذخیره نشده و هیچ قاعده، EXE یا hosts تغییر نکرده است. ذخیره بعداً با اقدام شماست.'
 if($Destination -ceq 'whitelist' -and $chosen.type -ceq 'domain'){$message+=' دامنه فعلاً فقط پیش‌نویس است: ذخیرهٔ وایت‌لیست موجود فقط IP/CIDR/بازه می‌پذیرد؛ تبدیل DNS خودکار نداریم.'}

 $status.Text=$message;$tip.SetToolTip($field,$message)
}
foreach($pair in @(@($liveGrid,'endpoint'),@($popupGrid,'endpoint'),@($domainMain,'dns'),@($domainPopup,'dns'),@($processGrid,'process'),@($popupProcessGrid,'process'))){
 $grid=$pair[0];$menu=New-Object Windows.Forms.ContextMenuStrip;$menu.RightToLeft='Yes';$menu.ShowItemToolTips=$true;$menu.Tag=[pscustomobject]@{grid=$grid;kind=[string]$pair[1]}
 foreach($entry in @(@('افزودن به بلک‌لیست — فقط انتقال به فیلد','blacklist'),@('افزودن به وایت‌لیست — فقط انتقال به فیلد','whitelist'))){
  $item=New-Object Windows.Forms.ToolStripMenuItem;$item.Text=$entry[0];$item.Tag=$entry[1];$item.ToolTipText='صرفاً پرکردن فیلد؛ ذخیره بعداً با اقدام خودتان است.';[void]$menu.Items.Add($item)
  $item.Add_Click({param($sender,$e)TryOp {$info=$sender.Owner.Tag;Prefill-Observed $info.grid $info.kind ([string]$sender.Tag)}})
 }
 $grid.ContextMenuStrip=$menu;$script:observedMenus.Add($menu)
 $grid.Add_CellMouseDown({param($sender,$e)if($e.Button -eq [Windows.Forms.MouseButtons]::Right){$sender.ClearSelection();if($e.RowIndex -ge 0 -and $e.ColumnIndex -ge 0){$sender.CurrentCell=$sender.Rows[$e.RowIndex].Cells[$e.ColumnIndex];$sender.Rows[$e.RowIndex].Selected=$true}}})
 $menu.Add_Opening({param($sender,$e)if($sender.Tag.grid.SelectedRows.Count -ne 1){$e.Cancel=$true}})
}
$stageObserved.Text='انتقال مقصد انتخابی به فیلد بلک‌لیست'
