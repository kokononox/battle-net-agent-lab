# Modal, form-based range builder. Preview calls a local pure backend operation, never DNS/firewall.
function Invoke-LocalRangePreview($payload) {
 $id=[Guid]::NewGuid().ToString('N');$request=Join-Path $private ('job-'+$id+'.request.json');$result=Join-Path $private ('job-'+$id+'.result.json')
 [IO.File]::WriteAllText($request,(@{action='preview_range';payload=$payload}|ConvertTo-Json -Depth 6),(New-Object Text.UTF8Encoding($false)))
 $psi=New-Object Diagnostics.ProcessStartInfo;$psi.FileName=Join-Path $root 'runtime\python.exe';$psi.Arguments='-I "'+(Join-Path $root 'app\backend.py')+'" "'+$request+'"';$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.WorkingDirectory=$root
 $process=$null
 try{
  $process=[Diagnostics.Process]::Start($psi)
  if(!$process.WaitForExit(5000)){try{$process.Kill()}catch{};throw 'preview_timeout'}
  $r=[IO.File]::ReadAllText($result)|ConvertFrom-Json
  if(!$r.ok){throw ([string]$r.error)};return $r.range_preview
 }finally{if($process){$process.Dispose()};Remove-Item -LiteralPath $request,$result -Force -ErrorAction SilentlyContinue}
}
function Invalidate-RangePreview {
 if(!$script:rw){return};$script:rw.preview=$null;$script:rw.add.Enabled=$false;$script:rw.output.Text='پس از واردکردن اطلاعات، «پیش‌نمایش رنج» را بزن. هیچ قانونی خودکار اعمال نمی‌شود.'
}
function Show-RangeWizard {
 $script:rw=@{preview=$null};$d=New-Object Windows.Forms.Form;$script:rw.dialog=$d
 $d.Text='افزودن آسان رنج IP';$d.ClientSize=New-Object Drawing.Size(700,620);$d.MinimumSize=New-Object Drawing.Size(640,580);$d.StartPosition='CenterParent';$d.Font=$form.Font;$d.AutoScaleMode='Dpi';$d.BackColor=[Drawing.Color]::White
 $t=New-Object Windows.Forms.TableLayoutPanel;$t.Dock='Fill';$t.Padding=New-Object Windows.Forms.Padding(16);$t.ColumnCount=2;$t.RowCount=9
 [void]$t.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Absolute,160)));[void]$t.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100)))
 foreach($h in @(54,48,66,48,48,48,-1,40,56)){$st=if($h -eq -1){New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)}else{New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$h)};[void]$t.RowStyles.Add($st)};$d.Controls.Add($t)
 $intro=Label 'بدون محاسبهٔ CIDR: الگو یا ابتدا و انتهای بازه را وارد کن؛ ابتدا پوشش دقیق را ببین، سپس به جدول اضافه کن.';$t.Controls.Add($intro,0,0);$t.SetColumnSpan($intro,2)
 $mode=New-Object Windows.Forms.ComboBox;$mode.DropDownStyle='DropDownList';$mode.Dock='Fill';[void]$mode.Items.AddRange(@('الگوی ساده / پیشوند IP','از IP تا IP','CIDR آماده'));$mode.SelectedIndex=0;$script:rw.mode=$mode
 $t.Controls.Add((Label 'روش ورود'),0,1);$t.Controls.Add($mode,1,1)
 $value=New-Object Windows.Forms.TextBox;$value.Dock='Fill';$value.RightToLeft='No';$value.Font=New-Object Drawing.Font('Consolas',11);$script:rw.value=$value
 $valueBox=New-Object Windows.Forms.TableLayoutPanel;$valueBox.Dock='Fill';$valueBox.RowCount=2;$valueBox.ColumnCount=1
 [void]$valueBox.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,30)));[void]$valueBox.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)))
 $hint=Label 'مثال: 2.*.*.* یا 2.19 یا 2.19.198.*';$hint.Font=New-Object Drawing.Font('Tahoma',9);$script:rw.hint=$hint;$valueBox.Controls.Add($value,0,0);$valueBox.Controls.Add($hint,0,1)
 $firstLabel=Label 'الگو / پیشوند';$script:rw.firstLabel=$firstLabel;$t.Controls.Add($firstLabel,0,2);$t.Controls.Add($valueBox,1,2)
 $last=New-Object Windows.Forms.TextBox;$last.Dock='Fill';$last.RightToLeft='No';$last.Font=$value.Font;$last.Enabled=$false;$script:rw.last=$last;$t.Controls.Add((Label 'تا IP (شامل انتها)'),0,3);$t.Controls.Add($last,1,3)
 $port=New-Object Windows.Forms.NumericUpDown;$port.Minimum=1;$port.Maximum=65535;$port.Value=80;$port.Dock='Left';$port.Width=120;$script:rw.port=$port;$t.Controls.Add((Label 'پورت مقصد'),0,4);$t.Controls.Add($port,1,4)
 $proto=New-Object Windows.Forms.ComboBox;$proto.DropDownStyle='DropDownList';[void]$proto.Items.AddRange(@('TCP','UDP'));$proto.SelectedIndex=0;$proto.Dock='Left';$proto.Width=120;$script:rw.proto=$proto;$t.Controls.Add((Label 'پروتکل'),0,5);$t.Controls.Add($proto,1,5)
 $output=New-Object Windows.Forms.TextBox;$output.Multiline=$true;$output.ReadOnly=$true;$output.ScrollBars='Both';$output.WordWrap=$false;$output.Dock='Fill';$output.RightToLeft='No';$output.Font=New-Object Drawing.Font('Consolas',10);$output.BackColor=[Drawing.Color]::FromArgb(249,248,247);$script:rw.output=$output;$t.Controls.Add($output,0,6);$t.SetColumnSpan($output,2)
 $warning=Label 'افزودن فقط جدول را تغییر می‌دهد؛ انسداد نیازمند «اعمال تغییرات» و تأیید رنج است.';$warning.ForeColor=[Drawing.Color]::FromArgb(145,75,20);$t.Controls.Add($warning,0,7);$t.SetColumnSpan($warning,2)
 $buttons=Flow;$buttons.WrapContents=$false;$preview=Button 'پیش‌نمایش رنج';$add=Button 'افزودن به لیست';$add.Enabled=$false;$cancel=Button 'انصراف';$cancel.DialogResult='Cancel';$script:rw.add=$add;$buttons.Controls.AddRange(@($add,$preview,$cancel));$t.Controls.Add($buttons,0,8);$t.SetColumnSpan($buttons,2);$d.CancelButton=$cancel;$d.AcceptButton=$preview
 $mode.Add_SelectedIndexChanged({
  $index=$script:rw.mode.SelectedIndex;$script:rw.last.Enabled=($index -eq 1)
  if($index -eq 0){$script:rw.firstLabel.Text='الگو / پیشوند';$script:rw.hint.Text='مثال: 2.*.*.* یا 2.19 یا 2.19.198.*'}elseif($index -eq 1){$script:rw.firstLabel.Text='از IP';$script:rw.hint.Text='مثال: از 2.19.198.10 تا 2.19.198.20'}else{$script:rw.firstLabel.Text='IP / CIDR';$script:rw.hint.Text='مثال: 2.19.198.0/24؛ مرز واقعی در پیش‌نمایش نمایش داده می‌شود'}
  Invalidate-RangePreview
 })
 $value.Add_TextChanged({Invalidate-RangePreview});$last.Add_TextChanged({Invalidate-RangePreview});$port.Add_ValueChanged({Invalidate-RangePreview});$proto.Add_SelectedIndexChanged({Invalidate-RangePreview})
 $preview.Add_Click({
  $w=$script:rw;$w.add.Enabled=$false;$w.preview=$null
  try{
   $w.preview=Invoke-LocalRangePreview @{mode=@('pattern','between','cidr')[$w.mode.SelectedIndex];value=$w.value.Text;last=$w.last.Text;port=[int]$w.port.Value;protocol=[string]$w.proto.SelectedItem}
   $p=$w.preview;$w.output.Text='First IP: '+$p.first_ip+[Environment]::NewLine+'Last IP:  '+$p.last_ip+[Environment]::NewLine+'IP count: '+$p.address_count+' | Rules: '+$p.rule_count+[Environment]::NewLine+[Environment]::NewLine+$p.text
   $w.add.Enabled=$true
  }catch{
   $code=[string]$_.Exception.Message
   $w.output.Text=if($code -match 'public_without_special'){'بازه باید کاملاً عمومی باشد؛ شامل IP خصوصی یا فضای ویژه است.'}elseif($code -match 'order_or_family'){'ترتیب ابتدا و انتها یا نسخهٔ IP معتبر نیست.'}elseif($code -match 'trailing|pattern'){'الگوی معتبر: 2.*.*.* یا 2.19 یا 2.19.198.*؛ بخش متغیر باید در انتها باشد.'}elseif($code -match 'too_many'){'این بازه به بیش از ۱۰۰ قانون نیاز دارد؛ بازه را کوچک‌تر کن.'}else{'اطلاعات رنج معتبر نیست یا پیش‌نمایش انجام نشد؛ ورودی‌ها را بررسی کن.'}
  }
 })
 $add.Add_Click({if($script:rw.preview){$script:rw.dialog.DialogResult='OK';$script:rw.dialog.Close()}})
 Invalidate-RangePreview
 $chosen=$null
 try{if($d.ShowDialog($form) -eq 'OK'){$chosen=$script:rw.preview}}finally{$d.Dispose();$script:rw=$null}
 return $chosen
}
