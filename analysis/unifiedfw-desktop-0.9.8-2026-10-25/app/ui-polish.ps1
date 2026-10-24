# Physical right navigation, independent fixed footer, responsive wrap and scroll-safe dialogs.
# ButtonBase reverses logical text alignment under RightToLeft.Yes; MiddleLeft renders at physical right.
function Get-NavigationMetrics([int]$Width,[int]$FontHeight){
 $side=[Math]::Min(330,[Math]::Max(222,[int]([Math]::Min(280,$Width*0.25))))
 return [pscustomobject]@{sidebar=$side;button=[Math]::Max(160,$side-30);counts=[Math]::Max(26,$FontHeight+8);status=[Math]::Max(42,$FontHeight+12);button_height=[Math]::Max(44,2*$FontHeight+12);alignment='MiddleLeft';rtl='Yes'}
}
function Get-DialogExtent([int]$Width,[int]$Height,[int]$AreaWidth,[int]$AreaHeight){
 if($AreaWidth -lt 80 -or $AreaHeight -lt 80){throw 'invalid_dialog_work_area'}
 return [pscustomobject]@{width=[Math]::Min($Width,$AreaWidth-24);height=[Math]::Min($Height,$AreaHeight-24);minimum_width=[Math]::Min(380,$AreaWidth-32);minimum_height=[Math]::Min(240,$AreaHeight-32)}
}
function Constrain-Dialog($Window){
 $area=[Windows.Forms.Screen]::FromControl($Window).WorkingArea;$e=Get-DialogExtent $Window.Width $Window.Height $area.Width $area.Height
 [int]$mw=$e.minimum_width;[int]$mh=$e.minimum_height;[int]$w=$e.width;[int]$h=$e.height
 $Window.MinimumSize=New-Object Drawing.Size -ArgumentList @($mw,$mh);$Window.Size=New-Object Drawing.Size -ArgumentList @($w,$h)
 [int]$x=[Math]::Max($area.Left,[Math]::Min($Window.Left,$area.Right-$w));[int]$y=[Math]::Max($area.Top,[Math]::Min($Window.Top,$area.Bottom-$h))
 $Window.Location=New-Object Drawing.Point -ArgumentList @($x,$y)
}
function Prepare-Dialog($Window){$Window.AutoScaleMode='Dpi';$Window.Add_Shown({param($sender,$e)Constrain-Dialog $sender})}
# Keep counts/status physically outside the percent-height workspace. A preferred-height table cannot push them below the client area.
$main.Controls.Remove($footer);$main.RowCount=3;while($main.RowStyles.Count -gt 3){$main.RowStyles.RemoveAt($main.RowStyles.Count-1)}
$footer.Dock='Bottom';$footer.AutoSize=$false;$footer.AutoScroll=$false;$footer.Margin=New-Object Windows.Forms.Padding(0);$footer.Padding=New-Object Windows.Forms.Padding(12,4,12,8)
$footer.ColumnCount=2;$footer.ColumnStyles.Clear();[void]$footer.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent,100)));[void]$footer.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::AutoSize)))
$footer.RowCount=2;$footer.RowStyles.Clear();[void]$footer.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,28)));[void]$footer.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,42)))
$footer.SetColumnSpan($counts,2)
foreach($v in @($counts,$status)){$v.AutoSize=$false;$v.AutoEllipsis=$true;$v.Dock='Fill';$v.MinimumSize=New-Object Drawing.Size(0,0);$v.MaximumSize=New-Object Drawing.Size(0,0);$v.Margin=New-Object Windows.Forms.Padding(4,1,4,1);$v.RightToLeft='Yes';$v.TextAlign='MiddleLeft'}
$counts.Add_MouseEnter({$tip.SetToolTip($counts,$counts.Text)})
$fullStatus=Button 'نمایش کامل پیام';$fullStatus.MinimumSize=New-Object Drawing.Size(125,30);$fullStatus.Anchor='Right';$footer.Controls.Add($fullStatus,1,1)
$fullStatus.Add_Click({[void][Windows.Forms.MessageBox]::Show(($counts.Text+"`r`n`r`n"+$status.Text),'پیام کامل وضعیت','OK','Information')})
$form.Controls.Add($footer);$footer.SendToBack()
$main.MinimumSize=New-Object Drawing.Size(0,0);$workspace.MinimumSize=New-Object Drawing.Size(0,0);$main.Padding=New-Object Windows.Forms.Padding(12,12,12,0)
$script:desktopNavigationPanel.RightToLeft='No';$script:desktopNavigationPanel.WrapContents=$false;$script:desktopNavigationPanel.FlowDirection='TopDown';$script:desktopNavigationPanel.AutoScroll=$true
$script:reflowing=$false
function Sync-DesktopLayout {
 if($script:reflowing -or $form.IsDisposed){return};$script:reflowing=$true
 try{
  $v=Get-NavigationMetrics $form.ClientSize.Width $form.Font.Height
  $workspace.ColumnStyles[1].Width=$v.sidebar
  foreach($entry in $script:menuEntries){$entry.button.RightToLeft=$v.rtl;$entry.button.TextAlign=$v.alignment;$entry.button.AutoSize=$false;$entry.button.Width=$v.button;$entry.button.Height=$v.button_height;$entry.button.MinimumSize=New-Object Drawing.Size(160,44)}
  $helpToggle.RightToLeft=$v.rtl;$helpToggle.TextAlign=$v.alignment;$helpToggle.Width=$v.button;$helpToggle.Height=$v.button_height
  [int]$statusHeight=[Math]::Max($v.status,$fullStatus.GetPreferredSize([Drawing.Size]::Empty).Height+$fullStatus.Margin.Vertical)
  $footer.RowStyles[0].Height=$v.counts;$footer.RowStyles[1].Height=$statusHeight;$footer.Height=$v.counts+$statusHeight+$footer.Padding.Vertical
  foreach($label in $script:wrapLabels){
   if($label.IsDisposed -or -not $label.AutoSize -or $null -eq $label.Parent -or $label.Parent.ClientSize.Width -lt 80){continue}
   [int]$available=[Math]::Max(100,$label.Parent.ClientSize.Width-$label.Parent.Padding.Horizontal-$label.Margin.Horizontal-24)
   if($label.MaximumSize.Width -ne $available){$label.MaximumSize=New-Object Drawing.Size -ArgumentList @($available,0)}
  }
 }finally{$script:reflowing=$false}
}
$form.Add_ClientSizeChanged({Sync-DesktopLayout});$form.Add_FontChanged({Sync-DesktopLayout});$form.Add_Shown({Sync-DesktopLayout})
$livePopup.Add_ClientSizeChanged({Sync-DesktopLayout})
# Explicit shortcut from selected IP rows. Does not register an EXE, save or apply anything.
$observedPortRange=Local-Button 'IPهای منتخب ← بازهٔ پورت';Local-Control $monitorPrimary $observedPortRange
$popupPortRange=Button 'IPهای منتخب ← بازهٔ پورت';Add-ToolControl $popupTools $popupPortRange
function Open-ObservedPortRange($Grid){
 if($null -eq $script:state){throw 'تنظیمات هنوز خوانده نشده است.'}
 if($Grid -eq $liveGrid -and $mainLiveTabs.SelectedIndex -ne 0){throw 'در زبانهٔ IP یک یا چند ردیف را با Ctrl انتخاب کنید.'}
 if($Grid -eq $popupGrid -and $popupLiveTabs.SelectedIndex -ne 0){throw 'در زبانهٔ IP یک یا چند ردیف را با Ctrl انتخاب کنید.'}
 $rows=@($Grid.SelectedRows|ForEach-Object{$_.Tag});$seed=Get-ObservedPortRangeSeed $rows @($script:state.config.programs)
 Open-RangeBuilder $seed
}
$observedPortRange.Add_Click({TryOp {Open-ObservedPortRange $liveGrid}});$popupPortRange.Add_Click({TryOp {Open-ObservedPortRange $popupGrid}})
$popupPortRange.AccessibleDescription='Choose IP rows for the same registered EXE; stop recording first; explicit destination port range preview; unsaved draft only'
Sync-DesktopLayout
