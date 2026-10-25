# WinForms-compatible upsert helpers. Existing row objects survive refresh and keep pulse expiry.
function Get-OrAddDisplayRow($Grid,[string]$Key,$Index=$null){
 if($null -ne $Index -and $Index.ContainsKey($Key)){return $Index[$Key]}
 if($null -eq $Index){foreach($row in $Grid.Rows){if($null -ne $row.Tag -and [string]$row.Tag.record_id -ceq $Key){return $row}}}
 $i=$Grid.Rows.Add();$row=$Grid.Rows[$i];$row.Selected=$false;if($null -ne $Index){$Index[$Key]=$row};return $row
}
function Remove-OldDisplayRows($Grid,[hashtable]$Visible){
 for($i=$Grid.Rows.Count-1;$i -ge 0;$i--){$row=$Grid.Rows[$i];if($null -eq $row.Tag -or -not $Visible.ContainsKey([string]$row.Tag.record_id)){$Grid.Rows.RemoveAt($i)}}
}
function Set-ActivityRowStyle($Row,$Base,[string]$Kind,[bool]$Enabled){
 $pulse=$Row.Cells['pulse'].Tag
 if($Enabled -and $Kind -ceq 'none' -and $null -ne $pulse -and [DateTime]::UtcNow -lt $pulse.until){$pulse.base=$Base;$pulse.selection=$Base;return}
 $Row.DefaultCellStyle.BackColor=$Base;$Row.DefaultCellStyle.SelectionBackColor=$Base;$Row.Cells['pulse'].Tag=$null
 Apply-PulseCell $Row $Kind $Enabled
}
