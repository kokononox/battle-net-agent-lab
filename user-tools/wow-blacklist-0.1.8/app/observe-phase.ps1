# The user chooses the stage. This is not game-state detection or packet inspection.
$script:phaseTransitions=@();$script:phaseReadErrors=0;$script:phaseLastStamp=[DateTime]::MinValue;$script:phaseInputValid=$false
function Phase-UtcText($value){if($value -is [DateTimeOffset]){return $value.UtcDateTime.ToString('o')};if($value -is [DateTime]){return $value.ToUniversalTime().ToString('o')};return [string]$value}
function Read-StageJournal {
 if(!$j.phase_path -or !(Test-Path -LiteralPath $j.phase_path)){$script:phaseInputValid=$false;return}
 try{
  $info=Get-Item -LiteralPath $j.phase_path;if($info.Length -gt 262144){throw 'phase_journal_too_large'}
  if($info.LastWriteTimeUtc -eq $script:phaseLastStamp){return}
  $data=[IO.File]::ReadAllText($j.phase_path)|ConvertFrom-Json
  if($data.schema -ne 'wow-stage-journal-1' -or $data.capture_id -cne $j.capture_id -or $null -eq $data.transitions){throw 'invalid_phase_journal'}
  $entries=@($data.transitions);if($entries.Count -gt 500 -or $entries.Count -lt $script:phaseTransitions.Count){throw 'phase_journal_not_append_only'}
  $previous=[DateTimeOffset]::MinValue;$index=0;$clean=@()
  foreach($entry in $entries){
   $index++;$when=[DateTimeOffset]::MinValue;$text=Phase-UtcText $entry.selected_utc
   if($entry.sequence -ne $index -or $entry.stage -notin @('unknown','launch','login','dashboard','in_game') -or $text -notmatch '(Z|[+-]\d\d:\d\d)$' -or ![DateTimeOffset]::TryParse($text,[ref]$when) -or $when -lt $previous -or $when.UtcDateTime -lt $start.AddHours(-1) -or $when.UtcDateTime -gt [DateTime]::UtcNow){throw 'invalid_phase_transition'}
   $text=$when.UtcDateTime.ToString('o')
   if($index -le $script:phaseTransitions.Count){$old=$script:phaseTransitions[$index-1];if($old.stage -ne $entry.stage -or $old.selected_utc -cne $text){throw 'phase_journal_rewritten'}}
   $clean+=([pscustomobject]@{sequence=$index;stage=[string]$entry.stage;selected_utc=$text});$previous=$when
  }
  $script:phaseTransitions=$clean;$script:phaseLastStamp=$info.LastWriteTimeUtc;$script:phaseInputValid=$true
 }catch{$script:phaseReadErrors++;$script:phaseInputValid=$false}
}
function Stage-AtSample([DateTime]$when){
 if(!$script:phaseInputValid){return 'unknown'}
 $code='unknown'
 foreach($entry in $script:phaseTransitions){if(([DateTimeOffset]::Parse([string]$entry.selected_utc)).UtcDateTime -gt $when){break};$code=[string]$entry.stage}
 return $code
}
function Add-PhaseSample($row,[DateTime]$when){
 $code=Stage-AtSample $when;$text=$when.ToString('o')
 if(!$row.phase_hits.ContainsKey($code)){$row.phase_hits[$code]=@{samples=0;first_seen_utc=$text;last_seen_utc=$text}}
 $hit=$row.phase_hits[$code];$hit.samples++;$hit.last_seen_utc=$text
}
function Stage-Recording {return @{schema='wow-stage-recording-1';transitions=@($script:phaseTransitions);read_errors=$script:phaseReadErrors;truncated=$false;source='user_selected_global_stage_not_game_detection'}}
