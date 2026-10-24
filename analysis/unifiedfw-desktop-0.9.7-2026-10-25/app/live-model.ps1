# Pure monitor display semantics; presence is a sample, never packet/drop evidence.
Set-StrictMode -Version 2.0
function Set-LivePresence([hashtable]$Flows,[string]$SampleUtc,[bool]$Succeeded){
 foreach($row in $Flows.Values){
  $row['presence']=if(-not $Succeeded){'unknown'}elseif([string]$row.last_seen_utc -ceq $SampleUtc){'present'}else{'absent'}
 }
}
function Get-LivePulse($Before,$After){
 if($After.presence -cne 'present'){return 'none'}
 if($null -eq $Before){return 'discovery'}
 if($Before.presence -ceq 'absent'){return 'reappeared'}
 if([int]$After.samples -gt [int]$Before.samples){return 'sample'}
 return 'none'
}
