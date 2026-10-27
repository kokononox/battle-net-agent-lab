# Bind to the existing REAL runtime coordinator, not a replacement fake collector.
# Dot-source the pinned existing candidate/runtime dependencies in a PRIVATE module first.
function Invoke-UfwUnifiedRuntimeBridge($RuntimeOps,$ReviewBinding,$Guard){
 if($ReviewBinding -isnot [string] -or $ReviewBinding -cnotmatch '^[a-f0-9]{64}$' -or $Guard -isnot [scriptblock]){throw 'ufw_unified_runtime_bridge_binding'}
 if($RuntimeOps -isnot [hashtable] -or -not $RuntimeOps.ContainsKey('FirewallGuard')){throw 'ufw_unified_runtime_adapter_missing'}
 $copy=@{};foreach($key in $RuntimeOps.Keys){$copy[$key]=$RuntimeOps[$key]}
 $original=$copy.FirewallGuard
 # Closure uses ONLY already-bound callbacks. A fresh session guard adds to the
 # existing runtime check; it never replaces/bypasses its conservative firewall gate.
 $copy.FirewallGuard={
  $ok=& $Guard $ReviewBinding
  if($ok -isnot [bool] -or -not $ok){throw 'ufw_unified_policy_guard_refused'}
  return & $original
 }.GetNewClosure()
 return Invoke-UfwRuntimeCallbacks $copy
}
