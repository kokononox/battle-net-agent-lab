# Central refusal list. No public native Apply/Set-NetFirewallRule entrypoint exists.
# A user file, checksum, local-name match or test assertion MUST NOT flip these.
function Get-UfwIntegratedNativeReadiness {
 return [pscustomobject][ordered]@{
  private_snapshot_readback='observed_one_Windows_storage_run'
  live_semantic_local_effective_match='two_full_pass_reader_implemented_not_run_on_private_Windows_data'
  current_profile_Block='requires_fresh_local_and_effective_read'
  exact_SSTP_transport_review='unresolved_exact_local_binding'
  warm_SSTP_operating_scope='requires_current_connected_SSTP_and_abort_on_disconnect'
  network_independent_recovery='local_intent_reconciler_implemented_native_restore_not_qualified'
  documented_threat_scope='normal_firewall_not_admin_or_IPC_sandbox_requires_enforcement_check'
  scoped_native_policy_writer='private_local_Enabled_writer_implemented_transport_and_live_binding_missing'
  scoped_native_restore='private_local_restore_implemented_owned_transport_and_live_binding_missing'
  capture_adapter_binding='implemented_bridge_native_flow_not_qualified'
 }
}
