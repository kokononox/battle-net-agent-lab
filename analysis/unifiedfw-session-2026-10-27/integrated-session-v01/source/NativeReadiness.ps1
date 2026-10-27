# Central refusal list. No public native Apply/Set-NetFirewallRule entrypoint exists.
# A user file, checksum, local-name match or test assertion MUST NOT flip these.
function Get-UfwIntegratedNativeReadiness {
 return [pscustomobject][ordered]@{
  private_snapshot_readback='observed_one_Windows_storage_run'
  live_semantic_local_effective_match='two_full_pass_reader_implemented_not_run_on_private_Windows_data'
  current_profile_Block='requires_fresh_local_and_effective_read'
  exact_SSTP_transport_review='unresolved_exact_local_binding'
  warm_SSTP_operating_scope='requires_current_connected_SSTP_and_abort_on_disconnect'
  network_independent_recovery='local_and_owned_transport_reconciler_implemented_native_recovery_entrypoint_unbound'
  documented_threat_scope='normal_firewall_not_admin_or_IPC_sandbox_requires_enforcement_check'
  scoped_native_policy_writer='local_and_owned_transport_writers_implemented_live_binding_unqualified'
  scoped_native_restore='local_and_owned_transport_restore_implemented_native_flow_unqualified'
  capture_adapter_binding='implemented_bridge_native_flow_not_qualified'
 }
}
