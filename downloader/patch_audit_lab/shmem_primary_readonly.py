"""Pinned Agent 9824 primary-payload geometry; copied bytes, never a writer.
Arrays are deliberately labelled A/B: exact allocation semantics are not a full
CASC specification. State 2 is an observed rollback path, not proof of damage.
"""
import struct
import patch_audit as a
SIZE=0x2ab8
CAPACITY=0x442
ARRAY_A=0x20
ARRAY_B=0x156a
WIDTH=5
LIMIT=1<<40

def inspect(raw):
    a.require(isinstance(raw,bytes) and len(raw)==SIZE,'primary_exact_size_required')
    state,count,index,opaque=struct.unpack_from('<4I',raw)
    a.require(state in (0,1,2),'primary_unobserved_state')
    a.require(count<=CAPACITY,'primary_count_exceeds_bounded_capacity')
    # The Agent recovery path uses index without checking it here. Our narrow
    # observer validates it rather than emulating an unchecked memory access.
    pending=state==2
    if pending:
        a.require(index<count,'primary_pending_index_outside_count')
        saved_b,saved_a=struct.unpack_from('<QQ',raw,0x10)
        # Agent's 5-byte writer truncates. We decline non-40-bit saved values;
        # this is an observer policy, not a proven Agent rejection condition.
        a.require(saved_a<LIMIT and saved_b<LIMIT,'primary_saved_value_outside_observer_policy')
    pairs=[(int.from_bytes(raw[ARRAY_A+i*WIDTH:ARRAY_A+(i+1)*WIDTH],'big'),
            int.from_bytes(raw[ARRAY_B+i*WIDTH:ARRAY_B+(i+1)*WIDTH],'big')) for i in range(count)]
    changed=None
    if pending:
        # Compare only in memory. No reconstructed file, raw entries or offsets
        # are returned; original bytes and caller's filesystem remain untouched.
        changed=sum((pairs[index][0]!=saved_a,pairs[index][1]!=saved_b))
    return {'format':'agent-9824-primary-observation-1',
      'status':{0:'reset_or_rebuild_in_progress',1:'state_one_observed_not_health_proof',2:'rollback_pending_do_not_activate'}[state],
      'state':state,'record_count':count,'bounded_capacity':CAPACITY,
      'entry_width':WIDTH,'entry_byte_order':'big','array_a_offset':ARRAY_A,'array_b_offset':ARRAY_B,
      'layout_geometry_decoded':True,'allocation_semantics_complete':False,
      'rollback_pending':pending,'rollback_index_checked':pending,
      'rollback_projection_changed_fields':changed,'rollback_performed':False,
      'opaque_header_word_interpreted':False,'tail_padding_interpreted':False,
      'raw_entries_exported':False,'saved_values_exported':False,
      'rebuild_required_proven':False,'coherent_live_snapshot_proven':False,
      'installation_ready':False,'files_written':0,'network_requests':0}
