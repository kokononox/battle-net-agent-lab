"""Read-only locating proof for paired V7 references, NOT a native-header writer.
A zero 30-byte prefix is observed data, not an Agent-shaped header or damage.
"""
import hashlib
from release_core import need,sha
from local_candidates import ObjectSpec,LocalRef,classify
from local_blte import verify_blte

def verify_paired_zero_prefix(index_raw,index_sha256,prefix_ref,direct_ref,archive_bytes,raw,spec):
 sha(index_sha256);need(type(index_raw)is bytes and len(index_raw)<=4*1024**2 and hashlib.sha256(index_raw).hexdigest()==index_sha256,'paired_index_identity');need(type(spec)is ObjectSpec and type(prefix_ref)is LocalRef and type(direct_ref)is LocalRef,'paired_types');need(type(raw)is bytes and len(raw)==spec.encoded_size+30,'paired_span_geometry')
 need(classify(direct_ref,spec,archive_bytes)=='direct_blte_candidate_NOT_proof','paired_direct_candidate');need(prefix_ref.prefix==direct_ref.prefix and prefix_ref.archive_id==direct_ref.archive_id and prefix_ref.offset+30==direct_ref.offset and prefix_ref.span==direct_ref.span+30 and prefix_ref.offset+prefix_ref.span<=archive_bytes,'paired_reference_relation')
 for ref in (prefix_ref,direct_ref):
  at=40+18*ref.ordinal;want=ref.prefix+((ref.archive_id<<30)|ref.offset).to_bytes(5,'big')+ref.span.to_bytes(4,'little');need(index_raw[at:at+18]==want,'paired_index_row')
 need(raw[:30]==bytes(30),'prefix_not_the_observed_zero_profile');proof=verify_blte(raw[30:],spec.public())
 return dict(proof,locator_profile='paired_references_with_observed_zero_30byte_prefix',zero_prefix_observed=True,native_archive_header_validity_proven=False,general_archive_header_policy_proven=False,fresh_live_state_proven=False,reuse_authorized=False,installation_ready=False,apply_authorized=False)
