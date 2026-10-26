"""Narrow native send adapter: no rewriting and no fabricated success count."""
from pre_send_gate import MAX_REQUEST

def admit_exact(policy,data):
    if type(data) is not bytes or not 0<len(data)<=MAX_REQUEST:
        return {'allow':False,'reason':'native_input_bound'}
    try:
        d=policy.evaluate(data)
        if not d.allowed:return {'allow':False,'reason':d.reason}
        if d.wire!=data:return {'allow':False,'reason':'requires_canonical_input'}
        return {'allow':True,'reason':'exact_canonical_public_input'}
    except Exception:
        return {'allow':False,'reason':'native_validation_failure'}
