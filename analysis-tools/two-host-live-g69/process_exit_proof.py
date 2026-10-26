"""Only a signalled Windows process handle proves termination.

WAIT_TIMEOUT, WAIT_FAILED, errors or any unrecognised value remain fail-closed.
"""
class CandidateAlreadyExited(RuntimeError):
    pass

def termination_proven(wait_result):
    return type(wait_result) is int and wait_result == 0  # WAIT_OBJECT_0