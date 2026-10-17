"""INTERNAL subprocess failpoint driver; deterministic fixture capability only."""
import json
import os
from pathlib import Path
import sys
import transaction_fixture as t


def audit(event, args):
    if event.startswith("socket."):
        raise RuntimeError("Network forbidden")


sys.addaudithook(audit)
if __name__ == "__main__":
    mode, root, capability, phase = sys.argv[1:]
    def hook(current):
        if current == phase:
            os._exit(91)
    try:
        if mode == "advance":
            result = t.advance(Path(root), capability, hook=hook)
        elif mode == "rollback":
            result = t.rollback(Path(root), capability, hook=hook)
        elif mode == "reader_experiment":
            for _ in range(40):
                t.advance(Path(root), capability)
                t.rollback(Path(root), capability)
            result = {"state": "reader_experiment_complete", "installation_ready": False}
        else:
            raise t.Stopped("internal_mode_only")
        print(json.dumps(result))
    except (t.Stopped, OSError):
        print(json.dumps({"state": "stopped_safely", "installation_ready": False}))
        sys.exit(2)