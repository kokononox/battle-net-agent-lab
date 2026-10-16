"""Use trusted repository code with an unchanged original portable data folder.
No imports from the fixture folder, no network, no installation writes.
"""
import argparse
import json
from pathlib import Path
from unittest.mock import patch
import portable_run

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture',required=True,type=Path)
    args=parser.parse_args()
    with patch('socket.socket',side_effect=RuntimeError('offline_reproduction_network_forbidden')):
        result=portable_run.run(args.fixture)
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
