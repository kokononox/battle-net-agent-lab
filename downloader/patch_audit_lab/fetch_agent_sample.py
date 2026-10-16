"""Fetch one exact public Agent sample for offline static analysis; never execute it.

Run explicitly with --output NEW_DIRECTORY, outside any game/Lab. No login/API
commands. Re-fetching does not select the currently installed user's Agent.
"""
import argparse
import json
from pathlib import Path
import urllib.request
import patch_audit as a
import source_binding as b
from refs_source_check import decode_source
from agent_static_audit import AGENT_SHA256

URL='https://level3.ssl.blizzard.com/tpr/bnt001/data/be/01/be01238052df6d390b52f6818a2b72f7'
EKEY='be01238052df6d390b52f6818a2b72f7'
CKEY='1c2df2ab827c54b70fb831dec9693067'
SIZE=3611501

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True);args=p.parse_args()
    out=Path(args.output).absolute();b.safe(out.parent)
    b.need(not out.exists() and not out.is_symlink(),'new_output_required')
    request=urllib.request.Request(URL,headers={'Accept-Encoding':'identity','User-Agent':'Agent-Static-Research/1'})
    with urllib.request.build_opener(a.NoRedirect()).open(request,timeout=45) as response:
        a.validate_response(response,URL,SIZE,SIZE);raw=response.read(SIZE+1)
    a.require(len(raw)==SIZE,'agent_encoded_size')
    decoded,proof=decode_source(raw,EKEY,7275216)
    a.require(a.md5(decoded)==CKEY and a.sha256(decoded)==AGENT_SHA256,'agent_content_identity')
    out.mkdir()
    for name,data in [('agent.blte',raw),('Agent.9824.exe',decoded)]:
        with (out/name).open('xb') as f:f.write(data)
    with (out/'sample-receipt.json').open('x') as f:json.dump({'url':URL,'version':'2.41.1.9824','ekey':EKEY,'ckey':CKEY,'sha256':AGENT_SHA256,'bytes':len(decoded),'proof':proof,'executed':False},f,indent=2)
    print('Pinned sample downloaded and verified. Not executed.')

if __name__=='__main__':main()
