"""One reviewed Blizzard helper, not a generic child or publisher bypass."""
from pathlib import Path
import os
HASH='a3a444e6bd163732a648967c01a5fd509f7f33d6963b381c19bdffb604138651'
PARENTS={'b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5','7d20ba6ef1d34a3cedbd7d3fd7c14228f173668a9a1e338351d529048de45079'}
def allowed(path,parent_path,parent_row,digest,signature,env,parent_identity_matches,is_reparse):
    if path.name.lower()!='agenthelper.exe' or digest!=HASH or parent_identity_matches is not True:return False
    if parent_row.get('process_name')!='agent.exe' or parent_row.get('sha256') not in PARENTS or parent_row.get('instrumented_before_resume') is not True:return False
    if any(signature.get(k) is not True for k in ('authenticode_valid','expected_blizzard_publisher','accepted_for_execution')):return False
    env={k.upper():v for k,v in env.items()}
    if not env.get('PROGRAMDATA'):return False
    root=Path(env['PROGRAMDATA'])/'Battle.net'/'Agent'
    if not path.is_absolute() or not parent_path.is_absolute():return False
    if path.parent.resolve()!=parent_path.parent.resolve() or not path.resolve().is_relative_to(root.resolve()):return False
    # No junction/symlink escape in the version directory or helper itself.
    cur=path
    while cur!=root:
        if is_reparse(cur):return False
        if cur.parent==cur:return False
        cur=cur.parent
    if is_reparse(root):return False
    return True
