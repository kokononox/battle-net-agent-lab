"""Content/signature/location/owned-parent policy for one reviewed Blizzard helper.
Same-version-directory is diagnostic, NOT proof of parent trust: bootstrap updaters
can own an installed helper in a different directory. No unpinned parent is allowed.
"""
from pathlib import Path
HASH='a3a444e6bd163732a648967c01a5fd509f7f33d6963b381c19bdffb604138651'
PARENTS={'b422e8d4f0fe0cbcb2d106b455aa44d78eb3a4e173340f05e6cadac5091571b5','7d20ba6ef1d34a3cedbd7d3fd7c14228f173668a9a1e338351d529048de45079'}
SETUP='f4643a2086c0cecb1ab68cc601bf38c1a0a6f7ef5914ad03375cc9449385bec6'
DIAGNOSTIC={'same_version_directory','parent_creation_matches','parent_path_matches','parent_live_image_pinned'}
CRITICAL={'basename_pinned','content_pinned','parent_process_pinned','live_parent_identity_matches','signature_trusted_blizzard','helper_under_agent_root','path_not_reparse'}
def checks(path,parent_path,parent_row,digest,signature,env,parent_identity_matches,is_reparse):
    out=dict(basename_pinned=path.name.lower()=='agenthelper.exe',content_pinned=digest==HASH,
        parent_process_pinned=bool(parent_row.get('instrumented_before_resume') is True and ((parent_row.get('process_name')=='agent.exe' and parent_row.get('sha256') in PARENTS) or (parent_row.get('process_name')=='battle.net-setup.exe' and parent_row.get('sha256')==SETUP))),
        live_parent_identity_matches=parent_identity_matches is True,
        signature_trusted_blizzard=all(signature.get(k) is True for k in ('authenticode_valid','expected_blizzard_publisher','accepted_for_execution')),
        helper_under_agent_root=False,path_not_reparse=False,same_version_directory=False)
    env={k.upper():v for k,v in env.items()}
    if env.get('PROGRAMDATA') and path.is_absolute() and parent_path.is_absolute():
        root=Path(env['PROGRAMDATA'])/'Battle.net'/'Agent'
        out['same_version_directory']=path.parent.resolve()==parent_path.parent.resolve()
        out['helper_under_agent_root']=path.resolve().is_relative_to(root.resolve())
        if out['helper_under_agent_root']:
            cur=path;ok=True
            while cur!=root:
                if is_reparse(cur) or cur.parent==cur:ok=False;break
                cur=cur.parent
            out['path_not_reparse']=bool(ok and not is_reparse(root))
    return out

def allowed(*args,**kwargs):return all(checks(*args,**kwargs)[k] for k in CRITICAL)

def decision(*args,**kwargs):
    extra=kwargs.pop('identity_diagnostics',None)
    c=checks(*args,**kwargs)
    c.update(extra if extra is not None else dict(parent_creation_matches=c['live_parent_identity_matches'],parent_path_matches=c['live_parent_identity_matches'],parent_live_image_pinned=c['live_parent_identity_matches']))
    return dict(checks=c,approved=all(c[k] for k in CRITICAL))

def validate_decision(d):
    if type(d) is not dict or set(d)!={'checks','approved'} or type(d['checks']) is not dict or set(d['checks'])!=CRITICAL|DIAGNOSTIC:raise ValueError('helper_decision')
    if type(d['approved']) is not bool or any(type(v) is not bool for v in d['checks'].values()):raise ValueError('helper_decision_boolean')
    if d['checks']['live_parent_identity_matches'] and not (d['checks']['parent_creation_matches'] and d['checks']['parent_live_image_pinned']):raise ValueError('parent_identity_gate')
    if d['approved']!=all(d['checks'][k] for k in CRITICAL):raise ValueError('helper_decision_gate')
    return d
