"""One approved setup-options Continue, never login or game installation."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

APPROVED_COMMIT='lab: approved identical-image client-install 2026-10-16 3b69a7d2'
STATUSES={'not_requested','pending','no_targets','ambiguous_window','process_mismatch','page_mismatch','forbidden_text','signature_refused','executable_identity_refused','pattern_unavailable','page_changed','page_confirmed','continue_attempted','continued','timeout','helper_failed','output_rejected','native_exception','journal_failed'}
FLAGS=('authorized','helper_started','page_confirmed','continue_attempted','continue_returned','journal_recovered','outcome_uncertain')

def blank(authorized=False):
    return dict(status='pending' if authorized else 'not_requested',**{f:(authorized if f=='authorized' else False) for f in FLAGS})

def authorized_environment(env):
    from language_step import authorized_environment as language_authorized
    return language_authorized(env) and env.get('BNET_LAB_ADVANCE_INSTALL')=='true'

def validate(r):
    if type(r) is not dict or set(r)!={'status',*FLAGS}:raise ValueError('install_schema')
    if type(r['status']) is not str or r['status'] not in STATUSES:raise ValueError('install_status')
    if any(type(r[f]) is not bool for f in FLAGS):raise ValueError('install_flags')
    if not r['authorized'] and r!=blank():raise ValueError('install_unauthorized')
    if r['continue_attempted'] and not r['page_confirmed']:raise ValueError('install_page')
    if r['continue_returned'] and not r['continue_attempted']:raise ValueError('install_returned')
    if any(r[f] for f in ('page_confirmed','continue_attempted','continue_returned')) and not r['helper_started']:raise ValueError('install_helper')
    if r['status']=='continued' and not r['continue_returned']:raise ValueError('install_success')
    return r

def decode(raw):
    if len(raw)>4096:raise ValueError('install_size')
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise ValueError('install_duplicate')
            d[k]=v
        return d
    return validate(json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique))

def setup_pid(processes,original_pid):
    """Only the original setup or a directly observed child; never by name alone."""
    candidates=[p['pid'] for p in processes if p.get('name')=='battle.net-setup.exe'
                and (p.get('pid')==original_pid or p.get('parent_pid')==original_pid)
                and type(p.get('pid')) is int and 0<p['pid']<2**32]
    return candidates[0] if len(candidates)==1 else None

def run(targets,pid,setup,authorized=False):
    result=blank(authorized)
    if not authorized:return result
    scoped=[t for t in targets if type(t) is dict and set(t)=={'pid','hwnd'} and type(t['pid']) is int and t['pid']==pid and type(t['hwnd']) is int and 0<t['hwnd']<2**63]
    if len(scoped)!=1:
        result['status']='no_targets' if not scoped else 'ambiguous_window';return result
    if sys.platform!='win32':result['status']='helper_failed';return result
    from observe_agent import clean_environment
    import ui_accessibility as uia
    env=clean_environment(os.environ)
    # Compile before declaring the action helper started. No action exists in compile mode.
    try:
        if uia._HELPER is None:uia._HELPER=uia.native_helper(env)
    except (uia.ToolchainError,OSError):result['status']='helper_failed';return result
    with tempfile.TemporaryDirectory(prefix='install-once-') as tmp:
        journal=Path(tmp)/'journal.json'
        env['BNET_LAB_INSTALL_CONFIG']=json.dumps(dict(target=scoped[0],setup=str(setup.resolve()),journal=str(journal)))
        result['helper_started']=True
        try:
            response=subprocess.run([str(uia._HELPER[0]),'advance-install'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=False)
            if response.returncode:raise OSError('helper_failed')
            parsed=decode(response.stdout)
            if not parsed['authorized'] or not parsed['helper_started']:raise ValueError('install_helper')
            return parsed
        except subprocess.TimeoutExpired:result['status']='timeout'
        except (ValueError,UnicodeError,TypeError,KeyError):result['status']='output_rejected'
        except OSError:result['status']='helper_failed'
        # A provider might have acted before hanging/failing. Never retry or claim no action.
        result['outcome_uncertain']=True
        try:
            if journal.stat().st_size<=4096:
                saved=decode(journal.read_bytes())
                if saved['authorized'] and saved['helper_started']:
                    saved.update(status=result['status'],journal_recovered=True,outcome_uncertain=True)
                    return validate(saved)
        except (OSError,ValueError,UnicodeError,TypeError,KeyError):pass
        return result
