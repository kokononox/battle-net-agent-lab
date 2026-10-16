"""One approved language-page action, never a general wizard driver."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

APPROVED_COMMIT='lab: approved language-only guard diagnostics 2026-10-16 d91e7a42'
STATUSES={'not_requested','pending','no_targets','ambiguous_window','process_mismatch','window_mismatch','page_not_language','control_ambiguous','pattern_unavailable','selection_failed','selection_attempted','selection_confirmed','continue_attempted','continued','timeout','helper_failed','output_rejected','native_exception','journal_failed'}
STATUSES.update({'control_ambiguous', 'pattern_unavailable', 'forbidden_control', 'page_changed', 'process_mismatch', 'forbidden_text', 'window_mismatch', 'name_too_long', 'selection_failed', 'unsafe_name', 'language_group_missing', 'continue_ambiguous', 'continue_missing', 'journal_failed', 'language_group_ambiguous'})
FLAGS=('authorized','helper_started','selection_attempted','selection_confirmed','continue_attempted','continue_returned','journal_recovered','outcome_uncertain')

def blank(authorized=False):
    return dict(status='pending' if authorized else 'not_requested',selection_already_set=None,**{f:(authorized if f=='authorized' else False) for f in FLAGS})

def authorized_environment(env):
    return (env.get('BNET_LAB_ADVANCE_LANGUAGE')=='true' and env.get('GITHUB_EVENT_NAME')=='push'
            and env.get('GITHUB_RUN_ATTEMPT')=='1')

def validate(r):
    if type(r) is not dict or set(r)!={'status','selection_already_set',*FLAGS}:raise ValueError('language_schema')
    if type(r['status']) is not str or r['status'] not in STATUSES:raise ValueError('language_status')
    if any(type(r[f]) is not bool for f in FLAGS):raise ValueError('language_flags')
    if r['selection_already_set'] is not None and type(r['selection_already_set']) is not bool:raise ValueError('language_selected')
    if not r['authorized'] and r!=blank():raise ValueError('language_unauthorized')
    if r['selection_confirmed'] and not (r['selection_attempted'] or r['selection_already_set'] is True):raise ValueError('language_confirmation')
    if r['continue_attempted'] and not r['selection_confirmed']:raise ValueError('language_continue')
    if r['continue_returned'] and not r['continue_attempted']:raise ValueError('language_returned')
    if any(r[f] for f in ('selection_attempted','selection_confirmed','continue_attempted','continue_returned')) and not r['helper_started']:raise ValueError('language_helper')
    if r['status']=='continued' and not r['continue_returned']:raise ValueError('language_success')
    return r

def decode(raw):
    if len(raw)>4096:raise ValueError('language_size')
    def unique(pairs):
        d={}
        for k,v in pairs:
            if k in d:raise ValueError('language_duplicate')
            d[k]=v
        return d
    return validate(json.loads(raw.decode('utf-8-sig'),object_pairs_hook=unique))

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
    with tempfile.TemporaryDirectory(prefix='language-once-') as tmp:
        journal=Path(tmp)/'journal.json'
        env['BNET_LAB_LANGUAGE_CONFIG']=json.dumps(dict(target=scoped[0],setup=str(setup.resolve()),journal=str(journal)))
        result['helper_started']=True
        try:
            response=subprocess.run([str(uia._HELPER[0]),'advance-language'],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=12,check=False)
            if response.returncode:raise OSError('helper_failed')
            parsed=decode(response.stdout)
            if not parsed['authorized'] or not parsed['helper_started']:raise ValueError('language_helper')
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
