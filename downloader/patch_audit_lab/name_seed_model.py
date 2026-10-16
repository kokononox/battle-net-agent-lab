"""Bounded ASCII name/path -> reserved archive seed model, not install binding.
Computer name and cwd are explicit inputs, never inferred from this Linux host.
"""
import argparse,hashlib,json,re,subprocess
from pathlib import Path
import patch_audit as a
import source_binding as b
import archive_prefix_poc as prefix

def text(value,limit,code,empty=False):
    a.require(isinstance(value,str) and (empty or len(value)>0) and len(value)<=limit and all(32<=ord(c)<=126 for c in value),code)
    return value

def lexical(raw):
    """Port of 0x86398b within printable ASCII and nontruncating bounds.
    Not ntpath.normpath: preserve case except drive, leading // and final slash;
    match the fragment's unusual dot/parent treatment without root protection.
    """
    text(raw,775,'seed_raw_path_ascii_bounds')
    out='';normal=parents=0;at=0
    while True:
        stop=at
        while stop<len(raw) and raw[stop] not in '/\\':stop+=1
        delim=raw[stop] if stop<len(raw) else ''
        segment=raw[at:stop];parent=False
        if segment=='.':segment=''
        elif segment=='..':
            if normal:
                # Output cursor moves back onto preceding slash or to beginning.
                cursor=len(out)
                while cursor:
                    cursor-=1
                    if out[cursor]=='/':break
                out=out[:cursor];normal-=1;segment=''
            parent=True
        skip=False
        if not segment and out:
            if not(len(out)==1 and out[0]=='/') and delim:skip=True
        if not skip:
            if at==0 and stop==0 and delim:
                out+='/'
            elif at==1 and stop==1 and out=='/' and delim:
                out+='/'
            else:
                if normal or parents:out+='/'
                out+=segment
                if segment:
                    if parent:parents+=1
                    else:normal+=1
        if not delim:break
        at=stop+1
    if len(out)>=3 and out[1:3]==':/' and 'A'<=out[0]<='Z':out=out[0].lower()+out[1:]
    a.require(len(out)<780,'seed_normalized_output_bounds')
    return out

def root(value):
    if re.match(r'^[A-Za-z]:[/\\]',value):return value[0].lower()+':'
    if value.startswith(('\\\\','//')):
        parts=re.split(r'[/\\]',value[2:]);a.require(len(parts)>=2 and parts[0] not in ('','.','..') and parts[1] not in ('','.','..'),'seed_unc_root')
        return '//'+parts[0]+'/'+parts[1]
    return None

def prepare(raw,cwd=None):
    """Caller preparation policy, deliberately narrower than Agent acceptance.
    Drive-absolute or UNC paths; plain relative names need an explicit absolute
    cwd. Reject device/root-relative/drive-relative/ADS/ambiguous roots instead
    of invoking host filesystem or emulating Windows drive state.
    """
    text(raw,775,'seed_path_ascii_bounds')
    a.require(not raw.startswith(('\\\\?\\','\\\\.\\','//?/','//./')),'seed_device_path_out_of_scope')
    initial=root(raw)
    if initial is not None:
        a.require(cwd is None,'seed_cwd_for_absolute_path_ambiguous');joined=raw
    else:
        a.require(not raw.startswith(('/','\\')) and ':' not in raw,'seed_path_form_out_of_scope')
        text(cwd,775,'seed_explicit_cwd_required');initial=root(cwd)
        a.require(initial is not None,'seed_absolute_cwd_required');joined=cwd.rstrip('/\\')+'/'+raw
    a.require(len(joined)<=775,'seed_joined_path_bounds')
    # Reject Windows filename semantics not covered by the pure lexical port.
    tail=joined[2:] if re.match(r'^[A-Za-z]:',joined) else joined
    a.require(not any(c in tail for c in ':*?<>|"'),'seed_windows_special_path_out_of_scope')
    result=lexical(joined)
    a.require(root(result)==initial and not any(v=='..' for v in result.split('/')),'seed_root_escape_or_unresolved_parent')
    return joined,result

def derive(computer,canonical):
    # Successful GetComputerNameW ASCII branch only; no lowercase/strip/NUL.
    text(computer,15,'seed_computer_ascii_bounds')
    a.require('/' not in computer and '\\' not in computer,'seed_computer_separator')
    text(canonical,779,'seed_canonical_ascii_bounds',empty=True)
    return hashlib.md5(computer.encode('ascii')+canonical.encode('ascii')).digest()

def model(computer,raw,cwd=None):
    joined,canonical=prepare(raw,cwd);seed=derive(computer,canonical)
    return {'format':'name-seed-ascii-model-1','canonical_path':canonical,'seed':seed.hex(),'reserved_keys':[k.hex() for k in prefix.keys(seed,0,1024)],'archive':0,'capacity':1024,'explicit_synthetic_inputs':True,'actual_user_installation_binding_proven':False,'windows_agent_process_executed':False,'installation_ready':False}

def oracle(binary,computer,joined):
    text(computer,15,'seed_computer_ascii_bounds');text(joined,775,'seed_raw_path_ascii_bounds')
    p=subprocess.run([str(b.safe(binary,True)),computer,joined],capture_output=True,timeout=5)
    a.require(len(p.stdout)<=1052 and len(p.stderr)<4096 and p.returncode==0,'seed_isolated_oracle_rejected')
    canonical,sep,rest=p.stdout.partition(b'\0');a.require(sep and len(rest)==272,'seed_isolated_oracle_output')
    try:value=canonical.decode('ascii')
    except UnicodeError:raise a.AuditError('seed_oracle_ascii') from None
    return {'canonical_path':value,'seed':rest[:16].hex(),'reserved_keys':[rest[i:i+16].hex() for i in range(16,len(rest),16)],'isolated_agent_pure_fragments_executed':True,'windows_agent_process_executed':False,'windows_apis_executed':False}

def compare(binary,computer,raw,cwd=None):
    joined,_=prepare(raw,cwd);got=model(computer,raw,cwd);native=oracle(binary,computer,joined)
    a.require(all(got[k]==native[k] for k in ('canonical_path','seed','reserved_keys')),'seed_model_fragment_disagreement')
    got['fragment_comparison']={'matched':True,'isolated_agent_pure_fragments_executed':True,'windows_apis_executed':False};return got

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--synthetic-computer',required=True);p.add_argument('--synthetic-path',required=True);p.add_argument('--synthetic-cwd');p.add_argument('--isolated-oracle',type=Path);args=p.parse_args()
    result=compare(args.isolated_oracle,args.synthetic_computer,args.synthetic_path,args.synthetic_cwd) if args.isolated_oracle else model(args.synthetic_computer,args.synthetic_path,args.synthetic_cwd)
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
