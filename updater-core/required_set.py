"""Pure candidate selection, NOT qualified vendor policy or an installer.
Explicit DNF: AND within a clause, OR across clauses. Optional missing tags
are logged, never silently converted into mandatory tags. No version constants.
Real installation expressions require independent policy qualification before apply.
"""
import hashlib,json,re,unicodedata
from dataclasses import dataclass
from release_core import need

TOKEN=re.compile(r'[A-Za-z0-9_-]{1,64}\??\Z')

@dataclass(frozen=True)
class Term:
 name:str
 optional:bool=False


def parse_expression(text):
 need(type(text)is str and 0<len(text)<=4096 and all(c==' ' or 33<=ord(c)<127 for c in text),'selection_expression_bounds')
 parts=text.split(':');need(0<len(parts)<=16,'selection_clause_limit');clauses=[]
 for part in parts:
  names=part.split();need(0<len(names)<=32,'selection_term_limit');terms=[];seen=set()
  for token in names:
   need(TOKEN.fullmatch(token)is not None,'selection_token_syntax');optional=token.endswith('?');name=token[:-1]if optional else token
   need(name not in seen,'selection_duplicate_term');seen.add(name);terms.append(Term(name,optional))
  clauses.append(tuple(terms))
 need(len(set(clauses))==len(clauses),'selection_duplicate_clause');return tuple(clauses)


def select_bitmap(tags,count,expression):
 need(type(count)is int and 0<count<=20000000,'selection_record_limit');need(type(tags)in (list,tuple) and 0<len(tags)<=256,'selection_tag_limit');clauses=parse_expression(expression);width=(count+7)//8;table={}
 for row in tags:
  need(type(row)in (tuple,list) and len(row)==4,'selection_tag_shape');ordinal,name,kind,bits=row
  need(type(ordinal)is int and ordinal==len(table) and type(name)is str and TOKEN.fullmatch(name)is not None and not name.endswith('?') and name not in table and type(kind)is int and 0<=kind<=65535 and type(bits)is bytes and len(bits)==width,'selection_tag_invalid');table[name]=(kind,bits)
 full=((1<<count)-1)<<(width*8-count);result=0;audits=[]
 for clause in clauses:
  mask=full;missing=[];used=[]
  for term in clause:
   if term.name not in table:
    need(term.optional,'selection_required_tag_missing:'+term.name);missing.append(term.name);continue
   used.append(term.name);mask&=int.from_bytes(table[term.name][1],'big')
  # Unknown optional-only expressions must NOT accidentally select everything.
  need(bool(used),'selection_unconstrained_clause');mask&=full;result|=mask
  audits.append({'used_tags':used,'optional_tags_absent':missing,'selected_records':mask.bit_count()})
 raw=result.to_bytes(width,'big')
 return raw,{'format':'candidate-tag-selection-1','expression':expression,'manifest_records':count,'selected_records':result.bit_count(),'bitmap_sha256':hashlib.sha256(raw).hexdigest(),'clauses':audits,'bit_order':'MSB-first','semantics':'candidate OR of AND clauses; optional absent ignored with audit','vendor_policy_qualified':False,'required_set_selected':False,'installation_ready':False,'apply_authorized':False}


def selected_indices(bits,count):
 need(type(count)is int and count>0 and type(bits)is bytes and len(bits)==(count+7)//8,'selection_bitmap_geometry')
 for i in range(count):
  if bits[i//8]&(0x80>>(i%8)):yield i


def windows_relative_path(label):
 """Strict candidate path only; never opens/resolves labels on host filesystem."""
 need(type(label)is str and 0<len(label)<=1024 and not any(unicodedata.category(c).startswith('C')for c in label),'install_path_text')
 need(unicodedata.normalize('NFC',label)==label,'install_path_noncanonical_unicode')
 value=label.replace('\\','/');need(not value.startswith('/') and not any(c in value for c in ':<>"|?*'),'install_path_absolute_or_reserved')
 parts=value.split('/');need(all(p and p not in ('.','..') and p[-1]not in ' .' and len(p.encode('utf-16-le'))//2<=255 for p in parts),'install_path_component')
 for part in parts:
  stem=part.split('.')[0].rstrip(' .').upper();need(re.fullmatch(r'CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³]',stem)is None,'install_path_reserved_device')
 return '/'.join(parts)


def install_candidates(entries,bits):
 need(type(entries)in (list,tuple) and 0<len(entries)<=1000000,'install_candidate_count');indices=set(selected_indices(bits,len(entries)));out=[];seen={}
 for ordinal,row in enumerate(entries):
  need(type(row)in (list,tuple) and len(row)==4 and type(row[0])is int and row[0]==ordinal,'install_candidate_order')
  if ordinal not in indices:continue
  _,label,ckey,size=row;need(type(ckey)is bytes and len(ckey)==16 and any(ckey) and type(size)is int and size>=0,'install_candidate_identity');path=windows_relative_path(label);fold=path.casefold()
  need(fold not in seen,'install_path_case_collision');seen[fold]=(ckey,size);out.append({'record_index':ordinal,'relative_path':path,'ckey':ckey.hex(),'decoded_size':size})
 # A file may not occupy a directory prefix of another candidate, regardless of case.
 names=set(seen)
 for folded in names:
  parts=folded.split('/')
  need(not any('/'.join(parts[:i])in names for i in range(1,len(parts))),'install_path_file_directory_collision')
 return out


def download_candidate_summary(records,bits,count):
 selected=set(selected_indices(bits,count));seen=set();total=0;chosen=0;priorities={}
 for ordinal,row in enumerate(records):
  need(type(row)in (tuple,list) and len(row)==4 and type(row[0])is int and row[0]==ordinal and ordinal<count,'download_candidate_order')
  _,key,size,priority=row
  need(type(key)is bytes and len(key)==16 and any(key) and type(size)is int and size>0 and type(priority)is int and 0<=priority<=255,'download_candidate_record')
  if ordinal in selected:
   need(key not in seen,'download_candidate_duplicate_ekey');seen.add(key);total+=size;chosen+=1;priorities[str(priority)]=priorities.get(str(priority),0)+1
 need(ordinal+1==count if 'ordinal'in locals() else False,'download_candidate_truncated')
 return {'selected_records':chosen,'unique_encoded_object_bytes_if_all_selected_candidates_missing':total,'priority_counts':priorities,'required_network_download_bytes':None,'reuse_proven':False,'vendor_policy_qualified':False,'installation_ready':False,'apply_authorized':False}
