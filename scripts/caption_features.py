"""Fixed technical vocabulary only; never return raw caption or unknown words."""
import re
WORDS=set('install installation location folder directory destination choose select path change battle.net start launch run startup automatically when windows computer desktop shortcut create account login sign log agreement license terms privacy accept agree continue update updating download downloading error failed retry network required space available disk recommended options additional open application'.split())
KINDS={'Text','CheckBox'}
TOGGLES={'not_applicable','unavailable','on','off','indeterminate'}

def summarize(raw):
    cut=len(raw)>512;raw=raw[:512]
    # Remove variable values before extracting ANY vocabulary words.
    has_path=bool(re.search(r'\b[a-z]:[\\/]|\\\\',raw,re.I))
    text=re.sub(r'\b[a-z]:[\\/][^\r\n]*|\\\\[^\r\n]*',' ',raw,flags=re.I)
    text=re.sub(r'(?:https?|file)://\S+|[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}',' ',text,flags=re.I)
    tokens=[];unknown=False
    for match in re.finditer(r'[a-z]+(?:\.[a-z]+)?',text.lower()):
        word=match.group()
        if word in WORDS:
            if word not in tokens:tokens.append(word)
        else:unknown=True
    return dict(tokens=tokens,has_path=has_path,has_unknown_words=unknown,truncated=cut,toggle_state='not_applicable')

def validate(f,element):
    if f is None:return
    if element['control_type'] not in KINDS or element['offscreen'] or element['password']:raise ValueError('caption_scope')
    if type(f) is not dict or set(f)!={'tokens','has_path','has_unknown_words','truncated','toggle_state'}:raise ValueError('caption_schema')
    if type(f['tokens']) is not list or len(f['tokens'])>len(WORDS) or any(type(t) is not str or t not in WORDS for t in f['tokens']):raise ValueError('caption_words')
    if len(f['tokens'])!=len(set(f['tokens'])):raise ValueError('caption_duplicate')
    if any(type(f[k]) is not bool for k in ('has_path','has_unknown_words','truncated')):raise ValueError('caption_flag')
    if f['toggle_state'] not in TOGGLES:raise ValueError('caption_toggle')
    if element['control_type']=='Text' and f['toggle_state']!='not_applicable':raise ValueError('caption_toggle')
    if element['control_type']=='CheckBox' and f['toggle_state']=='not_applicable':raise ValueError('caption_toggle')
