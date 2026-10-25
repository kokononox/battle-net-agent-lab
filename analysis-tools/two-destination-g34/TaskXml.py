import re
import xml.etree.ElementTree as E
NS='http://schemas.microsoft.com/windows/2004/02/mit/task';Q='{'+NS+'}'
def parse(text):
 if not isinstance(text,str) or len(text)>65536 or re.search(r'<!\s*(DOCTYPE|ENTITY)',text,re.I):raise ValueError('xml_refused')
 r=E.fromstring(text)
 if r.tag!=Q+'Task' or sum(1 for _ in r.iter())>512:raise ValueError('xml_refused')
 return r
def canon(n):
 # Preserve meaningful leaf text and ALL qualified names, attributes and child ordering.
 text=n.text or ''
 if len(n) and not text.strip():text=''
 tail=n.tail or ''
 if not tail.strip():tail=''
 return (n.tag,tuple(sorted(n.attrib.items())),text,tail,tuple(canon(x) for x in n))
