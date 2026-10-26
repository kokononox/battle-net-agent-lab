"""Fixed footer Range response contract. Reject whole-index replies before reads."""
import re,urllib.request
class Rejected(ValueError):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
def request(e):
 return urllib.request.Request(e['url'],method='GET',headers={'User-Agent':'BattleNetFixedIndexFooterReview/0.1','Accept':'application/octet-stream','Accept-Encoding':'identity','Connection':'close','Range':e['range_header']})
def read_response(r,e):
 if r.code!=206:raise Rejected('http_status_'+str(r.code))
 def one(name,required=False):
  values=r.headers.get_all(name,[])
  if len(values)>1 or required and len(values)!=1:raise Rejected('response_header_cardinality')
  return values[0] if values else None
 length=one('Content-Length',True);cr=one('Content-Range',True);ce=one('Content-Encoding');te=one('Transfer-Encoding')
 if te is not None or ce is not None and ce.lower()!='identity':raise Rejected('response_encoding_or_transfer')
 if not re.fullmatch('[0-9]{1,6}',length) or int(length)!=28:raise Rejected('response_length')
 m=re.fullmatch(r'bytes ([0-9]{1,10})-([0-9]{1,10})/([0-9]{1,10})',cr)
 if not m or tuple(map(int,m.groups()))!=(e['range_start'],e['range_end'],e['expected_content_range_total']):raise Rejected('content_range_mismatch')
 b=bytearray()
 while len(b)<=28:
  c=r.read(29-len(b))
  if not c:break
  b.extend(c)
 if len(b)!=28:raise Rejected('response_size')
 return bytes(b)
