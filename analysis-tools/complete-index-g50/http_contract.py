"""Exact-length metadata-only GET; reject unexpected headers before body reads."""
import re,urllib.request
class Rejected(ValueError):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None
def request(e):
 return urllib.request.Request(e['url'],method='GET',headers={'User-Agent':'BattleNetFixedFullIndexReview/0.1','Accept':'application/octet-stream','Accept-Encoding':'identity','Connection':'close'})
def read_response(r,expected):
 if r.code!=200:raise Rejected('http_status_'+str(r.code))
 def one(name,required=False):
  vals=r.headers.get_all(name,[])
  if len(vals)>1 or required and len(vals)!=1:raise Rejected('response_header_cardinality')
  return vals[0] if vals else None
 length=one('Content-Length',True);ce=one('Content-Encoding');te=one('Transfer-Encoding');cr=one('Content-Range')
 if ce is not None and ce.lower()!='identity' or te is not None or cr is not None:raise Rejected('response_encoding_transfer_or_range')
 if not re.fullmatch('[0-9]{1,9}',length) or int(length)!=expected:raise Rejected('response_length')
 b=bytearray()
 while len(b)<=expected:
  c=r.read(min(4096,expected+1-len(b)))
  if not c:break
  b.extend(c)
 if len(b)!=expected:raise Rejected('response_size')
 return bytes(b)
