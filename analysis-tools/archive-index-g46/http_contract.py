"""Offline-tested response/redirect contract copied from G45, unchanged."""
import urllib.request
class Rejected(ValueError):pass

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**k):return None

def read_response(response,expected):
 status=response.code
 if status!=200:raise Rejected('http_status_'+str(status))
 h=response.headers
 if h.get('Content-Encoding','identity').lower()!='identity' or h.get('Content-Range') is not None:raise Rejected('response_encoding_or_range')
 length=h.get('Content-Length');transfer=h.get('Transfer-Encoding')
 if transfer and (transfer.lower()!='chunked' or length is not None):raise Rejected('response_transfer_ambiguous')
 if length is not None and (not length.isdigit() or int(length)!=expected):raise Rejected('response_length')
 out=bytearray()
 while len(out)<=expected:
  chunk=response.read(min(4096,expected+1-len(out)))
  if not chunk:break
  out.extend(chunk)
 if len(out)!=expected:raise Rejected('response_size')
 return bytes(out)
