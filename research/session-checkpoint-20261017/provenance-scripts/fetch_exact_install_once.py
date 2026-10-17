import sys,json,hashlib,urllib.request,urllib.error,datetime
from pathlib import Path
sys.path.insert(0,'/data/lab')
import patch_audit as a
from refs_source_check import decode_source
out=Path('/data/install-metadata-fetch-1');out.mkdir(exist_ok=False)
url='https://level3.ssl.blizzard.com/tpr/wow/data/25/ed/25ed9bec6e5d43e266d93a8b191b42cc'
r={'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'url':url,'network_attempts':0,'redirects_followed':0,'fallback_attempts':0,'archive_payload_bytes_read':0,'game_or_lab_writes':False,'installation_ready':False,'unknown_is_not_missing_or_corrupt':True,'response_body_bytes_read':0}
try:
    cfg=Path('/data/retail-release-extracted/Portable-Retail-Sample/pinned_metadata/build.config').read_bytes()
    assert hashlib.sha256(cfg).hexdigest()=='f30cdd30bcbb613795557606c0015411640ffa4a2710f7419ea75dae345c964d','config_sha256'
    fields=a.config(cfg,'334a36cf5f3c32a5f7a167405487fa14')
    assert fields['install']==['d7c8cd9845e2b5d39821678f481324da','25ed9bec6e5d43e266d93a8b191b42cc'],'install_identity'
    assert fields['install-size']==['24078','23106'],'install_sizes'
    r['pinned_config_verified']=True
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*args,**kwargs):return None
    opener=urllib.request.build_opener(NoRedirect())
    req=urllib.request.Request(url,headers={'Accept-Encoding':'identity','User-Agent':'Bounded-Install-Metadata-Review/1'})
    r['network_attempts']=1
    with opener.open(req,timeout=30) as response:
        r['http_status']=response.status
        assert response.status==200 and response.geturl()==url,'unexpected_response'
        assert response.headers.get('Content-Range') is None,'partial_response'
        assert response.headers.get('Content-Encoding','identity').lower()=='identity','content_encoding'
        assert response.headers.get('Content-Length')=='23106','content_length'
        raw=response.read(23106);r['response_body_bytes_read']=len(raw)
        assert len(raw)==23106,'short_response'
    decoded,proof=decode_source(raw,'25ed9bec6e5d43e266d93a8b191b42cc',24078)
    assert hashlib.md5(decoded).hexdigest()=='d7c8cd9845e2b5d39821678f481324da','independent_ckey_mismatch'
    r.update(status='verified_exact_install_metadata',encoded_size=len(raw),decoded_size=len(decoded),expected_ckey_verified=True,expected_ekey_verified=True,encoded_sha256=hashlib.sha256(raw).hexdigest(),decoded_sha256=hashlib.sha256(decoded).hexdigest(),raw_header_first_10_bytes_hex=decoded[:10].hex(),install_selection_policy_proven=False)
    (out/'install.blte').write_bytes(raw)
    (out/'install.decoded').write_bytes(decoded)
except urllib.error.HTTPError as e:
    r.update(status='stopped_direct_request_rejected',http_status=e.code,error_type='HTTPError')
    e.close()
except Exception as e:
    r.update(status='stopped_safely',error_type=type(e).__name__)
    if isinstance(e,(AssertionError,a.AuditError)):r['safe_reason']=str(e)
finally:
    (out/'FETCH-RECEIPT.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2))
