"""Bounded public metadata snapshot, independent of all observed installer input."""
import sys, json, re, hashlib, urllib.request, urllib.parse
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from public_codecs import decode_blte, parse_download

ROOT = Path(__file__).resolve().parent / 'research-snapshot-output'
ROOT.mkdir(exist_ok=True)
MAX_TOTAL = 6 * 1024 * 1024
HOST = 'us.cdn.blizzard.com'
receipts, paths, configs = [], {}, {}
total = 0

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('redirect_forbidden')

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

def fetch(url, label, cap, expected=None):
    global total
    p = urllib.parse.urlsplit(url)
    if p.scheme != 'https' or p.hostname not in {'us.version.battle.net', HOST} or p.query or p.fragment or p.username or p.port not in (None,443):
        raise ValueError('research_url_rejected')
    if len(receipts) >= 24 or not 0 < cap <= 1048576 or total + cap > MAX_TOTAL:
        raise ValueError('snapshot_budget')
    total += cap  # Reserve before request; no refund or fallback.
    req = urllib.request.Request(url, headers={'User-Agent':'public-download-path-audit/1',
                                               'Accept':'*/*', 'Accept-Encoding':'identity'})
    with opener.open(req, timeout=30) as r:
        if r.status != 200 or r.headers.get('Content-Encoding','identity') != 'identity':
            raise ValueError('response_contract')
        data = r.read(cap + 1)
        if len(data) > cap or (expected is not None and len(data) != expected):
            raise ValueError('response_size')
    (ROOT/(label+'.bin')).write_bytes(data)
    receipts.append({'label':label,'url':url,'bytes':len(data),
                     'sha256':hashlib.sha256(data).hexdigest(),'status':200})
    return data

def table(data):
    lines = [x for x in data.decode('utf-8-sig').splitlines() if x and not x.startswith('#')]
    header = [x.split('!')[0] for x in lines[0].split('|')]
    result = []
    for line in lines[1:]:
        vals = line.split('|')
        if len(vals) != len(header):
            raise ValueError('table_shape')
        result.append(dict(zip(header, vals)))
    return result

def key(v):
    if not re.fullmatch('[a-f0-9]{32}',v):
        raise ValueError('key_shape')
    return v

def address(prefix, k, suffix=''):
    key(k)
    if not re.fullmatch(r'tpr/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*',prefix):
        raise ValueError('path_prefix')
    return '/'+prefix+'/'+k[:2]+'/'+k[2:4]+'/'+k+suffix

def add(path, kind, product, source, size=None):
    # References originate only in fetched public metadata, never installer paths.
    row={'kind':kind,'product':product,'source_label':source}
    if size is not None:
        row['public_encoded_bytes']=size
    paths.setdefault(path,[]).append(row)

for product in ('agent','bna'):
    versions=table(fetch('https://us.version.battle.net/v2/products/'+product+'/versions',
                         product+'-versions',131072))
    cdns=table(fetch('https://us.version.battle.net/v2/products/'+product+'/cdns',
                    product+'-cdns',131072))
    us=[x for x in cdns if x['Name']=='us']
    if len(us)!=1:
        raise ValueError('cdn_us_ambiguous')
    cdn=us[0]
    if not any(urllib.parse.urlsplit(x).scheme=='https' and
               urllib.parse.urlsplit(x).hostname==HOST and
               urllib.parse.urlsplit(x).path=='/' for x in cdn['Servers'].split()):
        raise ValueError('server_not_advertised')
    usv=[x for x in versions if x['Region']=='us']
    if len(usv)!=1:
        raise ValueError('version_us_ambiguous')
    v=usv[0]
    for kind,field in [('build','BuildConfig'),('cdn','CDNConfig'),('product','ProductConfig')]:
        k=key(v[field])
        prefix=cdn['ConfigPath'] if kind=='product' else cdn['Path']+'/config'
        path=address(prefix,k)
        label=product+'-'+kind
        b=fetch('https://'+HOST+path,label,131072)
        if hashlib.md5(b).hexdigest()!=k:
            raise ValueError('config_key_mismatch')
        add(path,'public_'+kind+'_config',product,label,len(b))
        if kind=='product':
            configs[label]=json.loads(b)
        else:
            values={}
            for line in b.decode('utf-8').splitlines():
                if not line or line.startswith('#'):
                    continue
                name,value=line.split(' = ',1)
                if name in values:
                    raise ValueError('duplicate_config_key')
                values[name]=value
            configs[label]=values
    build,cc=configs[product+'-build'],configs[product+'-cdn']
    # File/index archive references are public object identities. Existence,
    # archive size and Range validity are NOT inferred from hash-looking names.
    for field in ('archives','patch-archives'):
        for k in cc.get(field,'').split():
            prefix=cdn['Path']+('/patch' if field=='patch-archives' else '/data')
            add(address(prefix,k),'public_archive_key',product,product+'-cdn')
            add(address(prefix,k,'.index'),'public_archive_index_key',product,product+'-cdn')
    for field in ('file-index','patch-file-index','archive-group','patch-archive-group'):
        for k in cc.get(field,'').split():
            prefix=cdn['Path']+('/patch' if field.startswith('patch-') else '/data')
            add(address(prefix,k,'.index'),'public_'+field.replace('-','_'),product,product+'-cdn')
    for field in ('encoding','install','download','size','patch-index','root','patch'):
        ks=build.get(field,'').split()
        if len(ks)!=2 or not all(re.fullmatch('[a-f0-9]{32}',x) for x in ks):
            continue
        sizes=build.get(field+'-size','').split()
        encoded=int(sizes[1]) if len(sizes)==2 and all(x.isdigit() for x in sizes) else None
        add(address(cdn['Path']+'/data',ks[1]),'public_'+field+'_manifest_key',product,product+'-build',encoded)
    # Small DL metadata only, not installer payload or archive bodies.
    if 'download' in build and 'download-size' in build:
        ks=build['download'].split();sizes=list(map(int,build['download-size'].split()))
        if len(ks)!=2 or len(sizes)!=2 or not all(0<x<=1048576 for x in sizes):
            raise ValueError('download_manifest_bounds')
        path=address(cdn['Path']+'/data',ks[1])
        blob=fetch('https://'+HOST+path,product+'-download-manifest',sizes[1],sizes[1])
        decoded=decode_blte(blob,sizes[0],ks[1])
        if hashlib.md5(decoded).hexdigest()!=ks[0]:
            raise ValueError('download_CKey')
        dl=parse_download(decoded)
        for row in dl['entries']:
            add(address(cdn['Path']+'/data',row['ekey']),'public_download_manifest_entry',
                product,product+'-download-manifest',row['encoded_bytes'])

catalog={'schema':'independent-public-download-paths-g69-1','reference_hosts':[HOST],
         'prepared_before_installer_observation':True,'installer_input_used':False,
         'paths':paths,'receipts':receipts,'runtime_permission':False,
         'archive_ranges_validated':False,'publisher_signature_proven':False}
(ROOT/'reference.json').write_text(json.dumps(catalog,indent=2))
(ROOT/'configs.json').write_text(json.dumps(configs,indent=2))
print(json.dumps({'requests':len(receipts),'reference_paths':len(paths),
                  'body_bytes':sum(x['bytes'] for x in receipts),
                  'kinds':sorted({x['kind'] for rs in paths.values() for x in rs})}))