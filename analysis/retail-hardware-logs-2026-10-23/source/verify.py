"""Independent inventory/hash and selected log/format verification."""
from pathlib import Path
import os,zipfile,json,hashlib,re,struct
D=Path(__file__).resolve().parents[1];report=json.loads((D/'reports/inventory.json').read_text());anchors=json.loads((D/'reports/anchors.json').read_text());Z=Path(os.environ.get('ARCHIVE','_retail_a.zip'))
def h(b):return hashlib.sha256(b).hexdigest()
assert h(Z.read_bytes())==report['archive_sha256'];total=0
with zipfile.ZipFile(Z) as z:
 ms=z.infolist();assert len(ms)==report['member_count']==len(report['members'])
 for m,row in zip(ms,report['members']):
  b=z.read(m);assert h(m.filename.encode())==row['path_sha256'] and h(b)==row['sha256'] and len(b)==row['size_bytes'];total+=len(b)
 assert total==report['uncompressed_bytes_read']
 gx=z.read('Logs/gx.log').decode('utf-8-sig').splitlines();cpu=z.read('Logs/cpu.log').decode('utf-8-sig').splitlines()
 assert '12.1.5.70448' in gx[2]
 assert re.search(r'Motherboard: ".+" by ".+" \(BIOS:.+ version:.+ date:.+\)',gx[9])
 assert not re.search(r'serial|uuid',gx[9],re.I)
 assert all(k in cpu[i] for i,k in enumerate(['vendor:','branding:','features:','sockets:','cores:','threads:']))
 assert not any(re.search(r'(?<!\d)3724(?!\d)',z.read(n).decode('utf-8-sig')) for n in ['Logs/Connection.log','Logs/WowConnection.log'])
 assert not any(m.filename.lower().endswith(('.dmp','.etl','.pdb','.pcap','.pcapng','.exe')) for m in ms)
b=(Path(os.environ.get('INPUT_DIR','/data/wlab-inputs'))/'Wow.exe').read_bytes();assert h(b)==anchors['sha256'];pe=struct.unpack_from('<I',b,0x3c)[0];count=struct.unpack_from('<H',b,pe+6)[0];tab=pe+24+struct.unpack_from('<H',b,pe+20)[0]
for a in anchors['anchors']:
 o=a['file_offset'];raw=a['format_string'].encode()+b'\0';assert b[o:o+len(raw)]==raw and h(raw)==a['sha256']
 sections=[struct.unpack_from('<IIII',b,tab+40*i+8) for i in range(count)];assert any(ro<=o<ro+rs and va+o-ro==a['rva'] for vs,va,rs,ro in sections)
assert any(a['format_string']=='Motherboard: "%s" by "%s" (BIOS:%s version:%s date:%s)' for a in anchors['anchors'])
result={'archive_all_member_hashes_rechecked':True,'archive_uncompressed_bytes':total,'build_cpu_and_bios_log_lines_rechecked':True,'port_3724_literal_absent_in_two_connection_logs':True,'format_strings_file_offsets_rvas_hashes_rechecked':True,'limits':'Does not independently reimplement the Capstone/vectorized RIP-reference search or infer runtime collection APIs, message population, serialization, or sending. Local log presence does not imply networking.'}
(D/'reports/verification.json').write_text(json.dumps(result,indent=2)+'\n');print('Inventory, log fields, and seven binary string anchors independently checked.')
