"""Continue an existing official-table observation; at most two small configs."""
import json,datetime
from pathlib import Path
from release_core import TargetSnapshot,need,strict_json
from config_binding import ConfigTransport,config_urls,bind
base=Path(__file__).parent
observation=strict_json((base/'LIVE-RELEASE-OBSERVATION.json').read_bytes());need(observation['source']=='live_official_https_release_tables','live_source_required');target=TargetSnapshot.restore(observation['target']);transport=ConfigTransport(target);a,b=config_urls(target);raw_a=transport.fetch(a);raw_b=transport.fetch(b);report=bind(target,raw_a,raw_b);report.update(config_requests=len(transport.requested),config_bytes=transport.bytes_read,observed_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat());out=base/'LIVE-CONFIG-BINDING.json'
with out.open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
for name,raw in [('observed-build.config',raw_a),('observed-cdn.config',raw_b)]:
 with (base/name).open('xb') as f:f.write(raw)
print(json.dumps({'status':'dynamic_target_configs_and_three_manifest_descriptors_bound','version':target.version,'config_requests':len(transport.requested),'config_bytes':transport.bytes_read,'manifest_blobs_fetched':False,'game_assets_fetched':0,'installation_ready':False}))
