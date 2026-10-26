"""Bounded redacted check annotations: GitHub truncates each message at 4096."""
import json,hashlib
LIMIT=3400

def encoded(obj):return json.dumps(obj,separators=(',',':'),sort_keys=True)
def pack(result):
 rows=result['rows'];columns=sorted(rows[0]) if rows else []
 if any(sorted(r)!=columns for r in rows):raise ValueError('evidence_row_schema')
 chunks=[];current=[]
 def chunk(items,index):return {'kind':'g75_native_rows','run_id':result['run_id'],'source_commit':result['source_commit'],'index':index,'rows':items}
 for row in rows:
  compact=[row[k] for k in columns]
  if len(encoded(chunk(current+[compact],len(chunks))).encode())>LIMIT:
   if not current:raise ValueError('single_evidence_row_too_large')
   chunks.append(chunk(current,len(chunks)));current=[]
  if len(encoded(chunk([compact],len(chunks))).encode())>LIMIT:raise ValueError('single_evidence_row_too_large')
  current.append(compact)
 if current:chunks.append(chunk(current,len(chunks)))
 summary={k:v for k,v in result.items() if k!='rows'}
 summary.update(kind='g75_native_summary',columns=columns,row_count=len(rows),chunk_count=len(chunks),
                rows_sha256=hashlib.sha256(encoded(rows).encode()).hexdigest())
 if len(encoded(summary).encode())>LIMIT or len(chunks)>8:raise ValueError('evidence_publication_bound')
 return summary,chunks

def unpack(summary,chunks):
 if summary['kind']!='g75_native_summary' or len(chunks)!=summary['chunk_count']:raise ValueError('incomplete_evidence')
 rows=[]
 for i,c in enumerate(sorted(chunks,key=lambda x:x['index'])):
  if c['kind']!='g75_native_rows' or c['index']!=i or c['run_id']!=summary['run_id'] or c['source_commit']!=summary['source_commit']:raise ValueError('evidence_identity')
  for values in c['rows']:
   if len(values)!=len(summary['columns']):raise ValueError('evidence_width')
   rows.append(dict(zip(summary['columns'],values)))
 if len(rows)!=summary['row_count'] or hashlib.sha256(encoded(rows).encode()).hexdigest()!=summary['rows_sha256']:raise ValueError('evidence_digest')
 result={k:v for k,v in summary.items() if k not in {'kind','columns','row_count','chunk_count','rows_sha256'}}
 result['rows']=rows;return result
