"""Precondition only; the native exact-page guard remains authoritative."""
def candidate(snapshot):
 u=snapshot.get('UIA',{})
 if u.get('status')!='completed_bounded_read' or u.get('truncated') is not False or u.get('errors')!=0:return False
 rows=u.get('rows',[])
 return (sum(r.get('type')=='Window' and r.get('label')=='battle.net setup' for r in rows)==1
         and sum(r.get('type')=='Button' and r.get('label')=='continue' and r.get('enabled') is True for r in rows)==1
         and any(r.get('type')=='RadioButton' and 'english' in r.get('markers',[]) and r.get('enabled') is True for r in rows))
