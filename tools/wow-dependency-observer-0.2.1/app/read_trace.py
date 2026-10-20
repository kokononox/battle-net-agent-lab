"""Isolated, time-limited analysis entry point. Writes only minimized JSON."""
import json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from pml_read import analyze
if __name__=='__main__':
    try: result=analyze(sys.argv[1],sys.argv[2]); code=0
    except Exception as exc:
        s=str(exc)
        result={'status':'analysis_inconclusive','error_code':s if re.fullmatch(r'[A-Za-z0-9_]{1,110}',s) else 'pml_decode_failed','error_kind':type(exc).__name__};code=2
    Path(sys.argv[3]).write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    sys.exit(code)
