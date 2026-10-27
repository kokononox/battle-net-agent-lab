import json,sys
from pathlib import Path
from guard_report import read
from transfer_probe import validate
if __name__=='__main__':
 r=validate(read(sys.argv[1]));p=Path(sys.argv[2]);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(r,indent=2)+'\n')
