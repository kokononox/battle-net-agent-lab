import unittest,subprocess,sys,os,tempfile,json
from pathlib import Path
import transfer_probe as t
class Cli(unittest.TestCase):
 def test_sanitizer_fresh_interpreter_no_pythonpath(self):
  with tempfile.TemporaryDirectory()as d:
   a=Path(d)/'input.json';b=Path(d)/'output.json';a.write_text(json.dumps(t.blank('a'*40,'1')));env=os.environ.copy();env.pop('PYTHONPATH',None)
   p=subprocess.run([sys.executable,str(Path(__file__).with_name('transfer_sanitize.py')),str(a),str(b)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=10)
   self.assertEqual(p.returncode,0);self.assertEqual(t.validate(json.loads(b.read_text()))['status'],'not_started')
if __name__=='__main__':unittest.main()
