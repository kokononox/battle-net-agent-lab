"""Portable C + independent ZIP/JSON compatibility checks; no Windows claims."""
import json, pathlib, subprocess, tempfile, zipfile
root=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as temp:
    exe=pathlib.Path(temp)/'core-test'
    subprocess.run(['gcc','-std=c11','-O2','-g',str(root/'tests/core_test.c'),'-o',str(exe)],check=True)
    subprocess.run([str(exe),temp],check=True)
    assert json.loads((pathlib.Path(temp)/'escaping.json').read_text())=='سلام\n\t\r\x01"\\'
    with zipfile.ZipFile(pathlib.Path(temp)/'bundle.zip') as z:
        assert z.namelist()==['a.txt','empty.txt','binary.dat']
        assert z.testzip() is None
        assert z.read('a.txt')==b'hello\n'
        assert z.read('empty.txt')==b''
        assert z.read('binary.dat')==bytes(i%256 for i in range(100003))
    with zipfile.ZipFile(pathlib.Path(temp)/'empty.zip') as z: assert z.namelist()==[]
print('Independent ZIP CRC/content and UTF-8 JSON checks passed.')
