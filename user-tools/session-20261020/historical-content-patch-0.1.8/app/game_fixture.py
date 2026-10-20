"""Owned loopback worker ONLY, never launch or control Blizzard."""
import socket,sys
print('FIXTURE_READY',flush=True)
port=int(sys.stdin.readline())
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('127.0.0.1',port))
raw=b'POST /tpr/fixture HTTP/1.1\r\nHost: level3.blizzard.com\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n'+b'{"cpu":"LOCAL-TEST-CPU","bios":"TEST123"}'
# Correct length generated here rather than trusting fixture constants.
body=raw.split(b'\r\n\r\n',1)[1]
raw=raw.split(b'Content-Length:',1)[0]+b'Content-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
s.sendall(raw)
# Synthetic ClientHello on owned loopback only; NOT a TLS/SSPI decryption test.
name=b'selftest.invalid'
entry=b'\x00'+len(name).to_bytes(2,'big')+name
names=len(entry).to_bytes(2,'big')+entry
ext=b'\x00\x00'+len(names).to_bytes(2,'big')+names
body=b'\x03\x03'+b'X'*32+b'\x00'+b'\x00\x02\x00\x2f'+b'\x01\x00'+len(ext).to_bytes(2,'big')+ext
hello=b'\x01'+len(body).to_bytes(3,'big')+body
record=b'\x16\x03\x01'+len(hello).to_bytes(2,'big')+hello
s.sendall(record);s.shutdown(socket.SHUT_WR)
while s.recv(4096):pass
s.close()
print('FIXTURE_SENT',flush=True)
sys.stdin.readline()
