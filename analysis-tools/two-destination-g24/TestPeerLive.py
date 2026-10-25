"""Read-only native TCP ownership integration; never grants network access."""
import os,socket,unittest
import peer_guard as p
class NativeOwner(unittest.TestCase):
 def run_family(self,family,address):
  with socket.socket(family,socket.SOCK_STREAM) as listener:
   listener.bind((address,0));listener.listen(1)
   with socket.socket(family,socket.SOCK_STREAM) as client:
    client.connect(listener.getsockname())
    accepted,_=listener.accept()
    with accepted:self.assertEqual(p.owner(accepted),os.getpid())
 def test_ipv4_reverse_tuple(self):self.run_family(socket.AF_INET,'127.0.0.1')
 def test_ipv6_reverse_tuple(self):self.run_family(socket.AF_INET6,'::1')
if __name__=='__main__':unittest.main()
