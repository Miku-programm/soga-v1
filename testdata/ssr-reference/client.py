"""Independent upstream Python SSR protocol client with cryptography AES/RC4.
No target executable is loaded. The cryptography bridge only supplies ciphers;
authentication framing is imported unchanged from the pinned SSR reference.
"""
import collections,collections.abc,sys,types,hashlib,os,socket,struct
collections.MutableMapping=collections.abc.MutableMapping
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4

def evp(password,n):
 if isinstance(password,str):password=password.encode()
 b=b'';prev=b''
 while len(b)<n:prev=hashlib.md5(prev+password).digest();b+=prev
 return b[:n]
class Encryptor:
 def __init__(self,password,method,iv=None):
  self.method=method;self.key=evp(password,16);self.ivlen=0 if method=='rc4' else 16
  self.cipher_iv=iv if iv is not None else os.urandom(self.ivlen)
  self.enc=self.make(self.cipher_iv).encryptor();self.dec=None;self.buf=b'';self.sent=False
 def make(self,iv):
  if self.method=='rc4':return Cipher(ARC4(self.key),mode=None)
  return Cipher(algorithms.AES(self.key),modes.CBC(iv) if self.method=='aes-128-cbc' else modes.CFB(iv))
 def encrypt(self,b):
  result=self.enc.update(b)
  if not self.sent:self.sent=True;result=self.cipher_iv+result
  return result
 def decrypt(self,b):
  if self.dec is None:
   self.buf+=b
   if len(self.buf)<self.ivlen:return b''
   self.dec=self.make(self.buf[:self.ivlen]).decryptor();b=self.buf[self.ivlen:];self.buf=b''
  return self.dec.update(b)
bridge=types.ModuleType('shadowsocks.encrypt');bridge.Encryptor=Encryptor;sys.modules['shadowsocks.encrypt']=bridge
from shadowsocks.obfsplugin import auth,auth_chain,obfs_tls
addr,protocol=sys.argv[1:3]
obfuscator=sys.argv[3] if len(sys.argv)>3 else "plain"
def exact(sock,n):
 result=b""
 while len(result)<n:
  part=sock.recv(n-len(result))
  if not part:raise RuntimeError("premature TLS EOF")
  result+=part
 return result
for uid,password in [(101,'user-one'),(202,'user-two')]:
 p=(auth.obfs_map|auth_chain.obfs_map)[protocol][0](protocol)
 outer=Encryptor('outer-secret','aes-128-cfb')
 info=types.SimpleNamespace(data=p.init_data(),host='127.0.0.1',port=int(addr.rsplit(':',1)[1]),
  protocol_param=f'{uid}:{password}',obfs_param='',iv=outer.cipher_iv,recv_iv=b'',key=outer.key,key_str='outer-secret',
  head_len=30,tcp_mss=1460,buffer_size=32768-p.get_overhead(True),overhead=p.get_overhead(True),users={})
 b=obfs_tls.obfs_map[obfuscator][0](obfuscator) if obfuscator!="plain" else None
 if b:
  info.overhead+=b.get_overhead(True);info.buffer_size=32768-info.overhead
  binfo=types.SimpleNamespace(**vars(info));binfo.data=b.init_data();binfo.obfs_param="example.com";b.set_server_info(binfo)
 p.set_server_info(info)
 target=b'\x03\x0bexample.com\x01\xbb';payload=(b'independent Python SSR client '+str(uid).encode())*1300
 with socket.create_connection((addr.rsplit(':',1)[0],int(addr.rsplit(':',1)[1])),timeout=5) as sock:
  wire=outer.encrypt(p.client_pre_encrypt(target+payload))
  sock.sendall(b.client_encode(wire) if b else wire)
  if b:
   handshake=b"";seen_change=False
   while True:
    header=exact(sock,5);record=exact(sock,int.from_bytes(header[3:5],"big"));handshake+=header+record
    if header[0]==20:seen_change=True
    elif seen_change and header[0]==22:break
   _,reply=b.client_decode(handshake)
   assert reply
   sock.sendall(b.client_encode(b""))
  got=b''
  while len(got)<len(payload):
   chunk=sock.recv(700)
   if not chunk:raise RuntimeError('premature EOF')
   if b:chunk,_=b.client_decode(chunk)
   got+=p.client_post_decrypt(outer.decrypt(chunk))
  assert got==payload,(len(got),len(payload))
 print(protocol,uid,'TCP OK')
