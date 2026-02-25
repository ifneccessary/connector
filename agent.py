import socket,os,struct,json,threading,subprocess,platform,getpass
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF



class DB():
 crypto_key=None
 sk:socket.SocketType;
 system_expose=False
 shell_channels=list()
 
class Crypto(DB):
 def encrypt(self,data,token):
  iv=os.urandom(12)
  cipher=Cipher(
   algorithms.AES128(token),
   modes.GCM(iv)
   ).encryptor()
  f_encrypted=cipher.update(data)+cipher.finalize()
  encrypted=iv+cipher.tag+f_encrypted
  return encrypted
 def decrypt(self,data,token):
  iv=data[0:12]
  tag=data[12:28]
  payload=data[28:]
  cipher=Cipher(
   algorithms.AES128(token),
   modes.GCM(iv,tag)
   ).decryptor()
  data_bytes=cipher.update(payload)+cipher.finalize()
  return data_bytes
#cli

class ShellSession(DB):
   def shell_handle(self,process:subprocess.Popen):
     #fn will  be executed
     pass

   
   def shell_req_handler(self,data:dict,send_activate:threading.Event):
    
    # accept request if shell is registered.
    # store active shell sessions and assign id
    # return positive or negative to server. if positive server will also store session
    resp=None
    if self.system_expose:
     session_config={
       'connector':data['connector'],
       'shell':self.register_shell()
     }
     self.shell_channels.append(session_config)
     resp=b'TRUE'
    else:
     resp=b'FALSE'
    
    
   
   def register_shell(self):
    OS=platform.system().lower()
    shell_process=None
    if 'windows' in OS:
      shell_process='cmd.exe'
    elif 'linux' in OS:
      shell_process='bash'
    elif 'macos' in OS or 'darwin' in OS:
      shell_process='bash'
    if shell_process:
      return subprocess.Popen(
        shell_process,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.PIPE,
        shell=True,
        text=False
       )
      
      #inter-process-communication 
      # (python agent process <----> local shell child process)

      
      


class ProtocolEncaps(ShellSession):     
  @staticmethod
  def validate(protocol,cmd):
    # not finished #######
    if protocol=='PUB':
     return True
     
    elif  protocol=='PRIV':
      return True
    elif  protocol=='LS':
      return True
    elif protocol=='PROXY':
      pass
    elif protocol=='SHELL':
      return True

  def encaps(self,data:str,recv_activate:threading.Event)->dict:
   formatted=dict()
   cmd=data.split(' ')
   proto=cmd[0].upper()
   if proto=='PUB' and self.validate(proto,cmd):
      formatted['type']=proto
      formatted['payload']=' '.join(cmd[1:]).strip()
      return formatted
   
   elif proto=='PRIV' and self.validate(proto,cmd):
       formatted['type']=proto
       formatted['target']=cmd[1] 
       formatted['payload']=' '.join(cmd[2:])
       return formatted
   
   elif proto=='SHELL' and self.validate(proto,cmd):
       if cmd[1].upper()=='SHARE': 
        self.system_expose=True
        formatted['type']='SHELL_SHARE'
        formatted['OS']=platform.system()
        formatted['OS-RELEASE']=platform.release()
        formatted['RUN-AS']=getpass.getuser()
       elif cmd[1] and not cmd[2]:
         formatted['type']='SHELL_REQ'
         formatted['target']=cmd[1]
       elif cmd[1] and cmd[1].upper()!='SHARE' and cmd[2]:
         formatted['type']='SHELL_SESSION'
         formatted['target']=cmd[1]
    
       return formatted
 
   elif proto=='PROXY' and self.validate(proto,cmd):
       formatted['type']=proto
       formatted['target']=cmd[1]    
       return formatted
   elif proto=='LS' and self.validate(proto,cmd):
     formatted['type']=proto
     return formatted
   raise ValueError()
   
class ProtocolDecaps(ShellSession,Crypto):
  
  def proto_handler(self,data:dict,send_activate:threading.Event): 
    proto=data['type']
    if proto=='PUB':
      self.pub_handler(data)
    elif proto=='PRIV':
      self.priv_handler(data)
    elif proto=='SHELL_REQ':
     self.shell_req_handler(data,send_activate)
    elif proto=='MSG':
      self.msg_handler(data)
    elif proto=='LS':
      self.ls_handler(data)

  @staticmethod
  def pub_handler(data:dict):
    print(f'{data["src"]}: {data["payload"]}')

  @staticmethod
  def priv_handler(data:dict):
   src=data['src']
   print(f'//PRIVATE// {src}: {data["payload"]}')
  
  
  @staticmethod
  def ls_handler(data:dict):
    print(data['payload'])
              
  @staticmethod
  def msg_handler(data:dict):
    msg=data['payload']
    print(msg)


class Protocol(ProtocolEncaps,ProtocolDecaps):
  CONDITION=True
    
  
class Security(Protocol):
 def encrypt_session(self,session):
  #locals initialization
  private_key_local=ec.generate_private_key(ec.SECP256R1())
  public_key_local=private_key_local.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  pub_key_local_length=struct.pack('!I',len(public_key_local))

  # recieve server pub key
  pub_key_server_length=struct.unpack('!I',session.recv(4))[0]
  pub_key_server_recvd_length=0
  pub_key_server_bytes=b''
  while pub_key_server_recvd_length<pub_key_server_length:
   pub_key_server_part=session.recv(1024)
   pub_key_server_recvd_length+=len(pub_key_server_part)
   pub_key_server_bytes+=pub_key_server_part
  pub_key_server=serialization.load_pem_public_key(pub_key_server_bytes)
  #send local pub key.
  session.send(pub_key_local_length)
  session.sendall(public_key_local)

  shared_sec=private_key_local.exchange(ec.ECDH(),pub_key_server)
  #encrypted session key (!IMPORTANT!)
  return HKDF(
   algorithm=hashes.SHA256(),
   length=16,
   salt=None,
   info=b'Exchange'
  ).derive(shared_sec)
  

class Auth(Security):
  def info(self):
    print("// Warning:")
    print("// Group access requires authentication")
    print("// If you don't know password, ask IF_NECESSARY OR check DOCUMENTATION WEBSITE!")
    print("// You can see Documentation on http://192.168.145.241:8888/")
  
  def authenticate(self,session,key):
    self.register_as(session,key)
    self.info()
    self.send_password(session,key)
    return self.resp(session,key)
   
  def resp(self,session,key):
    r_len=session.recv(4)
    response_length=struct.unpack('!I',r_len)[0]
    recvd_res_length=0
    extracted=b''
    while recvd_res_length<response_length:
      got=session.recv(response_length)
      recvd_res_length+=len(got)
      extracted+=got
    extracted:str=self.decrypt(extracted,key).decode()
    print(extracted)
    if 'failure' in extracted.lower():
      return False
    return True 
    
  def send_password(self,session,key):
    password=input("Enter Password: ").encode('utf-8')
    encrypted_pass=self.encrypt(password,key)
    pass_length=len(encrypted_pass)
    size=struct.pack('!I',pass_length)
    data=size+encrypted_pass 
    session.send(data)
  
  def register_as(self,session,key):
    registered=False
    while not registered:
      username=input('WHO_ARE_YOU?: ').encode('utf-8')
      encrypted_alias=self.encrypt(username,key)
      alias_length=struct.pack('!I',len(encrypted_alias))
      data=alias_length+encrypted_alias
      session.send(data)
      res_len=struct.unpack('!I',session.recv(4))[0]
      recvd_len=0
      recvd=b''
      while recvd_len<res_len:
        got=session.recv(res_len)
        recvd_len+=len(got)
        recvd+=got
      msg=self.decrypt(recvd,key).decode()
      if 'success' not in msg:
        print(msg)
        continue
      registered=True

class Client(Auth):
 def __init__(self):
  self.sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  self.send_activate=threading.Event()
  self.recv_activate=threading.Event()
 
 def initiate(self):
    server_ip=input("Server IP: ")
    server_port=int(input("Server Port: "))
    self.sk.connect((server_ip,server_port))     
    self.crypto_key=self.encrypt_session(self.sk)
    authenticated=self.authenticate(self.sk,self.crypto_key)
    if not authenticated:
      raise  PermissionError()
    
 def send(self,recv_activate:threading.Event):
    while True:
      self.send_activate.wait()
      data=input("")
      try:
       formatted:dict=self.encaps(data,recv_activate)
      except ValueError:
        print('// Unknown Protocol.type HELP to list Commnds.')
        continue
      jsonized=json.dumps(formatted).encode()
      encrypted=self.encrypt(jsonized,self.crypto_key)
      encrypted_len=struct.pack('!I',len(encrypted))
      data_tosend=encrypted_len+encrypted
      try:
       self.sk.send(data_tosend)
      except OSError:
        print("Connection is closed!")
        break

        
 def recv(self,send_activate:threading.Event):
   while True:
     self.recv_activate.wait()
     length=struct.unpack('!I',self.sk.recv(4))[0]
     recvd_len=0
     recvd=b''
     while recvd_len<length:
       got=self.sk.recv(length)
       recvd_len+=len(got)
       recvd+=got
     decrypted_data=self.decrypt(recvd,self.crypto_key)  
     formatted:dict=json.loads(decrypted_data)  
     self.proto_handler(formatted,send_activate)
   

 def activate(self):
   try:
    self.initiate()
   except (ConnectionError,PermissionError,RuntimeError) as ERROR:
     if isinstance(ERROR,ConnectionError):
       print("Connection Error! Server might be down. (Contact If Necessary)")
       return 1
     elif isinstance(ERROR,PermissionError):
       print("Authentication Failure! Check Documentation: http://192.168.145.241:8888/")
       return 1
     elif isinstance(ERROR,RuntimeError):
       print("Encryption Error! (Contact If Necessary)")
       return 1
   self.send_activate.set()
   self.recv_activate.set()  
   threading.Thread(target=self.send,args=(self.recv_activate,),daemon=False).start()
   threading.Thread(target=self.recv,args=(self.send_activate,),daemon=False).start()
       
     
if __name__=='__main__':
   cli=Client()
   cli.activate()

