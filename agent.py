import socket,os,struct,json,threading,subprocess,platform,getpass
from queue import Queue
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF



class DB():
 @staticmethod
 def HELP():
  HEADER = '\033[95m'
  CMD = '\033[94m'
  DESC = '\033[92m'
  ENDC = '\033[0m'
  commands = [
      ("pub", "send message to all members"),
      ("priv [user]", "send message to a specific member"),
      ("ls", "list all active members"),
      ("shell share [users(optional)]", "expose your system; optional users restrict access, default public"),
      ("ssh [user]", "open shell session to a user who exposed their system"),
      ("systems", "list all exposed systems"),
      ("shells", "list active shell sessions"),
      ("shell exit", "stop exposing your system"),
      ("help", "display command list")
  ]
  print(f"{HEADER}{'COMMAND':<20}DESCRIPTION{ENDC}")
  print("-"*60)
  for cmd, desc in commands:
      print(f"{CMD}{cmd:<20}{DESC}{desc}{ENDC}")

 crypto_key=None
 sk:socket.SocketType;
 system_expose=False
 shell_channels=[]
 shell_mode=False
 shell_executions=None

 
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


class Crafters(Crypto):
 @staticmethod
 def recv_length(sock,n):
  len_len=n
  recvd_len_len=0
  recvd=b''
  while recvd_len_len<len_len:
   data=sock.recv(len_len-recvd_len_len)
   recvd_len_len+=len(data)
   recvd+=data
  return recvd

 def craft(self,data,key=None)->bytes:
  _data:bytes;
  if isinstance(data,dict):
   _data=json.dumps(data).encode()
  elif not isinstance(data,bytes) and isinstance(data,str):
   _data=data.encode() 
  if key: 
   _data=self.encrypt(_data,key)
  data_len=struct.pack('!I',len(_data))
  to_send=data_len+_data
  return to_send
 
 def inbound_uncraft(self,sock,key=None)->dict:
    data_length=struct.unpack('!I',self.recv_length(sock,4))[0]
    data_bytes=b''
    recvd_bytes_len=0
    while recvd_bytes_len < data_length:
      recvd=sock.recv(data_length-recvd_bytes_len)
      recvd_bytes_len+=len(recvd)
      data_bytes+=recvd
    if key:
     data_bytes=self.decrypt(data_bytes,key)
    formatted:dict=json.loads(data_bytes)
    return formatted
 
 def outbound_uncraft(self,sock,key=None)->str:
   l=struct.unpack('!I',self.recv_length(sock,4))[0]
   recvd_l=0
   recvd_b=b''
   while recvd_l<l:
    recvd=sock.recv(l-recvd_l) 
    recvd_l+=len(recvd)
    recvd_b+=recvd
   if key:
    recvd_b=self.decrypt(recvd_b,key) 
   return recvd_b.decode()


class ShellHandlers(Crafters):
   @staticmethod
   def shell_stdout_proto_wrapper(dst,stdout):
    return {
      'type':'SHELL_SESSION',
      'dir':'<--',
      'stdout':stdout,
      #src isset by server
      'dst':dst
    }
   
   def shell_handle(self,data:dict):
     shell=None
     marker='__CMD_FIN__'
     chann_id=data['src']
     cmd_raw=data['cmd']
     if cmd_raw=='EXIT':
      self.terminate_channel(chann_id)
      self.craft({'type':'SHELL_TERMINATION_REQUEST','connector':chann_id,'sharer':data['dst']},self.crypto_key)
      return 0
     command=f"{cmd_raw};echo {marker}\n"
     output=''
     for channel in self.shell_channels:
       if channel['id']==chann_id:
        shell=channel['process']
        break
     shell.stdin.write(command)
     shell.stdin.flush()
     output_lines=[]
     while True:
       line=shell.stdout.readline()
       if not line:
          break
       if marker in line:
          break
       output_lines.append(line) 
     output=''.join(output_lines)   
     on_wire=self.craft(self.shell_stdout_proto_wrapper(chann_id,output),self.crypto_key)
     self.sk.sendall(on_wire)
 # stopped hier

   def register_shell(self,data):
     system=platform.system().lower()
     shell_process=''
     if system in ('linux','darwin','macos'):
       shell_process='/bin/bash'
     elif system in ('windows'):
       shell_process='cmd.exe'
     channel_config={
       'id':data['connector'],
       'process':subprocess.Popen(
         shell_process,
         text=True,
         shell=False,
         stdout=subprocess.PIPE,
         stderr=subprocess.PIPE,
         stdin=subprocess.PIPE,
         bufsize=1
       )
     }
     self.shell_channels.append(channel_config)
     return 0
   
   def terminate_channel(self,c_id):
    actives=[]
    for channel in self.shell_channels:
      if channel['id']==c_id:
        channel['process'].kill()
      else:
        actives.append(channel)
    self.shell_channels=actives    
   
   def shell_req_handler(self,data:dict,send_activate:threading.Event):
    print(f'***Sys Access has been requested from {data['connector']}!')
    if self.system_expose:
     self.register_shell(data)
     print(f'***Sys Access has been Granted!')
    else:
      print(f"***Sys Access has been Denied!\n ***If you'd like to grant access type SHELL SHARE***")


# below is shell handler Connector SIde!!!!!

   @staticmethod 
   def shell_protocol_wrapper(cmd,sharer):
     return {
       'type':'SHELL_SESSION',
       'dir':'-->',
       'cmd':cmd,
       #src is added by server
       'dst':sharer
     }
   @staticmethod
   def extract_stdout(resp:dict):
     if resp['type']=='SHELL_SESSION':
      executed_bin=resp['stdout']
      return executed_bin
     return None
  
   def spawn_shell(self,data):
     # spawn_shell() [local agent]  ----> shell_forward() [server] ---> shell_handle() [remote agent]
    sharer=data['sharer']
    run_as=data['run-as']
    try:
     while True:
      cmd=input(f'{run_as}# ').strip()
      if cmd.upper()=='EXIT':
        raise KeyboardInterrupt()
      on_wire=self.craft(self.shell_protocol_wrapper(cmd,sharer),self.crypto_key)
      self.sk.sendall(on_wire)
      resp=self.shell_executions.get(timeout=None)
      cmd_exec=self.extract_stdout(resp)
      if cmd_exec:
       print(cmd_exec)
    except KeyboardInterrupt:
      self.shell_executions=None
      self.shell_mode=False
      self.sk.sendall(self.craft(self.shell_protocol_wrapper('EXIT',sharer),self.crypto_key))
      print("Exiting shell...")
   def shell_req_res(self,data,send_activate:threading.Event,recv_activate:threading.Event):
      status=data['status']
      if status=='TRUE':
       self.shell_mode=True
       self.shell_executions=Queue()
       send_activate.clear()
       self.spawn_shell(data)
       send_activate.set()
       return 0
      msg=data['code']
      print(msg)
       
      
class ProtocolEncapsMethods(DB):
  @staticmethod
  def shell_req_encaps(cmd):
    return {
      'type':'SHELL_REQ',
      'target':cmd[1]
    }
  @staticmethod 
  def shell_share_encaps(args):
     return {
       'type':'SHELL_SHARE',
        'OS':platform.system(),
        'OS-RELEASE':platform.release(),
        'RUN-AS':getpass.getuser(),
        'scope':args[0:] if len(args)>=1 else ['PUBLIC']
     }
   
  @staticmethod
  def priv_encaps(proto,cmd):
      return {
        'type':proto,
        'target':cmd[1],
        'payload':' '.join(cmd[2:])
      }
  @staticmethod
  def pub_encaps(proto,cmd):
    return {
      'type':proto,
      'payload':' '.join(cmd[1:]).strip()
    }
  @staticmethod
  def ls_encaps(proto):
   return {
     'type':proto
   }
  @staticmethod
  def sys_encaps(proto):
    return {
      'type':proto
    }
  @staticmethod
  def shells_encaps(proto):
    return {
      'type':proto
    }
  
  def cancel_shell_share(self):
    self.system_expose=False
    self.shell_channels=[]
    return {
      'type':'CANCEL_SHELL_SHARE'
    }
    

class InputValidation():
  @staticmethod
  def validate(protocol,cmd):
    # not finished #######
    if protocol=='PUB':
     return True
    elif  protocol=='PRIV':
      return True
    elif  protocol=='LS':
      return True
    elif protocol=='SHELL':
      return True
    
class ProtocolEncaps(ProtocolEncapsMethods,InputValidation):     
  def encaps(self,data:str,recv_activate:threading.Event)->dict:
   user_input=data.split(' ')
   proto=user_input[0].upper()
   if proto=='PUB' and self.validate(proto,user_input):
    return self.pub_encaps(proto,user_input)
   if proto=='PRIV' and self.validate(proto,user_input):
      return self.priv_encaps(proto,user_input)
   if proto=='LS' and self.validate(proto,user_input):
     return self.ls_encaps(proto)
   if proto=='SHELL' and self.validate(proto,user_input):
       if user_input[1].upper()=='SHARE': 
        self.system_expose=True
        return self.shell_share_encaps(user_input[2:])
       elif user_input[1].upper()=='EXIT':
         return self.cancel_shell_share()
   if proto=='SSH' and self.validate(proto,user_input):
     return self.shell_req_encaps(user_input)
   if proto=='SYSTEMS' and self.validate(proto,user_input):
     return self.sys_encaps(proto)  
   if proto=='SHELLS' and self.validate(proto,user_input):
     return self.shells_encaps(proto)    
   raise ValueError()
   

class GeneralHandlers():
  @staticmethod
  def pub_handler(data:dict):
    print(f'{data["src"]}: {data["payload"]}')

  @staticmethod
  def priv_handler(data:dict):
   src=data['src']
   print(f'*{src}*: {data["payload"]}')
  
  @staticmethod
  def ls_handler(data:dict):
    print(data['payload'])
              
  @staticmethod
  def msg_handler(data:dict):
    msg=data['payload']
    print(msg)


class ProtocolDecaps(GeneralHandlers,ShellHandlers,Crypto):
  def proto_handler(self,data:dict,send_activate:threading.Event,recv_activate:threading.Event): 
    proto=data['type']
    if not self.shell_mode:
      if self.system_expose and proto=='SHELL_SESSION':
        self.shell_handle(data)
      elif proto=='PUB':
        self.pub_handler(data)
      elif proto=='PRIV':
        self.priv_handler(data)
      elif proto=='SHELL_REQ':
        self.shell_req_handler(data,send_activate)
      elif proto=='MSG':
        self.msg_handler(data)
      elif proto=='LS':
        self.ls_handler(data)     
      elif proto=='SHELL_RESP':
       threading.Thread(target=self.shell_req_res,args=(data,send_activate,recv_activate,),daemon=True).start()
    elif self.shell_mode and proto=='SHELL_SESSION':
       self.shell_executions.put(data)       


class Protocol(ProtocolEncaps,ProtocolDecaps):
  IS_WRAPPER=True
    
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
  pub_key_server_length=struct.unpack('!I',self.recv_length(session,4))[0]
  pub_key_server_recvd_length=0
  pub_key_server_bytes=b''
  while pub_key_server_recvd_length<pub_key_server_length:
   pub_key_server_part=session.recv(pub_key_server_length-pub_key_server_recvd_length)
   pub_key_server_recvd_length+=len(pub_key_server_part)
   pub_key_server_bytes+=pub_key_server_part
  pub_key_server=serialization.load_pem_public_key(pub_key_server_bytes)
  #send local pub key.
  session.sendall(pub_key_local_length)
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
    extracted=self.outbound_uncraft(session,key)
    print(extracted)
    if 'failure' in extracted.lower():
      return False
    return True 
    
  def send_password(self,session,key):
    password=input("Enter Password: ").encode('utf-8')
    data=self.craft(password,key)
    session.send(data)
  
  def register_as(self,session,key):
    registered=False
    while not registered:
      username=input('WHO_ARE_YOU?: ').encode('utf-8')
      data=self.craft(username,key)
      session.send(data)
      msg=self.outbound_uncraft(session,key)
      if 'success' not in msg:
        print(msg)
        continue
      registered=True

class Client(Auth):
 def __init__(self):
  self.sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  self.send_activate=threading.Event()
  self.recv_activate=threading.Event()
 
 def check_status(self,sock):
   if 'error' in self.outbound_uncraft(sock).lower():
    return False
   return True
 
 def initiate(self):
    server_ip=input("Server IP: ")
    server_port=int(input("Server Port: "))
    self.sk.connect((server_ip,server_port))
    if not  self.check_status(self.sk):
      self.sk.close()
      raise PermissionError()     
    self.crypto_key=self.encrypt_session(self.sk)
    authenticated=self.authenticate(self.sk,self.crypto_key)
    if not authenticated:
      raise  PermissionError()
    
 def send(self,recv_activate:threading.Event):
    while True:
      self.send_activate.wait()
      data=input("")
      if data.upper()=='HELP':
        self.HELP()
        continue
      try:
       formatted:dict=self.encaps(data,recv_activate)
      except ValueError:
        print('// Unknown Protocol.type HELP to list available Commands.')
        continue
      data_to_send=self.craft(formatted,self.crypto_key)
      try:
       self.sk.send(data_to_send)
      except OSError:
        print("// Connection is closed!")
        break

        
 def recv(self,send_activate:threading.Event):
   while True:
     self.recv_activate.wait()
     formatted=self.inbound_uncraft(self.sk,self.crypto_key)
     self.proto_handler(formatted,send_activate,self.recv_activate)
   

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

