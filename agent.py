import socket,os,struct,json,threading,subprocess,platform,getpass,selectors,time
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
      ("shell share [pub/priv] [users(optional)]", "expose access to your system; optional users restrict access, default public. pub/priv manages whether all members or only connector member will see output of shell. IF set to 'pub' then any member can sniff shell outputs via get [channel_id] cmd. Default value is priv for your safety!"),
      ("ssh [user]", "open shell session to a user who exposed their system"),
      ("systems", "list all exposed systems"),
      ("shells", "list active shell sessions"),
      ("shell exit", "stop exposing your system"),
      ("help", "display commands")
  ]
  print(f"{HEADER}{'COMMAND':<20}DESCRIPTION{ENDC}")
  print("-"*60)
  for cmd, desc in commands:
      print(f"{CMD}{cmd:<20}{DESC}{desc}{ENDC}")
 
 def EXIT(self):
  print("// Exiting Connecion...")
  time.sleep(0.5)
  self.kill.set()
  if self.shell_channels:
    print('// Terminating shell channels...')
    time.sleep(0.2)
    for channel in self.shell_channels:
      channel['process'].kill()
  self.sk.sendall(self.craft({'type':"EXIT_MAIN"},self.crypto_key))
  try:
   self.sk.shutdown(socket.SHUT_RDWR)
  except OSError:
    pass
  finally: 
   self.sk.close()   
 kill=threading.Event()
 send_activate=threading.Event()
 recv_activate=threading.Event()
 crypto_key=None
 sk:socket.SocketType;
 system_expose=False
 shell_channels=[]
 shell_mode=False
 sniff_mode=False
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
   try:
    data=sock.recv(len_len-recvd_len_len)
   except (OSError,ConnectionResetError):
     return None
   if not data:
     return None
   recvd_len_len+=len(data)
   recvd+=data
  return recvd

 def craft(self,data,key=None)->bytes:
  _data:bytes=b'';
  if isinstance(data,dict):
   _data=json.dumps(data).encode()
  elif not isinstance(data,bytes) and isinstance(data,str):
   _data=data.encode() 
  else:
    _data=data 
  if key: 
   _data=self.encrypt(_data,key)
  data_len=struct.pack('!I',len(_data))
  to_send=data_len+_data
  return to_send
 
 def inbound_uncraft(self,sock,key=None)->dict:
    length=self.recv_length(sock,4)
    if not length:
      raise ConnectionResetError()
    data_length=struct.unpack('!I',length)[0]
    data_bytes=b''
    recvd_bytes_len=0
    while recvd_bytes_len < data_length:
      try:
       recvd=sock.recv(data_length-recvd_bytes_len)
      except (OSError,ConnectionResetError):
        raise ConnectionResetError()
      if not recvd:
        raise ConnectionResetError()  
      recvd_bytes_len+=len(recvd)
      data_bytes+=recvd
    if key:
     data_bytes=self.decrypt(data_bytes,key)
    formatted:dict=json.loads(data_bytes)
    return formatted
 
 def outbound_uncraft(self,sock,key=None,decode=True):
   length=self.recv_length(sock,4)
   if not length:
    raise OSError()
   l=struct.unpack('!I',length)[0]
   recvd_l=0
   recvd_b=b''
   while recvd_l<l:
    try:  
     recvd=sock.recv(l-recvd_l) 
    except (OSError,ConnectionResetError):
      recvd=b''
      break
    recvd_l+=len(recvd)
    recvd_b+=recvd
   if key:
    recvd_b=self.decrypt(recvd_b,key) 
   if decode: 
    return recvd_b.decode()
   return recvd_b

class Operations(Crafters):
 pass
class ShellHandlers(Crafters):
   
   def terminate_shell(self,chann_id,sharer):
     self.terminate_channel(chann_id)
     self.sk.sendall(self.craft({
      'type':'SHELL_TERM_REQUEST',
      'connector':chann_id,
      'sharer': sharer
     },self.crypto_key))
     return 0
   
   def shell_handle(self,data:dict):
      shell=None
      marker='__CMD_FIN__'
      chann_id=data['id']
      cmd_raw=data['cmd']
      src=data['src']
      command=''
      if cmd_raw=='EXIT':
        return self.terminate_shell(chann_id,data['dst'])
      if platform.system().lower() in ('linux','darwin','macos'):
       command=f"{cmd_raw}; echo {marker}\n"
      else:
        command=f"{cmd_raw} & echo {marker}\n"
      for channel in self.shell_channels:
        if channel['id']==chann_id:
          shell=channel['process']
          break
      shell.stdin.write(command)
      shell.stdin.flush()
      stdout_lines=[]
      stderr_lines=[]
# your code here
      if shell is None:
          return

      sel = selectors.DefaultSelector()
      sel.register(shell.stdout, selectors.EVENT_READ)
      sel.register(shell.stderr, selectors.EVENT_READ)

      stdout_done = False

      try:
          while not stdout_done:
              events = sel.select(timeout=0.5)

              if not events:
                  if shell.poll() is not None:
                      break
                  continue

              for key, _ in events:
                  stream = key.fileobj
                  line = stream.readline()

                  if not line:
                      continue

                  if stream is shell.stdout:
                      if marker in line:
                          stdout_done = True
                      else:
                          stdout_lines.append(line.rstrip())

                  elif stream is shell.stderr:
                      stderr_lines.append(line.rstrip())

          drain_start = time.time()
          while time.time() - drain_start < 0.2:
              events = sel.select(timeout=0)
              if not events:
                  break

              for key, _ in events:
                  stream = key.fileobj
                  line = stream.readline()
                  if not line:
                      continue

                  if stream is shell.stdout:
                      stdout_lines.append(line.rstrip())
                  elif stream is shell.stderr:
                      stderr_lines.append(line.rstrip())

      finally:
          sel.close()
#

      ssh_return=' '.join(stdout_lines+stderr_lines)
      self.sk.sendall(self.craft({
        'type':'SHELL_SESSION',
        'dir':'<--',
        'stdout':ssh_return,
        #src isset by server
        'id':chann_id,
        'dst':src
      },self.crypto_key))

   def register_shell(self,data):
        system=platform.system().lower()
        shell_process=''
        if system in ('linux','darwin','macos'):
         shell_process=['/bin/bash','-i']
        elif system in ('windows','nt'):
         shell_process='cmd.exe'
        channel_config={
        'id':data['id'],
        'process':subprocess.Popen(
            shell_process,
            text=True,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            bufsize=0
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
    print(f'***Sys Access has been requested from {data["connector"]}!')
    if self.system_expose:
     self.register_shell(data)
     print(f'***Sys Access has been Granted!')
    else:
      print(f"***Sys Access has been Denied!\n ***If you'd like to grant access type SHELL SHARE***")


   @staticmethod 
   
   @staticmethod
   def extract_stdout(resp:dict):
     if resp['type']=='SHELL_SESSION':
      executed_bin=resp['stdout']
      return executed_bin
     return None
  
   def spawn_shell(self,data,shell_id):
    sharer=data['sharer']
    run_as=data['run-as']
    try:
     while True:
      cmd=input(f'{run_as}# ').strip()
      if cmd.upper() in ('QUIT','EXIT'):
        raise ValueError()
      on_wire=self.craft({
       'type':'SHELL_SESSION',
       'dir':'-->',
       'cmd':cmd,
       'dst':sharer,
       'id':shell_id  
     },self.crypto_key)
      self.sk.sendall(on_wire)
      resp=self.shell_executions.get(timeout=None)
      cmd_exec=self.extract_stdout(resp)
      if cmd_exec:
       print(cmd_exec)
    except ValueError:
      self.shell_executions=None
      self.shell_mode=False
      self.sk.sendall(self.craft({
        'type':None
      },self.crypto_key))
      print("Exiting shell...")
   
   def shell_req_res(self,data,send_activate:threading.Event,recv_activate:threading.Event):
      status=data['status']
      shell_id=data['id']
      if status=='TRUE':
       self.shell_mode=True
       self.shell_executions=Queue()
       send_activate.clear()
       self.spawn_shell(data,shell_id)
       send_activate.set()
       return 0
      msg=data['code']
      print(msg)

class InputValidation():
  @staticmethod
  def validate(protocol,cmd:list):
    if protocol=='PUB':
     if len(cmd)>1:
      return True
     return False
    elif  protocol=='PRIV':
      if len(cmd)>2:
       return True
      return False
    elif  protocol=='LS':
      return True
    elif protocol=='SHELL':
      if len(cmd)>=2:
       return True
    elif protocol=='SSH':
      if len(cmd)==2:
        return True
      return False
    elif protocol=='SYSTEMS':
     return True
    elif protocol=='SHELLS':
      if len(cmd)==2:
        return True
      return False
    elif protocol=='READ':
      if len(cmd)>1:
        return True
      return False
      

class ProtocolEncapsMethods(DB):  
  @staticmethod
  def shell_req_encaps(cmd):
      return {
        'type':'SHELL_REQ',
        'target':cmd[0].strip()
      }
  @staticmethod 
  def shell_share_encaps(args):
      args=[arg.strip() for arg in args]
      scope=None
      subtype=args[0].upper() if args else 'PRIV'
      if subtype not in ('PRIV','PUB'):
       subtype='PRIV'
       scope=args
      else:
       scope=args[1:] if len(args)>1 else ['PUBLIC'] 
      return {
        'type':'SHELL_SHARE',
        'OS':platform.system(),
        'OS-RELEASE':platform.release(),
        'RUN-AS':getpass.getuser(),
        'scope':scope,
        'subtype':subtype.upper(),
     }
 
  
  @staticmethod
  def priv_encaps(proto,cmd):
      return {
        'type':proto,
        'target':cmd[1].strip(),
        'payload':' '.join(cmd[2:]).strip()
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
  def exit_sniff(self):
    print(f'// Exiting sniffing mode...')
    self.sniff_mode=False    
  def cancel_shell_share(self):
    self.system_expose=False
    self.shell_channels=[]
    return {
      'type':'CANCEL_SHELL_SHARE'
    }
  def read_shell_channel_encaps(self,proto,chann_id):
    self.sniff_mode=True
    return {
      'type':proto,
      'channel':chann_id
    } 
    
class ProtocolEncaps(ProtocolEncapsMethods,InputValidation):     
  def encaps(self,data:str,recv_activate:threading.Event):
   user_input=data.split(' ')
   proto=user_input[0].upper()
   if not self.sniff_mode:
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
      return self.shell_req_encaps(user_input[1:])
    if proto=='SYSTEMS' and self.validate(proto,user_input):
      return self.sys_encaps(proto)  
    if proto=='SHELLS' and self.validate(proto,user_input):
      return self.shells_encaps(proto)
    if proto=='READ' and self.validate(proto,user_input):
      return self.read_shell_channel_encaps(proto,user_input[1]) 
   else:
     if proto in ('EXIT','Q','QUIT'):
      return self.exit_sniff()   
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
  @staticmethod
  def shell_sniffer(data:dict):
    print(data['stdout'])
  @staticmethod
  def packet_sniffer(data:dict):
    print(data)
    pass
  
class ProtocolDecaps(GeneralHandlers,ShellHandlers,Crypto):
  def proto_handler(self,data:dict,send_activate:threading.Event,recv_activate:threading.Event): 
    proto=data['type']
    if proto=='SERVER_TERMINATION':
      self.EXIT()
    if not (self.shell_mode or self.sniff_mode):
      if self.system_expose and proto=='SHELL_SESSION':
        threading.Thread(target=self.shell_handle,args=(data,),daemon=True).start()
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
    elif self.sniff_mode:
      if proto=='SHELL_SNIFFED':
        self.shell_sniffer(data)
      elif proto=='PACKET_SNIFFED':
        self.packet_sniffer(data)
    elif self.shell_mode and proto=='SHELL_SESSION':
        self.shell_executions.put(data) 




class Protocol(ProtocolEncaps,ProtocolDecaps):
  IS_WRAPPER=True
    
class Security(Protocol):
 def encrypt_session(self,session):
  print('Exchanging encryption keys...')
  time.sleep(0.5)
  private_key_local=ec.generate_private_key(ec.SECP256R1())
  public_key_local=private_key_local.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  pub_key_server=self.outbound_uncraft(session,decode=False)
  session.sendall(self.craft(public_key_local))
  shared_sec=private_key_local.exchange(ec.ECDH(),serialization.load_pem_public_key(pub_key_server))
  print("// Connection has been encrypted successfully!")
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
    extracted=self.outbound_uncraft(session,key,decode=True)
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
      msg=self.outbound_uncraft(session,key,decode=True)
      if not 'success' in msg:
        print(msg)
        continue
      registered=True

class Client(Auth):
 def __init__(self):
  self.sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

 
 def check_status(self,sock):
   if 'error' in self.outbound_uncraft(sock,decode=True).lower():
    return False
   return True
 
 def initiate(self):
    server_ip=input("Server IP: ")
    server_port=int(input("Server Port: "))
    self.sk.connect((server_ip,server_port))
    # if not self.check_status(self.sk):
    #   print("ran")
    #   self.sk.close()
    #   raise PermissionError() 
    # 
    #     
    self.crypto_key=self.encrypt_session(self.sk)
    authenticated=self.authenticate(self.sk,self.crypto_key)
    if not authenticated:
      raise  PermissionError()
   
  
 def send(self,recv_activate:threading.Event):
   try: 
    while not self.kill.is_set():
      self.send_activate.wait()
      data=input("")
      if data.upper()=='HELP':
        self.HELP()
        continue
      if data.upper() in ("EXIT",'QUIT'):
        self.EXIT()
        break
      try:
       formatted=self.encaps(data,recv_activate)
       if not formatted:
         raise ValueError()
      except ValueError:
        print('// Unknown Protocol.type HELP to list available Commands.')
        continue
      data_to_send=self.craft(formatted,self.crypto_key)
      try:
       self.sk.sendall(data_to_send)
      except (OSError,BrokenPipeError):
        print("// Connection is closed!")
        break
   except KeyboardInterrupt:
     print("send keyboard interrupt")
     self.EXIT()

 def recv(self,send_activate:threading.Event):
  try: 
   while not self.kill.is_set():
     self.recv_activate.wait()
     try:
      formatted=self.inbound_uncraft(self.sk,self.crypto_key)
     except (OSError,ConnectionResetError):
      
      break 
     self.proto_handler(formatted,send_activate,self.recv_activate)
  except KeyboardInterrupt:
    print("recv keyboard interrupt")
    self.EXIT() 

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

