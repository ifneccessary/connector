import socket,sys,threading,os,struct,json,datetime
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class DB():
 connections=list() # connection format {user,sk,role,key}
 shell_listeners=list()
 shell_sessions=list()

 def get_connections(self):
  return self.connections
 def add_connection(self,connection):
  self.connections.append(connection)
 def terminate_connection(self,connection):
  for conn in self.connections:
    if conn['key']==connection['key']:
     conn['sk'].close()
     #remove from list

 def check_shell_session(self,connector,target):
  pass

 def terminate_shell_session(self,connector,target):
  pass
 
 @staticmethod
 def MSG(data:str)->dict:
   formatted=dict()
   formatted['type']='MSG'
   formatted['payload']=data
   return formatted

   


class Cryptography():
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




class Shell(DB,Cryptography):
 def shell_share_handle(self,data:dict,conn_config:dict):
  sharer_ip=conn_config['ip']
  sharer_sk=conn_config['sk']
  sharer_user=conn_config['user']
  sharer_os=data['OS']
  sharer_os_release=data['OS-RELEASE']
  sharer_privs=data['RUN-AS']
  shell_config={
   'sk':sharer_sk,
   'sharer':sharer_user,
   'os':f'{sharer_os} {sharer_os_release}',
   'priv':sharer_privs
  }
  self.shell_listeners.append(shell_config)
  broadcast_msg=f'// {sharer_user}:{sharer_ip} EXPOSED SYSTEM ACCESS...\n SYSTEM:{shell_config['os']}\n Privilege:{shell_config['priv']}\n  For accessing system type "SHELL {sharer_user}"'
  dt=json.dumps(self.MSG(broadcast_msg)).encode()
  for conn in self.connections:
   if conn['user']!=sharer_user:
    encr_data=self.encrypt(dt,conn['key'])
    encr_data_len=struct.pack('!I',len(encr_data))
    to_send=encr_data_len+encr_data
    conn['sk'].send(to_send)

 def shell_req_forward(self,data:dict,conn_config:dict):
  target=data['target']
  valid=False
  for listener in self.shell_listeners:
   if listener['user']==target:
    valid=True
    break
  if valid:
   data['connector']=conn_config['user']
   
   #forward request and wait for reply.
   #if reply is positive store shell session (connector <---> shell provider)
   # forward positive to connector. connector will spawn interractive shell abstraction
  
   pass
 def check_listener(self,sharer):
  for listener in self.shell_listeners:
   if listener['sharer']==sharer:
    return True
  return False

 def shell_session_handler(self,data:dict,conn_config:dict):
  target=data['target']
  if self.check_listener(target):
    data['src']=conn_config['user']

    pass
  else:
   #err message that use hs not  setlistener yet
   pass    

class ProtocolHandlers(Shell):
  
 def pub_handler(self,data:dict,conn_config:dict):
    sender=conn_config['user']
    for conn in self.connections:
     if conn['user']!=sender:
      sk=conn['sk']
      encr_key=conn['key']
      data['src']=sender
      jsonized=json.dumps(data).encode()
      encrypted_format=self.encrypt(jsonized,encr_key)
      encr_len=struct.pack('!I',len(encrypted_format))
      data_to_send=encr_len+encrypted_format
      sk.send(data_to_send)
      
  
 def priv_handler(self,data:dict,conn_config:dict):
    target=data['target']
    target_sk=None
    target_key=None
    for conn in self.connections:
     if conn_config['user']!=target and conn['user']==target:
      target_sk=conn['sk']
      target_key=conn['key']
    if not target_sk:
     # this code mustbe changed with non_exist fn from Alerts 
     # self.non_exist(conn_config)
     payload=self.MSG("// you are trying to reach NON-ACTIVE member")
     encrypted_p=self.encrypt(json.dumps(payload).encode(),conn_config['key'])
     encr_p_len=struct.pack('!I',len(encrypted_p))
     to_send=encr_p_len+encrypted_p
     conn_config['sk'].send(to_send)
     return 1
    data['src']=conn_config['user']
    encr_data=self.encrypt(json.dumps(data).encode(),target_key)
    encr_len=struct.pack('!I',len(encr_data))
    to_send=encr_len+encr_data
    target_sk.send(to_send)
    return 0
    
 def ls_handler(self,data:dict,conn_config:dict):
   banner=''
   for connection in self.connections:
    if connection['user'] != conn_config['user']:
     user=connection['user']
     ip=connection['ip'][0]
     time=str(connection['time']).split('.')[0]
     banner+=f'{user}:{ip} JOIN TIME: {time}\n'
   data['payload']=banner
   encr_data=self.encrypt(json.dumps(data).encode(),conn_config['key'])
   encr_d_len=struct.pack('!I',len(encr_data))
   to_send=encr_d_len+encr_data
   conn_config['sk'].send(to_send)   



class Protocol(ProtocolHandlers):

  def proto_handler(self,data:dict,conn_config):
   proto=data['type']
   if proto=='PUB':
    self.pub_handler(data,conn_config)
   elif proto=='PRIV':
    self.priv_handler(data,conn_config)
   elif proto=='LS':
    self.ls_handler(data,conn_config)
   elif proto=='SHELL_SHARE':
    self.shell_share_handle(data,conn_config)
   elif proto=='SHELL_REQ':
    self.shell_req_forward(data,conn_config)
   elif proto=='SHELL_SESSION':
    self.shell_session_handler(data,conn_config)
    

class Security(Protocol):
 def encrypt_session(self,session):
  private_key_local=ec.generate_private_key(ec.SECP256R1())
  public_key_local=private_key_local.public_key().public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  pub_key_server_length=struct.pack('!I',len(public_key_local))
  session.send(pub_key_server_length)
  session.sendall(public_key_local)

  public_key_peer_bytes=b""
  public_key_peer_length=struct.unpack('!I',session.recv(4))[0]
  public_key_peer_recvd_length=0
  while public_key_peer_recvd_length<public_key_peer_length:
   recvd=session.recv(1024)
   public_key_peer_recvd_length+=len(recvd)
   public_key_peer_bytes+=recvd
  public_key_peer=serialization.load_pem_public_key(public_key_peer_bytes)
  shared_sec=private_key_local.exchange(ec.ECDH(),public_key_peer)
  return HKDF(
   algorithm=hashes.SHA256(),
   length=16,
   salt=None,
   info=b'Exchange'
  ).derive(shared_sec)
 
class Auth(Security):
 credential='fidelio'
 
 def auth(self,connection,key):
  is_validname=False
  while not is_validname:
    user=self.get_username(connection,key)
    required_length=3
    if len(user)<required_length:
      msg=f'Username must be at least {required_length} characters'.encode()
      encr_msg=self.encrypt(msg,key)
      msg_len=struct.pack('!I',len(encr_msg))
      send_res=msg_len+encr_msg
      connection.send(send_res)
      continue
    unique=True
    for conn in self.connections:
     if conn['user']==user:
      unique=False
    if not unique:
      msg=b'Someone is already registered with that username'
      encr_msg=self.encrypt(msg,key)
      msg_len=struct.pack('!I',len(encr_msg))
      send_res=msg_len+encr_msg
      connection.send(send_res)
    else:
      is_validname=True
      msg=b'success'
      encr_msg=self.encrypt(msg,key)
      msg_len=struct.pack('!I',len(encr_msg))
      send_res=msg_len+encr_msg
      connection.send(send_res)
  authenticated=self.check(self.get_pass(connection,key))
  return (user,authenticated) 
 
 def get_pass(self,connection,key):
  p_len=connection.recv(4)
  password_length=struct.unpack('!I',p_len)[0]
  recived_pass=b''
  recived_size=0
  while recived_size<password_length:
   recvd=connection.recv(password_length)
   recived_size+=len(recvd)
   recived_pass+=recvd
  decrypted_pass=self.decrypt(recived_pass,key)
  return decrypted_pass.decode()
 
 def get_username(self,connection,key):
  n_len=connection.recv(4)
  username_length=struct.unpack('!I',n_len)[0]
  recived_pass=b''
  recived_size=0
  while recived_size<username_length:
   recvd=connection.recv(username_length)
   recived_size+=len(recvd)
   recived_pass+=recvd
  decrypted_pass=self.decrypt(recived_pass,key)
  return decrypted_pass.decode()
  
 def check(self,password):
  return True if self.credential==password else False

class Alerts(Auth):
 def joined_alert(self,conn_config):
  user=conn_config['user']
  banner=f'***{user} HAS JOINED***'
  for conn in self.connections:
   encr_data=self.encrypt(json.dumps(self.MSG(banner)).encode(),conn['key'])
   encr_data_len=struct.pack('!I',len(encr_data))
   to_send=encr_data_len+encr_data
   conn['sk'].send(to_send)

 
 def encryption_end(self,connection,key):
  pass 
 
 def exist_err(self,conn_config):
  payload=self.MSG("// you are trying to reach NON-ACTIVE member")
  encrypted_p=self.encrypt(json.dumps(payload).encode(),conn_config['key'])
  encr_p_len=struct.pack('!I',len(encrypted_p))
  to_send=encr_p_len+encrypted_p
  conn_config['sk'].send(to_send)
 
 def auth_err_alert(self,connection,key):
   error=b'***Authentication Failure*** ///Incorrect Credentials/// ***Connection Termination***'
   encr_err=self.encrypt(error,key) 
   err_msg_length=struct.pack('!I',len(encr_err))
   data=err_msg_length+encr_err
   connection.send(data)
   connection.close()
  
 def auth_success_alert(self,conn_config,key):
  user=conn_config['user']
  session=conn_config['sk']
  MSG1=f'Successfully joined the group as ***{user}***. type HELP to list Commands'.encode()
  encrypted_msg=self.encrypt(MSG1,key)
  encr_msg_len=struct.pack('!I',len(encrypted_msg))
  session.send(encr_msg_len)
  session.send(encrypted_msg)


class Interpretation(Alerts):
 def handle_l1(self,connection,host_addr):
  KEY=self.encrypt_session(connection)
  user,authenticated=self.auth(connection,KEY)
  conn_config={
     'user':user,
     'ip':host_addr,
     'sk':connection,
     'key':KEY
    }
  if authenticated:
   self.auth_success_alert(conn_config,KEY)
   conn_config['time']=datetime.datetime.now()
   self.joined_alert(conn_config)
   self.add_connection(conn_config)
   self.handle_connection(conn_config)
  else:
   self.auth_err_alert(connection,KEY)
   self.terminate_connection(conn_config)


 def handle_connection(self,conn_config:dict):
  _,_,sock,key,_=tuple(conn_config.values())
  try:
   while True:
    data_length=struct.unpack('!I',sock.recv(4))[0]
    encrypted_data_bytes=b''
    recvd_bytes_len=0
    while recvd_bytes_len < data_length:
      recvd=sock.recv(data_length)
      recvd_bytes_len+=len(recvd)
      encrypted_data_bytes+=recvd
    decrypted_data_bytes=self.decrypt(encrypted_data_bytes,key)
    formatted:dict=json.loads(decrypted_data_bytes)
    self.proto_handler(formatted,conn_config)
  except KeyboardInterrupt:
   pass
   
   
class Server(Interpretation): 
 def __init__(self):
  ip=input("IP: ")
  port=int(input("Port: "))
  self.sk=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  self.sk.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  self.sk.bind((ip,port))
 def run(self):
  self.sk.listen(15)
  try:
   while True:
    connected_socket,peer=self.sk.accept()
    threading.Thread(target=self.handle_l1,args=(connected_socket,peer),daemon=False).start()
  except KeyboardInterrupt:
   print("//Server Termination")
   #alert to connectors, server will be terminated soon
   #close all connections
   #exit program
   sys.exit(0)   
   
if __name__=='__main__':
 server=Server()
 server.run()



