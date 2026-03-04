import socket,sys,threading,os,struct,json,datetime,time
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class DB():
 terminate_threads=threading.Event()
 connections=list() # connection format {user,sk,role,key}
 shell_listeners=list()# {sharer,sk,key}
 shell_sessions=list() # {sharer_sk,sharer_user,sharer_key,connector_sk,connector_user,conector_key}
 
 def get_connections(self):
  return self.connections
 def add_connection(self,connection):
  self.connections.append(connection)
 def terminate_connection(self,connection):
  for conn in self.connections:
    if conn['key']==connection['key']:
     conn['sk'].close()
     break
  self.connections=[c for c in self.connections if c['key']!=connection['key']]  
 def terminate_connections(self):
  for conn in self.connections:
    conn['sk'].close()

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

class Crafters(DB,Cryptography):
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
 
 # fix this
 def craft(self,data,key=None)->bytes:
  _data:bytes=b''
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
    raise ConnectionResetError()
   l=struct.unpack('!I',length)[0]
   recvd_l=0
   recvd_b=b''
   while recvd_l<l:
    recvd=sock.recv(l-recvd_l) 
    recvd_l+=len(recvd)
    recvd_b+=recvd
   if key:
    recvd_b=self.decrypt(recvd_b,key) 
   if decode: 
    return recvd_b.decode()
   return recvd_b
 
 def broadcast(self,msg,filter_by=None,subtype=None):
  msg=self.MSG(msg)
  if subtype:
    msg['type']=subtype
  for conn in self.connections:
   if filter_by and conn['user']==filter_by: 
    continue
   key=conn['key']
   sk=conn['sk']
   sk.sendall(self.craft(msg,key))

class Validator(Crafters):
 def validate(self,data,conn_config):
    proto=data['type'].upper()
    if proto=='PUB':
     data['payload']=data['payload'].strip()
     return data
    if proto=='PRIV':
     data['target']=data['target'].strip()
     data['payload']=data['payload'].strip()
     return data
    if proto=='LS' or proto=='SHELLS' or proto=='SHELL_REQ' or proto=='SYSTEMS' or proto=='CANCEL_SHELL_SHARE':
      return data
    if proto=='SHELL_SHARE':
     data['scope']=[scp.strip() for scp in data['scope']]
     return data
    if proto=='SHEL_REQ':
     return data
    if proto=='SHELL_SESSION':
     data['dst']=data['dst'].strip()
     if data['dir']=='-->':
      data['cmd']=data['cmd'].strip()
     else:
      data['stdout']=data['stdout'].strip()
     return data  
    if proto=='SHELL_TERM_REQUEST':
     data['connector']=data['connector'].strip()
     data['sharer']=data['sharer'].strip()
     return data    
    if proto=='READ':
     data['channel']=data['channel'].strip()
     return data
   
class Shell(Crafters):
 def shell_share_broadcast(self,data:dict,conn_config:dict):
  sharer_ip=conn_config['ip']
  sharer_sk=conn_config['sk']
  scope=data['scope']
  SCOPE=' '.join([user for user in scope])
  sharer_user=conn_config['user']
  sharer_os=data['OS']
  sharer_os_release=data['OS-RELEASE']
  sharer_privs=data['RUN-AS']
  subtype=data['subtype']
  shell_config={
   'sharer_sk':sharer_sk,
   'sharer':sharer_user,
   'sharer_key':conn_config['key'],
   'os':f'{sharer_os} {sharer_os_release}',
   'priv':sharer_privs,
   'scope':scope,
   'subtype':subtype
  }
  self.shell_listeners.append(shell_config)
  broadcast_msg=f'// {sharer_user}:{sharer_ip} EXPOSED SYSTEM ACCESS...\n SYSTEM: {shell_config['os']}\n RUN-AS: {shell_config['priv']}\n Scope: [{SCOPE}]\n For accessing system type "SHELL {sharer_user}"'
  self.broadcast(broadcast_msg)
 
 def shell_req_forward(self,data:dict,conn_config:dict):
  initiator_sk=conn_config['sk']
  initiator_user=conn_config['user']
  sharer=data['target']
  run_as=None
  sharer_sk:socket.SocketType;
  sharer_key=None
  subtype=None
  
  valid=False
  for listener in self.shell_listeners:
   if listener['sharer']==sharer and (listener['scope']==['PUBLIC'] or initiator_user in listener['scope']):
    sharer_sk=listener['sharer_sk']
    sharer_key=listener['sharer_key']
    run_as=listener['priv']
    subtype=listener['subtype']
    valid=True
    break
  
  if valid:
   sess_id=len(self.shell_sessions)+1
   data['connector']=initiator_user
   data['id']=sess_id
   fin_forw=self.craft(data,sharer_key)
   sharer_sk.sendall(fin_forw)

   shell_sess_config={
     'id':sess_id,
     'connector_sk':initiator_sk,
     'sharer_sk':sharer_sk,
     'connector_user':initiator_user,
     'sharer_user':sharer,
     'connector_key':conn_config['key'],
     'sharer_key': sharer_key,
     'time':time.perf_counter(),
     'subtype':subtype,
     'channel_sniffers':[]
    }
   self.shell_sessions.append(shell_sess_config)
   response={
     'type':'SHELL_RESP',
     'status':'TRUE',
     'sharer':sharer,
     'run-as':run_as,
     'id':sess_id
    }
   req_res=self.craft(response,conn_config['key'])
   initiator_sk.sendall(req_res)
  else:
    response={
     'type':'SHELL_RESP',
     'status':'FALSE',
     'code':f'// Failed to get shell...\n {sharer} either does not expose system access or does not exist!\n'
    }
    res=self.craft(response,conn_config['key'])
    initiator_sk.sendall(res)

 def shell_forward(self, data: dict, conn_config: dict):
    session_id = data.get('id')
    target_session = None
    for session in self.shell_sessions:
        if session['id'] == session_id:
            target_session = session
            break

    if not target_session:
        return
      
    direction = data['dir']

    if direction == '-->':
        target_sk = target_session['sharer_sk']
        target_key = target_session['sharer_key']
    else:
        target_sk = target_session['connector_sk']
        target_key = target_session['connector_key']

    data['src'] = conn_config['user']
    data['id']=session_id
    target_sk.sendall(self.craft(data, target_key))

    # sniffers
    if direction == '<--' and target_session['channel_sniffers']:
        for sk, key, _ in target_session['channel_sniffers']:
            sniffed = data.copy()
            sniffed['type'] = 'SHELL_SNIFFED'
            sk.sendall(self.craft(sniffed, key))

 
 def terminate_sSession(self,data:dict,conn_config:dict):
  x=data['connector']
  y=data['sharer']
  self.shell_sessions=[session for session in self.shell_sessions if session['connector_user']!=x and session['sharer_user']!=y]

 def cancel_share(self,conn_config:dict):
  sharer=conn_config['user']
  self.shell_listeners=[listener for listener in self.shell_listeners if listener['sharer']!=sharer]
  self.broadcast(f'// {sharer} has stopped System Sharing...\n')
 
 def read_channel(self,chann_id,conn_config:dict):
  failed=True
  for channel in self.shell_sessions:
   if channel['id']==int(chann_id.strip()) and channel['subtype']=='PUB':
     channel['channel_sniffers'].append((conn_config['sk'],conn_config['key'],conn_config['user']))
     failed=False
     print('added to snifferrs')
     break
  if failed:
   conn_config['sk'].sendall(self.craft(self.MSG('// Channel Sniffing is not enabled for that specific Shell!'),conn_config['key'])) 
   

class ProtocolHandlers(Shell):
  
 def pub_handler(self,data:dict,conn_config:dict):
    sender=conn_config['user']
    for conn in self.connections:
     if conn['user']!=sender:
      sk=conn['sk']
      encr_key=conn['key']
      data['src']=sender
      sk.sendall(self.craft(data,encr_key))
      
  
 def priv_handler(self,data:dict,conn_config:dict):
    target=data['target']
    target_sk=None
    target_key=None
    for conn in self.connections:
     if conn_config['user']!=target and conn['user']==target:
      target_sk=conn['sk']
      target_key=conn['key']
    if not target_sk:
     payload=self.MSG("// you are trying to reach NON-ACTIVE member")
     to_send=self.craft(payload,conn_config['key'])
     conn_config['sk'].send(to_send)
     return 1
    data['src']=conn_config['user']
    to_send=self.craft(data,target_key)
    target_sk.send(to_send)
    return 0
    
 def ls_handler(self,data:dict,conn_config:dict):
   banner=''
   if len(self.connections)>1:
    for connection in self.connections:
      if connection['user'] != conn_config['user']:
        user=connection['user']
        ip=connection['ip'][0]
        time=str(connection['time']).split('.')[0]
        banner+=f'{user}:{ip} JOIN TIME: {time}\n'
   else:
    banner=f'// no active members except you...'
   data['payload']=banner
   to_send=self.craft(data,conn_config['key'])
   conn_config['sk'].send(to_send)   
 
 def ls_systems(self,data:dict,conn_config:dict):
  display=''
  if len(self.shell_listeners)>=1:
    display=f'List of Exposed System Access:\n'
    for listener in self. shell_listeners:
      os=listener['os']
      priv=listener['priv']
      scope=listener['scope']
      sharer=listener['sharer']
      if len(scope)>1:
       scope=",".join([to for to in scope])
      else:
        scope=scope[0] 
      active=f'USER: {sharer} | SYSTEM: {os} | RUN-AS: {priv} | SCOPE: {scope}\n'
      display+=active
  else:    
   display='// no systems has been exposed...'    
  on_wire=self.craft(self.MSG(display),conn_config['key'])
  conn_config['sk'].sendall(on_wire)
 
 def ls_shells(self,data:dict,conn_config:dict):
  display=''
  if len(self.shell_sessions)>=1:
    display=f'List of Currently Active Shell Sessions:\n'
    sniffers=''
    for session in self.shell_sessions:
      connector=session['connector_user']
      sharer=session['sharer_user']
      duration=round(time.perf_counter()-session['time'])
      chann_id=session['id']
      if session['channel_sniffers']:
       print(f'sniffers {session['channel_sniffers']}')
       for sniffer in session['channel_sniffers']:
        sniffers+=f'/{sniffer[2]}/'
      active=f'ID: {chann_id} | {connector} ---> {sharer} | sniffing:{"ON" if session['subtype']=="PUB" else "OFF"} | {f"sniffers:[{sniffers}] |" if sniffers else ''} --- [Active for {duration}s]\n'
      display+=active
  else:
   display='// no active shell sessions...'    
  on_wire=self.craft(self.MSG(display),conn_config['key'])
  conn_config['sk'].sendall(on_wire)
 
 def EXIT(self,conn_config):
  user=conn_config['user']
  updated=[]
  for conn in self.connections:
   if conn['user']==user:
    try:
     conn['sk'].shutdown(socket.SHUT_RDWR)
    except OSError:
      pass
    finally:
     conn['sk'].close()
   else:
    updated.append(conn)
  self.connections=updated   
  self.broadcast(f'// {user} left')


class Protocol(ProtocolHandlers):
  
  def proto_handler(self,data:dict,conn_config):
   proto=data['type'].upper()
   if proto=='EXIT_MAIN':
    self.EXIT(conn_config)
   elif proto=='PUB':
    self.pub_handler(data,conn_config)
   elif proto=='PRIV':
    self.priv_handler(data,conn_config)
   elif proto=='LS':
    self.ls_handler(data,conn_config)
   elif proto=='SHELL_SHARE':
    self.shell_share_broadcast(data,conn_config)
   elif proto=='SHELL_REQ':
    self.shell_req_forward(data,conn_config)
   elif proto=='SHELL_SESSION':
    self.shell_forward(data,conn_config)
   elif proto=='SHELLS':
    self.ls_shells(data,conn_config)
   elif proto=='SYSTEMS':
    self.ls_systems(data,conn_config)
   elif proto=='SHELL_TERM_REQUEST':
    self.terminate_sSession(data,conn_config)
   elif proto=='CANCEL_SHELL_SHARE':
    self.cancel_share(conn_config)
   elif proto=='READ':
    self.read_channel(data['channel'],conn_config)
   

class Security(Protocol):
 def encrypt_session(self,session):
  private_key_local=ec.generate_private_key(ec.SECP256R1())
  public_key_local=private_key_local.public_key().public_bytes(
   encoding=serialization.Encoding.PEM,
   format=serialization.PublicFormat.SubjectPublicKeyInfo
  )
  session.sendall(self.craft(public_key_local))
  public_key_peer=self.outbound_uncraft(session,decode=False)
  shared_sec=private_key_local.exchange(ec.ECDH(),serialization.load_pem_public_key(public_key_peer))
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
    print(user)
    if len(user)<required_length:
      msg=f'Username must be at least {required_length} characters'.encode()
      send_res=self.craft(msg,key)
      print(f'sending {msg}')
      connection.send(send_res)
      continue
    unique=True
    for conn in self.connections:
     if conn['user']==user:
      unique=False
    if not unique:
      msg=b'Someone is already registered with that username'
      send_res=self.craft(msg,key)
      print(f'sending {msg}')
      connection.send(send_res)
    else:
      is_validname=True
      msg='success'
      send_res=self.craft(msg,key)
      print(f'sending {msg}')
      connection.sendall(send_res)
  authenticated=self.check(self.get_pass(connection,key))
  return (user,authenticated) 
 
 def get_pass(self,connection,key):
  return self.outbound_uncraft(connection,key)

 def get_username(self,connection,key):
   return self.outbound_uncraft(connection,key)
  
 def check(self,password):
  return True if self.credential==password else False

class Alerts(Auth):
 def joined_alert(self,conn_config):
  user=conn_config['user']
  banner=f'***{user} HAS JOINED***'
  for conn in self.connections:
   to_send=self.craft(self.MSG(banner),conn['key'])
   conn['sk'].send(to_send)

 def exist_err(self,conn_config):
  payload=self.MSG("// you are trying to reach NON-ACTIVE member")
  to_send=self.craft(payload,conn_config['key'])
  conn_config['sk'].send(to_send)
 
 def auth_err_alert(self,connection,key):
   error=b'***Authentication Failure*** ///Incorrect Credentials/// ***Connection Termination***'
   data=self.craft(error,key)
   connection.send(data)
   connection.close()
  
 def auth_success_alert(self,conn_config,key):
  user=conn_config['user']
  session=conn_config['sk']
  MSG1=f'Successfully joined the group as ***{user}***. type HELP to list Commands'.encode()
  msg=self.craft(MSG1,key)
  session.send(msg)


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
 
 def allow_ip(self,ip):
  count=0
  if len(self.connections)==0:return True
  for conn in self.connections:
   if ip==conn['ip']:
    count+=1
  if count<=3:  
   return True
  return  False
    
 def allow_connection(self):
  if len(self.connections)<10:
    return True
  return False
 
 def deny_connection(self,sk,msg):
   sk.sendall(self.craft(msg))
   sk.close()
  
 def handle_connection(self,conn_config:dict):
  _,_,sock,key,_=tuple(conn_config.values())
  try:
   while not self.terminate_threads.is_set():
    try:
     formatted=self.inbound_uncraft(sock,key)
    except (OSError,ConnectionResetError):
     sock.close()
     break
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
  self.sk.listen(10)
  try:
   while True:
    connected_socket,peer=self.sk.accept()    
    if not self.allow_connection():   
     self.deny_connection(connected_socket,'// group is full... Connection Error!')
     continue
    if not self.allow_ip(peer[0]):
     self.deny_connection(connected_socket,f'// more than 3 connections has been detected from your IP address. Connection Error!\n')
     continue
    threading.Thread(target=self.handle_l1,args=(connected_socket,peer[0]),daemon=True).start()
  except KeyboardInterrupt:
   print("\n// Server Termination")
   self.broadcast("// Server will be terminated soon...")
   time.sleep(0.2)
   self.broadcast("// Terminating shell channels...",subtype='SERVER_TERMINATION')
   sys.exit(0)  
    
   
if __name__=='__main__':
 server=Server()
 server.run()



