# World-Writable Files
If config files like /etc/passwd, /etc/shadow, or /etc/sudoers are writable, you can manipulate them for privilege escalation.
As an ethical hacker or penetration tester, exploiting world-writable files is a common technique for privilege escalation on Linux systems. World-writable files allow any user to write to them, which can be leveraged to gain higher privileges. Here are some techniques to exploit world-writable files for privilege escalation:

## /etc/shadow file:
The /etc/shadow file contains user password hashes and is usually readable only by the root user.

### Method-1: Crack Password using John The Ripper:
Try to Creach the password using John The Ripper.
```
ls -la /etc/shadow		# Check the /etc/shadow file permission
cat /etc/shadow			# View the content.
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

### Method-2: 
