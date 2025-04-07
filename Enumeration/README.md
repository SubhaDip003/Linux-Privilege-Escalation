# Enumeration

Enumeration is the first step you have to take once you gain access to any system. You may have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account. Penetration testing engagements, unlike CTF machines, don't end once you gain access to a specific system or user privilege level. As you will see, enumeration is as important during the post-compromise phase as it is before.

# 🔍Manual Enumeration

## 📌hostname Commands:
The hostname command will return the hostname of the target machine. Although this value can easily be changed or have a relatively meaningless string (e.g. Ubuntu-3487340239), in some cases, it can provide information about the target system’s role within the corporate network (e.g. SQL-PROD-01 for a production SQL server).
```
hostname   		# → Displays the system’s hostname (computer name)
hostname -i		# → Shows the IP address associated with the hostname
hostname -I		# → Lists all IP addresses assigned to the system
hostname -f 		# → Displays the FQDN (Fully Qualified Domain Name)
hostname -d		# → Shows the domain name of the system
hostname -A 		# → Displays all FQDNs for the host
hostnamectl 		# → Gives detailed info about the hostname and OS
cat /etc/hostname	# → Prints the hostname from the config file
```

## 📌uname Commands:
Will print system information giving us additional detail about the kernel used by the system. This will be useful when searching for any potential kernel vulnerabilities that could lead to privilege escalation.
```
uname 		# → Shows the kernel name (usually "Linux").
uname -a 	# → Displays all system information: kernel name, version, architecture, etc. Useful for quick recon.
uname -r	# → Shows the kernel version. Important for identifying potential vulnerabilities.
uname -s	# → Displays only the kernel name (similar to uname).
uname -v	# → Shows the kernel build version/date (when it was compiled).
uname -m	# → Displays the machine hardware name (e.g., x86_64, i686), which tells you the architecture.
uname -p	# → Shows the processor type (might be same as -m, or "unknown").
uname -i	# → Displays the hardware platform (can also show "unknown" on some systems).
uname --help	# → Shows help info with all available options.
uname --version	# → Shows the version of the uname utility itself.
```

## 📌/proc/version file:
The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.
Looking at /proc/version may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.
```
cat /proc/version
```

## 📌/etc/issue file:
Systems can also be identified by looking at the /etc/issue file. This file usually contains some information about the operating system but can easily be customized or changed. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.
```
cat /etc/issue
```

## 📌ps Commands:
The ps command is an effective way to see the running processes on a Linux system. Typing ps on your terminal will show processes for the current shell.
The output of the ps (Process Status) will show the following;
- **PID:** The process ID (unique to the process)
- **TTY:** Terminal type used by the user
- **Time:** Amount of CPU time used by the process (this is NOT the time this process has been running for)
- **CMD:** The command or executable running (will NOT display any command line parameter)
```
ps -A		# → View all running processes
ps aux		# → Lists all running processes with details like user, PID, CPU usage, memory, command, etc.
ps -ef		# → Displays full-format listing of all processes (similar to ps aux).
ps axjf		# → Displays processes in a tree format to see relationships.

ps aux | grep root		# → Filters all processes run by or related to the root user.
ps -eo pid,ppid,user,cmd	# → Customized output showing process ID, parent process ID, user, and command.
ps aux | grep apache		# → Checks if Apache (web server) is running and under which user.
ps aux | grep mysql		# → Finds running MySQL database processes.
ps -u <username>		# → Shows all processes run by a specific user.
ps -p <pid> -o cmd=		# → Shows the full command of a specific process by PID.
ps -eo user,group,comm		# → Shows which user/group is running which command.

```

## 📌env Command:
The env command will show environmental variables.
```
env	# → The env command will show environmental variables.

```
The PATH variable may have a compiler or a scripting language (e.g. Python) that could be used to run code on the target system or leveraged for privilege escalation.

## sudo -l Command:
The target system may be configured to allow users to run some (or all) commands with root privileges. The sudo -l command can be used to list all commands your user can run using sudo.
```
sudo -l
```

## 📌ls Command:
One of the common commands used in Linux is probably ls.
While looking for potential privilege escalation vectors, please remember to always use the ls command with the -la parameter to show the hidden files (.files).
```
ls -la
```

## 📌Id Command:
The id command will provide a general overview of the user’s privilege level and group memberships.
It is worth remembering that the id command can also be used to obtain the same information for another user as seen below.
```
id
```

## 📌/etc/passwd file:
Reading the /etc/passwd file can be an easy way to discover users on the system. 
```
cat /etc/passwd				# → Read the content of the file.
cat /etc/passwd | cut -d ":" -f 1	# → Lists all the usernames on the system.
cat /etc/passwd | grep home		# → Shows users who have a home directory, usually real human users, not system accounts.
```

##  📌history Command:
Looking at earlier commands with the history command can give us some idea about the target system and, albeit rarely, have stored information such as passwords or usernames. 
```
history
```

## 📌ifconfig Command:
The target system may be a pivoting point to another network. The ifconfig command will give us information about the network interfaces of the system.
```
ifconfig
ip route	# → To see which network routes exist.
```

## 📌netstat Commands:
Following an initial check for existing interfaces and network routes, it is worth looking into existing communications. The netstat command can be used with several different options to gather information on existing connections. 
```
netstat -a	# → shows all listening ports and established connections.
netstat -at	# → Displays TCP connections only.
netstat -au	# → Displays UDP connections only.
netstat -l	# → list ports in “listening” mode. These ports are open and ready to accept incoming connections.
netstat -lt	# → Lists listening TCP ports only.
netstat -s	# → Shows network statistics (like packets sent/received, errors).
netstat -tp	# → list connections with the service name and PID information.
netstat -ltp	# → Lists listening TCP ports with PIDs.
netstat -i	# → Displays network interfaces and statistics.
netstat -ano	# → Lists all connections with: a=all connections, n=shows numeric addresses, o=shows owning process ID (PID)
```

## 📌find Command:
Searching the target system for important information and potential privilege escalation vectors can be fruitful. The built-in “find” command is useful and worth keeping in your arsenal.
Below are some useful examples for the “find” command. 
```
find . -name flag1.txt 2>/dev/null		# → find the file named “flag1.txt” in the current directory
find /home -name flag1.txt 2>/dev/null		# → find the file names “flag1.txt” in the /home directory
find / -type d -name config 2>/dev/null		# → find the directory named config under “/”
find / -type f -perm 0777 2>/dev/null		# → find files with the 777 permissions (files readable, writable, and executable by all users)
find / -perm a=x 2>/dev/null			# → find executable files
find /home -user frank 2>/dev/null		# → find all files for user “frank” under “/home”
find / -mtime 10 2>/dev/null			# → find files that were modified in the last 10 days
find / -atime 10 2>/dev/null			# → find files that were accessed in the last 10 day
find / -cmin -60 2>/dev/null			# → find files changed within the last hour (60 minutes)
find / -amin -60 2>/dev/null			# → find files accesses within the last hour (60 minutes)
find / -size 50M 2>/dev/null			# → find files with a 50 MB size. This command can also be used with (+) and (-) signs to specify a file that is larger or smaller than the given size.

find / -writable -type d 2>/dev/null		# → Find world-writeable folders
find / -perm -222 -type d 2>/dev/null		# → Find world-writeable folders
find / -perm -o w -type d 2>/dev/null		# → Find world-writeable folders

find / -perm -o x -type d 2>/dev/null		# → Find world-executable folders

# → Find development tools and supported languages:
find / -name perl*
find / -name python*
find / -name gcc*

# → Find specific file permissions:
find / -perm -u=s -type f 2>/dev/null		# → Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.

# Enumerate Backups:
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \(-name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null

# Enumerate DBs:
find / -name '.db' -o -name '.sqlite' -o -name '*.sqlite3' 2>/dev/null

# Enumerate Hidden Files
find / -type f -iname ".*" -ls 2>/dev/null
```

# 🔍Some Other Manual Enumeration

## 📌Basic System Enumeration:
```
uname -a		# → Displays detailed system information including kernel name, version, and architecture.
hostname              	# → Displays the system’s hostname (computer name).
lscpu                	# → Shows CPU architecture details like number of cores, threads, model name, etc.
ls /home              	# → Lists user directories in the /home directory.
ls /var/www/html      	# → Lists web files in the default Apache web server directory.
ls /var/www/          	# → Lists contents of the main web server directory.
ps aux | grep root    	# → Shows running processes owned by root.
netstat -tulpn        	# → Displays active TCP/UDP connections with the process ID and names.
ifconfig              	# → Displays network interface configurations (IP address, MAC, etc.).
locate pass | more    	# → Finds file paths with "pass" in their name using the locate database and shows them page by page.
sudo -V			# → Sudo Version
netstat -anlp		# Enumerate Services
netstat -ano		# Enumerate Services
ps aux | grep root	# Enumerate root run binaries.
cat /etc/shells		# Enumerate shells
echo $SHELL		# Enumerate current shell.
/bin/bash --version	# Enumerate shell version.



find . -type f -exec grep -i -I "PASSWORD=" {} /dev/null \;  # → Searches for files containing "PASSWORD=" in the current directory and subdirectories.
ps -aux | grep root | grep mysql  	# → Filters processes running as root and related to MySQL.
cat /etc/passwd | cut -d ":" -f 1	# Enumerate System users.
cat /etc/group | cut -d ":" -f 1 	# Enumerate system groups.
cat /etc/crontab | grep 'root'		# Enumerate root crontab.

# Enumerate binary Version:
program -v
program --version
program -V
dpkg -l | grep "program"

# Enumerate Programming Languages
which python
which perl
which ruby
which lua0					
```
## 📌Bash History
```
history                            
cat /home/<user>/.bash_history     
cat ~/.bash_history | grep -i passw 
```
## 📌OpenVPN Credentials
```
locate *.ovpn                       
```
## 📌Credentials in tcpdump files
```
tcpdump -nt -r capture.pcap -A 2>/dev/null | grep -P 'pwd='                    
```

## General Linux Commands:
As we are in the Linux realm, familiarity with Linux commands, in general, will be very useful. Please spend some time getting comfortable with commands such as find, locate, grep, cut, sort, etc. 

# Automated Enumeration Tools
Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

The target system’s environment will influence the tool you will be able to use. For example, you will not be able to run a tool written in Python if it is not installed on the target system. This is why it would be better to be familiar with a few rather than having a single go-to tool.

  - **LinPeas:** https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS
  - **LinEnum:** https://github.com/rebootuser/LinEnum
  - **LES (Linux Exploit Suggester):** https://github.com/mzet-/linux-exploit-suggester
  - **Linux Smart Enumeration:** https://github.com/diego-treitos/linux-smart-enumeration
  - **Linux Priv Checker:** https://github.com/linted/linuxprivchecker 

