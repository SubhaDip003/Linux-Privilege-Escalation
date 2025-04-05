# Enumeration

Enumeration is the first step you have to take once you gain access to any system. You may have accessed the system by exploiting a critical vulnerability that resulted in root-level access or just found a way to send commands using a low privileged account. Penetration testing engagements, unlike CTF machines, don't end once you gain access to a specific system or user privilege level. As you will see, enumeration is as important during the post-compromise phase as it is before.

## hostname:
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

## uname:
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

## /proc/version file:
The proc filesystem (procfs) provides information about the target system processes. You will find proc on many different Linux flavours, making it an essential tool to have in your arsenal.
Looking at /proc/version may give you information on the kernel version and additional data such as whether a compiler (e.g. GCC) is installed.

## /etc/issue file:
Systems can also be identified by looking at the /etc/issue file. This file usually contains some information about the operating system but can easily be customized or changed. While on the subject, any file containing system information can be customized or changed. For a clearer understanding of the system, it is always good to look at all of these.

## ps Command:
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

## 
