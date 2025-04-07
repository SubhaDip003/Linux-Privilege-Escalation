# SUID & SGID Executables
**SUID:** Set User ID is a type of permission that allows users to execute a file with the permissions of a specified user. Those files which have suid permissions run with higher privileges. Assume we are accessing the target system as a non-root user and we found suid bit enabled binaries, then those file/program/command can run with root privileges.

Basically, you can change the permission of any file either using the “Numerical” method or “Symbolic” method. As result, it will replace x from s as shown in the below image which denotes especial execution permission with the higher privilege to a particular file/command. Since we are enabling SUID for Owner (user) therefore bit 4 or symbol s will be added before read/write/execution operation. Basic Enumeration

**GUID** permission is similar to the SUID permission, only difference is – when the script or command with SGID on is run, it runs as if it were a member of the same group in which the file is a member
