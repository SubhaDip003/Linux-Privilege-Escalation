# Linux-Privilege-Escalation

Welcome to the **Linux-Privilege-Escalation** repository! This project is dedicated to exploring, demonstrating, and documenting various techniques used to escalate privileges on Linux systems. Whether you're a security enthusiast, a penetration tester, or a student learning about Linux security, this repository provides practical insights into how vulnerabilities can be exploited, and how system administrators can better secure their systems.

---

## Table of Contents

- [Overview](https://github.com/SubhaDip003/Linux-Privilege-Escalation/edit/main/README.md)
- [Techniques](https://github.com/SubhaDip003/Linux-Privilege-Escalation)
  - [1. Enumeration](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/1-Enumeration)
  - [2. World-Writable Files](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/2-World-Writable%20Files)
  - [3. SUDO](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/3-SUDO)
  - [4. SUID & SGID Executables](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/4-SUID%20%26%20SGID%20Executables)
  - [5. Capabilities](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/5-Capabilities)
  - [6. Cron Jobs](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/6-Cron%20Jobs)
  - [7. PATH](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/7-PATH)
  - [8. NFS](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/8-NFS)
  - [9. SSH Private Keys](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/9-SSH%20Private%20Keys)
  - [10. Kernel Exploits](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/10-Kernel%20Expliots)
- [Automated Enumeration Tools](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/Automated-Tools)
  
---

---

## Repository Structure

This repository is organized into several subdirectories, each focused on a specific privilege escalation technique:

### 1. [Enumeration:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/1-Enumeration)
- **Description:** Learn the basics and advanced techniques of Linux system enumeration. This section covers methods to gather system information, user data, running services, network configurations, and more, laying the foundation for identifying potential escalation vectors.
- **Directory:** `Enumeration/`

### 2. [World-Writable Files:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/2-World-Writable%20Files)
- **Description:** Explore how world-writable files can be abused to escalate privileges. This section details techniques from basic misconfigurations to advanced exploitation scenarios, emphasizing the importance of proper file permissions.
- **Directory:** `World-Writable-Files/`

### 3. [SUDO:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/3-SUDO)
- **Description:** Investigate methods to escalate privileges via weak or misconfigured sudo permissions. Learn how attackers can abuse SUDO rules and how to mitigate such vulnerabilities.
- **Directory:** `SUDO/`

### 4. [SUID & SGID Executables:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/4-SUID%20%26%20SGID%20Executables)
- **Description:** Understand how weak or misconfigured SUID/SGID permissions can lead to privilege escalation. This section covers how to identify problematic binaries and demonstrates exploitation techniques.
- **Directory:** `SUID-SGID-Executables/`

### 5. [Capabilities:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/5-Capabilities)
- **Description:** Delve into Linux Capabilities and how they can be leveraged by attackers if not configured correctly. Explore techniques for abusing capabilities to achieve unauthorized privilege escalation.
- **Directory:** `Capabilities/`

### 6. [Cron Jobs:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/6-Cron%20Jobs)
- **Description:** Learn how misconfigured Cron Jobs can be exploited to run arbitrary code with elevated privileges. This section includes both common vulnerabilities and advanced exploitation methods.
- **Directory:** `Cron-Jobs/`

### 7. [PATH Environment Variable:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/7-PATH)
- **Description:** Discover how improper configuration of the PATH environmental variable can be a security risk. This section explains techniques for exploiting PATH vulnerabilities to escalate privileges.
- **Directory:** `PATH/`

### 8. [NFS (Network File System):](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/8-NFS)
- **Description:** Understand the risks of NFS root squashing and how improper NFS configurations can provide a means for privilege escalation. Learn about the underlying mechanics and exploitation techniques.
- **Directory:** `NFS/`

### 9. [SSH Private Keys:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/9-SSH%20Private%20Keys)
- **Description:** Examine scenarios where weak or misconfigured SSH private keys can allow unauthorized access. This section outlines techniques to exploit such weaknesses and proper practices for key management.
- **Directory:** `SSH-Private-Keys/`

### 10. [Kernel Exploits:](https://github.com/SubhaDip003/Linux-Privilege-Escalation/tree/main/10-Kernel%20Expliots)
- **Description:** Explore how vulnerable or outdated Linux kernels can be exploited to gain root access. This directory covers known kernel exploits along with mitigation strategies to prevent such attacks.
- **Directory:** `Kernel-Exploits/`

---
## 🤖Automated Enumeration Tools

To streamline and enhance your enumeration efforts, this repository also includes several powerful automated tools:
- [**LinEnum.sh:**](https://github.com/SubhaDip003/Linux-Privilege-Escalation/blob/main/Automated-Tools/LinEnum.sh) A comprehensive bash script for enumerating Linux environments, gathering valuable system information.
- [**LinPEAS.sh:**](https://github.com/SubhaDip003/Linux-Privilege-Escalation/blob/main/Automated-Tools/LinPEAS.sh)  A popular script that automates Linux privilege escalation checks by highlighting potential vulnerabilities.
- [**LinuxExploitSuggester.sh:**](https://github.com/SubhaDip003/Linux-Privilege-Escalation/blob/main/Automated-Tools/LinuxExploitSuggester.sh) An essential tool for suggesting potential kernel exploits based on your system's configuration.
- [**LinuxPrivChecker.sh:**](https://github.com/SubhaDip003/Linux-Privilege-Escalation/blob/main/Automated-Tools/LinuxPrivChecker.sh) Automates the identification of common privilege escalation vectors in Linux.
- [**pspy64s:**](https://github.com/SubhaDip003/Linux-Privilege-Escalation/blob/main/Automated-Tools/pspy64s)  A tool to monitor processes and observe system activity without requiring elevated privileges.
- [**sucrack:**](https://github.com/SubhaDip003/Linux-Privilege-Escalation/blob/main/Automated-Tools/sucrack)  A utility designed to test and expose weaknesses in SUID/SGID binaries for privilege escalation.

Each tool comes with its documentation and usage examples in its respective directory or repository link.

---


## 🔍Resources
- [https://github.com/gurkylee/Linux-Privilege-Escalation-Basics/tree/master]
- [https://github.com/Divinemonk/linux_privesc_cheatsheet]
- [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md]
- [https://github.com/Ignitetechnologies/Linux-Privilege-Escalation]
