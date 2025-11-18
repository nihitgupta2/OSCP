# Active Directory Enumeration - Cheat Sheet

## 1. AD Fundamentals

### Core Concepts

-   Active Directory (AD): Centralized service for managing users,
    computers, and resources
-   Domain Controller (DC): Hub storing all OUs, objects, and attributes
-   LDAP: Protocol used to communicate with AD
-   Distinguished Name (DN): Unique identifier for objects (e.g.,
    CN=User,CN=Users,DC=corp,DC=com)
-   Domain Components (DC): Top of LDAP tree representing domain
    (DC=corp,DC=com)
-   Common Name (CN): Identifier of an object within the domain

### Key Groups

-   Domain Admins
-   Enterprise Admins
-   Service Accounts

### Enumeration Goals

-   Map the domain structure
-   Identify high-value targets
-   Find misconfigurations
-   Discover privilege escalation paths

## 2. Manual Enumeration Tools

### Legacy Windows Tools (net.exe)

    net user /domain
    net user <username> /domain
    net group /domain
    net group "Group Name" /domain

### PowerShell & .NET Classes

    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DN = ([adsi]'').distinguishedName
    $LDAP = "LDAP://$PDC/$DN"      //LDAP://HostName[:PortNumber][/DistinguishedName]

#### Directory Search Function

    function LDAPSearch {
        param ([string]$LDAPQuery)
        $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
        $DN = ([adsi]'').distinguishedName
        $LDAP = "LDAP://$PDC/$DN"
        $direntry = New-Object System.DirectoryServices.DirectoryEntry($LDAP)
        $dirsearcher = New-Object System.DirectoryServices.DirectorySearcher($direntry, $LDAPQuery)
        return $dirsearcher.FindAll()
    }

#### Examples

    LDAPSearch -LDAPQuery "(samAccountType=805306368)"
    LDAPSearch -LDAPQuery "(objectClass=group)"
    LDAPSearch -LDAPQuery "(name=username)"
    
    foreach ($group in $(LDAPSearch -LDAPQuery "(objectCategory=group)")) {$group.properties | select {$_.cn}, {$_.member}}

    LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Development Department*))"

### PowerView Commands

    Import-Module .\PowerView.ps1
    Get-NetDomain
    Get-NetUser
    Get-NetGroup
    Get-NetGroupMember
    Get-NetComputer
    Get-NetSession
    Find-LocalAdminAccess
    Get-NetUser -SPN

## 3. Manual Advanced Enumeration

### PowerView
```
Get-NetComputer | select operatingsystem,dnshostname
```
- PowerView's Find-LocalAdminAccess command scans the network to determine if our current user has administrative permissions on any computers in the domain.

### PsLoggedOn

    .\PsLoggedon.exe \\<hostname>
    Example - .\PsLoggedon.exe \\files04

### SPNs

    setspn -L <username>
    Get-NetUser -SPN

### Object Permissions (ACLs)

    Get-ObjectAcl -Identity "Object Name"
    Convert-SidToName <SID>

#### Exploiting Weak Permissions

    net group "Group Name" <username> /add /domain
    net group "Group Name" <username> /del /domain

### Domain Shares

    Find-DomainShare
    Find-DomainShare -CheckShareAccess
    ls \<hostname>\<share>
    cat \<hostname>\<share>\<file>

### GPP Password Decryption
System administrators often changed local workstation passwords through Group Policy Preferences (GPP).However, even though GPP-stored passwords are encrypted with AES-256, the private key for the encryption has been posted on MSDN.
    
    gpp-decrypt "<encrypted_password>"

## 4. Automated Enumeration - BloodHound

### SharpHound Collection

    Import-Module .\Sharphound.ps1
    Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Path\ -OutputPrefix prefix

### BloodHound Analysis

-   Upload SharpHound ZIP
-   Mark owned principals
-   Run prebuilt queries

  ```
  # To start bloodhound we need to start Neo4j
  sudo neo4j start
  # http://localhost:7474. Let's browse this location and authenticate using the default credentials (neo4j as both username and password):
  bloodhound
  ```

## 5. Common Attack Paths

    stephanie → AdminTo CLIENT74 → jeffadmin HasSession → MemberOf Domain Admins

## 6. Important Notes

-   Re-enumerate after each pivot
-   Document all findings
-   SharpHound generates significant traffic

## 7. Quick Reference Commands

    Get-NetUser
    Get-NetGroup
    Get-NetComputer
    Invoke-BloodHound -CollectionMethods All

## 8. Tool Summary

-   net.exe
-   PowerShell
-   PowerView
-   PsLoggedOn
-   SharpHound
-   BloodHound

## 9. Key Registry Paths

    HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity

## 10. Troubleshooting

    powershell -ep bypass
    Get-Help <command>
