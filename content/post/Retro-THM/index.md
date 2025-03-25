---
title: "Retro Writeup THM"
description: "My writeup of the TryHackMe room [Retro](https://tryhackme.com/room/retro)"
date: 2024-01-23T17:00:00+01:00
image: https://raw.githubusercontent.com/Blueaulo/Retro-writeup-THM/main/86aeeb34-ae2f-4bd6-9c9e-4b097945e629_Export-e1ce40fe-b4be-42af-ae4e-bdd7093a35ea/Retro%201d42eb309fba416b8c2ec50ed807d03e/Untitled%201.png
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Windows
    - Privilege Escalation
categories:
    - Room
    - Hard
---

# Retro

First of all I am going to do an nmap scan:

```bash
nmap -Pn -sC -sV -p- 10.10.185.96

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-23 11:18 EST
Nmap scan report for 10.10.185.96
Host is up (0.057s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-01-23T16:20:36+00:00; -3s from scanner time.
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2024-01-22T16:18:23
|_Not valid after:  2024-07-23T16:18:23
| rdp-ntlm-info:
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2024-01-23T16:20:31+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -3s, deviation: 0s, median: -3s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.57 seconds
```

Here we can see that it is hosting a web server and accepts rdp connections.

First of all I am goin g to visit the web page:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Retro-writeup-THM/main/86aeeb34-ae2f-4bd6-9c9e-4b097945e629_Export-e1ce40fe-b4be-42af-ae4e-bdd7093a35ea/Retro%201d42eb309fba416b8c2ec50ed807d03e/Untitled.png)

This is the default page of Microsoft IIS.

Now I am going to start a fuzzer, so we can discover subdirectories:

```bash
ffuf -u 'http://10.10.185.96/FUZZ' -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.185.96/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

retro                   [Status: 301, Size: 149, Words: 9, Lines: 2, Duration: 194ms]
```

We found the subdirectory “retro”

Let’s see what’s in there:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Retro-writeup-THM/main/86aeeb34-ae2f-4bd6-9c9e-4b097945e629_Export-e1ce40fe-b4be-42af-ae4e-bdd7093a35ea/Retro%201d42eb309fba416b8c2ec50ed807d03e/Untitled%201.png)

Ok, from there we can retrieve a lot of informations, first of all is running wordpress 5.2.1 which is kinda old, so maybe I can find some exploit.

Second I found the login page, and we can see that after entering the username “wade” which is the one that is writing the posts, we see that the username exists using a known information disclosure vuln of wp:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Retro-writeup-THM/main/86aeeb34-ae2f-4bd6-9c9e-4b097945e629_Export-e1ce40fe-b4be-42af-ae4e-bdd7093a35ea/Retro%201d42eb309fba416b8c2ec50ed807d03e/Untitled%202.png)

After browsing the site I came upon this message:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Retro-writeup-THM/main/86aeeb34-ae2f-4bd6-9c9e-4b097945e629_Export-e1ce40fe-b4be-42af-ae4e-bdd7093a35ea/Retro%201d42eb309fba416b8c2ec50ed807d03e/Untitled%206.png)

I tried to use it as a password and it worked!

Now we just want to spawn a reverse shell using the dashboard.

Actually, for now we don’t need that. I also tried the credentials with rdp and it worked.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Retro-writeup-THM/main/86aeeb34-ae2f-4bd6-9c9e-4b097945e629_Export-e1ce40fe-b4be-42af-ae4e-bdd7093a35ea/Retro%201d42eb309fba416b8c2ec50ed807d03e/Untitled%204.png)

And we can get our fist flag.

Now, I wanted to use the UAC method to exploit the machine, but I searched and that is bugged, so I used this exploit:

[](https://github.com/SecWiki/windows-kernel-exploits/blob/master/CVE-2017-0213/CVE-2017-0213_x64.zip)

![Untitled](https://raw.githubusercontent.com/Blueaulo/Retro-writeup-THM/main/86aeeb34-ae2f-4bd6-9c9e-4b097945e629_Export-e1ce40fe-b4be-42af-ae4e-bdd7093a35ea/Retro%201d42eb309fba416b8c2ec50ed807d03e/Untitled%205.png)

We just need to open it and we are root.
