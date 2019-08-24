# **Vulnerable System** : Symphonos2

**Operating System** : Debian 9

**Kernel** : 4.9.0

----------------1st low privilege------------------

**Vulnerability Exploited** : Poorly configured SMB shares/weak password

**Vulnerability Explained** :  Poorly configured SMB shares allowed to obtain a file containing configurations for various services. A username found of the file had a weak password which was then bruteforced.

**Vulnerability fix** : Implement strong permissions on SMB shares implement strong password policy.

**Severity** : **Medium**

----------------2nd low privilege------------------

**Vulnerability Exploited** : LibreNMS addhost Command Injection

**Exploit Used** : Metasploit&#39;s exploit/linux/http/librenms\_addhost\_cmd\_inject

**Proof of Concept Code** : [https://www.exploit-db.com/exploits/46970](https://www.exploit-db.com/exploits/46970)

**Vulnerability Explained** :  This vulnerability allows attacker to execute commands as a user who owns the instance of LibreNMS running. The vulnerability resulted in obtaining a low privilege shell.

**Vulnerability fix** :

**Severity** : **Medium**

**Privilege Escalation Vulnerability** : SQL database running with administrative privileges and is accessible to non privileged user.

**Privilege Escalation Vulnerability Explained:** Due to SQL running as root, a low privileged user was able to connect to MYSQL database and escape into root interface.

**Vulnerability fix** : Make a separate user for MySQL with as least privileges as needed.

**Severity** : **High**

## Nmap

All ports scan:

nmap -p- 192.168.20.142

 ![]()

nmap -sV -sC -A (Version &amp; Default Scripts &amp; Aggressive) scan of selected ports. 

![]()

## Port 80 Enumeration

### Nikto

Nikto enumeration of port 80:

 ![]()

### Gobuster

Gobuster enumeration of port 80:

 ![]()

### Browser

 ![]()

## SMB

SMB enumeration for accessible shares found anonymous share:

 ![]()

Connecting to anonymous share and discovering log.txt file:

 ![]()

The file consisted of a couple of configuration files: smb.conf and proftpd.conf

 ![]()

 ![]()

## FTP

Proftpd.conf file provided us with 2 usersnames: anonymous(ftp) and Aeolus.

As can be seen from the screenshot below anonymous login failed.

 ![]()

## hydra

Hydra was used to bruteforce the password for user Aeolus.

 ![]()

Nothing different was found when enumerating FTP.

 ![]()

## SSH (Low Privilege Shell)

SSH credentials were the same as discovered ftp credentials, which allowed to obtain low privilege shell.

 ![]()

## Privilege Escalation Enumeration:

Doing basic enumeration:

 ![]()

Netstat wasn&#39;t available on the system but SS was:

 ![]()

It seems that there&#39;s an internal webserver running.

## SSH Local Port Forwarding

SSH local port forwarding can be used to enumerate this webpage further:

 ![]()

With Firefox configured to use manual proxy as follows:

 ![]()

Internal port 8080 is now available in the browser:

 ![]()

Successful login with Aeolus&#39; credentials:

 ![]()

## Exploitation

Searching exploit-db for suitable exploit, as can be seen there are 2 version of it a manual exploit and Metasploit:

 ![]()

### Manual Exploit

First attempt will be made with a manual exploit.

 ![]()

A manual exploit was found at: [https://www.exploit-db.com/exploits/47044](https://www.exploit-db.com/exploits/47044)

 ![]()

The exploit requires a cookie, which can be obtained by pressing F12 in your browser after logging in with aoelus&#39; credentials:

 ![]()

Instead of using apache webserver and /var/www/html folder, python&#39;s Simple HTTP Server can be used to serve the exploit from working directory:

 ![]()

Downloading exploit to the victim&#39;s machine:

 ![]()

Although the exploit ran successfully no reverse shell was obtained:

 ![]()

 ![]()

### Metasploit Exploit

Next Metasploit framework can be checked.

In order to access internal website with Metasploit, local port forwarding and proxychains can be used with SSH tunnel we created earlier.

Proxychains allows to proxy traffic through the SSH proxy, allowing Metasploit access to the internal applications of victim&#39;s machine.

In order for Metasploit to launch successfully through proxychains the following line has to be added to /etc/proxychains.conf for postgresql not to error out when launching msfconsole.

localnet 127.0.0.1 000 255.255.255.255

 ![]()

 ![]()

When trying to use the exploit for some reason it was not present in Metasploit:

 ![]()

In this case it can be manually imported from exploit-db as follows:

Create appropriate folder for the exploit in /root/.mfs4/modules/exploits:

 ![]()

Once created copy the exploit into the appropriate folder:

 ![]()

Once done run the updatedb command.

 ![]()

Let&#39;s try this again:

 ![]()

One selected we can use info command to learn more about the exploit:

 ![]()

As can be seen the required options are: password, rhost, rport, targeturi and username. For the reverse shell lhost has to be specified as well.

 ![]()

Once all the options are set, it&#39;s ready to be exploited:

 ![]()

## Second Low Privilege Shell &amp; Enumeration

This time around the low privilege shell was obtained for user cronus and python -c &quot;import pty;pty.spawn(&#39;/bin/bash&#39;)&quot; command was used to escape the default shell.

 ![]()

Sudo -l can be used to check if this user has any sudo privileges:

 ![]()

## Root

As can be seen on the screenshot above, user cronus can execute /usr/bin/mysql with administrative privileges.

Mysql also can be escaped into a shell with \! /bin/bash commands.

Using mysql command execution and escape capability, high privileged shell can be obtained as following:

 ![]()

Proof file:

 ![]()
