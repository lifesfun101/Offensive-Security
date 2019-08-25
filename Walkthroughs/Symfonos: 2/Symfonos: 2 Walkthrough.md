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

**Vulnerability fix** : No fixes were found.

**Severity** : **Medium**

**Privilege Escalation Vulnerability** : SQL database running with administrative privileges and is accessible to non privileged user.

**Privilege Escalation Vulnerability Explained:** Due to SQL running as root, a low privileged user was able to connect to MYSQL database and escape into root interface.

**Vulnerability fix** : Make a separate user for MySQL with as least privileges as needed.

**Severity** : **High**

## Nmap

All ports scan:

nmap -p- 192.168.20.142

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/nmap%20all%20ports.png)

nmap -sV -sC -A (Version &amp; Default Scripts &amp; Aggressive) scan of selected ports. 

![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/nmap_sv_sc.png)

## Port 80 Enumeration

### Nikto

Nikto enumeration of port 80:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/nikto.png)

### Gobuster

Gobuster enumeration of port 80:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/gobuster.png)

### Browser

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/browser.png)

## SMB

SMB enumeration for accessible shares found anonymous share:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/smb1.png)

Connecting to anonymous share and discovering log.txt file:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/smb2.png)

The file consisted of a couple of configuration files: smb.conf and proftpd.conf

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/file.png)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/file1.png)

## FTP

Proftpd.conf file provided us with 2 usersnames: anonymous(ftp) and Aeolus.

As can be seen from the screenshot below anonymous login failed.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/ftp.png)

## hydra

Hydra was used to bruteforce the password for user Aeolus.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/hydra.png)

Nothing different was found when enumerating FTP.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/ftp2.png)

## SSH (Low Privilege Shell)

SSH credentials were the same as discovered ftp credentials, which allowed to obtain low privilege shell.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/ssh.png)

## Privilege Escalation Enumeration:

Doing basic enumeration:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/uname.png)

Netstat wasn&#39;t available on the system but SS was:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/Ss.png)

It seems that there&#39;s an internal webserver running.

## SSH Local Port Forwarding

SSH local port forwarding can be used to enumerate this webpage further:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/ssh_port_forward.png)

With Firefox configured to use manual proxy as follows:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/proxyconfig.png)

Internal port 8080 is now available in the browser and LibreNMS software discovered:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/librenms.png)

Successful login with Aeolus&#39; credentials:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/librenms_dash.png)

## Exploitation

Searching exploit-db for suitable exploit, as can be seen there are 2 version of it a manual exploit and Metasploit:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/searchsploit.png)

### Manual Exploit

First attempt will be made with a manual exploit.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/searchsploit1.png)

A manual exploit was found at: [https://www.exploit-db.com/exploits/47044](https://www.exploit-db.com/exploits/47044)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/exploitdb.png)

The exploit requires a cookie, which can be obtained by pressing F12 in your browser after logging in with aoelus&#39; credentials:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/cookies.png)

Instead of using apache webserver and /var/www/html folder, python&#39;s Simple HTTP Server can be used to serve the exploit from working directory:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/pythonHTTP.png)

Downloading exploit to the victim&#39;s machine:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/wget_expliot.png)

Although the exploit ran successfully no reverse shell was obtained:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/exploit_success.png)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/nc-nvlp.png)

### Metasploit Exploit

Next Metasploit framework can be checked.

In order to access internal website with Metasploit, local port forwarding and proxychains can be used with SSH tunnel we created earlier.

Proxychains allows to proxy traffic through the SSH proxy, allowing Metasploit access to the internal applications of victim&#39;s machine.

In order for Metasploit to launch successfully through proxychains the following line has to be added to /etc/proxychains.conf for postgresql not to error out when launching msfconsole.

localnet 127.0.0.1 000 255.255.255.255

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/localnet.png)

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msfconsole.png)

When trying to use the exploit for some reason it was not present in Metasploit:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf_not_found.png)

In this case it can be manually imported from exploit-db as follows:

Create appropriate folder for the exploit in /root/.mfs4/modules/exploits:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf4.png)

Once created copy the exploit into the appropriate folder:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf_exploitdb.png)

Once done run the updatedb command.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/updatedb.png)

Let&#39;s try this again:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/search_librenms.png)

One selected we can use info command to learn more about the exploit:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/info.png)

As can be seen the required options are: password, rhost, rport, targeturi and username. For the reverse shell lhost has to be specified as well.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf_settings.png)

Once all the options are set, it&#39;s ready to be exploited:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/msf_run_exploit.png)

## Second Low Privilege Shell &amp; Enumeration

This time around the low privilege shell was obtained for user cronus and python -c &quot;import pty;pty.spawn(&#39;/bin/bash&#39;)&quot; command was used to escape the default shell.

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/cronus.png)

Sudo -l can be used to check if this user has any sudo privileges:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/sudo_l.png)

## Root

As can be seen on the screenshot above, user cronus can execute /usr/bin/mysql with administrative privileges.

Mysql also can be escaped into a shell with \! /bin/bash commands.

Using mysql command execution and escape capability, high privileged shell can be obtained as following:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/sudo_sql.png)

Proof file:

 ![](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Symfonos:%202/Images/proof_txt.png)
