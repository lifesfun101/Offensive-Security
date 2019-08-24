# **Vulnerable System** : 192.168.20.141 (Stapler)

**Operating System** : Ubuntu 16.04

**Kernel** : 4.4.0

**Vulnerability Exploited** : WordPress Plugin Advanced Video 1.0 - Local File Inclusion

**Proof of Concept Code** : [https://www.exploit-db.com/exploits/39646](https://www.exploit-db.com/exploits/39646)

**Vulnerability Explained** :  WordPress Plugin local file inclusion can be used by the attacker to gain access to confidential files, in this case /etc/passwd and WordPress configuration file.

**Vulnerability fix** : There is no current patches or fixes for this vulnerability.

**Severity** : **Medium**

**Privilege Escalation Vulnerability** : Administrative user&#39;s password is stored

**Privilege Escalation Vulnerability Explained:** Administrative user&#39;s password was found in a .bash\_history file of a low privilege user that could be read by anyone on the system.

**Vulnerability fix** : Implement strong permissions on user owned private files (such as chmod 400). Users should not share passwords with each other.

**Severity** : **High**

## Arp-scan

Arp-scan -l:

![arp_scan)](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/Lin%20Enum.png?raw=true)

## nmap

Nmap all ports scan:

![nmap_allports](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/nmap_all_scan.png)

Nmap -sV -sC -A:

![nmap_sv_sc](https://github.com/lifesfun101/Offensive-Security/blob/master/Walkthroughs/Stapler/Images/nmap_sv_sc1.png)

## nikto

Nikto 80:
![]()

Nikto 12380:
![]()

## FTP

ftp enumeration:
![]()

## SMB

SMB enumeration:
![]()



## 666

Port 666 Enumeration:
![]()



## Port 12380

As a &quot;red.initech&quot; entry has been added to /etc/hosts on the kali machine.

Port 12380 enumeration:
![]()

Robots.txt content:
![]()

## WordPress

/blogblog/ directory presents us with WordPress style website:
![]()

Wp-scan is ran to find low hanging fruit, however it does not find anything interesting:
![]()

-------------------------------------------------Snippet---------------------------------------------------


Manual enumeration of WordPress plugins and themes, presents an interesting plugin called Advanced Video Embed – Embed Videos or Playlists:
![]()
![]()
![]()
![]()

As per readme.txt, the plugin&#39;s version is 1.0.
![]()

## Searchsploit

Search exploit-db for suitable exploit
![]()
![]()


Reviewing the exploit and subbing the URL parameter, the default settings is to download wp-config.php:
![]()

## Exploitation

As the exploit is ran, errors regarding SSL appear.
![]()


To work around the error, quick google search suggests importing SSL library and editing SSL context as shown below:
![]()

After running the exploit again, change the file to /etc/passwd and run it again:
![]()

When visiting the blog once more, notice that new entries were created (the exploit does not mention that or how it obtains the file):
![]()


These .jpeg files can be found in the wp-content upload folder (as can be seen per the multiple images being uploaded it took a little bit to figure out that this how the exploit worked):
![]()


They can be then manually saved (Oh no he didn&#39;t just use GUI to download files):
![]()
![]()



Change the file extensions to text:
![]()


File.txt is wp-config.php:
![]()


File2.txt is /etc/passwd:
![]()


Clean up /etc/passwd (removing false and nologin):
![]()


Create user list:
![]()

##Hydra
Use hydra to bruteforce SSH:

-e nsr option:
![]()


Password obtained from WordPress:
![]()


Logging in in with Zoe&#39;s credentials:
![]()


## Privilege Escalation

### Enumerating (Manual way):

Determining users with administrative privileges:
![]()


Determining readable files in home directory:
![]()
---------------------------Snippet--------------------------
![]()


Enumerating JKanode&#39;s bash\_history file:
![]()


Alternatively:
![]()


### Enumerating (Automated Way):

LinEnum.sh, scripted by rebootuser, can be used to automate enumeration process. The script can be obtained from rebootuser&#39;s [GitHub](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh).

Although automated scripts might seem as an easier way, sometimes one can get lost in abundance of information it provides. Personally, enumerating manually have helped me just as many times as automatic scripts. Automatic scripts are more for the low hanging fruit in my opinion.

First the script has to be downloaded to the victim machine.
![]()


![]()

-------------------------------------------------------------Snippet-----------------------------------------------------------
![]()
-------------------------------------------------------------Snippet-----------------------------------------------------------
![]()


As per script&#39;s result it can be seen that &quot;peter&quot; is an admin user and that the possible password is JZQuyIN5.

Logging into Peter&#39;s account and changing root&#39;s password:
![]()


Flag file:
![]()

