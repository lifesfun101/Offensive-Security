# Helpful books related to Offensive Security

*These are books I personally read and my humble review of them*

### Penetration Testing - Hands-On Introduction to Hacking

* By Georgia Wiedman

Even though this book and the material in it are little older (It was published in 2014 I believe), it is still a pretty good starting point in my opinion. Georgia Weidman helps the reader through setting up the whole lab environment, which I have not seen a lot of other books do. 

The lab environment in the book consists of 4 virtual machines, 1 attacker (Kali) and 3 targets (Windows 7, Windows XP and Ubuntu 12). It was a little troublesome to get the exact Windows XP version setup, as it requires unpatched SP3 32 bit; however, if you are attending a college or university for a security related program or some sort of IT related program, chances are your school has old ISOs. Windows 7 32 bit was a bit easier to find as it was available for download directly from my school's website. Finally, the ubuntu machine comes already set up and you can download it from the book's website.

The Kali machine is provided by the book, however the image is, as I mentioned before, outdated and I personally used a new Kali image and it took me a bit of googling to find equivalent for some of the packages/tools.

some of the packages required to be installed.

ftp - file transfer protocol.

* `<apt install ftp>` (for some reason latest Kali did not have it)

The book mentions package called mingw32 which is used in creation of Windows applications on Linux distros. 
This package's development has been stopped, however another author created a replacement for it called mingw64.

* `<apt install mingw-w64>`

The book takes you through penetration process step by step: information gathering, enumeration, vulnerability analysis, exploitation and post exploitation. Georgia's explanations are pretty simple and I think it's a really good book to get a foothold in the area of offensive security.

--------------------------------------------------------------------------------------------------------
### Hacker's Playbook 2

* By Peter Kim

Ironically with the name, it was the second book that I've read. Also a really good, informative book. However, I would say this book is not as beginner friendly as the one above.

I would grade this book as begginer to light intermediate. The lab setup instructions in it are not as detailed and beginner friendly as in Georgia's book. However, the book is newer and the techniques that are discussed in the book are newer as well. There are also many more intriquete techniques than there were in the first book. For example, the book covers a good chunk of powershell related material, which is not mentioned in the first book at all.

Although most of the tools mentioned in the setup part already come pre-installed in modern Kali, author does go over on how to install a lot of extra interesting tools that might not have been available preset at the time and a lot of scripts that one might have to search for otherwise manually.
