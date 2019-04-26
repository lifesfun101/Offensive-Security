# Helpful books related to Offensive Security

*These are books I personally read and my humble review of them*

### Penetration Testing - Hands-On Introduction to Hacking

Even though this book and the material in it are little older (It was published in 2014 I believe), it is still a pretty good starting point in my opinion. Georgia Weidman helps the reader through setting up the whole lab environment, which I have not seen a lot of other books do. 

The lab environment in the book consists of 4 virtual machines, 1 attacker (Kali) and 3 targets (Windows 7, Windows XP and Ubuntu 12). It was a little troublesome to get the exact Windows XP version setup, as it requires unpatched SP3 32 bit; however, if you are attending a college or university for a security related program or some sort of IT related program, chances are your school has old ISOs. Windows 7 32 bit was a bit easier to find as it was available for download directly from my school's website. Finally, the ubuntu machine comes already set up and you can download it from the book's website.

The Kali machine is provided by the book, however the image is, as I mentioned before, outdated and I personally used a new Kali image and it took me a bit of googling to find equivalent for some of the packages/tools.

some of the packages required to be installed.

ftp - file transfer protocol.

* `<apt install ftp>` (for some reason latest Kali did not have it)

The book mentions package called mingw32 which is used in creation of Windows applications on Linux distros. 
This package's development has been stopped, however another author created a replacement for it called mingw64.

* `<apt install mingw-w64>`

