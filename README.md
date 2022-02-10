# Octoberfest7 Edit:
This is a modified version of KillDefender by pwn1sher.  The original POC fails when run from an Administrator prompt because even though SeDebugPrivilege is enabled, the Admin user doesn't have the required permissions to access a System level process.  To get around this I added a small snippet of code to open winlogon's token and impersonate system via that token.  After impersonating System, the POC works like a dream.

Some observations about this technique:
1) Unlike other methods to disable defender features (powershell Set-MpPreference...), tamper protection doesn't prevent an attacker from neutering Defender with this method.
2) The MsMpEng.exe process remains running after removing it's privileges; this seems preferential to killing the process as Defender not running at all could flag elsewhere.
3) The changes are reverted after a reboot and Defender is functional again.

Full credit to pwn1sher for the POC.  

# KillDefender
A small POC to make defender useless by removing its token privileges and lowering the token integrity  

# Usage

killdefender.exe pid

# Preview 

![Alt Text](poc.PNG)

![Alt Text](POC2.PNG)

# Credits
 https://elastic.github.io/security-research/whitepapers/2022/02/02.sandboxing-antimalware-products-for-fun-and-profit/article/
