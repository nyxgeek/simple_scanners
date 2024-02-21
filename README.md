## Simple Scanners

A collection of scripts for pentesting

- No databases.
- No interactive interface.
- Simple, text ouptut



### Scripts

- simple_onedrive_enum.py -- user enumeration via OneDrive URL

<!--
- simple_directsend_enum.py -- user enumeration via Direct Send (SMTP RCPT)
- simple_onedrive_domain_scan.py -- identifies domains which have OneDrive enabled
- simple_azure_domain_scan.py -- identifies domains which exist in Azure
-->

---

## simple_onedrive_enum.py

Same features as current build PLUS one more:
- quiet mode (-q).

Quiet mode ONLY displays valid usernames and nothing else -- no title, no scan status, nothing.


#### Normal usage
```
simple_scanners % ./simple_onedrive_enum.py -d acmecomputercompany.com -U users.tmp

              ███
             ░░░
  ███████    ████    █████████████    ████████    ███          ███████
 ░██░░░      ░███  ░░███░░███░░███   ░███░░░███  ░███        ░███░░░███
 ░███████    ░███   ░███ ░███ ░███   ░███░░░███  ░███        ░████████
 ░░░░░░██    ░███   ░███ ░███ ░███   ░███░░░███  ░███        ░███
 ░███████   ░█████  █████░███ █████  ░████████   ░████████   ░░███████
 ░░░░░░     ░░░░░  ░░░░░  ░░░ ░░░░░  ░████        ░░░░░░░      ░░░░░░░
                                    ░██████
                                    ░░░░░
                                         ██████               ███
                                        ░░████               ░░░
   ██████    █████████     ███████    ████████   █████████   ████   █████  █████   ███████
  ███░░███  ░░███░░░███   ███░░░███  ███░░░███  ░░███░░░███ ░░███  ░░███  ░░███   ███░░░███
 ░███  ░███  ░███  ░███  ░████████  ░███ ░░███   ░███  ░░░   ░███   ░███   ░███  ░████████
 ░███  ░███  ░███  ░███  ░███░░░░   ░███ ░░███   ░███        ░███   ░░███  ███   ░███░░░
 ░░██████    ████  █████ ░░███████  ░░█████████  ██████      █████   ░░██████    ░░███████
  ░░░░░░    ░░░░  ░░░░░   ░░░░░░░    ░░░░░░░░░  ░░░░░░      ░░░░░     ░░░░░░      ░░░░░░░


   ██████  ████████   █████ ████ █████████████      +-------------------------------------------------+
  ███░░███░░███░░███ ░░███ ░███ ░░███░░███░░███     |           Simple OneDrive Enumerator            |
 ░███████  ░███ ░███  ░███ ░███  ░███ ░███ ░███     |           2024 @nyxgeek - TrustedSec            |
 ░███░░░   ░███ ░███  ░███ ░███  ░███ ░███ ░███     |                 version 1.0                     |
 ░░██████  ████ █████ ░░████████ █████░███ █████    |  https://github.com/nyxgeek/simple_scanners     |
  ░░░░░░  ░░░░ ░░░░░   ░░░░░░░░ ░░░░░ ░░░ ░░░░░     +-------------------------------------------------+

*********************************************************************************************************


Tenants Identified:
---------------------
acmecomputercompany

OneDrive hosts found:
---------------------
acmecomputercompany-my.sharepoint.com


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


Beginning enumeration of https://acmecomputercompany-my.sharepoint.com/personal/USER_acmecomputercompany_com/ at 2024-02-21 14:54:35
--------------------------------------------------------------------------------------------------------
403:VALID USERNAME:acmecomputercompany,acmecomputercompany.com:nyxgeek:nyxgeek@acmecomputercompany.com


OneDrive Enumeration Complete at 2024-02-21 14:54:38, taking a total of 0h0m3s to scan 201 usernames.

Completed
```

#### Quiet Mode

```
simple_scanners % ./simple_onedrive_enum.py -d acmecomputercompany.com -U users.tmp -q
403:VALID USERNAME:acmecomputercompany,acmecomputercompany.com:nyxgeek:nyxgeek@acmecomputercompany.com
simple_scanners %
```
