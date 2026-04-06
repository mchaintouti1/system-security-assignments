## Assignment 6 Description
This project implements a simple firewall mechanism using a Bash script to block connections based on domain names and IP addresses. The script utilizes iptables and ip6tables to configure, save, load, reset, and list firewall rules for IPv4 and IPv6 traffic.

## How to Run:
- Run the following commands in your terminal: 
1. `chmod +x firewall.sh` (this is only if the file is not executable at first)
Then run the script as root (required for iptables and ip6tables commands):
2. `sudo ./firewall.sh`
    Available options:
    - `config` : Configure adblock rules based on the domain names and IPs listed in config.txt.
    - `save`   : Save the current rules to rulesV4 and rulesV6 files.
    - `load`   : Load rules from rulesV4 and rulesV6 files.
    - `reset`  : Reset rules to default settings (accept all traffic).
    - `list`   : List current rules for IPv4 and IPv6.
    - `help`   : Display usage instructions.

## Question:
After configuring the firewall rules, test your script by visiting your favorite
websites without any other adblocking mechanism (e.g., adblock browser
extensions). Can you see ads? Do they load? Some ads persist, why?
# Answer: 
After configuring the firewall rules, ads may still persist for several reasons. That may happen, because some websites use multiple domains for serving ads, and blocking only the domains in the config file may not block all ad sources. Additionally, Content Delivery Networks (CDNs) may provide multiple IP addresses for a single domain, meaning blocking a few may not stop all ads. Some ads might also be loaded from non-blocked domains. Therefore, additional rules or more thorough domain blocking might be required.

