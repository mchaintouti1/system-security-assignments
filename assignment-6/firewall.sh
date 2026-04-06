#!/bin/bash
# You are NOT allowed to change the files' names!
config="config.txt"
rulesV4="rulesV4"
rulesV6="rulesV6"

function firewall() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-config"  ]; then
        # Configure adblock rules based on domain names and IPs of $config file.
        # Write your code here...
        
        echo "Configuring adblock rules based on domain names and IPs of config.txt"
        
        while read -r line; do
            if [[ "$line" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "Blocking Ipv4: $line"
                if sudo iptables -C INPUT -s "$line" -j REJECT; then
                    echo "Rule for IPv4 $line already exists."
                else   
                    sudo iptables -A INPUT -s "$line" -j REJECT
                    echo "Rule for IPv4 $line added."
                fi
            elif [[ "$line" =~ ^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$ ]]; then
                echo "Blocking Ipv6: $line"
                if sudo ip6tables -C INPUT -s "$line" -j REJECT; then
                    echo "Rule for IPv6 $line already exists."
                else   
                    sudo ip6tables -A INPUT -s "$line" -j REJECT
                    echo "Rule for IPv6 $line added."
                fi
            else
                for ip in $(dig +short A "$line"); do
                    echo "Blocking IPv4: $ip for domain $line"
                    if sudo iptables -C INPUT -s "$ip" -j REJECT; then
                        echo "Rule for IPv4 $ip already exists."
                    else 
                        sudo iptables -A INPUT -s "$ip" -j REJECT
                        echo "Rule for IPv4 $ip added."
                    fi
                done

                for ip6 in $(dig +short AAAA "$line"); do
                    echo "Blocking IPv6: $ip6 for domain $line"
                    if sudo ip6tables -C INPUT -s "$ip6" -j REJECT; then
                        echo "Rule for IPv6 $ip6 already exists."
                    else 
                       sudo ip6tables -A INPUT -s "$ip6" -j REJECT
                        echo "Rule for IPv6 $ip6 added."
                    fi
                done
            fi
        done < $config

        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $rulesV4/$rulesV6 files.
        # Write your code here...

        echo "Saving the rules to $rulesV4/$rulesV6 files"

        sudo iptables-save > $rulesV4
        sudo ip6tables-save > $rulesV6

        echo "The rules have been successfully saved to $rulesV4/$rulesV6 files"

        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $rulesV4/$rulesV6 files.
        # Write your code here...

        echo "Loading the rules from $rulesV4/$rulesV6 files"

        sudo iptables-restore < $rulesV4
        sudo ip6tables-restore < $rulesV6

        echo "The rules have been successfully loaded from $rulesV4/$rulesV6 files"

        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset IPv4/IPv6 rules to default settings (i.e. accept all).
        # Write your code here...
        
        echo "Resetting the IPv4/IPv6 rules to default (accept all)"

        sudo iptables -F
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P FORWARD ACCEPT
        sudo iptables -P OUTPUT ACCEPT

        sudo ip6tables -F
        sudo ip6tables -P INPUT ACCEPT
        sudo ip6tables -P FORWARD ACCEPT
        sudo ip6tables -P OUTPUT ACCEPT

        echo "All rules have been successfully resetted."

        true

        
    elif [ "$1" = "-list"  ]; then
        # List IPv4/IPv6 current rules.
        # Write your code here...
        
        echo "Listing the IPv4/IPv6 rules"

        sudo iptables -L -v -n --line-numbers
        sudo ip6tables -L -v -n --line-numbers

        echo "The rules have been successfully listed."
        
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple firewall mechanism. It rejects connections from specific domain names or IP addresses using iptables/ip6tables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -config\t  Configure adblock rules based on the domain names and IPs of '$config' file.\n"
        printf "  -save\t\t  Save rules to '$rulesV4' and '$rulesV6'  files.\n"
        printf "  -load\t\t  Load rules from '$rulesV4' and '$rulesV6' files.\n"
        printf "  -list\t\t  List current rules for IPv4 and IPv6.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

firewall $1
exit 0