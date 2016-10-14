# linux-firewall-tool
Linux iptables automation tool. It manages the firewall on CERN 's DB Servers.

# [Documentation](https://cerndb.github.io/linux-firewall-tool/)
https://cerndb.github.io/linux-firewall-tool/

# Usage

To fully use this tool rub=n either **host_manager.py** or **iptables_manager.py**

The real power of the tool is the use of custom commands/scripts you can use to 
populate the option and finaly have a fully working firewall setup for both
IPv4 and IPv6. 

There a set of predefined rules called default. 

On both scripts **host_manager.py** or **iptables_manager.py** you have to specify the 
**--deploy** argument in order for the configuration to be applied on the machine.
There is also an option of generating the actual files so you can use them along with
**iptables-restore**, **ip6tables-restore**, **ipset-restore** commands.

## iptables_manager.py
This is the heart of the tool. You have to provide one or more config files to this script
in order to create the rules.

## host_manager.py
This script is calling the iptables_manager.py script. With the host_manager.py you can tell
which configuration will be applied to this machine by providing a list of hostnames. If the 
machine is in that list the given configuration will be served to the iptables.

The meaning of the the above is that your configuration can be in one place an all the machines.
By using a tool such as Puppet or Ansible you just have a list of machines that will get certain 
configuration regarding the firewall. 