IPtables Manager
================

**iptables_manager.py**

We use the argument **--no_default_config** so we can see only what we generated. In order to deploy the configuration use the
**--deploy** argument. If you start the firewall for the first time is better to also apply the default config also.

Command usage:

    .. code-block:: bash

        bin/iptables_manager.py -h
        usage: iptables_manager.py [-h] [--config CONFIG [CONFIG ...]]
                                   [--no_default_config] [--allow] [--drop_all]
                                   [--interface INTERFACE] [--update_sets] [--deploy]
                                   [--generate_files]

        optional arguments:
          -h, --help            show this help message and exit
          --config CONFIG [CONFIG ...]
                                Type the location of your config file to parse(absolut
                                path)
          --no_default_config   Apply default configuration from scratch
          --allow               Apply ACCEPT policy to everything
          --drop_all            Apply DROP policy to everything
          --interface INTERFACE
                                Type the name of nic card you want the default rules
                                to be applied for
          --update_sets         Update only the ipsets
          --deploy              Deploy the configuration
          --generate_files      Generate iptables and ip6tables files


Check what we will apply.
    ..  code-block:: bash

        bin/iptables_manager.py --no_default_config --config custom_conf_files/example_config_14.cfg

    ..  code-block:: bash

        Set type is:  hash:ip
        /usr/sbin/ipset create admin_workstations_x_v4 hash:ip family inet hashsize 1024 maxelem 65536
        Set  admin_workstations_x_v4  created
        /usr/sbin/ipset add admin_workstations_x_v4 128.142.159.200
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.88.15
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.92.172
        /usr/sbin/ipset add admin_workstations_x_v4 10.18.16.58
        /usr/sbin/ipset add admin_workstations_x_v4 128.142.147.69
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.90.241
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.92.51
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.92.181
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.94.26
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.92.253
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.90.205
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.90.217
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.92.114
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.92.101
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.90.55
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.91.95
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.92.218
        /usr/sbin/ipset add admin_workstations_x_v4 188.184.91.164
        /usr/sbin/ipset add admin_workstations_x_v4 128.142.153.55
        admin_workstations_x_v4
        Script  ['test_nets_v4.sh']  not in system path
        Trying herlpers: /root/cerndb-infra-firewall/helpers/test_nets_v4.sh
        ['100.64.0.0/10', '192.91.242.0/24', '188.184.0.0/15']
        Set type is:  hash:net
        /usr/sbin/ipset create static_dns_servers4_v4 hash:net family inet hashsize 1024 maxelem 65536
        Set  static_dns_servers4_v4  created
        /usr/sbin/ipset add static_dns_servers4_v4 100.64.0.0/10
        /usr/sbin/ipset add static_dns_servers4_v4 188.184.0.0/15
        /usr/sbin/ipset add static_dns_servers4_v4 192.91.242.0/24
        static_dns_servers4_v4
        Script  ['test_nets_v6.sh']  not in system path
        Trying herlpers: /root/cerndb-infra-firewall/helpers/test_nets_v6.sh
        ['2001:1458::/32', 'FD01:1459::/32']
        Set type is:  hash:net
        /usr/sbin/ipset create static_dns_servers4_v6 hash:net family inet6 hashsize 1024 maxelem 65536
        Set  static_dns_servers4_v6  created
        /usr/sbin/ipset add static_dns_servers4_v6 2001:1458::/32
        /usr/sbin/ipset add static_dns_servers4_v6 FD01:1459::/32
        static_dns_servers4_v6
        /etc/init.d/ipset save

        ######### USER DEFINED FIREWALL RULES #########
        /sbin/iptables -A INPUT -i eth0 -p tcp -m state --state ESTABLISHED -m set --match-set admin_workstations_x_v4 src -j ACCEPT -m comment --comment essential_services
        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m state --state NEW,ESTABLISHED -m multiport --dports 22,50 -m set --match-set admin_workstations_x_v4 dst -j ACCEPT -m comment --comment essential_services
        /sbin/iptables -A INPUT -i eth0 -p tcp -m state --state NEW,ESTABLISHED -m set --match-set static_dns_servers4_v4 src -j ACCEPT -m comment --comment access_outgoing_ports_tcp
        /sbin/iptables -A INPUT -i eth0 -p udp -m state --state NEW,ESTABLISHED -m set --match-set static_dns_servers4_v4 src -j ACCEPT -m comment --comment access_outgoing_ports_tcp
        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m state --state ESTABLISHED -m set --match-set static_dns_servers4_v4 dst -j ACCEPT -m comment --comment access_outgoing_ports_tcp
        /sbin/iptables -A OUTPUT -o eth0 -p udp -m state --state ESTABLISHED -m set --match-set static_dns_servers4_v4 dst -j ACCEPT -m comment --comment access_outgoing_ports_tcp
        /sbin/ip6tables -A INPUT -i eth0 -p tcp -m state --state NEW,ESTABLISHED -m set --match-set static_dns_servers4_v6 src -j ACCEPT -m comment --comment access_outgoing_ports_tcp
        /sbin/ip6tables -A INPUT -i eth0 -p udp -m state --state NEW,ESTABLISHED -m set --match-set static_dns_servers4_v6 src -j ACCEPT -m comment --comment access_outgoing_ports_tcp
        /sbin/ip6tables -A OUTPUT -o eth0 -p tcp -m state --state ESTABLISHED -m set --match-set static_dns_servers4_v6 dst -j ACCEPT -m comment --comment access_outgoing_ports_tcp
        /sbin/ip6tables -A OUTPUT -o eth0 -p udp -m state --state ESTABLISHED -m set --match-set static_dns_servers4_v6 dst -j ACCEPT -m comment --comment access_outgoing_ports_tcp
        ######### USER DEFINED FIREWALL RULES #########

This way we deploy the configuration. On each deploy is better **not to** specify the **--no_default_config** so the default
rules apply. It cleans also everything and the ipsets so you have a clean deploy from scratch.

If you are absolutely certain that you applied the default before and just want what you defined then use the argument


Like this we deploy the configuration

    ..  code-block:: bash

        bin/iptables_manager.py --config custom_conf_files/example_config_14.cfg --deploy

If you have a running firewall and just want to update ipsets that are in use you have to use the **--update_sets**
argument.

    .. code-block:: bash

        bin/iptables_manager.py --config custom_conf_files/example_config_14.cfg --update_sets

    .. code-block:: bash

        UPDATE IPsets ONLY
        Set type is:  hash:ip
        admin_workstations_x_v4


        To be added:  []


        To be removed:  []


        0 ['admin_workstations_x']
        Script  ['test_nets_v4.sh']  not in system path
        Trying herlpers: /root/cerndb-infra-firewall/helpers/test_nets_v4.sh
        ['100.64.0.0/10', '192.91.242.0/24', '188.184.0.0/15']
        Set type is:  hash:net
        static_dns_servers4_v4


        To be added:  []


        To be removed:  []


        0 ['static_dns_servers4']
        Script  ['test_nets_v6.sh']  not in system path
        Trying herlpers: /root/cerndb-infra-firewall/helpers/test_nets_v6.sh
        ['2001:1458::/32', 'FD01:1459::/32']
        Set type is:  hash:net
        static_dns_servers4_v6


        To be added:  ['FD01:1459::/32']


        To be removed:  ['fd01:1459::/32']


        /usr/sbin/ipset  add  static_dns_servers4_v6   FD01:1459::/32
        /usr/sbin/ipset  del  static_dns_servers4_v6   fd01:1459::/32
        0 ['static_dns_servers4']
        /etc/init.d/ipset save

Like this we deploy the update of the ipsets

    ..  code-block:: bash

        bin/iptables_manager.py --config custom_conf_files/example_config_14.cfg --update_sets --deploy