Host Manager
============

**host_manager.py**

We use the argument **--no_default_config** so we can see only what we generated. In order to deploy the configuration use the
**--deploy** argument. If you start the firewall for the first time is better to also apply the default config also.

Command usage:

    .. code-block:: bash

        bin/host_manager.py --help

        usage: host_manager.py [-h] [--no_default_config] [--update_sets]
                       [--update_list UPDATE_LIST [UPDATE_LIST ...]]
                       [--exclude_list EXCLUDE_LIST [EXCLUDE_LIST ...]]
                       [--config CONFIG [CONFIG ...]] [--deploy]
                       [--generate_files] [--allow] [--drop_all]
                       [--ignore_check] [--check_matches] [--map_hostfile]

        optional arguments:
          -h, --help            show this help message and exit
          --no_default_config   Default configuration
          --update_sets         Only update IPSets
          --update_list UPDATE_LIST [UPDATE_LIST ...]
                                Update only the specified ipsets: Use general section
                                names
          --exclude_list EXCLUDE_LIST [EXCLUDE_LIST ...]
                                Exclude these ipsets from update: Use general section
                                names
          --config CONFIG [CONFIG ...]
                                Type the location of your config file to parse(absolut
                                path)
          --deploy              Deploy the configuration
          --generate_files      Generate iptables and ipset configuration files
          --allow               Set policy to ACCEPT
          --drop_all            Set policy to DENY
          --ignore_check        Ignore needed network components check
          --check_matches       Check all section of the file and print at which
                                sections is this machine matching
          --map_hostfile        Generates dot language code in order to visualize host
                                file contents


Check what we will apply.
    ..  code-block:: bash

        bin/host_manager.py --no_default_config --config /root/linux-firewall-tool/custom_conf_files/test_hosts.cfg

    ..  code-block:: bash

        ####### SECTION matched: 'itdb_test_2' ################
        Deploy is: False
        Section name: access_incoming_sshd
        Set type is:  hash:net
        /usr/sbin/ipset create static_cern_networks_v4 hash:net family inet hashsize 1024 maxelem 65536
        Set  static_cern_networks_v4  created
        /usr/sbin/ipset add static_cern_networks_v4 172.16.0.0/12
        /usr/sbin/ipset add static_cern_networks_v4 10.0.0.0/8
        /usr/sbin/ipset add static_cern_networks_v4 188.184.0.0/15
        /usr/sbin/ipset add static_cern_networks_v4 192.91.242.0/24
        /usr/sbin/ipset add static_cern_networks_v4 137.138.0.0/16
        /usr/sbin/ipset add static_cern_networks_v4 194.12.128.0/18
        /usr/sbin/ipset add static_cern_networks_v4 192.16.155.0/24
        /usr/sbin/ipset add static_cern_networks_v4 192.16.165.0/24
        /usr/sbin/ipset add static_cern_networks_v4 192.168.0.0/16
        /usr/sbin/ipset add static_cern_networks_v4 128.142.0.0/16
        /usr/sbin/ipset add static_cern_networks_v4 128.141.0.0/16
        /usr/sbin/ipset add static_cern_networks_v4 100.64.0.0/10
        Section name: access_incoming_sshd
        Set type is:  hash:net
        /usr/sbin/ipset create static_cern_networks_v6 hash:net family inet6 hashsize 1024 maxelem 65536
        Set  static_cern_networks_v6  created
        /usr/sbin/ipset add static_cern_networks_v6 fd01:1459::/32
        /usr/sbin/ipset add static_cern_networks_v6 2001:1458::/32
        /usr/sbin/ipset add static_cern_networks_v6 2001:1459::/32
        /usr/sbin/ipset add static_cern_networks_v6 fd01:1458::/32
        /etc/init.d/ipset save

        ######### USER DEFINED FIREWALL RULES #########
        /sbin/iptables -A INPUT -i eth0 -p tcp -m multiport --dports 22 -m set --match-set static_cern_networks_v4 src -j ACCEPT -m comment --comment access_incoming_sshd
        /sbin/ip6tables -A INPUT -i eth0 -p tcp -m multiport --dports 22 -m set --match-set static_cern_networks_v6 src -j ACCEPT -m comment --comment access_incoming_sshd
        ######### USER DEFINED FIREWALL RULES #########

This way we deploy the configuration. On each deploy is better **not to** specify the **--no_default_config** so the default
rules apply. It cleans also everything and the ipsets so you have a clean deploy from scratch.

If you are absolutely certain that you applied the default before and just want what you defined then use the argument


Like this we deploy the configuration

    ..  code-block:: bash

        bin/host_manager.py --config /root/linux-firewall-tool/custom_conf_files/test_hosts.cfg --deploy

If you have a running firewall and just want to update ipsets that are in use you have to use the **--update_sets**
argument.

    .. code-block:: bash

        bin/host_manager.py --config /root/linux-firewall-tool/custom_conf_files/test_hosts.cfg --update_sets

    .. code-block:: bash

        ####### SECTION matched: 'itdb_test_2' ################
        Deploy is: False
        UPDATE IPsets ONLY
        Set type is:  hash:net
        static_cern_networks_v4


        To be added:  []


        To be removed:  []


        0 ['static_cern_networks']
        Set type is:  hash:net
        static_cern_networks_v6


        To be added:  []


        To be removed:  []


        0 ['static_cern_networks']
        /etc/init.d/ipset save

You can also use **--update_list** and **--exclude_list** so to define a list of sets,
to either update those only or update all except those in the list.

    ..  code-block:: bash

        bin/iptables_manager.py --config custom_conf_files/example_config_14.cfg --update_sets --update_list "SET_SECTION_NAME_1" "SET_SECTION_NAME_2"

        bin/iptables_manager.py --config custom_conf_files/example_config_14.cfg --update_sets --exclude_list "SET_SECTION_NAME_1" "SET_SECTION_NAME_2"


Like this we deploy the update of the ipsets

    ..  code-block:: bash

        bin/host_manager.py --config /root/cerndb-infra-firewall-tool/custom_conf_files/test_hosts.cfg --update_sets --deploy

        bin/iptables_manager.py --config custom_conf_files/example_config_14.cfg --update_sets --update_list "SET_SECTION_NAME_1" "SET_SECTION_NAME_2" --deploy

        bin/iptables_manager.py --config custom_conf_files/example_config_14.cfg --update_sets --exclude_list "SET_SECTION_NAME_1" "SET_SECTION_NAME_2" --deploy