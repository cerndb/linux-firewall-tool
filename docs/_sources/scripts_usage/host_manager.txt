Host Manager
============

**host_manager.py**

We use the argument **--no_default_config** so we can see only what we generated. In order to deploy the configuration use the
**--deploy** argument. If you start the firewall for the first time is better to also apply the default config also.

Check what we will apply.
    ..  code-block:: bash

        bin/host_manager.py --no_default_config --config /root/cerndb-infra-firewall-tool/custom_conf_files/test_hosts.cfg

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

        bin/host_manager.py --config /root/cerndb-infra-firewall-tool/custom_conf_files/test_hosts.cfg --deploy

If you have a running firewall and just want to update ipsets that are in use you have to use the **--update_sets**
argument.

    .. code-block:: bash

        bin/host_manager.py --config /root/cerndb-infra-firewall-tool/custom_conf_files/test_hosts.cfg --update_sets

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

Like this we deploy the update of the ipsets

    ..  code-block:: bash

        bin/host_manager.py --config /root/cerndb-infra-firewall-tool/custom_conf_files/test_hosts.cfg --update_sets --deploy