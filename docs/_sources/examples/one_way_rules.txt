Single rules
============

**Example rules for INPUT or OUTPUT chain**

    .. code-block:: ini

        [access_outgoing_ports_tcp_signle]
        section_type = general
        action = ['drop']
        default_chain = OUTPUT
        ip_version = ipv4
        interface = main
        protocol = tcp,udp
        #ports = "ports.sh"
        set = static_dns_servers4_single


        [static_dns_servers4_single]
        section_type = ipset
        ipset_type = hash:ip,port
        set_name = ['static_dns_servers4_single']
        set_ips_v4 = ['137.138.16.5,80', '137.138.17.5,443', '172.18.16.5,5550', '172.18.17.5,6598']
        set_hostnames = ["script:test_port.sh","script:test_port_2.sh","agkara-train,6178"]


The section **[access_outgoing_ports_tcp_signle]** will create a **kernel ipset** called **static_dns_servers4_single_v4** since its set to ipv4.

**Output of the scripts**

    .. code-block:: bash

        helpers/test_port.sh
        itrac5160,443
        itrac5161,890
        itrac5120,5366
        itrac5162,3321
        itrac5121,7563
        itrac5163,7363
        itrac5122,6564

    .. code-block:: bash

        helpers/test_port_2.sh
        itrac5164,9079
        itrac5123,1023
        itrac5165,5547
        itrac5124,6987
        itrac5166,6123
        itrac5125,787
        itrac5167,443
        itrac5126,80


**Kernel ipset**

    .. code-block:: bash

        Section name: access_outgoing_ports_tcp_signle
        Script  ['test_port.sh']  not in system path
        Trying herlpers: /root/cerndb-infra-firewall/helpers/test_port.sh
        Script  ['test_port_2.sh']  not in system path
        Trying herlpers: /root/cerndb-infra-firewall/helpers/test_port_2.sh
        Set type is:  hash:ip,port
        /usr/sbin/ipset create static_dns_servers4_single_v4 hash:ip,port family inet hashsize 1024 maxelem 65536
        Set  static_dns_servers4_single_v4  created
        /usr/sbin/ipset add static_dns_servers4_single_v4 10.17.6.55,tcp:3321
        /usr/sbin/ipset add static_dns_servers4_single_v4 172.18.17.5,tcp:6598
        /usr/sbin/ipset add static_dns_servers4_single_v4 137.138.17.5,tcp:443
        /usr/sbin/ipset add static_dns_servers4_single_v4 10.17.6.56,tcp:7363
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.45.151,tcp:5366
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.45.155,tcp:6987
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.37.104,tcp:6123
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.45.153,tcp:6564
        /usr/sbin/ipset add static_dns_servers4_single_v4 10.17.6.25,tcp:80
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.45.154,tcp:1023
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.37.103,tcp:5547
        /usr/sbin/ipset add static_dns_servers4_single_v4 10.17.6.54,tcp:890
        /usr/sbin/ipset add static_dns_servers4_single_v4 137.138.16.5,tcp:80
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.37.102,tcp:9079
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.45.163,tcp:443
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.45.152,tcp:7563
        /usr/sbin/ipset add static_dns_servers4_single_v4 172.18.16.5,tcp:5550
        /usr/sbin/ipset add static_dns_servers4_single_v4 10.17.6.24,tcp:787
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.37.105,tcp:443
        /usr/sbin/ipset add static_dns_servers4_single_v4 188.184.185.176,tcp:6178

The logic of the action is the following:
    .. code-block:: ini

        action = ['drop']

If the list has 1 element it means that it will create a single rule for the defined chain.
The above section will create two rules in reality one for each protocol tcp,udp

    .. code-block:: bash

        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m set --match-set static_dns_servers4_single_v4 dst,dst -j DROP -m comment --comment access_outgoing_ports_tcp_signle
        /sbin/iptables -A OUTPUT -o eth0 -p udp -m set --match-set static_dns_servers4_single_v4 dst,dst -j DROP -m comment --comment access_outgoing_ports_tcp_signle



**Example with ipset triplet**

    .. code-block:: ini

        [triplet_set]
        section_type = general
        action = ['accept']
        default_chain = INPUT,OUTPUT
        ip_version = ipv4
        interface = all
        protocol = tcp,udp
        set = triplet_ipset
        set_directions = src,dst,dst

        [triplet_ipset]
        section_type = ipset
        ipset_type = hash:ip,port,ip
        set_name = ['triplet_ip_set']
        set_hostnames = ['lxplus,443,agkara-train','syscontrol-dev,5555,pcjcano2','kubernetes-node,80,kubernetes-master']


The output of the above section is the following:

**Kernel ipset**

    .. code-block:: bash

        /usr/sbin/ipset create triplet_ip_set_v4 hash:ip,port,ip family inet hashsize 1024 maxelem 65536

    .. code-block:: bash

        /usr/sbin/ipset add triplet_ip_set_v4 188.184.94.29,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.92.227,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 128.142.153.55,tcp:80,128.142.147.69
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.95.215,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.94.26,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.89.225,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.90.207,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.92.114,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.95.36,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.92.51,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.91.82,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.91.170,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.92.95,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.95.238,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.92.172,tcp:443,188.184.185.176
        /usr/sbin/ipset add triplet_ip_set_v4 188.184.93.17,tcp:443,188.184.185.176
        /etc/init.d/ipset save

**Rules**

    .. code-block:: bash

        /sbin/iptables -A INPUT -i eth0 -p tcp -m set --match-set triplet_ip_set_v4 src,dst,dst -j ACCEPT -m comment --comment triplet_set
        /sbin/iptables -A INPUT -i lo -p tcp -m set --match-set triplet_ip_set_v4 src,dst,dst -j ACCEPT -m comment --comment triplet_set
        /sbin/iptables -A INPUT -i eth0 -p udp -m set --match-set triplet_ip_set_v4 src,dst,dst -j ACCEPT -m comment --comment triplet_set
        /sbin/iptables -A INPUT -i lo -p udp -m set --match-set triplet_ip_set_v4 src,dst,dst -j ACCEPT -m comment --comment triplet_set
        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m set --match-set triplet_ip_set_v4 src,dst,dst -j ACCEPT -m comment --comment triplet_set
        /sbin/iptables -A OUTPUT -o lo -p tcp -m set --match-set triplet_ip_set_v4 src,dst,dst -j ACCEPT -m comment --comment triplet_set
        /sbin/iptables -A OUTPUT -o eth0 -p udp -m set --match-set triplet_ip_set_v4 src,dst,dst -j ACCEPT -m comment --comment triplet_set
        /sbin/iptables -A OUTPUT -o lo -p udp -m set --match-set triplet_ip_set_v4 src,dst,dst -j ACCEPT -m comment --comment triplet_set


**Example using CERN LanDB sets to create an ipset**

    .. code-block:: ini

        [test_triplet_from_iptables_manager]
        section_type = general
        action = ['accept']
        default_chain = INPUT
        ip_version = ipv4
        interface = other
        protocol = tcp,udp
        set = triplet_set
        set_directions = src,dst,dst



        [triplet_set]
        section_type = ipset
        ipset_type = hash:ip,port,ip
        netgroups_list = ['CERNVM-CLUSTER-ESX,tcp:5530,CDS LB','DRUPAL,tcp:6677,FRONTIER-MONITORING']
        set_name = ['CERN_TEST_SET_LIST']


The output of the above sections is the following:
**Kernel ipset**

    .. code-block:: bash

        /usr/sbin/ipset create CERN_TEST_SET_LIST_v4 hash:ip,port,ip family inet hashsize 1024 maxelem 65536

        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.67,tcp:5530,188.184.3.51
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.208,tcp:6677,128.142.140.249
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.68,tcp:5530,188.184.3.51
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.206,tcp:6677,128.142.192.174
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.71,tcp:5530,188.184.3.51
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.72,tcp:5530,188.184.3.51
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.208,tcp:6677,128.142.192.174
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.68,tcp:5530,188.184.66.111
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.65,tcp:5530,188.184.3.51
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.206,tcp:6677,188.184.150.138
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.208,tcp:6677,128.142.192.53
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.65,tcp:5530,188.184.66.111
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.205,tcp:6677,128.142.192.53
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.206,tcp:6677,128.142.140.249
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.205,tcp:6677,188.184.150.138
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.67,tcp:5530,188.184.66.111
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.72,tcp:5530,188.184.66.111
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.208,tcp:6677,188.184.150.138
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.205,tcp:6677,128.142.140.249
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.71,tcp:5530,188.184.66.111
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.70,tcp:5530,188.184.66.111
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.66,tcp:5530,188.184.3.51
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.205,tcp:6677,128.142.192.174
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 188.184.37.206,tcp:6677,128.142.192.53
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.66,tcp:5530,188.184.66.111
        /usr/sbin/ipset add CERN_TEST_SET_LIST_v4 137.138.234.70,tcp:5530,188.184.3.51
        /etc/init.d/ipset save

**Rules**

    .. code-block:: bash

        /sbin/iptables -A INPUT -i lo -p tcp -m set --match-set CERN_TEST_SET_LIST_v4 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
        /sbin/iptables -A INPUT -i lo -p udp -m set --match-set CERN_TEST_SET_LIST_v4 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
