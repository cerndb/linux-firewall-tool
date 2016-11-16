Single rules
============

**Example rules for INPUT or OUTPUT chain**

In case your script can provide the combo of hostname,port you have to use the tag **script_double**. If the script returns only a list of hostnames
the you have to provide the port for each list element and use the **script:** tag.

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
        set_hostnames = ["script_double:test_port.sh","script_double:test_port_2.sh","agkara-train,6178"]


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
        ALIENDB1,9079
        ALIENDB2,1023
        ALIENDB3,5547
        ALIENDB4,6987
        ALIENDB5,6123
        ALIENDB7,787
        ALIENDB8,443


**Kernel ipset**

    .. code-block:: bash

        Section name: access_outgoing_ports_tcp_signle
        Script  ['test_port.sh']  not in system path
        Trying herlpers: /root/linux-firewall/helpers/test_port.sh
        Script  ['test_port_2.sh']  not in system path
        Trying herlpers: /root/linux-firewall/helpers/test_port_2.sh
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


**Example using CERN LanDB sets to create an ipset of hash:ip,port,ip**

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
        cern_set_list = ['CERNVM-CLUSTER-ESX,tcp:5530,CDS LB','DRUPAL,tcp:6677,FRONTIER-MONITORING']
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


**Example of hash:ip,port,ip using mix of script and network set**
In case your script can provide the combo of hostname,port you have to use the tag **script_double**. If you want to return only a list of hostnames
then you have to provide the port for each list element and use the **script:** or **netgroup:** tags. Please note that last part of each element in the list can only
use the **script:** or **netgroup:**(which extracts hostnames from LanDB) tags and has to return as output a list with single elements

    .. code-block:: ini

        [test_triplet_from_iptables_manager_3]
        section_type = general
        action = ['accept']
        default_chain = OUTPUT,INPUT
        ip_version = both
        interface = ['main']
        protocol = tcp,udp
        set = triplet_set_3
        set_directions = dst,dst,src


        [triplet_set_3]
        section_type = ipset
        ipset_type = hash:ip,port,ip
        set_hostnames = ['script_double:test_port_2.sh,netgroup:IT PES NAGIOS','netgroup:IT SECURITY FIREWALL ALIENDB,8080,script:test_2.sh']
        set_name = ['triplet_set_test_3']

The output of the above sections is the following:
**Kernel ipset v4**

    .. code-block:: bash

        /usr/sbin/ipset create triplet_set_test_3_v4 hash:ip,port,ip family inet hashsize 1024 maxelem 65536
        Set  triplet_set_test_3_v4  created
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:6987,128.142.137.117
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:8080,188.184.9.235
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:8080,188.184.9.236
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:443,128.142.192.160
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:8080,188.184.9.234
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:8080,188.184.9.239
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:9079,128.142.192.160
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:8080,188.184.9.239
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:1023,128.142.192.160
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:8080,188.185.96.137
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:8080,188.184.9.240
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:8080,188.185.96.137
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:8080,188.184.9.239
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:9079,128.142.157.127
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:8080,188.184.9.235
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:8080,188.184.9.234
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:8080,188.185.96.137
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:5547,128.142.157.127
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:8080,188.184.9.236
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:8080,188.185.96.137
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:8080,188.184.9.236
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:8080,188.184.9.235
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:6123,128.142.192.160
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:787,128.142.192.160
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:8080,188.184.9.236
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:8080,188.184.9.235
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:8080,188.184.9.234
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:5547,128.142.137.117
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:8080,188.184.9.239
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:8080,188.184.9.240
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:8080,188.184.9.236
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:8080,188.184.9.235
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:8080,188.185.96.137
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:8080,188.184.9.239
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:8080,188.184.9.239
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:1023,128.142.157.127
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:443,128.142.157.127
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:8080,188.184.9.240
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:8080,188.184.9.240
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:8080,188.184.9.234
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:8080,188.185.96.137
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:8080,188.185.96.137
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:443,128.142.137.117
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:8080,188.184.9.234
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:8080,188.184.9.235
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:8080,188.184.9.236
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:8080,188.184.9.234
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:8080,188.184.9.235
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:8080,188.184.9.236
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:8080,188.184.9.239
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:6123,128.142.157.127
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:787,128.142.157.127
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:8080,188.184.9.240
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:8080,188.184.9.234
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.139,tcp:9079,128.142.137.117
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.140,tcp:1023,128.142.137.117
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:6987,128.142.157.127
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.216,tcp:787,128.142.137.117
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:6123,128.142.137.117
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.136,tcp:6987,128.142.192.160
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.141,tcp:5547,128.142.192.160
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.47.221,tcp:8080,188.184.9.240
        /usr/sbin/ipset add triplet_set_test_3_v4 137.138.99.145,tcp:8080,188.184.9.240

**Kernel ipset v6**

    .. code-block:: bash

        /usr/sbin/ipset create triplet_set_test_3_v6 hash:ip,port,ip family inet6 hashsize 1024 maxelem 65536
        Set  triplet_set_test_3_v6  created
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:12,tcp:8080,2001:1458:201:70::100:2c
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:27,tcp:8080,2001:1458:201:70::100:28
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:12,tcp:8080,2001:1458:201:70::100:2b
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:27,tcp:8080,2001:1458:201:70::100:26
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:27,tcp:8080,2001:1458:201:70::100:27
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:17,tcp:8080,2001:1458:201:70::100:2b
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:17,tcp:8080,2001:1458:201:70::100:2c
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:6,tcp:8080,2001:1458:201:70::100:26
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:6,tcp:8080,2001:1458:201:70::100:27
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:6,tcp:8080,2001:1458:201:70::100:28
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:12,tcp:8080,2001:1458:201:70::100:28
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:2,tcp:8080,2001:1458:201:70::100:26
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:2,tcp:8080,2001:1458:201:70::100:27
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:5,tcp:8080,2001:1458:201:70::100:27
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:5,tcp:8080,2001:1458:201:70::100:26
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:5,tcp:8080,2001:1458:201:70::100:28
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:2,tcp:8080,2001:1458:201:70::100:28
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:7,tcp:8080,2001:1458:201:70::100:2c
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:7,tcp:8080,2001:1458:201:70::100:2b
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:6,tcp:8080,2001:1458:201:70::100:2b
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:6,tcp:8080,2001:1458:201:70::100:2c
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:17,tcp:8080,2001:1458:201:70::100:28
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:17,tcp:8080,2001:1458:201:70::100:26
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:17,tcp:8080,2001:1458:201:70::100:27
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:27,tcp:8080,2001:1458:201:70::100:2b
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:27,tcp:8080,2001:1458:201:70::100:2c
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:7,tcp:8080,2001:1458:201:70::100:27
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:7,tcp:8080,2001:1458:201:70::100:26
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:7,tcp:8080,2001:1458:201:70::100:28
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:5,tcp:8080,2001:1458:201:70::100:2c
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:5,tcp:8080,2001:1458:201:70::100:2b
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:2,tcp:8080,2001:1458:201:70::100:2b
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:2,tcp:8080,2001:1458:201:70::100:2c
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:12,tcp:8080,2001:1458:201:70::100:27
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:12,tcp:8080,2001:1458:201:70::100:26

**Rules**

    .. code-block:: bash

        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m set --match-set triplet_set_test_3_v4 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/iptables -A OUTPUT -o eth0 -p udp -m set --match-set triplet_set_test_3_v4 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/iptables -A INPUT -i eth0 -p tcp -m set --match-set triplet_set_test_3_v4 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/iptables -A INPUT -i eth0 -p udp -m set --match-set triplet_set_test_3_v4 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/ip6tables -A OUTPUT -o eth0 -p tcp -m set --match-set triplet_set_test_3_v6 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/ip6tables -A OUTPUT -o eth0 -p udp -m set --match-set triplet_set_test_3_v6 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/ip6tables -A INPUT -i eth0 -p tcp -m set --match-set triplet_set_test_3_v6 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/ip6tables -A INPUT -i eth0 -p udp -m set --match-set triplet_set_test_3_v6 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3

**Example using script to define host,ports combined with network/s hash:ip,port,net**

In case your script can provide the combo of hostname,port you have to use the tag **script_double**. If want to return only a list of hostnames
the you have to provide the port for each list element and use the **script:** or **netgroup:** tag. Please note that last part of each element in the list can only
use the **script:** tag and has to get as input a list with single elements list only net range
Check the following examples

    .. code-block:: ini

        [test_triplet_from_iptables_manager]
        section_type = general
        action = ['accept']
        default_chain = OUTPUT,INPUT
        ip_version = both
        interface = ['main']
        protocol = tcp,udp
        set = triplet_set
        set_directions = src,dst,dst



        [triplet_set]
        section_type = ipset
        ipset_type = hash:ip,port,net
        set_hostnames = ['script_double:test_port_2.sh,script:test_nets_v4.sh','script_double:test_port_2.sh,script:test_nets_v6.sh']
        set_name = ['triplet_set_both']

The output of the above sections is the following:
**Kernel ipset**

    .. code-block:: bash

        /usr/sbin/ipset create triplet_set_both_v4 hash:ip,port,net family inet hashsize 1024 maxelem 65536
        Set  triplet_set_both_v4  created
        /usr/sbin/ipset add triplet_set_both_v4 137.138.47.221,tcp:443,100.64.0.0/10
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.140,tcp:1023,192.91.242.0/24
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.145,tcp:6123,100.64.0.0/10
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.139,tcp:9079,188.184.0.0/15
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.136,tcp:6987,188.184.0.0/15
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.145,tcp:6123,188.184.0.0/15
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.145,tcp:6123,192.91.242.0/24
        /usr/sbin/ipset add triplet_set_both_v4 137.138.47.216,tcp:787,192.91.242.0/24
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.139,tcp:9079,192.91.242.0/24
        /usr/sbin/ipset add triplet_set_both_v4 137.138.47.216,tcp:787,100.64.0.0/10
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.140,tcp:1023,100.64.0.0/10
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.141,tcp:5547,188.184.0.0/15
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.141,tcp:5547,192.91.242.0/24
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.136,tcp:6987,192.91.242.0/24
        /usr/sbin/ipset add triplet_set_both_v4 137.138.47.221,tcp:443,192.91.242.0/24
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.136,tcp:6987,100.64.0.0/10
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.139,tcp:9079,100.64.0.0/10
        /usr/sbin/ipset add triplet_set_both_v4 137.138.47.216,tcp:787,188.184.0.0/15
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.140,tcp:1023,188.184.0.0/15
        /usr/sbin/ipset add triplet_set_both_v4 137.138.47.221,tcp:443,188.184.0.0/15
        /usr/sbin/ipset add triplet_set_both_v4 137.138.99.141,tcp:5547,100.64.0.0/10


    .. code-block:: bash

        /usr/sbin/ipset create triplet_set_both_v6 hash:ip,port,net family inet6 hashsize 1024 maxelem 65536
        Set  triplet_set_both_v6  created
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b50e::100:12,tcp:787,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:5,tcp:9079,2001:1458::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:6,tcp:1023,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:5,tcp:9079,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b50e::100:17,tcp:443,2001:1458::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b50e::100:17,tcp:443,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:2,tcp:6987,2001:1458::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:2,tcp:6987,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:7,tcp:5547,2001:1458::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:7,tcp:5547,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b50e::100:12,tcp:787,2001:1458::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:27,tcp:6123,2001:1458::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:27,tcp:6123,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_both_v6 2001:1458:201:b49f::100:6,tcp:1023,2001:1458::/32

**Rules**

    .. code-block:: bash

        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m set --match-set triplet_set_both_v4 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
        /sbin/iptables -A OUTPUT -o eth0 -p udp -m set --match-set triplet_set_both_v4 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
        /sbin/iptables -A INPUT -i eth0 -p tcp -m set --match-set triplet_set_both_v4 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
        /sbin/iptables -A INPUT -i eth0 -p udp -m set --match-set triplet_set_both_v4 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
        /sbin/ip6tables -A OUTPUT -o eth0 -p tcp -m set --match-set triplet_set_both_v6 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
        /sbin/ip6tables -A OUTPUT -o eth0 -p udp -m set --match-set triplet_set_both_v6 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
        /sbin/ip6tables -A INPUT -i eth0 -p tcp -m set --match-set triplet_set_both_v6 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager
        /sbin/ip6tables -A INPUT -i eth0 -p udp -m set --match-set triplet_set_both_v6 src,dst,dst -j ACCEPT -m comment --comment test_triplet_from_iptables_manager

Another example of mix network set and scripts to create ipsets

    .. code-block:: ini

        [test_triplet_from_iptables_manager_3]
        section_type = general
        action = ['accept']
        default_chain = OUTPUT,INPUT
        ip_version = ipv6
        interface = ['main']
        protocol = tcp,udp
        set = triplet_set_3
        set_directions = dst,dst,src


        [triplet_set_3]
        section_type = ipset
        ipset_type = hash:ip,port,net
        set_hostnames = ['netgroup:IT SECURITY FIREWALL ALIENDB,8080,script:test_nets_v6.sh']
        set_name = ['triplet_set_test_3']


The output of the above sections is the following:
**Kernel ipset**

    .. code-block:: bash

        /usr/sbin/ipset create triplet_set_test_3_v6 hash:ip,port,net family inet6 hashsize 1024 maxelem 65536
        Set  triplet_set_test_3_v6  created
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:5,tcp:8080,2001:1458::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:17,tcp:8080,2001:1458::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:6,tcp:8080,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:12,tcp:8080,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:12,tcp:8080,2001:1458::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:5,tcp:8080,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:2,tcp:8080,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:2,tcp:8080,2001:1458::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b50e::100:17,tcp:8080,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:6,tcp:8080,2001:1458::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:7,tcp:8080,FD01:1459::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:7,tcp:8080,2001:1458::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:27,tcp:8080,2001:1458::/32
        /usr/sbin/ipset add triplet_set_test_3_v6 2001:1458:201:b49f::100:27,tcp:8080,FD01:1459::/32

**Rules**

    .. code-block:: bash

        /sbin/ip6tables -A OUTPUT -o eth0 -p tcp -m set --match-set triplet_set_test_3_v6 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/ip6tables -A OUTPUT -o eth0 -p udp -m set --match-set triplet_set_test_3_v6 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/ip6tables -A INPUT -i eth0 -p tcp -m set --match-set triplet_set_test_3_v6 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3
        /sbin/ip6tables -A INPUT -i eth0 -p udp -m set --match-set triplet_set_test_3_v6 dst,dst,src -j ACCEPT -m comment --comment test_triplet_from_iptables_manager_3

**Example to create an ipset of hash:ip,port**

In case your script can provide the combo of hostname,port you have to use the tag **script_double**. If the script returns only a list of hostnames
the you have to provide the port for each list element and use the **script:** tag. Please note that last part of each element in the list can only
use the **script:** tag and has to get as input a list with single elements list only hostnames
Check the following examples

    .. code-block:: ini

        [test_doublet_from_iptables_manager_2]
        section_type = general
        action = ['accept']
        default_chain = OUTPUT,INPUT
        ip_version = both
        interface = ['main']
        protocol = tcp,udp
        set = triplet_set_2
        set_directions = dst,dst

    .. code-block:: ini

        [doublet_set_2]
        section_type = ipset
        ipset_type = hash:ip,port
        set_hostnames = ['script_double:test_port_2.sh','script:test.sh,443']
        set_name = ['doublet_set_test_2']

The output of the above sections is the following:
**Kernel ipset**

    .. code-block:: bash

        /usr/sbin/ipset create doublet_set_test_2_v4 hash:ip,port family inet hashsize 1024 maxelem 65536
        Set  doublet_set_test_2_v4  created
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.45.152,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.45.151,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.45.153,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 10.17.6.54,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 137.138.47.216,tcp:787
        /usr/sbin/ipset add doublet_set_test_2_v4 137.138.99.145,tcp:6123
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.37.103,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 10.18.16.52,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 10.17.6.56,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 10.17.6.55,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 137.138.99.139,tcp:9079
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.45.163,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 137.138.99.140,tcp:1023
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.45.155,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 137.138.99.141,tcp:5547
        /usr/sbin/ipset add doublet_set_test_2_v4 137.138.99.136,tcp:6987
        /usr/sbin/ipset add doublet_set_test_2_v4 10.17.6.25,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.37.105,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.37.104,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 10.17.6.24,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.45.154,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 188.184.37.102,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v4 137.138.47.221,tcp:443

    .. code-block:: bash

        /usr/sbin/ipset create doublet_set_test_2_v6 hash:ip,port family inet6 hashsize 1024 maxelem 65536
        Set  doublet_set_test_2_v6  created
        /usr/sbin/ipset add doublet_set_test_2_v6 2001:1458:201:b49f::100:27,tcp:6123
        /usr/sbin/ipset add doublet_set_test_2_v6 2001:1458:201:b50e::100:12,tcp:787
        /usr/sbin/ipset add doublet_set_test_2_v6 2001:1458:201:b49f::100:7,tcp:5547
        /usr/sbin/ipset add doublet_set_test_2_v6 2001:1458:201:b49f::100:6,tcp:1023
        /usr/sbin/ipset add doublet_set_test_2_v6 2001:1458:201:b50e::100:17,tcp:443
        /usr/sbin/ipset add doublet_set_test_2_v6 2001:1458:201:b49f::100:5,tcp:9079
        /usr/sbin/ipset add doublet_set_test_2_v6 2001:1458:201:b49f::100:2,tcp:6987


**Rules**

    .. code-block:: bash

        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m set --match-set doublet_set_test_2_v4 dst,dst -j ACCEPT -m comment --comment test_doublet_from_iptables_manager_2
        /sbin/iptables -A OUTPUT -o eth0 -p udp -m set --match-set doublet_set_test_2_v4 dst,dst -j ACCEPT -m comment --comment test_doublet_from_iptables_manager_2
        /sbin/iptables -A INPUT -i eth0 -p tcp -m set --match-set doublet_set_test_2_v4 dst,dst -j ACCEPT -m comment --comment test_doublet_from_iptables_manager_2
        /sbin/iptables -A INPUT -i eth0 -p udp -m set --match-set doublet_set_test_2_v4 dst,dst -j ACCEPT -m comment --comment test_doublet_from_iptables_manager_2
        /sbin/ip6tables -A OUTPUT -o eth0 -p tcp -m set --match-set doublet_set_test_2_v6 dst,dst -j ACCEPT -m comment --comment test_doublet_from_iptables_manager_2
        /sbin/ip6tables -A OUTPUT -o eth0 -p udp -m set --match-set doublet_set_test_2_v6 dst,dst -j ACCEPT -m comment --comment test_doublet_from_iptables_manager_2
        /sbin/ip6tables -A INPUT -i eth0 -p tcp -m set --match-set doublet_set_test_2_v6 dst,dst -j ACCEPT -m comment --comment test_doublet_from_iptables_manager_2
        /sbin/ip6tables -A INPUT -i eth0 -p udp -m set --match-set doublet_set_test_2_v6 dst,dst -j ACCEPT -m comment --comment test_doublet_from_iptables_manager_2