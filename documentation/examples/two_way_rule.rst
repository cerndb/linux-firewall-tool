Bidirectional Rules
===================

**Example rule for INPUT and OUTPUT chains in one section**

**Sections without an ipset**

    ..  code-block:: ini

        [essential_services]
        section_type = general
        action = ['accept','out','in']
        ip_version = ipv6
        interface = eth0
        protocol = tcp
        ports = 22:32

The section [essential_services] will create a kernel ipset called admin_workstations_x_v4 since its set to ipv4.
The logic of the action is the following:

    .. code-block:: bash

        action = ['accept','out','in']

If the list has 3 elements it means that it will create two rules. One for INPUT and one for OUTPUT.
Elements 2 and 3 define the 'direction of the connection'. So the `'out'`,`'in'` means that new connections will be
allowed initiating from an outside ip. This create two following rules.

    .. code-block:: bash

        /sbin/iptables -A INPUT -i eth0 -p tcp -m state --state **NEW,ESTABLISHED** -m multiport --dports 22,50 -j ACCEPT
        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m state --state **ESTABLISHED** -j ACCEPT

    .. code-block:: ini

        [essential_services_4]
        section_type = general
        action = ['accept','in','out']
        ip_version = both
        interface = main
        protocol = tcp,udp

**Sections with an ipset**

    ..  code-block:: ini

        [essential_services]
        section_type = general
        action = ['accept','out','in']
        ip_version = ipv4
        interface = eth0
        protocol = tcp
        ports = 22,50
        set = new_set

        [new_set]
        section_type = ipset
        ipset_type = hash:ip
        set_name = ['admin_workstations_x']
        #set_ips_v4 = ['137.138.142.166','137.138.25.22','10.18.2.204','137.138.160.37','137.138.142.156']
        set_hostnames = ['lxplus','pcthanos','syscontrol-dev','pcjcano2','kubernetes-node','kubernetes-master','agkara-train-2']


The section [essential_services] will create a kernel ipset called admin_workstations_x_v4 since its set to ipv4.
The logic of the action is the following:

    .. code-block:: bash

        action = ['accept','out','in']

If the list has 3 elements it means that it will create two rules. One for INPUT and one for OUTPUT.
Elements 2 and 3 define the 'direction of the connection'. So the `'out'`,`'in'` means that new connections will be
allowed initiating from an outside ip. This create two following rules.

    .. code-block:: bash

        /sbin/iptables -A INPUT -i eth0 -p tcp -m state --state NEW,ESTABLISHED -m multiport --dports 22,50 -m set --match-set admin_workstations_x_v4 src -j ACCEPT
        /sbin/iptables -A OUTPUT -o eth0 -p tcp -m state --state ESTABLISHED -m set --match-set admin_workstations_x_v4 dst -j ACCEPT

So new connections are allowed from the outside inside.

