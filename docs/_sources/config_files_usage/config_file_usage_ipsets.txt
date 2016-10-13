Explanation of the config files for creating ipsets
===================================================

**Allowed options on ipset section**


:ipset: **Section for ipset**

    :description: *Free text to add description to each ipset*

    :ipset_type: ``hash:net,port`` or ``hash:ip,port`` or ``hash:net`` or ``hash:ip`` or ``hash:ip,port,net`` or ``hash:ip,port,ip``

        The above types are allowed to be defined when describing an ipset.

    :set_name: Here we define the name this ipset

        Please note that depending for each IP protocol version ``_v4`` or ``_v6`` will be appended when the set is
        actually created on the kernel side.

    :netgroup_name: Here we define the name of a netgroup from which host we will create the ipset

        Note that if we don't specify a name the set will take the LanDB name if its smaller than 29 chars

    :netgroups_list: Here we define a list of netgroups so we can create ipsets based on many LanDB sets

        Note that depending on the ipset type each element of the list should in the appropriate format

        * e.g. ``["script:test_port.sh","script:test_port_2.sh","agkara-train,6178"]``
        * e.g. ``['CERNVM-CLUSTER-ESX,tcp:5530,CDS LB','DRUPAL,tcp:6677,FRONTIER-MONITORING']``

    :set_hostnames: Here we define the hostname or list of hostnames or script that returns list of hostnames

        This option is used on almost all set types to define the appropriate data depending on the set type.

    :set_ips_v4: Here we define ip or ip,port or list of ips or ips,ports or script that returns list of each type for IPv4 ipset

    :set_ips_v6: Here we define ip or ip,port or list of ips or ips,ports or script that returns list of each type for IPv6 ipset

    :set_net_ranges_v4: Here we define network range and/or port or list of network ranges and/or ports or script that returns list of each type for IPv4 ipset

    :set_net_ranges_v6: Here we define network range and/or port or list of network ranges and/or ports or script that returns list of each type for IPv6 ipset

    :set_ip_port_ip_v4: Here we define ip,port,ip for IPv4 ipset

    :set_ip_port_ip_v6: Here we define ip,port,ip for IPv6 ipset

    :set_ip_port_net_v4: Here we define ip,port,net_range for IPv4 ipset

    :set_ip_port_net_v6: Here we define ip,port,net_range for IPv6 ipset



:script: When you want to use a script inside the ipset for either **hostnames** or **cern_set_list** you have to define
         the **script:** "*keyword*" and then the script as you would normally type in the command line.