Log rules
=========

**Example rule for jumping to the LOG chain**

    .. code-block:: ini

        [essential_services_5]
        section_type = general
        action = ['log','drop']
        ip_version = both
        interface = main
        default_chain = INPUT
        protocol = tcp,udp
        custom_chain = TEST_DROP_CHAIN
        limit = 1/sec
        log-level = 6
        log-prefix = TEST_DROP_CUSTOM_CHAIN
        log-specific-options = ['log-tcp-sequence','log-tcp-options','log-ip-options']

The logic of the action is the following:
    .. code-block:: ini

        action = ['log','drop']

If the list has 2 elements it means that it will create rules for logging the traffic of the input.
First element tells the script that it will create logging rules.
Second element tells the action of the packet after logging to either `'allow'` or `'drop'`

    .. code-block:: bash

        /sbin/iptables -N TEST_DROP_CHAIN
        /sbin/ip6tables -N TEST_DROP_CHAIN

        /sbin/iptables -A INPUT -i eth0 -p tcp -j TEST_DROP_CHAIN
        /sbin/iptables -A INPUT -i eth0 -p udp -j TEST_DROP_CHAIN
        /sbin/iptables -A TEST_DROP_CHAIN -m limit --limit 1/sec -j LOG --log-prefix TEST_DROP_CUSTOM_CHAIN --log-level 6 --log-tcp-sequence --log-tcp-options
        /sbin/iptables -A TEST_DROP_CHAIN -j DROP


        /sbin/ip6tables -A INPUT -i eth0 -p tcp -j TEST_DROP_CHAIN
        /sbin/ip6tables -A INPUT -i eth0 -p udp -j TEST_DROP_CHAIN
        /sbin/ip6tables -A TEST_DROP_CHAIN -m limit --limit 1/sec -j LOG --log-prefix TEST_DROP_CUSTOM_CHAIN --log-level 6 --log-tcp-sequence --log-tcp-options
        /sbin/ip6tables -A TEST_DROP_CHAIN -j DROP