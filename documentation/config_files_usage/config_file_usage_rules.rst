Explanation of the config files for creating rules
==================================================

**Allowed options on each section**

:section_type: ``general`` / ``ipset`` / ``policy``

* ``general`` This value indicates this section defines rule/s
* ``ipset``   This value indicates this section defines a kernel ipset
* ``policy``  This value indicates this section defines policy we want to apply (ACCEPT, DROP)

:general: **Section for rules**

    :description: *Free text to add description to each rule*

    :action: ``['accept','out','in']`` / ``['log','drop']`` / ``['drop']``

        #. ``['accept'/'drop','out','in']`` or ``['accept'/'drop','in','out']``:
            This value indicates this section is a **bidirectional rules**
        #. ``['log','drop'/'accept']``:
            This value indicates this section is a **log rule**
        #. ``['accept'/'drop']``:
            This value indicates this section is a **single rule/s**

    :default_chain: ``INPUT``

        * ``INPUT / OUTPUT``
            Here we state at which chain the rule is going to be added

    :ip_version: ``ipv6``

        * ``ipv4 / ipv6 / both``
            Here we define the version of the iptables we want the rules to be applied on.

    :interface: ``main``

        Here we define the nic card that the rule will be using.

        * ``main / all / other / name_of_real_interface(eth1)``
        * ``main`` returns the interface that has a routeable address and can be resolved via DNS
        * ``all`` return all the interfaces of a machine
        * ``other`` returns all the interfaces of a machine excpet the ``main``
        * ``['main','+interface_name']`` return tha main plus specified interface e.g.(eth2), so we configure rules for both
        * ``['other','-interface_name']`` return all except main and also omits the specified interface, so there will be rules for all the other

    :protocol: ``tcp,udp``

        Here we define the protocol on which the rule will be applied on. We can define either one e.g. ``tcp`` or both
        ``udp,tcp`` to create rule for both.

    :jump_chain: ``DROP``

        Here we define the chain we want to jump to when a packet matches on a rule

    :ports: ``443`` / ``22:35`` / ``443,547,80,..`` / ``"/sbin/port_script.sh"``

        Here we define the ports we want this rule to be applied on. We add a tell the option to run a script and return
        one of the previous formats of ports.

:general: **Section for log,accept/drop**

    :custom_chain: ``NAME_OF_CHAIN``

        Here we define a user chain we want the packets to jump into so we perform logging and the accept or drop

    :limit: ``1/sec``

        Followed by a number. This determines the maximum number of matches to allow per unit time (default is per second).
        The number can explicitly units determined by '/ second /', '/ minute /', '/ hour /' or '/ day /' or parts of
        them (so '5 / second' is the same as' 5 / s ').

    :log-level: ``info``

        Followed by a level number or name. Valid names are (case-insensitive) 'debug', 'info', 'notice', 'warning',
        'err', 'crit', 'alert' and 'emerg', corresponding to numbers 7 through 0. See the man page for syslog.conf for
        an explanation of these levels. The default is 'warning'.

    :log-prefix: ``DROP:``

        Followed by a string of up to 29 characters, this message is sent at the start of the log message, to allow it
        to be uniquely identified.

    :log-specific-options: ``['log-tcp-sequence','log-tcp-options','log-ip-options']``

        Use this options inside a list without the double dash --

        * log-tcp-sequence
            Log TCP sequence numbers. This is a security risk if the log is readable by users.
        * log-tcp-options
            Log options from the TCP packet header.
        * log-ip-options
            Log options from the IP packet header.
        * log-uid
            Log the userid of the process which generated the packet.


:general: **Section for single way rule**

    :set: ``name_of_the_ipset_section``

        Here we define the name of the section that describes an ipset to be used with this rule

    :set_directions: ``src`` or ``src,dst`` or ``dst,dst,src``

        Here we define the 'direction' for each element of the ipset. Each element of an ipset can have 3 types

        * single: ipsets that hold only IPs or net ranges
        * double: ipsets that hold IPs or net ranges along with ports
            e.g. **192.168.1.1,tcp:443**
        * triple: ipsets that hold IPs or net ranges along with ports and IPs net ranges
            e.g. **192.168.1.1,tcp:80,192.168.2.1**

        So each part of an element should have a 'direction' on each rule


:policy: **Section to define the policy of our firewall. Only one section is allowed**

    :INPUT: ``ACCEPT`` or ``DROP``

        * Define the policy of the INPUT default chain

    :OUTPUT: ``ACCEPT`` or ``DROP``

        * Define the policy of the OUTPUT default chain

    :FORWARD: ``ACCEPT`` or ``DROP``

        * Define the policy of the FORWARD default chain