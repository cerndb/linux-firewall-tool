Policy
======

**Example to define the policy**

    .. code-block:: bash

        [mypolicy]
        section_type = policy
        ip_version = both
        INPUT = DROP
        OUTPUT = ACCEPT
        FORWARD = DROP

Option **ip_version = both** means to apply the policy on both **iptables** and **ip6tables**.