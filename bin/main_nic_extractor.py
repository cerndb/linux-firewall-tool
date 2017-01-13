#!/usr/bin/python

# Copyright (C) 2016, CERN
# This software is distributed under the terms of the GNU General Public
# Licence version 3 (GPL Version 3), copied verbatim in the file "LICENSE".
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as Intergovernmental Organization
# or submit itself to any jurisdiction.

"""
Author: Athanasios Gkaraliakos
email: a.gkaraliakos@gmail.com
email: athanasios.gkaraliakos@cern.ch

The script is written on python >=2.6

Script to identify which is the main network interface used by the current box.

"""

import subprocess
from ip_dns_resolve import ip_dns_resolver


def main_nic_extractor():
    """
    This script tries to identify which is the main network interface used by the current box using the machine
    host name. It resolves the host name via DNS and returns the interface ( nic ) that uses this IPv4/IPv6
    address

    :return: Returns only the name of the interface ( e.g. eth0 )
    """
    # Call to get machine 's hostname
    hostname_call = subprocess.Popen(['/bin/hostname'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    hostname, err = hostname_call.communicate()
    hostname = hostname.replace('\n', '')

    machine = ip_dns_resolver(hostname, 'ip')

    box_ipv4 = ''
    box_ipv6 = ''

    if machine[1] != 'IPv4NOTFOUND':
        box_ipv4 = machine[1]
    if machine[2] != 'IPv4NOTFOUND':
        box_ipv6 = machine[2]

    # Call to get the list of available network interfaces
    interfaces_call = subprocess.Popen(['/bin/ls', '-1', '/sys/class/net'], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
    interfaces, err = interfaces_call.communicate()
    interfaces = interfaces.split('\n')
    del interfaces[-1]

    main_interface = -1

    # Check if interface uses the current dns ipv4 and/or ipv6 and return it as the main interface
    if box_ipv4 != '' or box_ipv6 != '':
        for inter in xrange(len(interfaces)):
            interface_call = subprocess.Popen(['/sbin/ip', 'addr', 'show', interfaces[inter]],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            interface_info, err = interface_call.communicate()
            if (box_ipv4 in interface_info) or (box_ipv6 in interface_info):
                main_interface = inter
                break

    # Return the main interface
    if main_interface > -1:
        return interfaces[main_interface]
    else:
        return ''


def main():
    # pylint: disable=C0301
    """
    This script tries to identify which is the main network interface used by the current box using the machine
    host name. It resolves the host name via DNS and returns the interface ( nic ) that uses this IPv4/IPv6
    address

    :return: Returns only the name of the interface ( e.g. eth0 )
    """
    print main_nic_extractor()

if __name__ == '__main__':
    main()
