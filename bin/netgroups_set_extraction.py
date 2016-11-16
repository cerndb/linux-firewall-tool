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

The script is written on python >=2.6

Script to get IPv4 and/or IPv6 (if exists) for every machine in the given set

Depends on python-dns " yum install python-dns "

This script was querying the CERNs network service to obtain the hostnames of machine in specified groupings and then
 it was resolving the ipv4 and ipv6 addresses for all the hostnames. Then this list of lists is used from the
 ipset_manger.py script to create an ipset from all this ips.

 Format:     [['DB-51088.CERN.CH', '137.138.161.23', '2001:1458:201:ae::100:9'],
              ['DB-51089.CERN.CH', '137.138.161.68', '2001:1458:201:ae::100:36']]

"""
import argparse
import sys

from ip_dns_resolve import ip_dns_resolver


def netgroup_set_extractor(iptype, networksets, cmdcall=False, only_hostnames=False):
    # pylint: disable=C0301
    """
    This function is proxy between main and the rest of the script so it can be run both as script and as a module

    :param iptype: Type of ip version IPv4 or IPv6 or both
    :param networksets: Names of networks search to query for the LanDB service
    :param cmdcall: Determines if the script is called from cmd
    :return: Returns a list with host names and ip addresses or print to the screen if it called from the cmd
    """

    """The interface, not implemented"""
    raise NotImplementedError("This was CERN specific for dealing with the network service. If you want this feature "
                              "you have to implement it yourself. The expected format is a list of lists like the "
                              "following:"
                              "[['DB-51088.CERN.CH', '137.138.161.23', '2001:1458:201:ae::100:9'],"
                              " ['DB-51089.CERN.CH', '137.138.161.68', '2001:1458:201:ae::100:36']]"
                              "On each list you specify first the IPv4 addresses and then the IPv6")



def main():
    # pylint: disable=C0301
    """
    This is the main function. It parses the command line arguments and calls the appropriate function to handle
    each the job.

    :return: Does not return anything
    """

    parser = argparse.ArgumentParser()

    parser.add_argument('--username', nargs=1, help='type the username for the network service')
    parser.add_argument('--password', nargs=1, help='type the password for the network service')
    parser.add_argument('--iptype', nargs=1, choices=['ipv4', 'ipv6', 'ip'], help='specify ipv4 or ipv6 or ip for both')
    parser.add_argument('--networksets', nargs='+', help='Define network sets like "IT SECURITY FIREWALL ALIENDB" use '
                                                         '" " or the escape char \ if spaces or special characters '
                                                         'included')
    parser.add_argument('--only_hostnames', action='store_true', help='Return only hostnames without resolving them to '
                                                                      'ips')

    args = parser.parse_args()

    if args.iptype:
        iptype = args.iptype[0]
    else:
        iptype = 'ip'

    if args.only_hostnames:
        only_hostnames = True
    else:
        only_hostnames = False

    cmdcall = True

    if args.networksets:
        # Authentication information
        if type(args.username) is list:
            user = args.username[0]
            if args.password:
                password = args.password[0]
                netgroup_set_extractor(iptype, args.networksets, user, password, cmdcall, only_hostnames)
            else:
                print parser.usage()
                sys.exit(1)
        else:
            user = args.username
        # Create the soap client instance
            netgroup_set_extractor(iptype, args.networksets, user, None, cmdcall, only_hostnames)
    else:
        print parser.print_usage()
        sys.exit(1)


if __name__ == '__main__':
    main()
