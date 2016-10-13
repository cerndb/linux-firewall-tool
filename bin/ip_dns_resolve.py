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

"""
import sys
import argparse
try:
    import dns.resolver
except ImportError:
    print "Plase install python-dns rpm: 'yum install python-dns' "
    sys.exit(1)

# create a new instance named 'my_resolver'
my_resolver = dns.resolver.Resolver()


def ip_dns_resolver(hostname, iptype, silent=False):
    """
    This function receives a host name and tries to resolve it via DNS and get the IPv4/IPv6 address/es

    :param hostname: Hostname
    :param iptype: Type of ip address ( IPv4 or IPv6 or both )
    :return: IP addresses found ( IPv4 or IPv6 or both )
    """
    if iptype not in ['ipv4', 'ipv6', 'ip']:
        sys.stderr("Not given ip type ", ' ipv4', ' ipv6', ' ip')
        sys.exit(1)

    iplist = []

    hostname = hostname.upper()

    if not silent:
        iplist.append(str(hostname))

    if iptype == 'ipv4' or iptype == 'ip':
        try:
            ipv4 = my_resolver.query(hostname, "A")
            for ip in ipv4:
                iplist.append(str(ip))
        except dns.resolver.NoAnswer:
            if not silent:
                iplist.append("IPv4NOTFOUND")
        except dns.resolver.NXDOMAIN:
            if not silent:
                iplist.append("IPv4NOTFOUND")
    if iptype == 'ipv6' or iptype == 'ip':
        try:
            ipv6 = my_resolver.query(hostname, "AAAA")
            for ip in ipv6:
                iplist.append(str(ip))
        except dns.resolver.NoAnswer:
            if not silent:
                iplist.append("IPv6NOTFOUND")
        except dns.resolver.NXDOMAIN:
            if not silent:
                iplist.append("IPv6NOTFOUND")
    return iplist


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('--iptype', nargs=1, choices=['ipv4', 'ipv6', 'ip'], help='specify ipv4 or ipv6 or ip for both')
    parser.add_argument('--hostname', nargs='+', help='Define the hostname you want to resolve ')
    parser.add_argument('--silent', action='store_true', help='Print only ips')

    args = parser.parse_args()

    if args.iptype:
        iptype = args.iptype[0]
    else:
        iptype = 'ip'

    if args.hostname:
        hostname = args.hostname[0]
    else:
        print parser.print_usage()
        sys.exit(1)
    if args.silent:
        print '\n'.join(map(str, ip_dns_resolver(hostname, iptype, True)))
    else:
        print '\n'.join(map(str, ip_dns_resolver(hostname, iptype)))

if __name__ == '__main__':
    main()
