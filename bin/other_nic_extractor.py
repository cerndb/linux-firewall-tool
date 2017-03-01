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

Script to identify all network interfaces expect main used by the current box.

"""
import argparse
import subprocess
import os.path
import sys
from main_nic_extractor import main_nic_extractor


def other_nic_extractor(all_nics=False):
    """
    This function returns a list with all network interfaces or all except the main ( the one that listens to the outside)

    :param all_nics: This flag tell the script whether to return all interface except main or everything
    :return: List of network interface names
    """
    interfaces_call = subprocess.Popen(['/bin/ls', '-1', '/sys/class/net'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    interfaces, err = interfaces_call.communicate()
    if not err:
        interfaces = interfaces.split('\n')
        del interfaces[-1]
    else:
        print err
        print "Cannot extract bonded interfaces"
        sys.exit(1)

    # Strip out none interface files (not symlink files)
    interfaces = [nic for nic in interfaces if os.path.islink('/sys/class/net/' + nic)]

    # Strip out bonded interfaces
    bonded_interfaces_call = subprocess.Popen('/bin/cat /sys/class/net/*/bonding/slaves', shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    bonded_interfaces, err = bonded_interfaces_call.communicate()
    if not err:
        bonded_interfaces = bonded_interfaces[:-1]
        bonded_interfaces = bonded_interfaces.split(' ')

        interfaces = [nic for nic in interfaces if nic not in bonded_interfaces]
    else:
        # print err
        print "No bonded interfaces detected"

    main_nic = main_nic_extractor()

    if not all_nics:
        index = interfaces.index(main_nic)
        del interfaces[index]

    return interfaces


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('--all', action='store_true', help='Show all nic including main')

    args = parser.parse_args()

    if args.all:
        print other_nic_extractor(True)
    else:
        print other_nic_extractor()

if __name__ == '__main__':
    main()