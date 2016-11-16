#!/usr/bin/python

# Copyright (C) 2016, CERN
# This software is distributed under the terms of the GNU General Public
# Licence version 3 (GPL Version 3), copied verbatim in the file "LICENSE".
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as Intergovernmental Organization
# or submit itself to any jurisdiction.

"""
Author: Athanasios Gkaraliakos
email: athanasios.gkaraliakos@cern.ch

The script is written on python >=2.6

Script to identify all network interfaces expect main used by the current box.

"""
import argparse
import subprocess
from main_nic_extractor import main_nic_extractor


def other_nic_extractor(all=False):
    """
    This function returns a list with all network interfaces or all except the main ( the one that listens to the outside)

    :param all: This flag tell the script whether to return all interface except main or everything
    :return: List of network interface names
    """
    interfaces_call = subprocess.Popen(['/bin/ls', '-1', '/sys/class/net'], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
    interfaces, err = interfaces_call.communicate()
    interfaces = interfaces.split('\n')
    del interfaces[-1]

    main_nic = main_nic_extractor()

    if not all:
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
