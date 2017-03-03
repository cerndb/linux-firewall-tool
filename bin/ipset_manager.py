#!/usr/bin/python

# Copyright (C) 2016, CERN
# This software is distributed under the terms of the GNU General Public
# Licence version 3 (GPL Version 3), copied verbatim in the file "LICENSE".
# In applying this license, CERN does not waive the privileges and immunities
# granted to it by virtue of its status as Intergovernmental Organization
# or submit itself to any jurisdiction.

# pylint: disable=C0301
"""
Author: Athanasios Gkaraliakos
email: a.gkaraliakos@gmail.com
email: athanasios.gkaraliakos@cern.ch

The script is written on python >=2.6

Script to create/modify/delete ipsets on CentOS6.x and older of IPv4 and/or IPv6 (if exists) from CERN's network sets.

"""

import sys
import argparse
import subprocess
import os
import ipaddress
from ip_dns_resolve import ip_dns_resolver
from netgroups_set_extraction import netgroup_set_extractor
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


######################################################################################
def read_config_file(parameter):

    project_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    return_parameter = None

    try:
        for line in open(project_folder + '/default_conf_files' + '/configuration_info.cfg', 'r').readlines():
            if parameter in line:
                return_parameter = line.partition('"')[-1].rpartition('"')[0]
                break
    except:
        print "Cannot read config file!!! Cannot read config file!!! \nPath: " + project_folder + \
              '/default_conf_files' + '/configuration_info.cfg' + " \nApplying defaults"
        call = subprocess.Popen(['/bin/cat', '/etc/redhat-release'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        vers, err = call.communicate()

        if parameter == 'ipset_script':
            if err:
                print "Linux Distro Check FAILED!!"
                sys.exit(1)
            if 'release 7' in vers:
                return_parameter = "/usr/libexec/ipset/ipset.start-stop"

            elif 'release 6' in vers:
                return_parameter = "/etc/init.d/ipset"

        elif parameter == 'ipset_command':
            if err:
                print "Linux Distro Check FAILED!!"
                sys.exit(1)
            if 'release 7' in vers:
                return_parameter = "/sbin/ipset"

            elif 'release 6' in vers:
                return_parameter = "/usr/sbin/ipset"

        elif parameter == 'ipset_file':
            if err:
                print "Linux Distro Check FAILED!!"
                sys.exit(1)
            if 'release 7' in vers:
                return_parameter = "/etc/ipset/ipset"

            elif 'release 6' in vers:
                return_parameter = "/etc/sysconfig/ipset"

    return return_parameter


######################################################################################
# Extract Network sets using set name from the CERN network service
# Call the python script that handles the soap parsing and set extraction from the network service
def get_network_sets(set_names, iptype, username=None, password=None):
    # pylint: disable=C0301
    """
    The function uses the ip_extraction.py python script to query LanDB service based on a network set name and extract
    all the ip addresses of each machine inside this network set.

    :param set_names: Network set names to queried on LanDB
    :param iptype: define the ip version to use (IPv4 or IPv6)
    :param username: optional username for the LanDB service authentication
    :param password: mandatory if you specify username for the LanDB service authentication
    :return: String output containing all the ip address if they are successfully resolved
    """

    if (username is not None) and (password is not None):
        netgroup_set = netgroup_set_extractor(iptype, set_names, username, password)
        # print "Temp cred: ", temp
        return netgroup_set
    else:
        netgroup_set = netgroup_set_extractor(iptype, set_names)
        # print "Temp: ", temp
        return netgroup_set


######################################################################################
# Create a sub list of only IPv4 or IPv6 to feed to the ipset command
def extract_ips_from_network_set(network_set, iptype):
    # pylint: disable=C0301
    """
    This function receives a list of host names and ip addresses and returns a list containing only ip addresses

    :param network_set: List like machines[ [hostname, ipv4, ..., ipv6, ...], [hostname, ipv4, ..., ipv6, ...] ]
    :param iptype: Define ip version (IPv4 or IPv6)
    :return: A list of ip addresses
    """

    ips = []
    for i in xrange(len(network_set)):
        for j in xrange(len(network_set[i]) - 1):
            if iptype == 'ipv4':
                if '.' in network_set[i][j + 1]:
                    ips.append(network_set[i][j + 1])
            elif iptype == 'ipv6':
                if ':' in network_set[i][j + 1]:
                    ips.append(network_set[i][j + 1])
    return ips


######################################################################################
# Create a sub list of only IPv4 or IPv6 from the ipset command
def extract_ips_from_ipset(set_name):
    # pylint: disable=C0301
    """
    This function receives the name of an ipset currently active on the kernel strips out the part that contains the
    ip addresses and creates a list of those ip address ( along with the ports if the ipset contains ports also )

    :param set_name: Active kernel ipset
    :return: return a list with all the addresses inside this ipset of nothing if the ipset is empty or does not exist
    """
    ipset_command = read_config_file('ipset_command')

    call = subprocess.Popen([ipset_command, 'list', set_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    response, err = call.communicate()

    if "The set with the given name does not exist" in err:
        print "Set with name " + set_name + " does not exist"
        return ''
    else:
        # print response
        ips_of_set = response[response.find("Members:"):][9:]  # <-- Extract the IPs of the set
        ips_of_set = ips_of_set.split('\n')  # Format the IPs into a list for better handling
        del ips_of_set[-1]  # Delete the last element because its a void
        # for i in xrange(len(ips_of_set)):
        #     ips_of_set[i] = ips_of_set[i].replace('tcp:', '')
        #     ips_of_set[i] = ips_of_set[i].replace('upd:', '')
    return ips_of_set


######################################################################################
# Create ip sets of either IPv4 or IPv6
def create_ip_set(simulate, ips, setname, iptype, settype, port, generate_file, file_override):
    # pylint: disable=C0301
    """
    This function receives a list of ip addresses and tries to create an ip set using the system "ipset" command

    :param simulate: If is true just prints the actions on the screen and does not create a set
    :param ips: List with ip addresses (IPv4 or IPv6)
    :param setname: The name for the ipset
    :param iptype: Type of ip addresses and set family (IPv4 -> inet, IPv6 -> inet6)
    :param settype: Type of the ip set
    :param port: Port number if the ipset uses ports
    :param generate_file: Flag to write the ipset on the config file or not
    :param file_override: Flag to write a new config file or append to the current one in the folder
    :return: Does not return anything. Prints output messages and error messages if any
    """

    ipset_command = read_config_file('ipset_command')

    file_lines = []

    if iptype == "ipv4":
        setname += "_v4"
        if simulate:
            if generate_file:
                file_lines.append(['create', setname, settype, 'family', 'inet', 'hashsize', '1024', 'maxelem', '65536'])
            else:
                print ipset_command, 'create', setname, settype, 'family', 'inet', 'hashsize', '1024', 'maxelem', '65536'
        else:
            call = subprocess.Popen([ipset_command, 'create', setname, settype, 'family', 'inet', 'hashsize', '1024',
                                     'maxelem', '65536'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elif iptype == "ipv6":
        setname += "_v6"
        if simulate:
            if generate_file:
                file_lines.append(['create', setname, settype, 'family', 'inet6', 'hashsize', '1024', 'maxelem', '65536'])
            else:
                print ipset_command, 'create', setname, settype, 'family', 'inet6', 'hashsize', '1024', 'maxelem', '65536'
        else:
            call = subprocess.Popen([ipset_command, 'create', setname, settype, 'family', 'inet6', 'hashsize', '1024',
                                     'maxelem', '65536'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not simulate:
        response, err = call.communicate()
        exit_code = call.wait()
    else:
        err = ''
        exit_code = 0

    if "set with the same name already exists" in err:
        print "Set with name " + setname + " cannot be created. Set already exists"
    elif exit_code != 0:
        print "Error creating the specified set, exit code: ", exit_code
    else:
        print "Set ", setname, " created"
        if len(ips) > 0:
            if settype == 'hash:ip,port' or settype == 'hash:net,port':
                if port[0] != 'direct' and len(port) > 1:
                    for i in xrange(len(ips)):
                        ips[i] = ips[i] + "," + port[i]
            # print ips
            ips = list(set(ips))  # remove dublicates

            for i in xrange(len(ips)):
                if simulate:
                    if 'NOTFOUND' not in ips[i]:
                        # print ipset_command, ' add ', setname, ' ', ips[i]
                        if generate_file:
                            file_lines.append(['add', setname, ips[i]])
                        else:
                            print ipset_command, 'add', setname, ips[i]
                else:
                    if 'NOTFOUND' not in ips[i]:
                        call = subprocess.Popen([ipset_command, 'add', setname, ips[i]],
                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        response, err = call.communicate()
                        exit_code = call.wait()
                        if response:
                            print response
                        elif err:
                            print err
                        elif exit_code != 0:
                            print "Error adding the specified rule, exit code: ", exit_code
    if generate_file:
        write_config_file(setname, file_lines, file_override)


######################################################################################
# Delete ip sets of either IPv4 or IPv6
def destroy_ip_set(simulate, setname, iptype):
    # pylint: disable=C0301
    """
    This function destroys a running ipset

    :param simulate: If is true just prints the actions on the screen and does not create a set
    :param setname: The name for the ipset
    :param iptype: Type of ip addresses and set family (IPv4 -> inet, IPv6 -> inet6)
    :return: Does not return anything. Prints output messages and error messages if any
    """
    ipset_command = read_config_file('ipset_command')

    if iptype == "ipv4":
        setname += "_v4"
    elif iptype == "ipv6":
        setname += "_v6"

    if simulate:
        print ipset_command, ' destroy ', setname
    else:
        call = subprocess.Popen([ipset_command, 'destroy', setname],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if not simulate:
        response, err = call.communicate()
        exit_code = call.wait()
    else:
        err = ''
        exit_code = 0
    if "The set with the given name does not exist" in err:
        print "Set with name " + setname + " cannot be destroyed. Set does not exist"
    elif exit_code != 0:
        print "Error destroying the specified set, exit code: ", exit_code
    else:
        print "Set ", setname, " destroyed"


######################################################################################
# Modify ip sets of either IPv4 or IPv6
def update_ip_set(simulate, ips, set_name, ip_type, settype, port):
    # pylint: disable=C0301
    """
    This function receives a list of ip addresses and tries to update a current running ip set using the
    system "ipset" command

    :param simulate: If is true just prints the actions on the screen and does not create a set
    :param ips: List with ip addresses (IPv4 or IPv6)
    :param set_name: The name for the ipset
    :param ip_type: Type of ip addresses and set family (IPv4 -> inet, IPv6 -> inet6)
    :param settype: Type of the ip set
    :param port: Port number if the ipset uses ports
    :return: Does not return anything. Prints output messages and error messages if any
    """
    ipset_command = read_config_file('ipset_command')

    # lr_diff  difference  left elements, subtracting any in common with right
    lr_diff = lambda left, right: list(set(left).difference(right))

    if len(ips) > 0:
        if settype == 'hash:ip,port' or settype == 'hash:net,port':
            if port[0] != 'direct' and len(port) > 1:
                for i in xrange(len(ips)):
                    ips[i] = ips[i] + "," + port[i]

    if ip_type == "ipv4":
        set_name += "_v4"
    elif ip_type == "ipv6":
        set_name += "_v6"

    ips_of_set = extract_ips_from_ipset(set_name)

    if type(ips_of_set) is not list:
        print "Cannot extract ips from set"
        sys.exit(1)

    in_network_not_in_set = lr_diff(ips, ips_of_set)
    in_set_not_in_network = lr_diff(ips_of_set, ips)

    print set_name
    print "\n"
    print "To be added: ", in_network_not_in_set
    print "\n"
    print "To be removed: ", in_set_not_in_network
    print "\n"

    for address in in_network_not_in_set:
        if simulate:
            if 'NOTFOUND' not in address:
                print ipset_command, ' add ', set_name, ' ', address
                exit_code = 0
        else:
            if 'NOTFOUND' not in address:
                call = subprocess.Popen([ipset_command, 'add', set_name, address], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                response, err = call.communicate()
                exit_code = call.wait()
                if exit_code != 0:
                    print response, '\n', err

    for address in in_set_not_in_network:
        if simulate:
            print ipset_command, ' del ', set_name, ' ', address
            exit_code = 0
        else:
            call = subprocess.Popen([ipset_command, 'del', set_name, address], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            # print response, '\n', err
            exit_code = call.wait()
            if exit_code != 0:
                print response, '\n', err

    if not simulate:
        ips_of_set = extract_ips_from_ipset(set_name)

        in_network_not_in_set = lr_diff(ips, ips_of_set)
        in_set_not_in_network = lr_diff(ips_of_set, ips)

        if len(in_network_not_in_set) >= 1:
            print "To be added: ", in_network_not_in_set
        if len(in_set_not_in_network) >= 1:
            print "To be removed: ", in_set_not_in_network


######################################################################################
# Save the current ipsets currently in memory or delete the file if there is none
def save_current_ipset(simulate):
    """
    This function is used to save the ipset configuration currently in memory

    :param simulate: Flag to tell the method whether to actually save or just print the command
    :return: void
    """
    ipset_script = read_config_file('ipset_script')

    if simulate:
        print ipset_script + " save"

    else:

        if '.start-stop' in ipset_script:
            call = subprocess.Popen([ipset_script, 'reload'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            call = subprocess.Popen([ipset_script, 'save'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        # print response, '\n', err
        exit_code = call.wait()
        print response
        if exit_code != 0:
            print err


######################################################################################

def handle_list_set(simul, action, set_name, set_names_list, generate_file=False):
    """
    This function is used to handle the operation on list:set type of ipset.

    :param simul: Flag to print or not
    :param action: the action to perform
    :param set_name: name of the set
    :param set_names_list: list of names of other existing ipsets to add
    :param generate_file: Flag to write to the ipset generated file or not
    :return: 0 if ok or 1 if not ok
    """

    ipset_command = read_config_file('ipset_command')

    file_lines = []

    if action == 'create':
        call = subprocess.Popen([ipset_command, 'list', set_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        exit_code = call.wait()
        if exit_code != 0:
            if not simul:
                call = subprocess.Popen([ipset_command, 'create', set_name, 'list:set'], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                response, err = call.communicate()
                exit_code = call.wait()
            else:
                if generate_file:
                    file_lines.append(['create', set_name, 'list:set'])
                else:
                    print ipset_command, ' create ', set_name, ' list:set'
                exit_code = 0
            if exit_code != 0:
                print "Error creating the specified set, exit code: ", exit_code
                print err
            else:
                print "Set '" + set_name + "' created"
                if set_names_list is not None:
                    if not simul:
                        call = subprocess.Popen([ipset_command, 'list', '-n'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        response, err = call.communicate()
                        exit_code = call.wait()
                    else:
                        exit_code = 0
                    if exit_code != 0:
                        print "Error listing ipsets, exit code: ", exit_code
                        print err
                    else:
                        if not simul:
                            current_sets = response.split('\n')
                            for _set_ in set_names_list:
                                if _set_ in current_sets:
                                        call = subprocess.Popen([ipset_command, 'add', set_name, _set_],
                                                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                        response, err = call.communicate()
                                        exit_code = call.wait()
                                        if exit_code != 0:
                                            print "Error adding the specified set to the list set, exit code: ", exit_code
                                            print err
                                else:
                                    print "Set name: '" + str(_set_) + "' does not exist. Omitting"
                        else:
                            for _set_ in set_names_list:
                                if not generate_file:
                                    print ipset_command + ' add ' + set_name + ' ' + _set_
                                else:
                                    file_lines.append(['add', set_name, _set_])
                            if generate_file:
                                write_config_file(set_name, file_lines, False)
        else:
            print "Set '" + set_name + "' already exists. Cannot create"
            return 1
    elif action == 'update':
        call = subprocess.Popen([ipset_command, 'list', set_name, '-n'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        exit_code = call.wait()
        if exit_code == 0:
            update_ip_set(simul, set_names_list, set_name, "", "list:set", None)
        else:
            print "Set '" + set_name + "' does not exist. Cannot update"
            return 1
    elif action == 'destroy':
        call = subprocess.Popen([ipset_command, 'list', set_name, '-n'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        exit_code = call.wait()
        if exit_code == 0:
            destroy_ip_set(simul, set_name, "")
        else:
            print "Set '" + set_name + "' does not exist. Cannot delete"
            return 0


######################################################################################

# create/modify/delete ip sets based on cern network service of either IPv4 or IPv6
def handle_netgroups_set(simulate, action, iptype, set_names, settype, port, custom_name=None, username=None, password=None,
                         generate_file=False, file_override=False, cmd=False):
    # pylint: disable=C0301
    """
    This function handles the action to be performed based on the provided input action of the user. The main role of
    this function is to call the appropriate end function that performs the task.

    :param simulate: Flag to passed to the handling function
    :param action: Action to be performed ( create, update, destroy )
    :param iptype:  IP type ( IPv4 or IPv6 )
    :param set_names: A list of cern 's network sets names on which the defined action will be performed upon
    :param settype: IPset type. Only the allowed sets
    :param port: Port number if the set type contains port
    :param custom_name: Custom ipset name if the regular name is to large of if the user wants a shorter one
    :param username: optional username for the LanDB service authentication
    :param password: mandatory if you specify username for the LanDB service authentication
    :param generate_file: Flag whether or not to generate ipset file
    :param file_override: Flag whether or not to override ipset file
    :param cmd: Flag to save current ipset state if script was called vim the command line
    :return: Does not return anything
    """

    if action == 'create':
        if (username is not None) and (password is not None):
            output = get_network_sets(set_names, iptype, username, password)
        else:
            output = get_network_sets(set_names, iptype)

        if "SETNOTFOUND" in output:
            # print output
            return output
        else:

            ips = extract_ips_from_network_set(output, iptype)

            if custom_name is not None:
                set_names = custom_name
            set_name = set_names.replace(' ', '_')

            # print set_names
            if len(ips) >= 1:
                print "IPs to be added:"
                for i in ips:
                    print i
                create_ip_set(simulate, ips, set_name, iptype, settype, port, generate_file, file_override)

            else:
                print "This networkset has no " + iptype + " addresses to put in a ipset"
                create_ip_set(simulate, ips, set_name, iptype, settype, port, generate_file, file_override)

    elif action == 'destroy':

        if custom_name is not None:
                set_names = custom_name
        set_name = set_names.replace(' ', '_')
        destroy_ip_set(simulate, set_name, iptype)

    elif action == 'update':

        if (username is not None) and (password is not None):
            output = get_network_sets(set_names, iptype, username, password)
        else:
            output = get_network_sets(set_names, iptype)

        if "SETNOTFOUND" in output:
            # print output
            return output
        else:
            ips = extract_ips_from_network_set(output, iptype)
            if custom_name is not None:
                set_names = custom_name
            set_name = set_names.replace(' ', '_')
            update_ip_set(simulate, ips, set_name, iptype, settype, port)

    # Save the current ipsets currently in memory or delete the file if there is none
    if cmd:
        save_current_ipset(simulate)


######################################################################################
# create/modify/delete custom ip sets of either IPv4 or IPv6
def handle_custom_set(simulate, action, setname, iptype, settype, ips=None, hostnames=None, port=None,
                      netgroup_net_list=None, generate_file=False, file_override=False, cmd=False):
    # pylint: disable=C0301
    """
    This function handles the action to be performed based on the provided input action of the user. The main role of
    this function is to call the appropriate end function that performs the task.

    :param simulate: Flag to passed to the handling function
    :param action: Action to be performed ( create, update, destroy )
    :param setname: The name of set
    :param iptype:  IP type ( IPv4 or IPv6 )
    :param settype: IPset type. Only the allowed sets
    :param ips: Individual ips to be added or deleted from the ipset
    :param hostnames: The hostnames of either single boxes or aliases ( to resolved via dns ) that will be added in
                      the ipset
    :param port: Port number if the set type contains port
    :param netgroup_net_list: A list of cern network set names to be added into the set.
    :param generate_file: Flag whether or not to generate ipset file
    :param file_override: Flag whether or not to override ipset file
    :param cmd: Flag to save current ipset state if script was called vim the command line
    :return: Does not return anything
    """

    if action in ['create', 'update']:
        hostsetfinal = []

        if settype in ['hash:ip,port,net', 'hash:ip,port,ip']:
            triplet_ip1 = []
            triplet_port = []
            triplet_ip2 = []

            if netgroup_net_list is not None:
                for netgroups in xrange(len(netgroup_net_list)):
                    name1, prt, name2 = netgroup_net_list[netgroups].split(',')
                    triplet_ip1.append(netgroup_set_extractor(iptype, name1))
                    if ':' not in prt:
                        prt = 'tcp:' + prt
                    triplet_port.append(prt)
                    if settype == 'hash:ip,port,ip':
                        triplet_ip2.append(netgroup_set_extractor(iptype, name2))
                    elif settype == 'hash:ip,port,net':
                        triplet_ip2.append(name2)
            if hostnames is not None:
                for _host_ in xrange(len(hostnames)):
                    # print "::::::::::::::::", hostnames[_host_]
                    ip1, prt, ip2 = hostnames[_host_].split(',')
                    triplet_ip1.append([ip_dns_resolver(ip1, iptype)])
                    if ':' not in prt:
                        prt = 'tcp:' + prt
                    triplet_port.append(prt)
                    if settype == 'hash:ip,port,ip':
                        triplet_ip2.append([ip_dns_resolver(ip2, iptype)])
                    elif settype == 'hash:ip,port,net':
                        triplet_ip2.append(ip2)

            for _host_ in xrange(len(triplet_ip1)):
                triplet_ip1[_host_] = extract_ips_from_network_set(triplet_ip1[_host_], iptype)
            if settype == 'hash:ip,port,ip':
                for _host_ in xrange(len(triplet_ip2)):
                    triplet_ip2[_host_] = extract_ips_from_network_set(triplet_ip2[_host_], iptype)

            for _prt_ in xrange(len(triplet_port)):
                for _host1_ip_ in xrange(len(triplet_ip1[_prt_])):
                    if settype == 'hash:ip,port,ip':
                        for _host2_ip_ in xrange(len(triplet_ip2[_prt_])):
                            hostsetfinal.append(triplet_ip1[_prt_][_host1_ip_] + ',' + triplet_port[_prt_] + ',' +
                                                triplet_ip2[_prt_][_host2_ip_])
                    elif settype == 'hash:ip,port,net':
                        hostsetfinal.append(triplet_ip1[_prt_][_host1_ip_] + ',' + triplet_port[_prt_] + ',' +
                                            triplet_ip2[_prt_])

            del triplet_ip1[:]
            del triplet_ip2[:]
            del triplet_port[:]

            if ips is not None:
                for _ip_trip_ in ips:
                    hostsetfinal.append(_ip_trip_)
        else:
            if (hostnames is not None) and (settype not in ['hash:net', 'hash:net,port']):
                for hst in xrange(len(hostnames)):
                    if 'port' not in settype:
                        hostsetfinal.append(ip_dns_resolver(hostnames[hst], iptype))
                    else:
                        if 'direct' in port:
                            if ',' in hostnames[hst]:
                                _hst_, _port_ = hostnames[hst].split(',')
                                tmp_addr = ip_dns_resolver(_hst_, iptype)
                                if ':' not in _port_:
                                    _port_ = 'tcp:' + _port_
                                for t_addr in xrange(len(tmp_addr)):
                                    tmp_addr[t_addr] += ',' + _port_
                                hostsetfinal.append(tmp_addr)
                            else:
                                print "Did not provide port for hostname: " + hst
                                sys.exit(1)
                        else:
                            tmp_addr = ip_dns_resolver(hostnames[hst], iptype)
                            for t_addr in xrange(len(tmp_addr)):
                                tmp_addr[t_addr] += ',' + port[hst]
                            hostsetfinal.append(tmp_addr)

                setname = setname.replace(' ', '_')

                hostsetfinal = extract_ips_from_network_set(hostsetfinal, iptype)

            if netgroup_net_list is not None:
                netgroup_net_ips = []
                if 'port' not in settype:
                    for _set_ in netgroup_net_list:
                        ips_tmp = get_network_sets(_set_, iptype)
                        netgroup_net_ips.extend(extract_ips_from_network_set(ips_tmp, iptype))
                else:
                    if 'direct' in port:
                        for __set__ in netgroup_net_list:
                            if ',' in __set__:
                                __set__name, __port__ = __set__.split(',')
                                __set__ips = netgroup_set_extractor(iptype, __set__name)
                                __set__ips = extract_ips_from_network_set(__set__ips, iptype)
                                for __st_ip_ in xrange(len(__set__ips)):
                                    if ':' not in __port__:
                                        __port__ = 'tcp:' + __port__
                                    __set__ips[__st_ip_] = __set__ips[__st_ip_] + ',' + __port__
                                netgroup_net_ips.extend(__set__ips)
                            else:
                                print "Did not provide port for netgroup: " + __set__name
                                sys.exit(1)

                hostsetfinal.extend(netgroup_net_ips)
                del netgroup_net_ips[:]
                del netgroup_net_ips

            if ips is not None:
                for ip in ips:
                    if 'port' not in settype:
                        hostsetfinal.append(ip)
                    else:
                        if 'direct' in port:
                            if ',' in ip:
                                _ip_, __port__ = ip.split(',')
                                if ':' not in __port__:
                                    __port__ = 'tcp:' + __port__
                                _ip_ = _ip_ + ',' + __port__
                                hostsetfinal.append(_ip_)
                            else:
                                print "Did not provide port for IP: " + ip
                                sys.exit(1)
        if action == 'create':
            create_ip_set(simulate, hostsetfinal, setname, iptype, settype, port, generate_file, file_override)
        elif action == 'update':
            update_ip_set(simulate, hostsetfinal, setname, iptype, settype, port)

    elif action == 'destroy':
        setname = setname.replace(' ', '_')
        destroy_ip_set(simulate, setname, iptype)

    # Save the current ipsets currently in memory or delete the file if there is none
    if cmd:
        save_current_ipset(simulate)


######################################################################################
# Check if a given list of ip addresses are valid IPv4 or IPv6 addresses
def ip_validation_check(ips, iptype, settype):
    """
    Check the validity of the given ip list

    :param ips: list of ip addresses provided
    :param iptype: version of ip to check against
    :param settype: determine if is a net or regular ip set
    :return: return True or False
    """
    valid = True
    if settype in ['hash:ip,port,net', 'hash:ip,port,ip']:
        for ip in ips:
            if ',' not in ip:
                print "Not valid triplet " + ip + " for set type: " + settype
                sys.exit(1)
            _ip_, prt_num, _ip2_ = ip.split(',')

            try:
                tmp = ipaddress.ip_address(unicode(_ip_))
                tp = 'ipv' + str(tmp.version)
                if iptype != tp:
                    valid = False
                    print _ip_, " is not a valid ", iptype
            except ValueError:
                valid = False
                if '.' in _ip_:
                    print "Not valid ip: ", _ip_, " of family IPv4"
                elif ':' in _ip_:
                    print "Not valid ip: ", _ip_, " of family IPv6"

            if ('net' in settype) and ('/' in _ip2_):
                try:
                    tmp = ipaddress.ip_network(unicode(_ip2_))
                    tp = 'ipv' + str(tmp.version)
                    if iptype != tp:
                        valid = False
                        print _ip2_, " is not a valid ", iptype
                except ValueError:
                    if '.' in _ip2_:
                        print "Not valid net: ", _ip2_, " of family IPv4"
                    elif ':' in _ip2_:
                        print "Not valid net: ", _ip2_, " of family IPv6"
            else:
                try:
                    tmp = ipaddress.ip_address(unicode(_ip2_))
                    tp = 'ipv' + str(tmp.version)
                    if iptype != tp:
                        valid = False
                        print _ip2_, " is not a valid ", iptype
                except ValueError:
                    valid = False
                    if '.' in _ip2_:
                        print "Not valid ip: ", _ip2_, " of family IPv4"
                    elif ':' in _ip2_:
                        print "Not valid ip: ", _ip2_, " of family IPv6"
    else:
        for ip in ips:
            if ',' in ip:
                _ip_, prt_num = ip.split(',')
            else:
                _ip_ = ip
            try:
                if ('net' in settype) and ('/' in _ip_):
                    tmp = ipaddress.ip_network(unicode(_ip_))
                    tp = 'ipv' + str(tmp.version)
                    if iptype != tp:
                        valid = False
                        print _ip_, " is not a valid ", iptype
                    # else:
                    #     print "valid ", iptype, " ", tmp
                elif ('net' in settype) and ('/' not in _ip_):
                    valid = False
                    print "Not valid net: ", _ip_
                elif ('net' not in settype) and ('/' in _ip_):
                    valid = False
                    print "Not valid ip: ", _ip_
                else:
                    tmp = ipaddress.ip_address(unicode(_ip_))
                    tp = 'ipv' + str(tmp.version)
                    if iptype != tp:
                        valid = False
                        print _ip_, " is not a valid ", iptype
            except ValueError:
                valid = False
                if ('.' in _ip_) and ('net' in settype):
                    print "Not valid net: ", _ip_, " of family IPv4"
                elif '.' in _ip_:
                    print "Not valid ip: ", _ip_, " of family IPv4"
                elif (':' in _ip_) and ('net' in settype):
                    print "Not valid net: ", _ip_, " of family IPv6"
                elif ':' in _ip_:
                    print "Not valid ip: ", _ip_, " of family IPv6"
                elif 'net' in settype:
                    print "Not valid net: ", _ip_, " of family IPv4 or IPv6"
                else:
                    print "Not valid ip: ", _ip_, " of family IPv4 or IPv6"

    return valid


def get_current_ipsets():
    """
    This function is used to get the current running ipsets in memory and print it to a file

    :return: void
    """

    file_path = "/var/tmp/firewall_files"
    if not os.path.exists(file_path):
        call = subprocess.Popen(['/bin/mkdir', '-p', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        exit_code = call.wait()
        if exit_code != 0:
            print err
            print "Cannot create file path!!"
            sys.exit(1)
        else:
            print response

    ipset_command = read_config_file('ipset_command')

    call = subprocess.Popen(ipset_command + ' save' + ' > ' + file_path + '/ipset.orig', shell=True,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    response, err = call.communicate()
    exit_code = call.wait()
    if exit_code != 0:
        print err
        print "Cannot get ipset default configuration!!!!!"
        sys.exit(1)
    else:
        print response


######################################################################################
def write_config_file(set_name, lines, override):
    """
    This function is used to write the generated ipsets configuration to a file for use with the ipset-restore command

    :param set_name: Name of an ipset
    :param lines: IPset elements to add to the set. Actually is the IPs or IPs with ports or triplets
    :param override: Flag to tell to the function whether to write a new file or not
    :return: void
    """

    file_path = "/var/tmp/firewall_files"
    if not os.path.exists(file_path):
        call = subprocess.Popen(['/bin/mkdir', '-p', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        exit_code = call.wait()
        if exit_code != 0:
            print err
            print "Cannot create file path!!"
            sys.exit(1)
        else:
            if not os.path.isfile(file_path+"/ipset.gen"):
                override = True
            print response

    if override:
        get_current_ipsets()
        try:
            with open(file_path + '/ipset.gen', 'w') as file_handler:
                _rule_ = ''
                for rule in lines:
                    for ru in rule:
                        _rule_ += ru + ' '
                    file_handler.write(_rule_.rstrip())
                    _rule_ = '\n'
            file_handler.close()
        except:
            print "Cannot write ipset configuration file!!!!!"
            sys.exit(1)
    else:
        print "Do not override ipset file"
        set_exits = False
        if lines[0][2] != "list:set":
            try:
                file_contents = open(file_path + '/ipset.gen').read()
                if set_name in file_contents:
                    set_exits = True
                del file_contents
            except:
                print "Cannot read generated ipset configuration file!!!!!"
                sys.exit(1)
        else:
            file_contents = open(file_path + '/ipset.gen').read()
            if not set_exits:
                print "Lines:", lines
                for _set_ in lines[1:]:
                    if _set_[2] not in file_contents:
                        print "Set: " + _set_ + " has not been created. Exiting..."
                        sys.exit(1)
        try:
            if not set_exits:
                with open(file_path + '/ipset.gen', 'a') as file_handler:
                    _rule_ = '\n'
                    for rule in lines:
                        for ru in rule:
                            _rule_ += ru + ' '
                        file_handler.write(_rule_.rstrip())
                        _rule_ = '\n'
                file_handler.close()
        except:
            print "Cannot write ipset configuration file!!!!!"
            sys.exit(1)


######################################################################################


def ipset_manager(args=None, action=None, iptype=None, settype=None, port=None, setname=None, netgroup_networks=None,
                  netgroup_set_list=None, hostnames=None, ips=None, simul=False, generate_file=False, file_override=False,
                  set_names=None):
    # type: (object, object, object, object, object, object, object, object, object) -> object

    """
    This function handles all the logic of running the script, both from terminal and as a module

    :param args: Arguments if ran from terminal
    :param action: action to perform
    :param iptype: type of ip address
    :param settype: type of ipset
    :param port: port number (optional protocol) udp:53
    :param setname: custom name for the ipset
    :param netgroup_networks: name of the netgroups networkset
    :param netgroup_set_list: list of netgroups network sets to be added
    :param hostnames: hostnames to resolve ips from
    :param ips: ips to add
    :param simul: simulate mode
    :param generate_file: generate ipset file for use with ipset-restore
    :param file_override: tell the script whether to override the ipset file
    :param set_names: Names of existing sets to be added inside a list:set ipset
    :return: 0 if ok 1 if error
    """

    if args is not None:

        cmd = True

        if args.simulate:
            simul = True
        else:
            simul = False
        # Catch the action to be performed (create, update, destroy)
        if args.action:
            action = args.action[0]
        else:
            return 1

        if args.setname:
            setname = args.setname

        # Catch ipset type
        if args.settype:
            settype = args.settype[0]

            if settype != "list:set":
                # Catch ip type IPv4 or IPv6
                if args.iptype:
                    iptype = args.iptype[0]
                else:
                    return 1

                if args.port:
                    # port = args.port[0]
                    port = args.port

                if args.netgroups_networks:
                    netgroup_networks = args.netgroups_networks

                if args.hostnames:
                    hostnames = args.hostnames

                if args.ips:
                    ips = args.ips

                if args.netgroup_set_list:
                    netgroup_set_list = args.netgroup_set_list

                if args.generate_file:
                    generate_file = True
                else:
                    generate_file = False

                if args.file_override:
                    file_override = True
                else:
                    file_override = False
            else:
                if args.set_names:
                    set_names = args.set_names
                else:
                    set_names = None
        else:
            return 1
    else:
        cmd = False

    if generate_file:      # File generation happens with simul on and always create
        action = 'create'
        simul = True

    if settype == 'list:set':
        handle_list_set(simul, action, setname[0], set_names, generate_file)
        return 0
    else:
        # Check for port argument if the given ipset type uses a port number
        if (action != 'destroy') and ('port' in settype):
            if port is not None:
                if 'direct' not in port:
                    for prt in port:
                        if ':' in prt:
                            prot, port_num = prt.split(':')
                            if (prot not in ['tcp', 'udp']) or (not 1 <= int(port_num) <= 65536):
                                print "IPset port number " + prot + ":" + port_num + " not valid"
                                return 1
                        elif not 1 <= int(prt) <= 65536:
                            print "IPset port number " + port + " not valid"
                            return 1
            else:
                print "Ports not set!!!!"
                return 1
        else:
            # port = ''
            port = []

        if netgroup_networks is not None:
            if (setname is not None) and (len(setname) != len(netgroup_networks)):
                print "Custom setnames if specified should be as many as the networksets"
                return 1
            if (settype is not None) and (settype[0] not in ['hash:net', 'hash:net,port']):
                # Authentication information
                if (args is not None) and (type(args.username) is list):
                    username = args.username[0]
                    if args.password:
                        password = args.password[0]
                        for nset in xrange(len(netgroup_networks)):
                            if (len(netgroup_networks[nset]) + 3) > 31:
                                if args.setname[nset] != '':
                                    handle_netgroups_set(simul, action, iptype, netgroup_networks[nset], settype, port,
                                                         setname[nset], username, password, generate_file, file_override, cmd)
                                    return 0
                                else:
                                    print "Name for network set " + netgroup_networks[nset] + " does not exist"
                                    return 1
                    else:
                        print "Password is missing to access the network service"
                        return 1
                else:
                    for nset in xrange(len(netgroup_networks)):
                        if (len(netgroup_networks[nset]) + 3) > 31:
                            if type(setname) is list:
                                try:
                                    if (len(setname[nset]) + 3) > 31:
                                        print "Please choose smaller name < 31 chars for ", netgroup_networks[nset]
                                        return 1
                                    else:
                                        output = handle_netgroups_set(simul, action, iptype, netgroup_networks[nset], settype,
                                                                      port, setname[nset], generate_file, file_override, cmd)
                                        if output == 'SETNOTFOUND':
                                            return output
                                        return 0
                                except IndexError:
                                    print "Setname longer than 31 chars please specify a shorter custom one using --setname"
                                    return 1
                            else:
                                print "Set name longer thatn 31 chars please specify a shorter custom name using --setname"
                                return 1
                        elif setname is not None:
                            try:
                                # output = handle_netgroups_set(simul, action, iptype, netgroup_networks[nset], settype, port,
                                #                          setname[nset], generate_file, file_override)
                                output = handle_netgroups_set(simul, action, iptype, netgroup_networks[nset], settype, port,
                                                              setname[nset], None, None, generate_file, file_override, cmd)
                                if output == 'SETNOTFOUND':
                                    return output
                                return 0
                            except IndexError:
                                output = handle_netgroups_set(simul, action, iptype, netgroup_networks[nset], settype, port, None,
                                                              None, None, generate_file, file_override, cmd)
                                if output == 'SETNOTFOUND':
                                    return output
                                return 1
                        else:
                            output = handle_netgroups_set(simul, action, iptype, netgroup_networks[nset], settype, port, None, None,
                                                          generate_file, file_override, cmd)
                            if output == 'SETNOTFOUND':
                                return output
                            return 0
            else:
                return 1
        elif setname is not None:
            if (len(setname[0]) + 3) > 31:
                print "Please choose smaller name < 31 chars for ", setname[0]
                return 1
            elif action == 'destroy':
                handle_custom_set(simul, action, setname[0], iptype, settype, ips, hostnames, port, netgroup_set_list,
                                  generate_file, file_override, cmd)
                return 0
            else:
                print "Set type is: ", settype
                if 'port' in settype:
                    if ('direct' not in port) and (len(port) > 1) and (len(port) < len(ips) + len(hostnames)):
                        print "Ports provided are not as many as the ips + hostnames"
                        return 1
                if ips is not None:
                    # print "IPS is not None"
                    valid = ip_validation_check(ips, iptype, settype)
                else:
                    valid = True

                if valid:
                    handle_custom_set(simul, action, setname[0], iptype, settype, ips, hostnames, port, netgroup_set_list,
                                      generate_file, file_override, cmd)
                    # print "Valid: ", valid
                    return 0
                else:
                    print "IP Validation unsuccessful: ", valid
                    return 1
        else:
            print "LAST ELSE !!!!!!!"
            return 1


######################################################################################
# This is where flag and argument parsing takes place
def main():
    # pylint: disable=C0301
    """
    This is the main function. It parses the command line arguments and calls the appropriate function to handle
    each the job.

    :return: Does not return anything
    """

    ipset_types = ['hash:net,port', 'hash:ip,port', 'hash:net', 'hash:ip', 'hash:ip,port,net', 'hash:ip,port,ip',
                   'list:set']

    parser = argparse.ArgumentParser()

    parser.add_argument('--username', nargs=1, help='Type the username for the network service')
    parser.add_argument('--password', nargs=1, help='Type the password for the network service')
    parser.add_argument('--action', nargs=1, choices=['create', 'update', 'destroy'], help='type the action to perform')
    parser.add_argument('--iptype', nargs=1, choices=['ipv4', 'ipv6'], help='Specify ipv4 or ipv6 ')
    parser.add_argument('--settype', nargs=1, choices=ipset_types,
                        help='Type the type of the ip set: {0} use \" \" to specify the type'.format(str(ipset_types)))
    parser.add_argument('--port', nargs='+', help='Type here "direct" to pass the port with the ip or the port if you '
                                                  '8080 or tcp:8080 or udp:8080')
    parser.add_argument('--setname', nargs='+', help='Define set name. This is mandatory for network ranges aliases '
                                                     'or custom ip sets. Regarding network sets, every argument '
                                                     'after setname is corresponding to each networkset. '
                                                     'If you want to omit names use \'\' ')
    parser.add_argument('--netgroup_networks', nargs='+', help='Define network sets like "IT SECURITY FIREWALL ALIENDB" use'
                                                           '" " or '' use the escape char \ if spaces or special '
                                                           'characters included')
    parser.add_argument('--netgroup_set_list', nargs='+', help='Define network sets like "IT SECURITY FIREWALL ALIENDB" in '
                                                           'a list to add them in one set use " " or '' use the escape '
                                                           'char \ if spaces or special characters included')
    parser.add_argument('--hostnames', nargs='+', help='Define machines hostnames like "agkara-train" or '
                                                       '"agkara-train.cern.ch"')
    parser.add_argument('--ips', nargs='+', help='Define machines IPs IPv4 or IPv6')
    parser.add_argument('--set_names', nargs='+', help='Define the names of the other sets to add to the list:set')
    parser.add_argument('--simulate', action='store_true')
    parser.add_argument('--generate_file', action='store_true', help='Tell the script to create the ipset restore file')
    parser.add_argument('--file_override', action='store_true', help='Flag whether to override the file or not')

    args = parser.parse_args()

    exit_code = 0

    exit_code = ipset_manager(args)

    if exit_code != 0:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
