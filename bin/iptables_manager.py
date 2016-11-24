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

"""

import sys
import os
import argparse
import configparser
from main_nic_extractor import main_nic_extractor
from other_nic_extractor import other_nic_extractor
from netgroups_set_extraction import netgroup_set_extractor
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iptables_manager_modules.default_rules import DefaultConfiguration
from iptables_manager_modules.rules_builder import FirewallRuleBuilder
from iptables_manager_modules.generate_files import IPTablesFileGenerator


class ReadWriteConfigFiles(object):
    """
    Reads the config files using python config parser module. It then creates an object(dict)
    and adds all the sections of the file as key and its options as value.
    It contains all the methods to parse extract info from the config files and then build and add the rules to both
    the 'iptables' and 'ip6tables' so you configure both IP protocols with the same tool.
    """

    # parser = configparser.RawConfigParser()
    parser = configparser.ConfigParser()

    def read_config_file(self, filepath):
        """
        Reads all the files on the file path list and creates a unique object to be returned to the Managed Rules
        class

        :param filepath: List of config file paths to read
        :return: object of config parser to access the configuration
        """
        try:
            self.parser.read(filepath)
            return self.parser
        except configparser.ParsingError, err:
            print 'Could not parse file: ' + filepath, err
            sys.exit(1)

    def write_config_file(self, file_path):
        """
        Method to write back the current config from memory to the files. (It is not in use for now)
        :param file_path: list of the files

        :return: void
        """
        cfgfile = open(file_path, 'w')
        self.parser.write(cfgfile)
        cfgfile.close()


class ManageRules(object):
    """
    The main class of this script. It handles the whole process of validating config files then parse them and create
    the kernel ipsets and rules to be applied.
    It create a list of all the rules to be applied and at the end runs all the iptables commands both for IPv4/IPv6
    """

    rule_builder = FirewallRuleBuilder()

    sections = []
    """
    All the allowed option of a section that defines iptables rules.
    """
    sect_general_options_list = ['description', 'section_type', 'action', 'default_chain', 'ip_version',
                                 'interface', 'protocol', 'ports', 'custom_chain', 'limit', 'log-level',
                                 'log-prefix', 'set', 'set_directions', 'log-specific-options']

    """
    All the allowed option of a section that defines ipsets.
    """
    sect_set_option_list = ['description', 'section_type', 'ipset_type', 'set_name', 'netgroup_set_name',
                            'set_hostnames', 'set_ips_v4', 'set_ips_v6', 'set_net_ranges_v4',
                            'set_net_ranges_v6', 'netgroup_set_list', 'set_ip_port_ip_v4', 'set_ip_port_ip_v6',
                            'set_ip_port_net_v4', 'set_ip_port_net_v6', 'list_set_sections']

    """
    All the allowed option of a section that defines Policy.
    """
    policy_opts = ['section_type', 'ip_version', 'input', 'forward', 'output']

    def __init__(self, parser, simul=True, generate=False):
        """
        Init method of the class

        :param parser: Config parser object to access the files configuration
        :param simul: Bool variable to check if we will print the generated config or run it.
        """
        self.parser = parser
        self.deploy = simul
        self.generate_files = generate
        if self.generate_files:
            self.file_override = True
        else:
            self.file_override = False


###########################################################################################################
    def config_integrity_check(self):
        """
        This method add all the section loaded from config files to a list for better handling. Its main purpose is to
        check the 'integrity' of the config files in terms of specifying the right things of avoid logical errors.

        :return: void
        """

        for i in self.parser.sections():
            self.sections.append(i.encode("utf-8"))
            # print i.encode("utf-8")
            if not self.parser.has_option(i.encode('utf-8'), "section_type"):
                print "Specify 'section_type' option for section '" + i.encode("utf-8") + "'"
                sys.exit(1)
            else:
                tmp_opt = self.parser.get(i.encode("utf-8"), 'section_type').encode("utf-8")
                if tmp_opt == 'general':

                    if not self.parser.has_option(i.encode('utf-8'), "action"):
                        print "Specify 'action' option for section '" + i.encode("utf-8") + "'"
                        sys.exit(1)
                    else:
                        if type(eval(self.parser.get(i.encode('utf-8'), "action"))) is not list:
                            print "Specify 'action' option for section '" + i.encode("utf-8") + "'"
                            sys.exit(1)
                    # Check for script and replace the name with the one returned from the script
                    if self.parser.has_option(i.encode('utf-8'), "set"):
                        script_command = self.parser.get(i.encode('utf-8'), "set").encode('utf-8')
                        if '"' in script_command:
                            script_command = script_command.replace('"', '')
                            script_command = script_command.split(" ")
                            replace_set, err, exit_code = self.rule_builder.sys_process_executor(script_command)
                            if err or (exit_code != 0):
                                print "Error with script defining set name on section: ", i.encode("utf-8")
                            elif replace_set != "":
                                replace_set = replace_set.replace("\n", "")
                                if self.parser.has_section(replace_set.encode("utf-8")):
                                    self.parser.set(i.encode('utf-8'), "set", replace_set)
                                else:
                                    print "Error on section: '" + i.encode('utf-8') + "' set section '" + \
                                      replace_set + "' does exist in the current loaded sections. Please create " \
                                                    "that section inside the config files"
                                    sys.exit(1)
                            else:
                                print "Error on section: '" + i.encode('utf-8') + "' set section '" + \
                                      replace_set + "' does exist in the current loaded sections. Please create " \
                                                    "that section inside the config files"
                                sys.exit(1)

                    if self.parser.has_option(i.encode('utf-8'), "default_chain"):
                        df_chain = self.parser.get(i.encode('utf-8'), "default_chain").encode('utf-8')
                        sup_chains = ['input', 'output']
                        if ',' in df_chain:
                            df_chain = df_chain.split(',')
                            for ch in df_chain:
                                if ch.lower() not in sup_chains:
                                    print "Default chain specified '" + i + "' not in supported list ", sup_chains
                                    sys.exit(1)
                        else:
                            if df_chain.lower() not in sup_chains:
                                print "Default chain specified '" + df_chain + "' not in supported list ", sup_chains
                                sys.exit(1)

                    if not self.parser.has_option(i.encode('utf-8'), "ip_version"):
                        print "Specify 'ip_version' option for section '" + i.encode("utf-8") + "'"
                        sys.exit(1)

                    if self.parser.has_option(i.encode('utf-8'), "protocol"):
                        protocol = self.parser.get(i.encode('utf-8'), 'protocol').encode('utf-8')
                        protocol = protocol.split(',')
                        for pl in protocol:
                            if pl not in ['tcp', 'udp']:
                                print "Protocol value '" + pl + "'for section'" + i.encode("utf-8") + "' not supported"
                                sys.exit(1)
                    else:
                        if self.parser.has_option(i.encode('utf-8'), "ports"):
                            self.parser.remove_option(i.encode('utf-8'), "ports")

                    if self.parser.has_option(i.encode('utf-8'), "ports"):
                        if self.parser.has_option(i.encode('utf-8'), "set"):
                            tmp_set = self.parser.get(i.encode('utf-8'), "set").encode('utf-8')
                            try:
                                tmp_ipset_type = self.parser.get(tmp_set.encode('utf-8'), "ipset_type").encode('utf-8')
                                if 'port' in tmp_ipset_type:
                                    print "Cannot have ports declared on the rule if you use a hash:ip,port or '" + \
                                          i.encode("utf-8") + "' and section '" + tmp_set + "'"
                                    sys.exit(1)
                            except configparser.NoOptionError:
                                pass

                        ports = self.parser.get(i.encode('utf-8'), "ports").encode('utf-8')
                        if ',' in ports:
                            ports = ports.split(',')
                            for pr in ports:
                                try:
                                    tmp = int(pr)
                                    if not 1 <= tmp <= 65535:
                                        print "Port values '" + pr + "' for section '" + i.encode("utf-8") + "' not valid"
                                        print "Linux ports range is from 1 to 65535"
                                        sys.exit(1)
                                except ValueError:
                                    print "Port values '" + pr + "' for section '" + i.encode("utf-8") + "' not valid"
                                    print "Ports are only integer numbers"
                                    sys.exit(1)
                        elif ':' in ports:
                            ports = ports.split(':')
                            try:
                                left_val = int(ports[0])
                                right_val = int(ports[1])
                                if not (1 <= left_val < right_val <= 65535):
                                    print "Port values '" + str(left_val) + ":" + str(right_val) + "' for section '"\
                                          + i.encode("utf-8") + "' not valid"
                                    print "Linux ports range is from 1 to 65535"
                                    sys.exit(1)
                            except ValueError:
                                print "Port values '" + ports[0] + ":" + ports[1] + "' for section '" \
                                      + i.encode("utf-8") + "' not valid"
                                print "Ports are only integer numbers"
                                sys.exit(1)
                    if self.parser.has_option(i.encode('utf-8'), "set_directions"):
                        params = self.parser.get(i.encode('utf-8'), "set_directions").encode('utf-8')
                        params = params.split(',')
                        if len(self.parser.get(i.encode('utf-8'), "action").encode('utf-8')) == 1 and len(params) > 1:
                            print "Set parameters cannot be defined for this '" + i.encode('utf-8') + "' section"
                            sys.exit(1)
                        if self.parser.has_option(i.encode('utf-8'), "set"):
                            tmp_set = self.parser.get(i.encode('utf-8'), "set").encode('utf-8')
                            for pr in params:
                                if pr not in ['src', 'dst']:
                                    print "Set parameters for '" + i.encode('utf-8') + "' are not valid"
                                    sys.exit(1)
                            try:
                                _tp_ = self.parser.get(tmp_set, "ipset_type").encode('utf-8')[5:].split(',')
                                if len(_tp_) != len(params):
                                    print "Set parameters for '" + i.encode('utf-8') + "' are not equal to the ipset_type"
                                    sys.exit(1)
                            except configparser.NoOptionError:
                                print "Cannot read ipset_type for section '" + tmp.encode('utf-8') + "' section"
                                sys.exit(1)

                    for opt in self.parser.options(i.encode("utf-8")):
                        if opt.encode("utf-8") not in self.sect_general_options_list:
                            print "option: '" + opt + "' not in supported list"

                elif tmp_opt == 'ipset':

                    if not self.parser.has_option(i.encode('utf-8'), "ipset_type"):
                        print "Specify 'ipset_type' option for section '" + i.encode("utf-8") + "'"
                        sys.exit(1)
                    else:
                        set_type = self.parser.get(i.encode("utf-8"), 'ipset_type').encode("utf-8")
                        if set_type not in ['hash:net,port', 'hash:ip,port', 'hash:net', 'hash:ip', 'hash:ip,port,net',
                                            'hash:ip,port,ip', 'list:set']:
                            print "Specify 'ipset_type' 'hash:net,port', 'hash:ip,port', 'hash:net', 'hash:ip', " \
                                  "'hash:ip,port,net', 'hash:ip,port,ip' option for section '" + i.encode("utf-8") + "'"
                            sys.exit(1)
                        else:
                            if set_type in ['hash:net,port', 'hash:net']:
                                if not ((self.parser.has_option(i.encode('utf-8'), "set_net_ranges_v4")) or
                                        (self.parser.has_option(i.encode('utf-8'), "set_net_ranges_v6"))):
                                    print "Specify 'set_net_ranges_v4' ,'set_net_ranges_v6' option for section '" \
                                          + i.encode("utf-8") + "'"
                                    sys.exit(1)

                            elif set_type in ['hash:ip,port', 'hash:ip']:
                                if not ((self.parser.has_option(i.encode('utf-8'), "set_ips_v4")) or
                                        (self.parser.has_option(i.encode('utf-8'), "set_ips_v6")) or
                                        (self.parser.has_option(i.encode('utf-8'), "set_hostnames")) or
                                        (self.parser.has_option(i.encode('utf-8'), "netgroup_set_list")) or
                                        (self.parser.has_option(i.encode('utf-8'), "netgroup_set_name"))):
                                    print "Specify 'set_ips_v4' ,'set_ips_v6', 'set_hostnames' option for section '" \
                                          + i.encode("utf-8") + "'"
                                    sys.exit(1)

                            elif set_type in ['hash:ip,port,ip']:
                                if not ((self.parser.has_option(i.encode('utf-8'), "set_ip_port_ip_v4")) or
                                        (self.parser.has_option(i.encode('utf-8'), "set_ip_port_ip_v6")) or
                                        (self.parser.has_option(i.encode('utf-8'), "set_hostnames")) or
                                        (self.parser.has_option(i.encode('utf-8'), "netgroup_set_list"))):
                                    print "Specify 'set_ip_port_ip_v4' ,'set_ip_port_ip_v6', 'set_hostnames' option " \
                                          "for section '" + i.encode("utf-8") + "'"
                                    sys.exit(1)

                            elif set_type in ['hash:ip,port,net']:
                                if not ((self.parser.has_option(i.encode('utf-8'), "set_ip_port_net_v4")) or
                                        (self.parser.has_option(i.encode('utf-8'), "set_ip_port_net_v6")) or
                                        (self.parser.has_option(i.encode('utf-8'), "set_hostnames"))):
                                    print "Specify 'set_ip_port_net_v4' ,'set_ip_port_net_v6', 'set_hostnames' option " \
                                          "for section '" + i.encode("utf-8") + "'"
                                    sys.exit(1)

                            elif set_type in ['list:set']:
                                if not self.parser.has_option(i.encode('utf-8'), "set_name"):
                                    print "Specify 'set_name' option for section '" + i.encode("utf-8") + "'"
                                    sys.exit(1)
                                if not self.parser.has_option(i.encode('utf-8'), "list_set_sections"):
                                    print "Specify 'list_set_sections' option for section '" + i.encode("utf-8") + "'"
                                    sys.exit(1)
                                else:
                                    try:
                                        list_sections = eval(self.parser.get(i.encode('utf-8'), 'list_set_sections')
                                                                 .encode('utf-8'))
                                        if type(list_sections) is list:
                                            for _sect_ in list_sections:
                                                if not self.parser.has_section(_sect_):
                                                    print "Section '" + _sect_ + "' is not present. Please define " \
                                                                                 "this section inside one of your " \
                                                                                 "config files"
                                                    sys.exit(1)
                                        else:
                                            print "You have tou provide a list for 'list_set_sections' option for " \
                                                  "section '" + i.encode("utf-8") + "'"
                                    except configparser.NoOptionError:
                                        pass

                        for opt in self.parser.options(i.encode("utf-8")):
                            if opt.encode("utf-8") not in self.sect_set_option_list:
                                print "option: '" + opt + "' not in supported list"

                elif tmp_opt == 'policy':
                    if not self.parser.has_option(i.encode('utf-8'), "ip_version"):
                        print "Specify 'ip_version' option for section '" + i.encode("utf-8") + "'"
                        sys.exit(1)
                    else:
                        if self.parser.get(i.encode('utf-8'), 'ip_version') not in ['ipv4', 'ipv6', 'both']:
                            print " 'ip_version' option for section '" + i.encode("utf-8") + "'" + " should be one of "\
                                  + ['ipv4', 'ipv6', 'both']
                            sys.exit(1)
                    for opt in self.parser.options(i.encode('utf-8')):
                        if opt.encode("utf-8") not in self.policy_opts:
                            print "option: '" + opt + "' not in supported list"
                            sys.exit(1)
                        elif (opt != 'section_type') and (opt != 'ip_version') and \
                             (self.parser.get(i, opt).encode('utf-8') not in ['ACCEPT', 'DROP']):
                            print "Policy: '" + opt + "' not in ", ['ACCEPT', 'DROP']
                            sys.exit(1)
                else:
                    print "Specify 'section_type' option for section '" + i.encode("utf-8") + "'"
                    sys.exit(1)

###########################################################################################################
    @staticmethod
    def handle_nic_cards(query):
        """
        This method is used to return a list of network interfaces in order for the rules to be applied to all of them
        It has 3 modes and can add or subtract interfaces from the list depending on which interfaces you want to apply
        firewall rules on.

        :param query: list of commands to perform e.g. ['main','+en5', '+en4'] or ['all', '-en5', '-en4']
        :return: the list of interfaces
        """
        nic = []
        if type(query) is list:
            if query[0] not in ['main', 'all', 'other']:
                nic = 'error'
            else:
                nic = []
                if query[0] == 'main':
                    main_nic = main_nic_extractor()
                    nic.append(main_nic)
                    del query[0]
                    for n in query:
                        if n[0] == '+':
                            tmp = n[1:]
                            nic.append(tmp)
                        else:
                            print 'The sign + was expected to add ' + n + ' this nic to the list. Omitting.. '
                elif query[0] == 'all':
                    nic = other_nic_extractor(True)
                    del query[0]
                    for n in query:
                        if n[0] == '-':
                            tmp = n[1:]
                            try:
                                nic.remove(tmp)
                            except:
                                pass
                        else:
                            print 'The sign - was expected to add ' + n + ' this nic to the list. Omitting.. '
                elif query[0] == 'other':
                    nic = other_nic_extractor()
                    del query[0]
                    for n in query:
                        if n[0] == '-':
                            tmp = n[1:]
                            try:
                                nic.remove(tmp)
                            except:
                                pass
                        else:
                            print 'The sign - was expected to add ' + n + ' this nic to the list. Omitting.. '
        return nic

###########################################################################################################
    def handle_script_runs(self, ipset_section, hostname, ipset_type, ip_version):

        """
        This method is used to handle set triplets to be used in ipsets.

        :param ipset_section:
        :param hostname:
        :param ipset_type:
        :param ip_version:
        :return:
        """
        return_list = []
        return_list_1 = None
        return_list_2 = None
        part_1 = None
        part_2 = None
        part_3 = None

        if ipset_type == 'hash:ip,port,net' or ipset_type == 'hash:ip,port,ip':

            if "script_double:" in hostname:
                part_1, part_2 = hostname.split(',')

                if "script_double:" in part_2:
                    print "\nSection '" + ipset_section + " cannot use a 'script_double' on last element of the triplet"
                    sys.exit(1)

            elif ("script:" in hostname) or ("netgroup:" in hostname):
                part_1, part_2, part_3 = hostname.split(',')

        elif ipset_type == 'hash:ip,port':
            if ("script:" in hostname) or ("netgroup:" in hostname):
                part_1, part_2 = hostname.split(',')

                if "script_double:" in part_2:
                    print "\nSection '" + ipset_section + " cannot use a 'script_double' on last element of the triplet"
                    sys.exit(1)

            elif "script_double:" in hostname:
                part_1 = hostname

        elif ipset_type == 'hash:net,port':
            print "\nSection '" + ipset_section + " cannot use a 'script' for set type hash:net,port"
            sys.exit(1)
        else:
            part_1 = hostname

        if 'script:' in part_1:
            command_1 = part_1[7:].split()
            return_list_1, err, exit_code = self.rule_builder.sys_process_executor(command_1)

        elif 'script_double:' in part_1:
            command_1 = part_1[14:].split()
            return_list_1, err, exit_code = self.rule_builder.sys_process_executor(command_1)

        elif 'netgroup:' in part_1:
            netgroup = part_1[9:]
            return_list_1 = netgroup_set_extractor(ip_version, netgroup, None, None, False, True)
            exit_code = 0
            # print "NetGroup_1:", return_list_1

        if (part_2 is not None) and (part_3 is None):
            if 'script:' in part_2:
                command_2 = part_2[7:].split()
                return_list_2, err, exit_code = self.rule_builder.sys_process_executor(command_2)
            elif 'netgroup:' in part_2:
                netgroup = part_2[9:]
                return_list_2 = netgroup_set_extractor(ip_version, netgroup, None, None, False, True)
                exit_code = 0
                # print "NetGroup_2:", return_list_2

        if part_3 is not None:
            if 'script:' in part_3:
                command_3 = part_3[7:].split()
                return_list_2, err, exit_code = self.rule_builder.sys_process_executor(command_3)
            elif 'netgroup:' in part_3:
                netgroup = part_3[9:]
                return_list_2 = netgroup_set_extractor(ip_version, netgroup, None, None, False, True)
                exit_code = 0
                # print "NetGroup_3:", return_list_2

        if exit_code == 0:

            if return_list_1 is not None:
                if type(return_list_1) is not list:
                    return_list_1 = return_list_1.splitlines()
                    return_list_1 = [x for x in return_list_1 if x != '-']
                # print "Result list 1:", return_list_1

            if return_list_2 is not None:
                if type(return_list_2) is not list:
                    return_list_2 = return_list_2.splitlines()
                if ipset_type != 'hash:ip,port,net':
                    return_list_2 = [x for x in return_list_2 if x != '-']
                else:
                    if ip_version == 'ipv4':
                        return_list_2 = [x for x in return_list_2 if (x != '-') and (':' not in x)]
                    elif ip_version == 'ipv6':
                        return_list_2 = [x for x in return_list_2 if (x != '-') and ('.' not in x)]
            else:
                if ipset_type == 'hash:ip,port,net':
                    if ip_version == 'ipv4':
                        if ':' in part_2:
                            return []
                    elif ip_version == 'ipv6':
                        if '.' in part_2:
                            return []

            if (return_list_1 is not None) and (return_list_2 is not None):
                if part_3 is not None:
                    for i in xrange(len(return_list_1)):
                        for j in xrange(len(return_list_2)):
                            return_list.append(return_list_1[i] + ',' + part_2 + ',' + return_list_2[j])
                else:
                    for i in xrange(len(return_list_1)):
                        for j in xrange(len(return_list_2)):
                            return_list.append(return_list_1[i] + ',' + return_list_2[j])

            elif return_list_1 is not None:
                if 'script_double:' in part_1:
                    if ipset_type != 'hash:ip,port':
                        for i in xrange(len(return_list_1)):
                            return_list.append(return_list_1[i] + ',' + part_2)
                    else:
                        for i in xrange(len(return_list_1)):
                            return_list.append(return_list_1[i])
                elif 'script:':
                    if 'port' in ipset_type:
                        for i in xrange(len(return_list_1)):
                            return_list.append(return_list_1[i] + ',' + part_2 + ',' + part_3)
                    else:
                        for i in xrange(len(return_list_1)):
                            return_list.append(return_list_1[i])
            else:
                pass
        else:
            print "\nSection '" + ipset_section + " script run error"
            sys.exit(1)

        # print "Return list:", return_list
        return return_list

###########################################################################################################
    def handle_ipsets(self, ipset_section, ip_version, update_only=False):
        """
        This method is used to handle the ipsets. It parses ipset sections by extracting the values from the options
        provided in the files. It is used to create or update(if set exists) an ipset so to be later used by the
        iptable rules.

        :param ipset_section:Name of the ipset section to be parsed
        :param ip_version: IPv4/IPv6
        :param update_only: Bool variable to tell the method to do an update of the existing set.
        :return: It returns two values. 1. The exit code of the other script that handles ipsets 2. The actual name of the created ipset to be used by the rule/s
        """
        ipset_action = None
        iptype = None
        settype = None
        port = None
        set_name = None
        netgroup_networks = None
        ips = None
        ips = None
        hostnames = None
        ips = None
        netgroup_set_list = None

        # set_ipver = self.parser.get(ipset_section, 'ip_version').encode('utf-8')
        set_ipver = ip_version
        ipset_type = self.parser.get(ipset_section, 'ipset_type').encode('utf-8')

        try:
            set_name = eval(self.parser.get(ipset_section, 'set_name').encode('utf-8'))
            set_name[0] = set_name[0].replace(' ', '_')
        except configparser.NoOptionError:
            set_name = None

        try:
            hostnames = eval(self.parser.get(ipset_section, 'set_hostnames').encode('utf-8'))
        except configparser.NoOptionError:
            hostnames = None
        if type(hostnames) is list:
            _hostnames_ = []
            for hst in xrange(len(hostnames)):
                # This part is executed when in the hostnames list we provided also scripts(commands) to be ran
                if ("script:" in hostnames[hst]) or ("script_double:" in hostnames[hst]) or ("netgroup:" in hostnames[hst]):
                    # if ipset_type == 'hash:ip,port,net':
                    #     command, _net_range_ = hostnames[hst].split(',')
                    #     command = command[7:].split()
                    # else:
                    #     command = hostnames[hst][7:].split()
                    # command, err, exit_code = self.rule_builder.sys_process_executor(command)
                    # if exit_code == 0:
                    #     command = command.splitlines()
                    #     command = [x for x in command if x != '-']
                    #     for addr in xrange(len(command)):
                    #         if (',' in command[addr]) and (ipset_type in ['hash:ip', 'hash:net']):
                    #             print "\nSection '" + ipset_section + "' type is '" + \
                    #                   ipset_type + "' but you provided extra elements. Change ipset_type option"
                    #             sys.exit(1)
                    #         elif (',' in command[addr]) and (ipset_type == 'hash:ip,port,net'):
                    #             command[addr] += ',' + _net_range_
                    #             command[addr] = command[addr].lower()
                    #     _hostnames_.extend(command)
                    _hostnames_.extend(self.handle_script_runs(ipset_section, hostnames[hst], ipset_type, ip_version))
                elif (',' in hostnames[hst]) and (ipset_type in ['hash:ip', 'hash:net']):
                    print "\nSection " + ipset_section + " type is '" + \
                          ipset_type + "' but you provided extra elements. Change ipset_type option"
                    sys.exit(1)
            for hst in xrange(len(hostnames)):
                if ("script:" not in hostnames[hst]) and ("script_double:" not in hostnames[hst]) \
                        and ("netgroup:" not in hostnames[hst]):
                    _hostnames_.append(hostnames[hst])

            del hostnames[:]
            hostnames = _hostnames_
            # print "Hostnames: ", hostnames

        # This part executes the script command if provided instead of hostname list
        elif type(hostnames) is str:
            hostnames = hostnames.split()
            hostnames, err, exit_code = self.rule_builder.sys_process_executor(hostnames)
            if exit_code == 0:
                hostnames = hostnames.splitlines()
                hostnames = [x for x in hostnames if x != '-']
                print hostnames
                for hst in hostnames:
                    if (',' in hst) and (ipset_type == "custom"):
                        print "\nSection '" + ipset_section + "' type is 'custom' but you provided ports also. " \
                                                                 " type should include port "
                        sys.exit(1)
            else:
                print err
                sys.exit(1)

        if ipset_type in ['hash:ip', 'hash:ip,port']:
            try:
                netgroup_networks = eval(self.parser.get(ipset_section, 'netgroup_set_name').encode('utf-8'))
            except configparser.NoOptionError:
                netgroup_networks = None

            if netgroup_networks is None:
                try:
                    if ip_version == 'ipv4':
                        ips = eval(self.parser.get(ipset_section, 'set_ips_v4').encode('utf-8'))
                    elif ip_version == 'ipv6':
                        ips = eval(self.parser.get(ipset_section, 'set_ips_v6').encode('utf-8'))
                except configparser.NoOptionError:
                    ips = None
                # if type(ips) is list:
                #     # print ips
                if type(ips) is str:
                    ips = ips.split()
                    ips, err, exit_code = self.rule_builder.sys_process_executor(ips)
                    if exit_code == 0:
                        ips = ips.splitlines()
                        ips = [x for x in ips if x != '-']
                        print ips
                    else:
                        print "The error is: ", err
                        sys.exit(1)
                if ipset_type == 'hash:ip':
                    try:
                        netgroup_set_list = eval(self.parser.get(ipset_section, 'netgroup_set_list').encode('utf-8'))
                    except configparser.NoOptionError:
                        netgroup_set_list = None
                    if netgroup_set_list is not None:
                        if type(netgroup_set_list) is not list:
                            print "\nOption netgroup_set_list for '" + ipset_section + "' section should be a list. " \
                                                                                    "Set it correctly"
                            sys.exit(1)

        elif ipset_type in ['hash:net', 'hash:net,port']:
            try:
                if ip_version == 'ipv4':
                    ips = eval(self.parser.get(ipset_section, 'set_net_ranges_v4').encode('utf-8'))
                elif ip_version == 'ipv6':
                    ips = eval(self.parser.get(ipset_section, 'set_net_ranges_v6').encode('utf-8'))
                    if type(ips) is list:
                        for nr in xrange(len(ips)):
                            ips[nr] = ips[nr].lower()
                # print ips
                ips = ips
            except configparser.NoOptionError:
                ips = None
            if type(ips) is str:
                ips = ips.split()
                ips, err, exit_code = self.rule_builder.sys_process_executor(ips)
                if exit_code == 0:
                    ips = ips.splitlines()
                    ips = [x for x in ips if x != '-']
                    print ips
                else:
                    print "The error is: ", err
                    sys.exit(1)

        elif ipset_type in ['hash:ip,port,ip']:
            try:
                netgroup_set_list = eval(self.parser.get(ipset_section, 'netgroup_set_list').encode('utf-8'))
            except configparser.NoOptionError:
                netgroup_set_list = None
            if netgroup_set_list is not None:
                if type(netgroup_set_list) is not list:
                    print "\nOption netgroup_set_list for '" + ipset_section + "' section should be a list. " \
                                                                            "Set it correctly"
                    sys.exit(1)
            try:
                if ip_version == 'ipv4':
                    ips = eval(self.parser.get(ipset_section, 'set_ip_port_ip_v4').encode('utf-8'))
                elif ip_version == 'ipv6':
                    ips = eval(self.parser.get(ipset_section, 'set_ip_port_ip_v6').encode('utf-8'))
                    if type(ips) is list:
                        for nr in xrange(len(ips)):
                            ips[nr] = ips[nr].lower()
                    # print ips
                    ips = ips
            except configparser.NoOptionError:
                ips = None

        elif ipset_type in ['hash:ip,port,net']:
            try:
                if ip_version == 'ipv4':
                    ips = eval(self.parser.get(ipset_section, 'set_ip_port_net_v4').encode('utf-8'))
                elif ip_version == 'ipv6':
                    ips = eval(self.parser.get(ipset_section, 'set_ip_port_net_v6').encode('utf-8'))
                    if type(ips) is list:
                        for nr in xrange(len(ips)):
                            ips[nr] = ips[nr].lower()
                    # print ips
            except configparser.NoOptionError:
                ips = None

        if set_name is not None:
            response = self.rule_builder.check_ipset(set_ipver, set_name[0])
        else:
            response = self.rule_builder.check_ipset(set_ipver, netgroup_networks[0])

        if 'port' in ipset_type:
            port = ['direct']

        if response == 'SetDoNotExist':

            if not update_only:
                ipset_action = 'create'
                response = self.rule_builder.manage_ipset(ipset_action, set_ipver, ipset_type, port, set_name,
                                                          netgroup_networks, hostnames, ips, netgroup_set_list, self.deploy,
                                                          self.generate_files, self.file_override)
                self.file_override = False
            else:
                # print "Create RESP: ", response
                return response, set_name

        elif response == 'SetExists':
            ipset_action = 'update'
            response = self.rule_builder.manage_ipset(ipset_action, set_ipver, ipset_type, port, set_name,
                                                      netgroup_networks, hostnames, ips, netgroup_set_list, self.deploy)
        elif response == 'IpsetCheckERROR':
            print response
            sys.exit(1)
        if set_name is None:
            return response, netgroup_networks

        else:
            return response, set_name

###########################################################################################################
    def handle_list_set(self, ipset_setction, ip_version, update_only=False):
        """
        This method is used to create a list:set type of ipset. This includes other already in memory sets.
        Works by reading the sections that define the other sets, builds them first and then adds them to it.

        :param ipset_setction: Section of the list set
        :param ip_version: ip version to build on IPv4 or IPv6
        :param update_only: flag to update sets only to be passed to handle ipsets method
        :return: the response and the name of the set
        """

        actual_set_names = []

        try:
            set_name = eval(self.parser.get(ipset_setction, 'set_name').encode('utf-8'))
            set_name[0] = set_name[0].replace(' ', '_')
        except configparser.NoOptionError:
            set_name = None

        try:
            list_set_sections = eval(self.parser.get(ipset_setction, 'list_set_sections').encode('utf-8'))
        except configparser.NoOptionError:
            list_set_sections = None

        set_name[0] = set_name[0].replace(' ', '_')
        if ip_version == 'ipv4':
            if '_v4' not in set_name[0]:
                set_name[0] += '_v4'
        elif ip_version == 'ipv6':
            if '_v6' not in set_name[0]:
                set_name[0] += '_v6'

        if not self.generate_files:
            response_exist = self.rule_builder.check_ipset("", set_name[0])
        else:
            response_exist = "SetDoNotExist"

        if list_set_sections is not None:
            if type(list_set_sections) is list:
                for sect in list_set_sections:
                    response, name = self.handle_ipsets(sect, ip_version, update_only)
                    name[0] = name[0].replace(' ', '_')
                    if ip_version == 'ipv4':
                        name[0] += '_v4'
                    elif ip_version == 'ipv6':
                        name[0] += '_v6'
                    actual_set_names.append(name[0])
                if response_exist == "SetDoNotExist":
                    self.rule_builder.manage_ipset("create", None, "list:set", None, set_name, None, None, None, None,
                                                   self.deploy, self.generate_files, False, actual_set_names)
                elif response_exist == "SetExists":
                    self.rule_builder.manage_ipset("update", None, "list:set", None, set_name, None, None, None, None,
                                                   self.deploy, self.generate_files, self.file_override,
                                                   actual_set_names)
            else:
                pass
        else:
            if response_exist == "SetDoNotExist":
                response = self.rule_builder.manage_ipset("create", None, "list:set", None, set_name, None, None, None,
                                                          None, self.deploy, self.generate_files, False, [])
            elif response_exist == "SetExists":
                response = self.rule_builder.manage_ipset("update", None, "list:set", None, set_name, None, None, None,
                                                          None, self.deploy, self.generate_files, self.file_override, [])

        return response, set_name


###########################################################################################################
    def handle_bidirectional_rules(self, general_section, ip_version):
        """
        This method is used to build rules serving both INPUT and OUTPUT chains.

        :param general_section: Name of the rule section
        :param ip_version: IPv4/IPv6
        :return: A list of iptables and ip6tables commands to be run so the rules are applied.
        """

        rules_list = []
        chain_name = None
        jump_chain = None
        comment = None
        protocol = None
        nic = None
        modules = {}

        action = eval(self.parser.get(general_section, 'action'))
        comment = general_section
        try:
            nic = self.parser.get(general_section, 'interface').encode('utf-8')
            if nic == "main":
                nic = main_nic_extractor()
            elif nic == "all":
                nic = other_nic_extractor(True)
            elif nic == "other":
                nic = other_nic_extractor()
            else:
                nic = eval(self.parser.get(general_section, 'interface').encode('utf-8'))
                nic = self.handle_nic_cards(nic)
                if nic == 'error':
                    print '\nInterfaces option not set correctly for section \'' + general_section + '\' Setting to None'
                    nic = None
        except configparser.NoOptionError:
            nic = None
        except:
            print '\nInterfaces option not set correctly for section \'' + general_section + '\' Setting to None'
            nic = None
        try:
            protocol = self.parser.get(general_section, 'protocol').encode('utf-8')
            protocol = protocol.split(',')
            # print protocol
            # sys.exit(1)
        except configparser.NoOptionError:
            protocol = None
        try:
            ports = self.parser.get(general_section, 'ports').encode('utf-8')
            if (',' not in ports) and (':' not in ports):
                if ' ' in ports:
                    ports = eval(ports)
                    ports = ports.split()
                    print "Ports script: ", ports
                    pr_tmp, err, exit_code = self.rule_builder.sys_process_executor(ports)
                    if exit_code != 0:
                        print "Section " + general_section + " ports script: " + ports
                        print err
                        sys.exit(1)
                    ports = pr_tmp
        except configparser.NoOptionError:
            ports = None

        if self.parser.has_option(general_section, 'set'):
            set_section = self.parser.get(general_section, 'set').encode('utf-8')
            if self.parser.has_section(set_section):
                if self.parser.get(set_section, "ipset_type") != "list:set":
                    response_set, set_name = self.handle_ipsets(set_section, ip_version)
                else:
                    response_set, set_name = self.handle_list_set(set_section, ip_version)
                if response_set == 'SETNOTFOUND':
                    print 'SETNOTFOUND'
                    print 'Section: ', general_section
                    print 'Set: ', set_name
                    sys.exit(1)
                # else:
                #     print "RESPONSE_SET: ", response_set
            else:
                print "Specified ipset section \"" + set_section + "\" does not exist"
                sys.exit(1)

        if (action[1] == 'out') and (action[2] == 'in'):
            jump_chain = 'ACCEPT'
            chain_name = 'INPUT'
            modules['state'] = 'NEW,ESTABLISHED'
            if self.parser.has_option(general_section, 'set'):
                if response_set == 0:
                    set_name[0] = set_name[0].replace(' ', '_')
                    if ip_version == 'ipv4':
                        set_name[0] += '_v4'
                    elif ip_version == 'ipv6':
                        set_name[0] += '_v6'
                    if 'port' in self.parser.get(set_section, 'ipset_type').encode('utf-8'):
                        modules['set'] = [set_name[0], 'src,dst']
                    else:
                        modules['set'] = [set_name[0], 'src']
                    print set_name[0]
                elif response_set == 1:
                    print "Usage problem with ipset"
                    print response_set
                    print set_name
                    sys.exit(0)
            if ports is not None:
                modules['multiport'] = ['dports', ports]
            # print chain_name, ip_version, nic, protocol, comment, modules, jump_chain
            if protocol is None:
                if type(nic) is list:
                    for _nic_ in nic:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                        protocol, _nic_, modules))
                else:
                    rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                    protocol, nic, modules))
            else:
                for pl in protocol:
                    if type(nic) is list:
                        for _nic_ in nic:
                            rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                            pl, _nic_, modules))
                    else:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment, pl,
                                                                        nic, modules))

            chain_name = 'OUTPUT'
            modules['state'] = 'ESTABLISHED'
            if self.parser.has_option(general_section, 'set'):
                if response_set == 0:
                    if 'port' in self.parser.get(set_section, 'ipset_type').encode('utf-8'):
                        modules['set'][1] = 'dst,dst'
                    else:
                        modules['set'][1] = 'dst'
            # if ports is not None:
            #     modules['multiport'][0] = 'sports'
            try:
                del modules['multiport']
            except KeyError:
                pass
            # print chain_name, ip_version, nic, protocol, comment, modules, jump_chain
            if protocol is None:
                if type(nic) is list:
                    for _nic_ in nic:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                        protocol, _nic_, modules))
                else:
                    rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                    protocol, nic, modules))
            else:
                for pl in protocol:
                    if type(nic) is list:
                        for _nic_ in nic:
                            rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                            pl, _nic_, modules))
                    else:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment, pl,
                                                                        nic, modules))

        elif (action[1] == 'in') and (action[2] == 'out'):
            jump_chain = 'ACCEPT'
            chain_name = 'INPUT'
            modules['state'] = 'ESTABLISHED'
            if self.parser.has_option(general_section, 'set'):
                if response_set == 0:
                    set_name[0] = set_name[0].replace(' ', '_')
                    if ip_version == 'ipv4':
                        set_name[0] += '_v4'
                    elif ip_version == 'ipv6':
                        set_name[0] += '_v6'
                    if 'port' in self.parser.get(set_section, 'ipset_type').encode('utf-8'):
                        modules['set'] = [set_name[0], 'src,dst']
                    else:
                        modules['set'] = [set_name[0], 'src']
                    print set_name[0]
                elif response_set == 1:
                    print "Usage problem with ipset"
                    print response_set
                    print set_name
                    sys.exit(1)
            # if ports is not None:
            #     modules['multiport'] = ['dports', ports]
            # print chain_name, ip_version, nic, protocol, comment, modules, jump_chain
            try:
                del modules['multiport']
            except KeyError:
                pass

            if protocol is None:
                if type(nic) is list:
                    for _nic_ in nic:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                        protocol, _nic_, modules))
                else:
                    rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                    protocol, nic, modules))
            else:
                for pl in protocol:
                    if type(nic) is list:
                        for _nic_ in nic:
                            rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                            pl, _nic_, modules))
                    else:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment, pl,
                                                                        nic, modules))
            chain_name = 'OUTPUT'
            modules['state'] = 'NEW,ESTABLISHED'
            if self.parser.has_option(general_section, 'set'):
                if response_set == 0:
                    if 'port' in self.parser.get(set_section, 'ipset_type').encode('utf-8'):
                        modules['set'][1] = 'dst,dst'
                    else:
                        modules['set'][1] = 'dst'
            if ports is not None:
                # modules['multiport'][0] = 'sports'
                modules['multiport'] = ['dports', ports]
            # print chain_name, ip_version, nic, protocol, comment, modules, jump_chain
            if protocol is None:
                if type(nic) is list:
                    for _nic_ in nic:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                        protocol, _nic_, modules))
                else:
                    rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                    protocol, nic, modules))
            else:
                for pl in protocol:
                    if type(nic) is list:
                        for _nic_ in nic:
                            rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                            pl, _nic_, modules))
                    else:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment, pl,
                                                                        nic, modules))
        else:
            print "Specify 'action' option for section '" + general_section + "' properly"
            sys.exit(1)

        return rules_list

###########################################################################################################

    def single_chain_rule(self, general_section, ip_version):
        """
        This method is used to create signle rules on one of/both the default chains. Tries to extract the values of the
        possible options in order to build the rule

        :param general_section: Name of the section
        :param ip_version: IPv4/IPv6
        :return: a list of rule/rules (2 rules if tcp and udp are defined)
        """

        rules_list = []
        jump_chain = None
        comment = None
        protocol = None
        nic = None
        modules = {}

        action = eval(self.parser.get(general_section, 'action'))
        # comment = self.parser.get(general_section, 'md5').encode('utf-8')
        comment = general_section
        try:
            print "Section name:", general_section
            nic = self.parser.get(general_section, 'interface').encode('utf-8')
            if nic == "main":
                nic = main_nic_extractor()
            elif nic == "all":
                nic = other_nic_extractor(True)
            elif nic == "other":
                nic = other_nic_extractor()
            else:
                nic = eval(self.parser.get(general_section, 'interface').encode('utf-8'))
                # nic = nic.split(',')
                print "nic: ", nic
                nic = self.handle_nic_cards(nic)
                if nic == 'error':
                    print '\nInterfaces option not set correctly for section \'' + general_section + '\' Setting to None'
                    nic = None
        except configparser.NoOptionError:
            nic = None
        except:
            print '\nInterfaces option not set correctly for section \'' + general_section + '\' Setting to None'
            nic = None
        try:
            protocol = self.parser.get(general_section, 'protocol').encode('utf-8')
            protocol = protocol.split(',')
            # print protocol
            # sys.exit(1)
        except configparser.NoOptionError:
            protocol = None
        try:
            ports = self.parser.get(general_section, 'ports').encode('utf-8')
            if (',' not in ports) and (':' not in ports):
                if ' ' in ports:
                    ports = eval(ports)
                    ports = ports.split()
                    print "Ports script: ", ports
                    pr_tmp, err, exit_code = self.rule_builder.sys_process_executor(ports)
                    if exit_code != 0:
                        print "Section " + general_section + " ports script: " + ports
                        print err
                        sys.exit(1)
                    ports = pr_tmp
        except configparser.NoOptionError:
            ports = None

        if self.parser.has_option(general_section, 'set'):
            set_section = self.parser.get(general_section, 'set').encode('utf-8')
            if self.parser.has_section(set_section):
                if self.parser.get(set_section, "ipset_type") != "list:set":
                    response_set, set_name = self.handle_ipsets(set_section, ip_version)
                else:
                    response_set, set_name = self.handle_list_set(set_section, ip_version)
                if response_set == 'SETNOTFOUND':
                    print 'SETNOTFOUND'
                    print 'Section: ', general_section
                    print 'Set: ', set_name
                    sys.exit(1)
                    # else:
                    #     print "RESPONSE_SET: ", response_set
            else:
                print "Specified ipset section \"" + set_section + "\" does not exist"
                sys.exit(1)

        if action[0] == 'accept':
            jump_chain = 'ACCEPT'
        elif action[0] == 'drop':
            jump_chain = 'DROP'
        # chain_name = 'INPUT'

        default_chain = self.parser.get(general_section, "default_chain").encode("utf-8")
        default_chain = default_chain.split(',')

        # modules['state'] = 'NEW,ESTABLISHED'

        for chain_name in default_chain:
            if self.parser.has_option(general_section, 'set'):
                if response_set == 0:
                    set_name[0] = set_name[0].replace(' ', '_')
                    # if self.parser.get(set_section, 'ipset_type').encode('utf-8') != "list:set":
                    if ip_version == 'ipv4':
                        if '_v4' not in set_name[0]:
                            set_name[0] += '_v4'
                    elif ip_version == 'ipv6':
                        if '_v6' not in set_name[0]:
                            set_name[0] += '_v6'
                    if chain_name.lower() == 'input':
                        if self.parser.has_option(general_section, 'set_directions'):
                            modules['set'] = [set_name[0], self.parser.get(general_section, 'set_directions').encode("utf-8")]
                        else:
                            if 'port' in self.parser.get(set_section, 'ipset_type').encode('utf-8'):
                                modules['set'] = [set_name[0], 'src,dst']
                            else:
                                modules['set'] = [set_name[0], 'src']
                    else:
                        if self.parser.has_option(general_section, 'set_directions'):
                            modules['set'] = [set_name[0], self.parser.get(general_section, 'set_directions')
                                              .encode("utf-8")]
                        else:
                            if 'port' in self.parser.get(set_section, 'ipset_type').encode('utf-8'):
                                modules['set'] = [set_name[0], 'dst,dst']
                            else:
                                modules['set'] = [set_name[0], 'dst']
                    # print set_name[0]

                elif response_set == 1:
                    print "Usage problem with ipset"
                    print response_set
                    print set_name
                    sys.exit(0)

            if ports is not None:
                modules['multiport'] = ['dports', ports]
            # print chain_name, ip_version, nic, protocol, comment, modules, jump_chain
            if protocol is None:
                if type(nic) is list:
                    for _nic_ in nic:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain,
                                                                        comment, protocol, _nic_, modules))
                else:
                    rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment,
                                                                    protocol, nic, modules))
            else:
                for pl in protocol:
                    if type(nic) is list:
                        for _nic_ in nic:
                            rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain,
                                                                            comment, pl, _nic_, modules))
                    else:
                        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain,
                                                                        comment, pl, nic, modules))

        return rules_list

###########################################################################################################

    def log_with_custom_chain(self, general_section, ip_version):
        """
        This method is used to create rules that jump to the LOG chain. It is mainly used by defining a custom chain to
        jump after INPUT or OUTPUT chain.

        :param general_section: Name of the section
        :param ip_version: IPv4/IPv6
        :return: A list of rule/rules to create the user defined chain and the rules for the default chains that jum to the user defined chain.
        """
        # print "INSIDE LOG DROP"

        rules_list = []
        default_chain = None
        jump_chain = None
        comment = None
        protocol = None
        nic = None
        modules = {}

        # Try top read all the supported options in order to build the rule
        action = eval(self.parser.get(general_section, 'action'))
        # comment = self.parser.get(general_section, 'md5').encode('utf-8')
        comment = general_section

        try:
            nic = self.parser.get(general_section, 'interface').encode('utf-8')
            if nic == "main":
                nic = main_nic_extractor()
            elif nic in ['all', 'other']:
                print "\nInterface for section '" + general_section + "' cannot be all or other "
                sys.exit(1)
        except configparser.NoOptionError:
            nic = None
        try:
            protocol = self.parser.get(general_section, 'protocol').encode('utf-8')
            protocol = protocol.split(',')
        except configparser.NoOptionError:
            protocol = None
        try:
            ports = self.parser.get(general_section, 'ports').encode('utf-8')
        except configparser.NoOptionError:
            ports = None
        # try:
        #     length = self.parser.get(general_section, 'length').encode('utf-8')
        # except configparser.NoOptionError:
        #     length = None
        try:
            limit = self.parser.get(general_section, 'limit').encode('utf-8')
        except configparser.NoOptionError:
            limit = None
        try:
            log_prefix = self.parser.get(general_section, 'log-prefix').encode('utf-8')
            log_prefix += " "
        except configparser.NoOptionError:
            log_prefix = None
        try:
            log_level = self.parser.get(general_section, 'log-level').encode('utf-8')
        except configparser.NoOptionError:
            log_level = None

        try:
            log_specific_options = eval(self.parser.get(general_section, 'log-specific-options').encode('utf-8'))
        except configparser.NoOptionError:
            log_specific_options = None

        default_chain = self.parser.get(general_section, "default_chain").encode("utf-8")
        default_chain = default_chain.split(',')

        if log_specific_options and (type(log_specific_options) is list):
            if 'log-tcp-sequence' in log_specific_options:
                log_tcp_sequence = True
            else:
                log_tcp_sequence = False

            if 'log-tcp-options' in log_specific_options:
                log_tcp_options = True
            else:
                log_tcp_options = False

            if self.parser.has_option(general_section, 'log-ip-options'):
                log_ip_options = True
            else:
                log_ip_options = False
        else:
            log_tcp_sequence = False
            log_tcp_options = False
            log_ip_options = False

        try:
            custom_chain = self.parser.get(general_section, 'custom_chain').encode('utf-8')
            ext_c, _cmd_ = self.rule_builder.manage_custom_chain('create', custom_chain, ip_version, None, self.deploy)
            if ext_c not in [0, 1]:
                custom_chain = None
                print "Error with chain: ", custom_chain
                sys.exit(1)
            if _cmd_ is not None:
                rules_list.append(_cmd_)
        except configparser.NoOptionError:
            print "Please specify custom chain for the section: ", general_section
            sys.exit(1)
        for chain_name in default_chain:
            # Jump first to the custom chain
            if custom_chain is not None:
                jump_chain = custom_chain
                # chain_name = 'INPUT'
            # if length is not None:
            #     modules['length'] = length

            if protocol is None:
                rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment, protocol, nic, modules))
            else:
                for pl in protocol:
                    rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment, pl, nic, modules))

        jump_chain = 'LOG'
        if custom_chain is not None:
            chain_name = custom_chain
        # else:
        #     chain_name = 'INPUT'

        # modules.pop('length')

        if limit is not None:
            modules['limit'] = limit

        jump_chain_list = []

        if log_prefix is not None:
            jump_chain_list.append('log-prefix')
            jump_chain_list.append(log_prefix)
        if log_level is not None:
            jump_chain_list.append('log-level')
            jump_chain_list.append(log_level)
        if log_tcp_sequence:
            jump_chain_list.append('log-tcp-sequence')
        if log_tcp_options:
            jump_chain_list.append('log-tcp-options')
        if log_ip_options:
            jump_chain_list.append('log-ip-options')

        protocol = None
        nic = None

        if jump_chain_list is not []:
            # Insert LOG chain at element 0 of the list in order to create the rule
            jump_chain_list.insert(0, 'LOG')
            rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain_list, comment, protocol, nic, modules))
        else:
            rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain_list, comment, protocol, nic, modules))

        if action[1] == 'drop':
            jump_chain = 'DROP'
        elif action[1] == 'accept':
            jump_chain = 'ACCEPT'
        modules = {}
        if custom_chain is not None:
            chain_name = custom_chain
        # else:
        #     chain_name = 'INPUT'

        rules_list.append(self.rule_builder.manage_rule(ip_version, chain_name, jump_chain, comment, protocol, nic, modules))

        return rules_list

###########################################################################################################

    def rules_logic_parse(self, general_section):
        """
        This method is used to decide which rule building method will be called for each section on the config
        files using the 'action' option list.

        :param general_section: The name iof the section
        :return: A list of rule/rules depending on the action.
        """

        rules_list = []
        ip_version = None
        chain_name = None
        jump_chain = None
        comment = None
        protocol = None
        nic = None
        modules = {}

        if self.parser.get(general_section, 'ip_version') not in ['ipv4', 'ipv6', 'both']:
            print "Specify 'ip_version' option for section '" + general_section + "' between ipv4 or ipv6 or both"
            sys.exit(1)

        # This part is for iptables
        if self.parser.get(general_section, 'ip_version') in ['ipv4', 'both']:
            ip_version = 'ipv4'
            action = eval(self.parser.get(general_section, 'action'))
            if (type(action) is list) and (len(action) == 3):
                if (action[0] in ['accept', 'drop']) and ((action[1] in ['in', 'out']) and
                                                          (action[2] in ['in', 'out']) and action[1] != action[2]):
                    rules_list.extend(self.handle_bidirectional_rules(general_section, ip_version))
                else:
                    print "Specify 'action' option for section '" + general_section + "' properly"
                    sys.exit(1)
            elif (type(action) is list) and (len(action) == 2):
                if action[0] == 'log' and (action[1] == 'drop' or action[1] == 'accept'):
                    if self.parser.has_option(general_section, 'default_chain'):
                        rules_list.extend(self.log_with_custom_chain(general_section, ip_version))
                    else:
                        print "You need to define the 'default_chain' option for the section '" + general_section + "'"
                        sys.exit(1)
                else:
                    print "Specify 'action' option for section '" + general_section + "' properly"
                    sys.exit(1)
            elif (type(action) is list) and (len(action) == 1):
                if action[0] in ['accept', 'drop']:
                    if self.parser.has_option(general_section, 'default_chain'):
                        rules_list.extend(self.single_chain_rule(general_section, ip_version))
                    else:
                        print "You need to define the 'default_chain' option for the section '" + general_section + "'"
                        sys.exit(1)
                else:
                    print "Specify 'action' option for section '" + general_section + "' properly"
                    sys.exit(1)
            else:
                print "Specify 'action' option for section '" + general_section + "' properly"
                sys.exit(1)

        # This part is for ip6tables
        if self.parser.get(general_section, 'ip_version') in ['ipv6', 'both']:
            ip_version = 'ipv6'
            action = eval(self.parser.get(general_section, 'action'))
            if (type(action) is list) and (len(action) == 3):
                if (action[0] in ['accept', 'drop']) and ((action[1] in ['in', 'out']) and
                                                          (action[2] in ['in', 'out']) and action[1] != action[2]):
                    rules_list.extend(self.handle_bidirectional_rules(general_section, ip_version))
            elif (type(action) is list) and (len(action) == 2):
                if action[0] == 'log' and (action[1] == 'drop' or action[1] == 'accept'):
                    if self.parser.has_option(general_section, 'default_chain'):
                        rules_list.extend(self.log_with_custom_chain(general_section, ip_version))
                    else:
                        print "You need to define the 'default_chain' option for the section '" + general_section + "'"
                        sys.exit(1)
                else:
                    print "Specify 'action' option for section '" + general_section + "' properly"
                    sys.exit(1)
            elif (type(action) is list) and (len(action) == 1):
                if self.parser.has_option(general_section, 'default_chain'):
                    rules_list.extend(self.single_chain_rule(general_section, ip_version))
                else:
                    print "You need to define the 'default_chain' option for the section '" + general_section + "'"
                    sys.exit(1)
            else:
                print "Specify 'action' option for section '" + general_section + "' properly"
                sys.exit(1)

        return rules_list

###########################################################################################################

    def ipsets_update(self):
        """
        This method is used to update existing kernel ipsets. It checks for rules that sections and on those that have an ipset
        defined calls the --> handle_ipsets() method to update the sets.

        :return: void
        """

        general_sections = []
        for sect in xrange(len(self.sections)):
            if self.parser.get(self.sections[sect], 'section_type').encode("utf-8") == 'general':
                general_sections.append(self.sections[sect])

        if len(general_sections) > 0:
            for sect in general_sections:
                if self.parser.has_option(sect, "set"):
                    set_sect = self.parser.get(sect, "set")
                    if self.parser.get(sect, 'ip_version') in ['ipv4', 'both']:
                        ip_version = 'ipv4'
                        if self.parser.get(set_sect, "ipset_type") != "list:set":
                            responce, set_name = self.handle_ipsets(set_sect, ip_version, True)
                        else:
                            responce, set_name = self.handle_list_set(set_sect, ip_version, True)
                        print responce, set_name

                    if self.parser.get(sect, 'ip_version') in ['ipv6', 'both']:
                        ip_version = 'ipv6'
                        if self.parser.get(set_sect, "ipset_type") != "list:set":
                            responce, set_name = self.handle_ipsets(set_sect, ip_version, True)
                        else:
                            responce, set_name = self.handle_list_set(set_sect, ip_version, True)
                        print responce, set_name

            self.rule_builder.save_ipset(self.deploy)

###########################################################################################################

    def iptables_policy(self, policy):
        """
        This method is used to create the rules that set the policy of the default chains.

        :param policy: Name of the section that contains the policy
        :return: A list of rule/rules depending on the action.
        """

        rules = []
        ip_ver = self.parser.get(policy, 'ip_version').encode('utf-8')

        if ip_ver in ['ipv4', 'both']:
            for p in ['input', 'output', 'forward']:
                try:
                    pol = self.parser.get(policy, p).encode('utf-8')
                    iptables_command = FirewallRuleBuilder.read_config_file('iptables_command')
                    rules.append([iptables_command, '-P', p.upper(), pol])
                except configparser.NoOptionError:
                    pass

        if ip_ver in ['ipv6', 'both']:
            for p in ['input', 'output', 'forward']:
                try:
                    pol = self.parser.get(policy, p).encode('utf-8')
                    ip6tables_command = FirewallRuleBuilder.read_config_file('ip6tables_command')
                    rules.append([ip6tables_command, '-P', p.upper(), pol])
                except configparser.NoOptionError:
                    pass

        return rules

###########################################################################################################

    def parse_file(self):
        """
        This method is used to distinguish if a section is rule or policy and

        :return: returns the final rules list - actual list of commands
        """

        general_sections = []
        rules = []
        policy = None

        for secti in xrange(len(self.sections)):
            if self.parser.get(self.sections[secti], 'section_type').encode("utf-8") == 'policy':
                if policy is None:
                    policy = self.sections[secti]
                else:
                    print 'More than one policy sections found, please leave only one'
                    sys.exit(1)

        for sect in xrange(len(self.sections)):
            if self.parser.get(self.sections[sect], 'section_type').encode("utf-8") == 'general':
                general_sections.append(self.sections[sect])

        if (len(general_sections) > 0) or (policy is not None):
            for sect in general_sections:
                rules.append(self.rules_logic_parse(sect))

            if policy is not None:
                rules.append(self.iptables_policy(policy))

        return rules

###########################################################################################################

    def apply_firewall_rules(self, command_list):
        """
        This method is used to apply the firewall rules. It receives a list of iptables commands and runs all the
        commands one after the other.
        The iptables rules come with '-C' param in order to check if the exist. If not the '-C' becomes '-A' so we can
        add them to the configuration.

        :param command_list: The final commands list to run.
        :return: void
        """

        self.rule_builder.save_ipset(self.deploy)

        final = []

        if command_list is not None:
            for i in xrange(len(command_list)):
                for j in xrange(len(command_list[i])):
                    if 'iptables' in command_list[i][j][0]:
                        final.append(command_list[i][j])
            for i in xrange(len(command_list)):
                for j in xrange(len(command_list[i])):
                    if 'ip6tables' in command_list[i][j][0]:
                        final.append(command_list[i][j])
            print ''
            print "######### USER DEFINED FIREWALL RULES #########"
            for j in final:
                if not self.deploy:
                    # Replace [comment] with "comment" so the comments on the rules are inserted properly
                    j[-1] = j[-1].replace('[', '')
                    j[-1] = j[-1].replace(']', '')
                    if j[1] == '-C':
                        responce, err, exit_code = self.rule_builder.sys_process_executor(j)
                    else:
                        exit_code = 1
                    if exit_code != 0:
                        # Change '-C' (check if rule exists) to '-A' (add the rule) and put it in a rule only list
                        if j[1] == '-C':
                            j[1] = '-A'
                        for k in xrange(len(j) - 1):
                            print j[k],

                        print j[-1]
                        responce, err, exit_code = self.rule_builder.sys_process_executor(j)
                    else:
                        # Change '-C' (check if rule exists) to '-A' (add the rule) and put it in a rule only list
                        if j[1] == '-C':
                            j[1] = '-A'
                        print "Rule already exists"
                        for k in xrange(len(j) - 1):
                            print j[k],
                        print j[-1]
                else:
                    # Replace [comment] with "comment" so the comments on the rules are inserted properly
                    j[-1] = j[-1].replace('[', '')
                    j[-1] = j[-1].replace(']', '')
                    # Change '-C' (check if rule exists) to '-A' (add the rule) and put it in a rule only list
                    if j[1] == '-C':
                        j[1] = '-A'
                    for k in xrange(len(j) - 1):
                        print j[k],
                    print j[-1]
            print "######### USER DEFINED FIREWALL RULES #########"
        else:
            print "Comand list empty !!!!!"
            sys.exit(1)

        print ''
        del command_list[:]
        del command_list
        del final[:]
        del final


def print_default_rules(rule_list):
    if len(rule_list) > 0:
        print ''
        print "######### DEFAULT FIREWALL RULES #########"
        for i in rule_list:
            print i
        print "######### DEFAULT FIREWALL RULES #########"


###########################################################################################################
def iptables_manager(args=None, config=None, interface="main", no_default_config=False, allow=False, drop_all=False,
                     update_sets=False, deploy=False, generate_files=False):
    """
    This function is the actual main function. It is used as 'proxy' method so you can either use this script from a
    another python script or directly from command line. This method is being called with either the 'args' param or the
    all others depending if its being called from the main function or from another python script.

    :param args: Basically all the other params but in arguments format.
    :param config: List of the config file paths to load for the configuration.
    :param interface: Network card to use for the default config
    :param no_default_config: If set it applies the default configuration
    :param allow: If set it sets the policy of all the default chains to ACCEPT.
    :param drop_all: If set it sets the policy of all the default chains to DROP.
    :param update_sets: If set it reads the config and updates all the existing kernel ipsets
    :param deploy: If set it applies the configuration. If not all the rules are being displayed instead of run.
    :param generate_files: It create the actual rule files for iptables and ip6tables to be used with the restore option
    :return: 0 if everything goes smoothly
    """
    default_rules_list =[]
    iptables_rules = []

    if args is not None:

        if args.config:
            config = args.config
        else:
            config = None

        if args.interface:
            interface = args.interface[0]

        if args.no_default_config:
            no_default_config = True
        else:
            no_default_config = False

        if args.drop_all:
            drop_all = True
        else:
            drop_all = False

        if args.allow:
            allow = True
        else:
            allow = False

        if args.update_sets:
            update_sets = True
            no_default_config = True
        else:
            update_sets = False

        if args.deploy:
            deploy = True
        else:
            deploy = False

        if args.generate_files:
            no_default_config = False
            deploy = False
            update_sets = False
            generate_files = True
        else:
            generate_files = False

    try:
        path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if deploy:
            default = DefaultConfiguration('deploy', path + '/default_conf_files', interface)
        else:
            default = DefaultConfiguration('simulate', path + '/default_conf_files', interface)
    except RuntimeError:
        sys.stderr.write("Error Creating the main objects")
        print "Please check the files are under the provided path/s"
        sys.exit(1)

    if not no_default_config:
        print "Apply DEFAULT RULES "
        if deploy:
            default.clean_iptables(default.read_config_file('iptables_command'))
            default.clean_iptables(default.read_config_file('ip6tables_command'))
            default.destroy_all_ipsets()
            default.perform_action()
        else:
            default_rules_list.extend(default.clean_iptables(default.read_config_file('iptables_command')))
            default_rules_list.extend(default.clean_iptables(default.read_config_file('ip6tables_command')))
            default_rules_list.extend(default.destroy_all_ipsets())
            default_rules_list.extend(default.perform_action())
    if allow:
        if deploy:
            default.accept_iptables(default.read_config_file('iptables_command'))
            default.accept_iptables(default.read_config_file('ip6tables_command'))
            default.iptables_save(default.read_config_file('iptables_command'))
            default.iptables_save(default.read_config_file('ip6tables_command'))
        else:
            default_rules_list.extend(default.accept_iptables(default.read_config_file('iptables_command')))
            default_rules_list.extend(default.accept_iptables(default.read_config_file('ip6tables_command')))
            default_rules_list.extend(default.iptables_save(default.read_config_file('iptables_command')))
            default_rules_list.extend(default.iptables_save(default.read_config_file('ip6tables_command')))

    if drop_all and (config is None):
        if deploy:
            default.final_drop_iptables(default.read_config_file('iptables_command'))
            default.final_drop_iptables(default.read_config_file('ip6tables_command'))
            default.iptables_save(default.read_config_file('iptables_command'))
            default.iptables_save(default.read_config_file('ip6tables_command'))
        else:
            default_rules_list.extend(default.final_drop_iptables(default.read_config_file('iptables_command')))
            default_rules_list.extend(default.final_drop_iptables(default.read_config_file('ip6tables_command')))
            default_rules_list.extend(default.iptables_save(default.read_config_file('iptables_command')))
            default_rules_list.extend(default.iptables_save(default.read_config_file('ip6tables_command')))

    if config is not None:

        try:
            file_reader = ReadWriteConfigFiles()
            file_parser = file_reader.read_config_file(config)
            # print file_parser.sections()
        except RuntimeError:
            sys.stderr.write("Error reading the files")
            print "Please check the files are under the provided path/s"
            sys.exit(1)

        if deploy:
            custom_rules = ManageRules(file_parser, False, False)
        else:
            custom_rules = ManageRules(file_parser, True, generate_files)

        custom_rules.config_integrity_check()

        if update_sets:
            print "UPDATE IPsets ONLY"
            custom_rules.ipsets_update()

        elif not update_sets:
            iptables_rules.extend(custom_rules.parse_file())
            if not generate_files:
                custom_rules.apply_firewall_rules(iptables_rules)
                default.iptables_save(default.read_config_file('iptables_command'))
                default.iptables_save(default.read_config_file('ip6tables_command'))
            if drop_all:
                if deploy:
                    default.final_drop_iptables(default.read_config_file('iptables_command'))
                    default.final_drop_iptables(default.read_config_file('ip6tables_command'))
                else:
                    default_rules_list.extend(default.final_drop_iptables(default.read_config_file('iptables_command')))
                    default_rules_list.extend(default.final_drop_iptables(default.read_config_file('ip6tables_command')))
                    default_rules_list.extend(default.iptables_save(default.read_config_file('iptables_command')))
                    default_rules_list.extend(default.iptables_save(default.read_config_file('ip6tables_command')))
            if generate_files:
                gen_files = IPTablesFileGenerator()
                gen_files.write_iptables_files(default_rules_list, iptables_rules)
            else:
                print_default_rules(default_rules_list)

    else:
        if generate_files:
            gen_files = IPTablesFileGenerator()
            gen_files.write_iptables_files(default_rules_list, [])
        else:
            print_default_rules(default_rules_list)

    return 0

############################################################################################################


def main():
    """
    Main function use to expose all the parameters to the command line and call iptables_manager function.

    :return: void
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--config', nargs='+', help='Type the location of your config file to parse(absolut path)')
    parser.add_argument('--no_default_config', action='store_true', help='Apply default configuration from scratch')
    parser.add_argument('--allow', action='store_true', help='Apply ACCEPT policy to everything')
    parser.add_argument('--drop_all', action='store_true', help='Apply DROP policy to everything')
    parser.add_argument('--interface', nargs=1,
                        help='Type the name of nic card you want the default rules to be applied for')
    parser.add_argument('--update_sets', action='store_true', help='Update only the ipsets')
    parser.add_argument('--deploy', action='store_true', help='Deploy the configuration')
    parser.add_argument('--generate_files', action='store_true', help='Generate iptables and ip6tables files')

    args = parser.parse_args()

    exit_code = iptables_manager(args)

    if exit_code != 0:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
