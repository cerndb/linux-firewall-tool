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

import os
import sys
import argparse
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import configparser
from iptables_manager import iptables_manager
from iptables_manager_modules.rules_builder import FirewallRuleBuilder
from ip_dns_resolve import ip_dns_resolver
from netgroups_set_extraction import netgroup_set_extractor


class ReadWriteConfigFiles(object):
    """
    Class that reads the config files using python config parser module. It then creates an object(dict)
    and adds all the sections of the file as key and its options as value
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


class ManageHosts(object):
    """
    Class that reads the config files using python config parser module. It then creates an object(dict)
    and adds all the sections of the file as key and its options as value
    """

    """
    This list holds all the section that are loaded from all the configs files that were passed as parameters
    """
    sections = []

    """
    This list holds all the allowed option you can define under a section on the config files
    """
    options = ['description', 'machines', 'config_folder', 'config_folder_files', 'config_files']

    def __init__(self, parser):
        """
        Init method of the class

        :param parser: Config parser object to access the files configuration
        """
        self.parser = parser

    def config_integrity_check(self):
        """
        This method add all the section loaded from config files to a list for better handling. Its main purpose is to
        check the 'integrity' of the config files in terms of specifying the right things of avoid logical errors.

        :return: void
        """
        for i in self.parser.sections():
            self.sections.append(i.encode("utf-8"))
            # print i.encode("utf-8")

            if not self.parser.has_option(i.encode('utf-8'), "machines"):
                print "Specify 'machines' option for section '" + i.encode("utf-8") + "'"
                sys.exit(1)
            else:
                machines = eval(self.parser.get(i, "machines").encode('utf-8'))
                if type(machines) is str:
                    script = machines.split()
                    machines, err, exit_code = FirewallRuleBuilder.sys_process_executor(script)
                    if exit_code != 0:
                        print "Script: ", script, " returned error code:", exit_code
                        sys.exit(1)

            if self.parser.has_option(i.encode('utf-8'), "config_folder_files"):
                if not self.parser.has_option(i.encode('utf-8'), "config_folder"):
                    print "Specify 'config_folder' option for section '" + i.encode("utf-8") + "'"
                    sys.exit(1)

            # if not (self.parser.has_option(i.encode('utf-8'), "config_folder_files") or
            #             (self.parser.has_option(i.encode('utf-8'), "config_files"))):
            #     print "Specify 'config_folder_files' or 'config_files' option for section '" + i.encode("utf-8") + "'"
            #     sys.exit(1)

    def parse_config_file(self, deploy=False, no_default_config=False, update_sets=False, allow=False, drop_all=False,
                          generate_files=False, check_matches=False):
        """
        This method is used to parse  the config files. It checks if the hostname of the machine is defined in the list
        of hostnames that this configuration will be applied. Then it calls the 'iptables_manager' function from the
        iptables_manager script instructing which config files to load and provides all the other arguments.

        :return: Void
        """

        config_files_list = []

        hostname = os.uname()[1].split('.')[0]

        for sect in self.sections:
            try:
                machines = eval(self.parser.get(sect, "machines").encode('utf-8'))
                if type(machines) is str:
                    machines = machines.split()
                    machines, err, exit_code = FirewallRuleBuilder.sys_process_executor(machines)
                    if exit_code == 0:
                        machines = machines.splitlines()
                        machines = [x for x in machines if x != '-']
            except configparser.NoOptionError:
                print "'machines' option for section '" + sect + "' must be a list or a sciprt to run"
                sys.exit(1)

            # if update_sets and not no_default_config:
            #     print "Cannot apply default config and update sets!!!!!!"
            #     sys.exit(1)
            if update_sets:
                no_default_config = True

            if hostname in machines:
                print "\n####### SECTION matched: '" + sect + "' ################"

                try:
                    default_interface = self.parser.get(sect.encode('utf-8'), "default_interface").encode('utf-8')
                except configparser.NoOptionError:
                    default_interface = 'main'

                try:
                    config_folder = self.parser.get(sect.encode('utf-8'), "config_folder").encode('utf-8')
                except configparser.NoOptionError:
                    config_folder = None

                try:
                    config_folder_files = eval(self.parser.get(sect.encode('utf-8'), "config_folder_files").encode('utf-8'))
                except TypeError:
                    print "'config_folder_files' option for section '" + sect + "' must be a list"
                    sys.exit(1)
                except configparser.NoOptionError:
                    config_folder_files = None

                try:
                    config_files = eval(self.parser.get(sect.encode('utf-8'), "config_files").encode('utf-8'))
                except TypeError:
                    print "'config_folder_files' option for section '" + sect + "' must be a list"
                    sys.exit(1)
                except configparser.NoOptionError:
                    config_files = None

                if config_folder_files is not None and config_folder is not None:
                    if os.path.exists(config_folder):
                        if config_folder[-1] != '/':
                            config_folder += '/'
                        for cfile in config_folder_files:
                            if os.path.exists(config_folder + cfile):
                                config_files_list.append(config_folder + cfile)
                            else:
                                print "File: '" + cfile + "' under folder '" + config_folder + "' of section '" + sect \
                                      + "' does not exits"
                                sys.exit(1)
                    else:
                        print "Folder: '" + config_folder + "' of section '" + sect + "' does not exits"
                        sys.exit(1)

                if config_files is not None:
                    for co_file in config_files:
                        if os.path.exists(co_file):
                            config_files_list.extend(co_file)
                        else:
                            print "File: '" + config_files + "' under folder '" + config_folder + "' of section " + sect \
                                  + " does not exits"

                # print "Config file list: ", config_files_list
                if config_files_list is []:
                    config_files_list = None
                if check_matches:
                    print "Config folder: ", config_folder
                    print "Config files: ", config_folder_files
                    print "Config individual files: ", config_files, "\n"
                else:
                    print "Deploy is:", deploy
                    iptables_manager(None, config_files_list, default_interface, no_default_config, allow, drop_all,
                                     update_sets, deploy, generate_files)
                    sys.exit(0)
            else:
                print "Machine list: ", machines
                print "Machine " + hostname + " not in this sections machine list. \nNothing to do.."

        print "\nNo matching sections"
        sys.exit(1)


###########################################################################################################

def check_machines_functions():
    """
    This function is used to perform health checks before the tool starts

    :return: Boolean
    """

    valid_dns = False
    valid_landb = False
    project_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    dns_ipv4 = {'ip-dns-1': '137.138.16.5',
                'ip-dns-2': '137.138.17.5',
                'ip-dns-3': '172.18.16.5',
                'ip-dns-4': '172.18.17.5'}

    dns_ipv6 = {'ip-dns-1.ipv6': '2001:1458:201:1000::5',
                'ip-dns-2.ipv6': '2001:1458:201:1100::5'}

    for key in dns_ipv4:
        value = ip_dns_resolver(key, 'ipv4')
        if value[1] == dns_ipv4[key]:
            valid_dns = True
            break

    if not valid_dns:
        for key in dns_ipv6:
            value = ip_dns_resolver(key, 'ipv6')
            if value[1] == dns_ipv4[key]:
                valid_dns = True
                break

    try:
        for line in open(project_folder + '/default_conf_files' + '/configuration_info.cfg', 'r').readlines():
            if 'landb_set_check' in line:
                check_landb_set = line.partition('"')[-1].rpartition('"')[0]
                # print check_landb_set
                break

        for line in open(project_folder + '/default_conf_files' + '/configuration_info.cfg', 'r').readlines():
            if 'landb_set_values' in line:
                check_landb_value = line.partition('"')[-1].rpartition('"')[0]
                # print check_landb_value
                break
    except:
        print "Cannot read config file!!! Cannot read config file!!! \nPath: " + project_folder + \
              '/default_conf_files' + '/configuration_info.cfg'
        sys.exit(1)

    check_value = netgroup_set_extractor('ip', check_landb_set, None, None, False, False)

    if check_value[0][0] == check_landb_value:
        valid_landb = True

    project_folder = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    command = None

    try:
        for line in open(project_folder + '/default_conf_files' + '/configuration_info.cfg', 'r').readlines():
            if "custom_check" in line:
                command = line.partition('"')[-1].rpartition('"')[0]
                break
    except:
        print "Cannot read config file!!! Cannot read config file!!! \nPath: " + project_folder + \
              '/default_conf_files' + '/configuration_info.cfg' + " \n"

    print "Command:", command

    if (command is not None) and command != "":
        command = command.split()
        output, err, exit_code = FirewallRuleBuilder.sys_process_executor(command)
        print "\n############## Check script output ###############################\n"
        print output
        if exit_code == 0:
            script_valid = True
        else:
            print "Error:", err
            script_valid = False
    else:
        script_valid = True

    return valid_dns and valid_landb and script_valid


###########################################################################################################

def main():
    """
    Main function use to expose all the parameters to the command line and call parse_config_file function.

    :return: void
    """

    parser = argparse.ArgumentParser()

    parser.add_argument('--no_default_config', action='store_true', help='Default configuration')
    parser.add_argument('--update_sets', action='store_true', help='Only update IPSets')
    parser.add_argument('--config', nargs='+', help='Type the location of your config file to parse(absolut path)')
    parser.add_argument('--deploy', action='store_true', help='Deploy the configuration')
    parser.add_argument('--generate_files', action='store_true', help='Generate iptables and ipset configuration files')
    parser.add_argument('--allow', action='store_true', help='Set policy to ACCEPT')
    parser.add_argument('--drop_all', action='store_true', help='Set policy to DENY')
    parser.add_argument('--ignore_check', action='store_true', help='Ignore needed network components check')
    parser.add_argument('--check_matches', action='store_true', help='Check all section of the file and print at which '
                                                                     'sections is this machine matching')

    args = parser.parse_args()

    if args.ignore_check or args.check_matches:
        valid = True
        print "\nIgnoring DNS and LanDB check result.\n"
    else:
        valid = check_machines_functions()

    if valid:
        if args.config:
            try:
                file_reader = ReadWriteConfigFiles()
                file_parser = file_reader.read_config_file(args.config)
                # print file_parser.sections()
            except RuntimeError:
                sys.stderr.write("Error reading the files")
                print "Please check the files are under the provided path/s"
                sys.exit(1)

            host_manager = ManageHosts(file_parser)

            host_manager.config_integrity_check()

            host_manager.parse_config_file(deploy=args.deploy, no_default_config=args.no_default_config,
                                           update_sets=args.update_sets, allow=args.allow, drop_all=args.drop_all,
                                           generate_files=args.generate_files, check_matches=args.check_matches)
    else:
        print "Network components check failed. Cannot operate"

if __name__ == '__main__':
    main()
