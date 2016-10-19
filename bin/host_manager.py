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
"""

import os
import sys
import argparse
import configparser
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from iptables_manager import iptables_manager
from iptables_manager_modules.rules_builder import FirewallRuleBuilder


class ReadWriteConfigFiles(object):
    """
    Class that reads the config files using python config parser module. It then creates an object(dict)
    and adds all the sections of the file as key and its options as value
    """

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

    def parse_config_file(self, deploy=False, no_default_config=False, update_sets=False, allow=False, drop_all=False,
                          generate_files=False):
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

            if update_sets:
                no_default_config = True

            if hostname in machines:
                print "####### SECTION matched: '" + sect + "' ################"

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
                            if os.path.exists(config_folder+cfile):
                                config_files_list.append(config_folder+cfile)
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

                if config_files_list is []:
                    config_files_list = None

                print "Deploy is:", deploy
                iptables_manager(None, config_files_list, default_interface, no_default_config, allow, drop_all,
                                 update_sets, deploy, generate_files)
                sys.exit(0)
            else:
                print "Machine list: ", machines
                print "Machine " + hostname + " not in this sections machine list. \nNothing to do.."


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

    args = parser.parse_args()

    if args.config:
        try:
            file_reader = ReadWriteConfigFiles()
            file_parser = file_reader.read_config_file(args.config)
        except RuntimeError:
            sys.stderr.write("Error reading the files")
            print "Please check the files are under the provided path/s"
            sys.exit(1)

        host_manager = ManageHosts(file_parser)

        host_manager.config_integrity_check()

        host_manager.parse_config_file(deploy=args.deploy, no_default_config=args.no_default_config,
                                       update_sets=args.update_sets, allow=args.allow, drop_all=args.drop_all,
                                       generate_files=args.generate_files)
    else:
        print "Please specify config file/s"
        sys.exit(1)

if __name__ == '__main__':
    main()
