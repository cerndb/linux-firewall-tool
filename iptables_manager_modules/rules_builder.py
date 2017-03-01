
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

"""

import os
import subprocess
import sys
import copy

# import from outer folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bin.ipset_manager import ipset_manager
from bin.ipset_manager import save_current_ipset


class FirewallRuleBuilder(object):
    """
    Here we create the actual rules to be added to the final list.
    """

    @staticmethod
    def sys_process_executor(command):
        """
        This method is static and is used to run OS commands across the other files. It tries to run all commands using
        system path($PATH). If the command/script is not in $PATH it tries to find it in its local helpers/ folder.

        :param command: A list that represents an OS command
        :return: Response, Error, exit code from piping standard output and standard error
        """

        print 'Command: "', ' '.join(command), '"'
        call = subprocess.Popen(' '.join(command), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        exit_code = call.wait()
        if exit_code == 0:
            return response, err, exit_code
        elif (exit_code != 0) and (('ipset' in command[0]) or ('iptables' in command[0])):
            return response, err, exit_code

        print 'Command: "', ' '.join(command), '" not in system path'
        command_new = copy.copy(command)
        script = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + '/helpers/' + command_new[0]
        command_new[0] = script
        print 'Trying helpers:"', ' '.join(command_new) + ' "'
        call = subprocess.Popen(' '.join(command_new), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        exit_code = call.wait()
        if exit_code == 0:
            return response, err, exit_code
        elif (exit_code != 0) and (('ipset' in command_new[0]) or ('iptables' in command_new[0])):
            return response, err, exit_code  # Not needed. Added  just in case

        print '\nError on running command: "', ' '.join(command), '"'
        print "Provide absolute path or place your script in helpers directory"
        print ''
        del command_new
        sys.exit(1)

    @staticmethod
    def read_config_file(parameter):
        """
        This method is static and is used to read the 'configuration_info.cfg' file that provides the paths of the OS
        commands we use to create the rules. If the file is not present the method tries to "guess" distro version so to
        run the appropriate command

        :param parameter: Parameter you want to extract from the file e.g.(iptables_script)
        :return: The value of the provided parameter e.g.(/etc/init.d/iptables)
        """

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

            if parameter == 'iptables_command':
                if err:
                    print "Linux Distro Check FAILED!!"
                    sys.exit(1)
                if vers in ['release 6', 'release 7']:
                    return_parameter = "/sbin/iptables"

            elif parameter == 'ip6tables_command':
                if err:
                    print "Linux Distro Check FAILED!!"
                    sys.exit(1)
                if vers in ['release 6', 'release 7']:
                    return_parameter = "/sbin/ip6tables"

            elif parameter == 'iptables_script':
                if err:
                    print "Linux Distro Check FAILED!!"
                    sys.exit(1)
                if 'release 7' in vers:
                    return_parameter = "/usr/libexec/iptables/iptables.init"
                elif 'release 6' in vers:
                    return_parameter = "/etc/init.d/iptables"

            elif parameter == 'ip6tables_script':
                if err:
                    print "Linux Distro Check FAILED!!"
                    sys.exit(1)
                if 'release 7' in vers:
                    return_parameter = "/usr/libexec/iptables/ip6tables.init"
                elif 'release 6' in vers:
                    return_parameter = "/etc/init.d/ip6tables"

            elif parameter == 'ipset_command':
                if err:
                    print "Linux Distro Check FAILED!!"
                    sys.exit(1)
                if 'release 7' in vers:
                    return_parameter = "/sbin/ipset"

                elif 'release 6' in vers:
                    return_parameter = "/usr/sbin/ipset"

        return return_parameter


######################################################################################################
    def check_ipset(self, iptype, ipset_name):
        """
        This method checks if an ipset is present in memory

        :param iptype: ipv4 or ipv6
        :param ipset_name: name of the ipset we want to check
        :return: Message with the state of the check
        """

        ipset_command = self.read_config_file('ipset_command')

        ipset_name = ipset_name.replace(' ', '_')

        if iptype == "ipv4":
            ipset_name += "_v4"
        elif iptype == "ipv6":
            ipset_name += "_v6"

        command = [ipset_command, 'list', ipset_name]
        response, err, exit_code = self.sys_process_executor(command)

        if exit_code != 0:
            if (response == '') and ("The set with the given name does not exist" in err):
                return "SetDoNotExist"
            elif response.find('31') == -1:
                print response.find('31')
                print 'Setname ' + ipset_name + ' is longer than 31 characters'
                sys.exit(1)
            else:
                return "IpsetCheckERROR"
        else:
            return "SetExists"


######################################################################################################
    @staticmethod
    def manage_ipset(action=None, iptype=None, settype=None, port=None, setname=None, cern_networks=None,
                     hostnames=None, ips=None, cern_set_list=None, simul=False, generate_files=False,
                     file_override=False, set_names=None):
        """
        This method calls the scripts that manages all the operations regarding ipsets and pass all the arguments to
        other script in order to create/update/destroy an ipset.

        :param action: create or update or destroy
        :param iptype: ipv4 or ipv6
        :param settype: (e.g. hash:ip)
        :param port: port number or
                    'direct' --> mostly used. Direct tell to the script that the ports are provided in the ips,hostnames
        :param setname: the custom name that the set will take
        :param cern_networks:  Name of the CERN LanDB set
        :param hostnames: list of hostnames to be resolved via DNS
        :param ips: list of ips to be added into the ipset
        :param cern_set_list: list of names with CERN LanDB network sets
        :param simul: flag whether to print or apply the actions
        :param generate_files: flag to generate the ipset.gen file to be user by the restore command
        :param file_override: flag used to tell the script to override the generated file or not
        :param set_names: list of names to be added inside a list:set ipset
        :return: the response of the ipset_a
        """
        # print action, iptype, settype, port, setname, cern_networks, hostnames, ips
        # print "Hostnames: ", hostnames
        resp = ipset_manager(None, action, iptype, settype, port, setname, cern_networks, cern_set_list, hostnames, ips,
                             simul, generate_files, file_override, set_names)
        # print "MANAGE IPSet resp: ", resp
        return resp

######################################################################################################
    @staticmethod
    def save_ipset(simulate):
        save_current_ipset(simulate)

######################################################################################################
    def manage_custom_chain(self, action, chain_name, iptype, new_chain_name=None, simul=False):
        """
        This method is managing user defined chains. Create, Delete, Rename

        :param action: create, delete, rename
        :param chain_name: name of the chain
        :param iptype: ipv4 or ipv6 (iptables or ip6tables)
        :param new_chain_name: name of the chain in case you rename
        :param simul: flag to print the commands instead of applying
        :return: exit code and the actual command if simulate flag is True
        """

        if iptype == 'ipv4':
            iptables_command = self.read_config_file('iptables_command')
        elif iptype == 'ipv6':
            iptables_command = self.read_config_file('ip6tables_command')

        if action == 'create':

            command = [iptables_command, '-N', chain_name]
            if simul:
                print command[0], command[1], command[2]
                exit_code = 0
            else:
                response, err, exit_code = self.sys_process_executor(command)

            if exit_code != 0:
                if (response == '') and ("iptables: Chain already exists" in err):
                    print "Chain: " + chain_name + " already exists"
                else:
                    print iptables_command + "|ERROR"
            else:
                print "Chain: " + chain_name + " created"

        elif action == 'delete':

            command = [iptables_command, '-X', chain_name]
            if not simul:
                response, err, exit_code = self.sys_process_executor(command)
            else:
                print command[0], command[1], command[2]
                exit_code = 0

            if exit_code != 0:
                if (response == '') and ("iptables: No chain/target/match by that name" in err):
                    print "Chain: " + chain_name + " does not exist"
                else:
                    print iptables_command + "|ERROR"
            else:
                print "Chain: " + chain_name + " deleted"

        elif action == 'rename':

            command = [iptables_command, '-E', chain_name, new_chain_name]
            if not simul:
                response, err, exit_code = self.sys_process_executor(command)
            else:
                print command[0], command[1], command[2], command[3]
                exit_code = 0

            if exit_code == 1:
                if (response == '') and ("iptables: File exists" in err):
                    print "Chain: " + chain_name + " possibly do not exist"
                else:
                    print iptables_command + "|ERROR"

            elif exit_code == 2:
                print iptables_command + "|USAGE|ERROR"

            elif exit_code == 0:
                print "Chain: " + chain_name + " renamed to " + new_chain_name

            if not simul:
                command = None
        return exit_code, command


######################################################################################################
    @staticmethod
    def module_load_handler(command_list, module_list):
        """
        This is a static method and is used to add all the parameters to each rule extracting them from module_list

        :param command_list: list that represents one command
        :param module_list: list of modules to be added to the command(rule)
        :return: the full command(rule/list) to be added to the rules list
        """

        if 'state' in module_list:
            if module_list['state'].find('NEW') or module_list['state'].find('ESTABLISHED') or module_list['state'].find('RELATED'):
                command_list.append('-m')
                command_list.append('state')
                command_list.append('--state')
                command_list.append(module_list['state'])

        if 'conntrack' in module_list:
            if module_list['conntrack'].find('NEW') or module_list['conntrack'].find('ESTABLISHED') or module_list['conntrack'].find('RELATED'):
                command_list.append('-m')
                command_list.append('conntrack')
                command_list.append('--ctstate')
                command_list.append(module_list['conntrack'])

        if 'limit' in module_list:
            command_list.append('-m')
            command_list.append('limit')
            command_list.append('--limit')
            if type(module_list['limit']) is list:
                for opts in xrange(len(module_list['limit'])):
                    if 'limit-burst' in module_list['limit'][opts]:
                        command_list.append('--limit-burst')
                    else:
                        command_list.append(module_list['limit'][opts])
            else:
                command_list.append(module_list['limit'])

        # if 'length' in module_list:
        #     command_list.append('-m')
        #     command_list.append('length')
        #     command_list.append('--length')
        #     command_list.append(module_list['length'])

        if 'tcp' in module_list:
            command_list.append('-m')
            command_list.append('tcp')
            if type(module_list['tcp']) is list:
                for mod_opt in xrange(len(module_list['tcp'])):
                    if module_list['tcp'][mod_opt][0] == 'sport':
                        command_list.append('--sport')
                        command_list.append(module_list['tcp'][mod_opt][1])
                    elif module_list['tcp'][mod_opt][0] == 'dport':
                        command_list.append('--dport')
                        command_list.append(module_list['tcp'][mod_opt][1])
            else:
                command_list.append(module_list['tcp'])

        if 'udp' in module_list:
            command_list.append('-m')
            command_list.append('udp')
            if type(module_list['udp']) is list:
                for mod_opt in xrange(len(module_list['udp'])):
                    if module_list['udp'][mod_opt][0] == 'sport':
                        command_list.append('--sport')
                        command_list.append(module_list['udp'][mod_opt][1])
                    elif module_list['udp'][mod_opt][0] == 'dport':
                        command_list.append('--dport')
                        command_list.append(module_list['udp'][mod_opt][1])
            else:
                command_list.append(module_list['udp'])

        if 'multiport' in module_list:
            if type(module_list['multiport']) is list:
                if module_list['multiport'][0] == 'sports':
                    command_list.append('-m')
                    command_list.append('multiport')
                    command_list.append('--sports')
                    command_list.append(module_list['multiport'][1])
                elif module_list['multiport'][0] == 'dports':
                    command_list.append('-m')
                    command_list.append('multiport')
                    command_list.append('--dports')
                    command_list.append(module_list['multiport'][1])
            else:
                print "Bad usage of multiport module"
                sys.exit(1)

        if 'set' in module_list:
            if type(module_list['set']) is list:
                # print "Inside set section"
                # for mod_opt in xrange(len(module_list['set'])):
                command_list.append('-m')
                command_list.append('set')
                command_list.append('--match-set')
                command_list.append(module_list['set'][0])
                command_list.append(module_list['set'][1])
            else:
                print sys.stderr.write("USAGE|ERROR")
                print "Sets modules options: " + module_list['set']
                sys.exit(1)


######################################################################################################
    @staticmethod
    def handle_log_chain(command_list, jump_chain):
        """
        This is a static method and is used to handle the LOG chain. It adds parameters to a rule(list) this jumps to
        the LOG chain

        :param command_list: list that represents one command
        :param jump_chain: extra parameter to add the rule(list)
        :return: the created rule(list) to be added to the rule list
        """
        for i in xrange(len(jump_chain)):
            if 'log-' in jump_chain[i]:
                temp = '--' + jump_chain[i]
                command_list.append(temp)
            else:
                command_list.append(jump_chain[i])


######################################################################################################
    def manage_rule(self, iptype, chain_name, jump_chain, comment, protocol=None, nic=None, modules=None):
        """
        This method is used to create an iptables rule.

        :param iptype: ipv4 or ipv6
        :param chain_name: the chain that this rule will be added to
        :param jump_chain: the chain that this rule will jump to
        :param comment: comment on the rule
        :param protocol: protocol of the rule
        :param nic: network interface that the rule will be applied on
        :param modules: the modules to be added on the rule
        :return: a fully created rule
        """

        command_list = []

        if iptype == 'ipv4':
            iptables_command = self.read_config_file('iptables_command')
        elif iptype == 'ipv6':
            iptables_command = self.read_config_file('ip6tables_command')

        else:
            print "Wrong usage of method manage_rule"
            sys.exit(1)

        command_list.append(iptables_command)
        command_list.append('-C')
        command_list.append(chain_name)

        if nic is not None:
            if chain_name == 'INPUT':
                command_list.append('-i')
                command_list.append(nic)
            elif chain_name == 'OUTPUT':
                command_list.append('-o')
                command_list.append(nic)

        if protocol is not None:
            if protocol in ['tcp', 'udp']:
                command_list.append('-p')
                command_list.append(protocol)
            else:
                print "Wrong protocol " + protocol
                sys.exit(1)

        if modules is not None:
            self.module_load_handler(command_list, modules)
        command_list.append('-j')

        if (type(jump_chain) is list) and ('LOG' in jump_chain[0]):
            command_list.append(jump_chain[0])
            del jump_chain[0]
            self.handle_log_chain(command_list, jump_chain)

        elif type(jump_chain) is not list:
            command_list.append(jump_chain)

        command_list.append('-m')
        command_list.append('comment')
        command_list.append('--comment')
        command_list.append("[" + comment + "]")

        return command_list
