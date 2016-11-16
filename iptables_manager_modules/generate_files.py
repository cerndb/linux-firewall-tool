
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
import subprocess


class IPTablesFileGenerator(object):
    """
    Here we generate iptables.gen and ip6tables.gen files to be used with the restore command.
    The class objects receives two lists for iptables and ip6tables and generates the files.
    """

    def __init__(self):
        """
        Does not take any parameters. Just add some initial stuff
        Empty list to used during the process of creating the final rule set to be put in the file.
        """
        self.iptables_custom_chains = []
        self.ip6tables_custom_chains = []
        self.iptables_rules = []
        self.ip6tables_rules = []

        # Setting the initial contents of the final lists. The 3 default chains
        self.iptables_rules_final = [['*filter'], [':INPUT', 'ACCEPT', '[0:0]'], [':FORWARD', 'ACCEPT', '[0:0]'],
                                     [':OUTPUT', 'ACCEPT', '[0:0]']]
        self.ip6tables_rules_final = [['*filter'], [':INPUT', 'ACCEPT', '[0:0]'], [':FORWARD', 'ACCEPT', '[0:0]'],
                                      [':OUTPUT', 'ACCEPT', '[0:0]']]

    @staticmethod
    def get_current_rules():
        """
        This method copies the current iptables and ip6tables configuration that is in memory and write it to files
        with '.orig' extension.

        :return: None
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
        # Calls the iptables-save command and redirects the exit on the file
        call = subprocess.Popen('/sbin/iptables-save > ' + file_path + '/iptables.orig', shell=True,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        exit_code = call.wait()
        if exit_code != 0:
            print err
            print "Cannot get iptables configuration!!!!!"
            sys.exit(1)
        else:
            print response
        # Calls the ip6tables-save command and redirects the exit on the file
        call = subprocess.Popen('/sbin/ip6tables-save > ' + file_path + '/ip6tables.orig', shell=True,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        exit_code = call.wait()
        if exit_code != 0:
            print err
            print "Cannot get ip6tables configuration!!!!!"
            sys.exit(1)
        else:
            print response

    def write_iptables_files(self, default_rules, user_rules):
        """
        This method receives 2 lists. By applying proper formatting on the lists it extracts the info to populate the
        'final' lists so to write their contents in the 'iptables.gen' and 'ip6tables.gen' generated rule files.

        :param default_rules: This list contains all the rules that will be applied on each machine
        :param user_rules: This list contains all the rules generated from the user that are defined in the provided
                           config files
        :return: None
        """

        self.get_current_rules()

        # Make default rules be in list format
        # Make each line of the default rule a new list for better manipulation of the contents
        for i in xrange(len(default_rules)):
            default_rules[i] = default_rules[i].split(' ')

        # Get default rules
        # Change '-C' (check if rule exists) to '-A' (add the rule) and put it in a rule only list
        for i in default_rules:
            if 'iptables' in i[0]:
                del i[0]
                if i[0] == '-C':
                    i[0] = '-A'
                self.iptables_rules.append(i)
            elif 'ip6tables' in i[0]:
                del i[0]
                if i[0] == '-C':
                    i[0] = '-A'
                self.ip6tables_rules.append(i)

        # Get user defined rules
        # Change '-C' (check if rule exists) to '-A' (add the rule) and put it in a rule only list
        # Replace [comment] with "comment" so the comments on the rules are inserted properly
        if user_rules is not None:
            for j in user_rules:
                for i in j:
                    if 'iptables' in i[0]:
                        del i[0]
                        if i[0] == '-C':
                            i[0] = '-A'
                        i[-1] = i[-1].replace('[', '"')
                        i[-1] = i[-1].replace(']', '"')
                        self.iptables_rules.append(i)
                    elif 'ip6tables' in i[0]:
                        del i[0]
                        if i[0] == '-C':
                            i[0] = '-A'
                        i[-1] = i[-1].replace('[', '"')
                        i[-1] = i[-1].replace(']', '"')
                        self.ip6tables_rules.append(i)

        # Handling chains for iptables
        # First apply the policy and if its set to DROP we change the default ACCEPT
        for i in self.iptables_rules:
            if i[0] == '-P':
                if (i[1] == 'INPUT') and (i[2] == 'DROP'):
                    self.iptables_rules_final[1][2] = 'DROP'
                elif (i[1] == 'FORWARD') and (i[2] == 'DROP'):
                    self.iptables_rules_final[2][2] = 'DROP'
                elif (i[1] == 'OUTPUT') and (i[2] == 'DROP'):
                    self.iptables_rules_final[3][2] = 'DROP'
            # Check for user defined chains so to create them
            elif i[0] == '-N':
                self.iptables_custom_chains.append([':' + i[1],  '-', '[0:0]'])

        # The custom chains are sorted by name so we will apply this order to rules also
        self.iptables_custom_chains.sort(key=lambda x: x[0])
        self.iptables_rules_final.extend(self.iptables_custom_chains)

        # Add all chains to a temp list removing ':' from the front so to add the rules in the order the chains appear
        # in this list (trying to imitate iptables ordering)
        chains_v4 = ['INPUT', 'FORWARD', 'OUTPUT']
        for ch in self.iptables_custom_chains:
            chains_v4.append(ch[0].strip(':'))

        for chain in chains_v4:
            for rule in self.iptables_rules:
                if len(rule) > 1:
                    if (rule[0] == '-A') and (rule[1] == chain):
                        # Exception on some rules that specify table. There is no point in this because all the rules
                        # belong to the *filter table we define in the begining of the file
                        for t in xrange(len(rule)):
                            if rule[t] == '-t':
                                del rule[t]
                                del rule[t]
                                break
                        self.iptables_rules_final.append(rule)
        self.iptables_rules_final.append(['COMMIT'])

        # Handling chains for ip6tables
        # First apply the policy and if its set to DROP we change the default ACCEPT
        for i in self.ip6tables_rules:
            if i[0] == '-P':
                if (i[1] == 'INPUT') and (i[2] == 'DROP'):
                    self.ip6tables_rules_final[1][2] = 'DROP'
                elif (i[1] == 'FORWARD') and (i[2] == 'DROP'):
                    self.ip6tables_rules_final[2][2] = 'DROP'
                elif (i[1] == 'OUTPUT') and (i[2] == 'DROP'):
                    self.ip6tables_rules_final[3][2] = 'DROP'
            # Check for user defined chains so to create them
            elif i[0] == '-N':
                self.ip6tables_custom_chains.append([':' + i[1],  '-', '[0:0]'])
        self.ip6tables_custom_chains.sort(key=lambda x: x[0])
        self.ip6tables_rules_final.extend(self.ip6tables_custom_chains)

        # Add all chains to a temp list removing ':' from the front so to add the rules in the order the chains appear
        # in this list (trying to imitate iptables ordering)
        chains_v6 = ['INPUT', 'FORWARD', 'OUTPUT']
        for ch in self.ip6tables_custom_chains:
            chains_v6.append(ch[0].strip(':'))

        for chain in chains_v6:
            for rule in self.ip6tables_rules:
                if len(rule) > 1:
                    if (rule[0] == '-A') and (rule[1] == chain):
                        # Exception on some rules that specify table. There is no point in this because all the rules
                        # belong to the *filter table we define in the begining of the file
                        for t in xrange(len(rule)):
                            if rule[t] == '-t':
                                del rule[t]
                                del rule[t]
                                break
                        self.ip6tables_rules_final.append(rule)
        self.ip6tables_rules_final.append(['COMMIT'])

        # Writing the iptables.gen files using the final list generated above
        try:
            file_path = "/var/tmp/firewall_files"
            with open(file_path + '/iptables.gen', 'w') as file_handler:
                file_handler.write("# Generated by iptables_manager.py")
                _rule_ = '\n'
                for rule in self.iptables_rules_final:
                    for ru in rule:
                        _rule_ += ru + ' '
                    file_handler.write(_rule_.rstrip())
                    _rule_ = '\n'
                file_handler.write("\n# Completed by iptables_manager.py")
            file_handler.close()
        except:
            print "Cannot write iptables configuration file!!!!!"
            sys.exit(1)

        # Writing the ip6tables.gen files using the final list generated above
        try:
            file_path = "/var/tmp/firewall_files"
            with open(file_path + '/ip6tables.gen', 'w') as file_handler:
                file_handler.write("# Generated by iptables_manager.py")
                _rule_ = '\n'
                for rule in self.ip6tables_rules_final:
                    for ru in rule:
                        _rule_ += ru + ' '
                    file_handler.write(_rule_.rstrip())
                    _rule_ = '\n'
                file_handler.write("\n# Completed by iptables_manager.py")
            file_handler.close()
        except:
            print "Cannot write ip6tables configuration file!!!!!"
            sys.exit(1)

