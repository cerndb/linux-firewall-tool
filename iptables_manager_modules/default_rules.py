
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
import subprocess
import sys

# import from outer folder
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from bin.main_nic_extractor import main_nic_extractor


class DefaultConfiguration(object):
    """
    Here is defined the default configuration that is gonna be applied on all the machines, if there no other additional
    configuration to be added.
    """

    def __init__(self, mode, path, interface):
        self.action = mode
        self.path = path
        self.nic = interface

    @staticmethod
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

    @staticmethod
    def check_state(response, err, exit_code):
        if exit_code != 0:
            print response
            print err
            sys.exit(1)

    def iptables_save(self, iptables_version):

        iptables_script = self.read_config_file('iptables_script')
        ip6tables_script = self.read_config_file('ip6tables_script')

        if self.action == 'deploy':
            if 'iptables' in iptables_version:
                call = subprocess.Popen([iptables_script, 'save'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif 'ip6tables' in iptables_version:
                call = subprocess.Popen([ip6tables_script, 'save'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            print response
            self.check_state(response, err, exit_code)
        elif self.action == 'simulate':
            if 'iptables' in iptables_version:
                return [iptables_script + ' save']
            elif 'ip6tables' in iptables_version:
                return [ip6tables_script + ' save']

    def clean_iptables(self, iptables_version):

        if self.action == 'deploy':

            call = subprocess.Popen([iptables_version, '-P', 'INPUT', 'ACCEPT'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-P', 'FORWARD', 'ACCEPT'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-P', 'OUTPUT', 'ACCEPT'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-F'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-X'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -P INPUT ACCEPT',
                    iptables_version + ' -P FORWARD ACCEPT',
                    iptables_version + ' -P OUTPUT ACCEPT',
                    iptables_version + ' -F',
                    iptables_version + ' -X']

    def destroy_all_ipsets(self):

        ipset_command = self.read_config_file('ipset_command')

        call = subprocess.Popen([ipset_command, 'list', '-n'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        response, err = call.communicate()
        exit_code = call.wait()
        self.check_state(response, err, exit_code)
        sets = response.split('\n')
        del sets[-1]
        if self.action == 'deploy':
            for i in sets:
                call = subprocess.Popen([ipset_command, 'destroy', i], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                response_dst, err = call.communicate()
                exit_code = call.wait()
                # self.check_state(response_dst, err, exit_code)
        elif self.action == 'simulate':
            cm_list = []
            for i in sets:
                cm_list.append(ipset_command + ' destroy ' + i)
            return cm_list

    def drop_portscan(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-N', 'PORTSCAN_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'PORTSCAN_' + self.nic, '-m', 'limit', '--limit', '1/second', '-j',
                                     'LOG', '--log-level', 'info', '--log-prefix', '"IPTABLES_DROP-PSCAN-DP "',
                                     '--log-tcp-sequence', '--log-tcp-options', '--log-ip-options'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'PORTSCAN_' + self.nic, '-j', 'DROP'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-flags', 'ALL',
                                     'FIN,URG,PSH', '-j', 'PORTSCAN_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-flags', 'SYN,FIN',
                                     'SYN,FIN', '-j', 'PORTSCAN_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-flags', 'ALL',
                                     'FIN', '-j', 'PORTSCAN_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-flags', 'ALL',
                                     'ALL', '-j', 'PORTSCAN_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-flags', 'ALL',
                                     'NONE', '-j', 'PORTSCAN_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-flags', 'ALL',
                                     'URG,ACK,PSH,RST,SYN,FIN', '-j', 'PORTSCAN_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -N PORTSCAN_' + self.nic,
                    iptables_version + ' -A PORTSCAN_' + self.nic + ' -m limit --limit 1/second -j LOG --log-level info --log-prefix "IPTABLES_DROP-PSCAN-DP " --log-tcp-sequence --log-tcp-options --log-ip-options',
                    iptables_version + ' -A PORTSCAN_' + self.nic + ' -j DROP',
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-flags ALL FIN,URG,PSH -j PORTSCAN_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-flags SYN,FIN SYN,FIN -j PORTSCAN_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-flags ALL FIN -j PORTSCAN_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-flags ALL ALL -j PORTSCAN_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-flags ALL NONE -j PORTSCAN_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-flags ALL URG,ACK,PSH,RST,SYN,FIN -j PORTSCAN_' + self.nic]

    def drop_bad_tcp_flags(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-N', 'BAD_FLAGS_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'BAD_FLAGS_' + self.nic, '-m', 'limit', '--limit', '1/second', '-j',
                                     'LOG', '--log-level', 'info', '--log-prefix', '"IPTABLES_DROP-BAD_FLAGS-DP "',
                                     '--log-tcp-sequence', '--log-tcp-options', '--log-ip-options'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'BAD_FLAGS_' + self.nic, '-j', 'DROP'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-option', '64', '-j',
                                     'BAD_FLAGS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-option', '128', '-j',
                                     'BAD_FLAGS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -N BAD_FLAGS_' + self.nic,
                    iptables_version + ' -A BAD_FLAGS_' + self.nic + ' -m limit --limit 1/second -j LOG --log-level info --log-prefix "IPTABLES_DROP-BAD_FLAGS-DP " --log-tcp-sequence --log-tcp-options --log-ip-options',
                    iptables_version + ' -A BAD_FLAGS_' + self.nic + ' -j DROP',
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-option 64 -j BAD_FLAGS_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-option 128 -j BAD_FLAGS_' + self.nic]

    def drop_strange_size(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-N', 'SMALL_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'SMALL_' + self.nic, '-m', 'limit', '--limit', '1/second', '-j',
                                     'LOG', '--log-level', 'info', '--log-prefix', '"IPTABLES_DROP-SM-DP "',
                                     '--log-tcp-sequence', '--log-tcp-options', '--log-ip-options'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'SMALL_' + self.nic, '-j', 'DROP'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'udp', '-m', 'length', '--length',
                                     '0:27', '-j', 'SMALL_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '-m', 'length', '--length',
                                     '0:39', '-j', 'SMALL_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'icmp', '-m', 'length', '--length',
                                     '0:27', '-j', 'SMALL_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', '30', '-m', 'length', '--length',
                                     '0:31', '-j', 'SMALL_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', '47', '-m', 'length', '--length',
                                     '0:39', '-j', 'SMALL_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', '50', '-m', 'length', '--length',
                                     '0:49', '-j', 'SMALL_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', '51', '-m', 'length', '--length',
                                     '0:35', '-j', 'SMALL_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-m', 'length', '--length',
                                     '0:19', '-j', 'SMALL_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -N SMALL_' + self.nic,
                    iptables_version + ' -A SMALL_' + self.nic + '-m limit --limit 1/second -j LOG --log-level info --log-prefix "PTABLES_DROP-SM-DP " --log-tcp-sequence --log-tcp-options --log-ip-options',
                    iptables_version + ' -A SMALL_' + self.nic + '-j DROP',
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p udp -m length --length 0:27 -j SMALL_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp -m length --length 0:39 -j SMALL_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p icmp -m length --length 0:27 -j SMALL_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p 30 -m length --length 0:31 -j SMALL_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p 47 -m length --length 0:39 -j SMALL_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p 50 -m length --length 0:49 -j SMALL_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p 51 -m length --length 0:35 -j SMALL_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -m length --length 0:19 -j SMALL_' + self.nic]

    def drop_invalid(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-N', 'BOGUS_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'BOGUS_' + self.nic, '-m', 'limit', '--limit', '1/second', '-j',
                                     'LOG', '--log-level', 'info', '--log-prefix', '"IPTABLES_DROP-BOS-DP "',
                                     '--log-tcp-sequence', '--log-tcp-options', '--log-ip-options'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'BOGUS_' + self.nic, '-j', 'DROP'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-t', 'filter', '-m', 'conntrack',
                                     '--ctstate', 'INVALID', '-j', 'BOGUS_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'OUTPUT', '-o', self.nic, '-t', 'filter', '-m', 'conntrack',
                                     '--ctstate', 'INVALID', '-j', 'BOGUS_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -N BOGUS_' + self.nic,
                    iptables_version + ' -A BOGUS_' + self.nic + ' -m limit --limit 1/second -j LOG --log-level info --log-prefix "IPTABLES_DROP-BOS-DP " --log-tcp-sequence --log-tcp-options --log-ip-options',
                    iptables_version + ' -A BOGUS_' + self.nic + ' -j DROP',
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -t filter -m conntrack --ctstate INVALID -j BOGUS_' + self.nic,
                    iptables_version + ' -A OUTPUT -o ' + self.nic + ' -t filter -m conntrack --ctstate INVALID -j BOGUS_' + self.nic]

    def drop_unassembled(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-N', 'NOFRAGS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'NOFRAGS_' + self.nic, '-m', 'limit', '--limit', '1/second', '-j', 'LOG', '--log-level', 'info', '--log-prefix', '"IPTABLES_DROP-NOFRAG-DP "',
                                     '--log-tcp-sequence', '--log-tcp-options', '--log-ip-options'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'NOFRAGS_' + self.nic, '-j', 'DROP'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'ip', '-f', '-j', 'NOFRAGS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'OUTPUT', '-o', self.nic, '-p', 'ip', '-f', '-j', 'NOFRAGS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -N NOFRAGS_' + self.nic,
                    iptables_version + ' -A NOFRAGS_' + self.nic + '-m limit --limit 1/second -j LOG --log-level info --log-prefix "IPTABLES_DROP-NOFRAG-DP " --log-tcp-sequence --log-tcp-options --log-ip-options',
                    iptables_version + ' -A NOFRAGS_' + self.nic + '-j DROP',
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p ip -f -j NOFRAGS_' + self.nic,
                    iptables_version + ' -A OUTPUT -o ' + self.nic + ' -p ip -f -j NOFRAGS_' + self.nic]

    def syn_flood(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-N', 'SYN-FLOOD_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'SYN-FLOOD_' + self.nic, '-m', 'limit', '--limit',
                                     '75/second', '--limit-burst', '100', '-j', 'RETURN'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'SYN-FLOOD_' + self.nic, '-m', 'limit', '--limit',
                                     '1/second', '-j', 'LOG', '--log-level', 'info', '--log-prefix',
                                     '"IPTABLES_DROP-SYN-FL-DP "', '--log-tcp-sequence', '--log-tcp-options',
                                     '--log-ip-options'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'SYN-FLOOD_' + self.nic, '-j', 'DROP'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--tcp-flags',
                                     'SYN,ACK,FIN,RST RST', '-j', 'SYN-FLOOD_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -N SYN-FLOOD_' + self.nic,
                    iptables_version + ' -A SYN-FLOOD_' + self.nic + ' -m limit --limit 75/second --limit-burst 100 ' \
                                                                   ' -j RETURN',
                    iptables_version + ' -A SYN-FLOOD_' + self.nic + ' -m limit --limit 1/second -j LOG --log-level info ' \
                                                                   '--log-prefix "IPTABLES_DROP-SYN-FL-DP " ' \
                                                                   '--log-tcp-sequence --log-tcp-options ' \
                                                                   '--log-ip-options',
                    iptables_version + ' -A SYN-FLOOD_' + self.nic + ' -j DROP',
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --tcp-flags SYN,ACK,FIN,RST RST -j SYN-FLOOD_' + self.nic]

    def odd_ports(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-N', 'ODDPORTS_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'ODDPORTS_' + self.nic, '-m', 'limit', '--limit', '1/second', '-j',
                                     'LOG', '--log-level', 'info', '--log-prefix', '"IPTABLES_DROP-ODDPORT-DP "',
                                     '--log-tcp-sequence', '--log-tcp-options', '--log-ip-options'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'ODDPORTS_' + self.nic, '-j', 'DROP'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'udp', '--sport', '2:21',
                                     '-j', 'ODDPORTS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'udp', '--dport', '2:21',
                                     '-j', 'ODDPORTS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'udp', '--sport', '0',
                                     '-j', 'ODDPORTS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'udp', '--dport', '0',
                                     '-j', 'ODDPORTS_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -N ODDPORTS_' + self.nic,
                    iptables_version + ' -A ODDPORTS_' + self.nic + ' -m limit --limit 1/second -j LOG --log-level info ' \
                                                                  '--log-prefix "IPTABLES_DROP-ODDPORT-DP " ' \
                                                                  '--log-tcp-sequence --log-tcp-options ' \
                                                                  '--log-ip-options',
                    iptables_version + ' -A ODDPORTS_' + self.nic + '-j DROP',
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p udp --sport 2:21 -j ODDPORTS_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p udp --dport 2:21 -j ODDPORTS_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p udp --sport 0 -j ODDPORTS_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p udp --dport 0 -j ODDPORTS_' + self.nic]

    def silently_drops(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-N', 'SILENT_' + self.nic],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'SILENT_' + self.nic, '-j', 'DROP'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--dport', '139',
                                     '-j', 'SILENT_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--sport', '137', '--dport',
                                     '137', '-j', 'SILENT_' + self.nic], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -N SILENT_' + self.nic,
                    iptables_version + ' -A SILENT_' + self.nic + ' -j DROP',
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --dport 139 -j SILENT_' + self.nic,
                    iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --sport 137 --dport 137 -j SILENT_' + self.nic]

    def new_not_syn(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '!', '--syn', '-m',
                                     'conntrack', '--ctstate', 'NEW', '-j', 'LOG', '--log-prefix',
                                     '"IPTABLES_DROP-New_not_syn: "'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '!', '--syn', '-m',
                                     'conntrack', '--ctstate', 'NEW', '-j', 'DROP'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp ! --syn -m conntrack --ctstate NEW -j ' \
                                                                 'LOG --log-prefix "IPTABLES_DROP-New_not_syn: "'

    def tcp_reset(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'tcp', '--dport', '113',
                                     '-j', 'REJECT', '--reject-with', 'tcp-reset'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return iptables_version + ' -A INPUT -i ' + self.nic + ' -p tcp --dport 113 -j REJECT --reject-with tcp-reset'

    def allow_icmp(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            if 'iptables' in iptables_version:
                call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'icmp', '-j', 'ACCEPT'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif 'ip6tables' in iptables_version:
                call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-p', 'ipv6-icmp', '-j', 'ACCEPT'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            if 'iptables' in iptables_version:
                call = subprocess.Popen([iptables_version, '-A', 'OUTPUT', '-o', self.nic, '-p', 'icmp', '-j', 'ACCEPT'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif 'ip6tables' in iptables_version:
                call = subprocess.Popen([iptables_version, '-A', 'OUTPUT', '-o', self.nic, '-p', 'ipv6-icmp', '-j', 'ACCEPT'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            if 'iptables' in iptables_version:
                return [iptables_version + ' -A INPUT -i ' + self.nic + ' -p icmp -j ACCEPT',
                        iptables_version + ' -A OUTPUT -o ' + self.nic + ' -p icmp -j ACCEPT']
            elif 'ip6tables' in iptables_version:
                return [iptables_version + ' -A INPUT -i ' + self.nic + ' -p ipv6-icmp -j ACCEPT',
                        iptables_version + ' -A OUTPUT -o ' + self.nic + ' -p ipv6-icmp -j ACCEPT']

    def allow_localhost(self, iptables_version):
        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'OUTPUT', '-o', 'lo', '-j', 'ACCEPT'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -A INPUT -i lo -j ACCEPT',
                    iptables_version + ' -A OUTPUT -o lo -j ACCEPT']

    def allow_dhcp(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            if 'iptables' in iptables_version:
                call = subprocess.Popen([iptables_version, '-A', 'OUTPUT', '-o', self.nic, '-p', 'udp',
                                         '--sport', '67:68', '--dport', '67:68', '-j', 'ACCEPT'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif 'ip6tables' in iptables_version:
                call = subprocess.Popen([iptables_version, '-A', 'OUTPUT', '-o', self.nic, '-p', 'udp',
                                         '--sport', '546', '--dport', '547', '-j', 'ACCEPT'],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                call2 = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-s', 'fe80::/10', '-d',
                                          'fe80::/10', '-p', 'udp', '-m', 'multiport', '--sports', '547', '-m',
                                          'multiport', '--dports', '546', '-m', 'state', '--state', 'NEW', '-j', 'ACCEPT'],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                response2, err2 = call2.communicate()
                exit_code2 = call2.wait()
                self.check_state(response2, err2, exit_code2)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            if 'iptables' in iptables_version:
                return iptables_version + ' -A OUTPUT -o ' + self.nic + ' -p udp --dport 67:68 --sport 67:68 -j ACCEPT'
            elif 'ip6tables' in iptables_version:
                return [iptables_version + ' -A OUTPUT -o ' + self.nic + ' -p udp --sport 546 --dport 547 -j ACCEPT',
                        iptables_version + ' -A INPUT -i ' + self.nic + ' -s fe80::/10 -d fe80::/10 -p udp -m ' +
                                                                        'multiport --sports 547 -m multiport ' +
                                                                        '--dports 546 -m state --state NEW -j ACCEPT']

    def state_tracking(self, iptables_version):

        if self.nic == 'main':
            self.nic = main_nic_extractor()

        if self.action == 'deploy':
            call = subprocess.Popen([iptables_version, '-A', 'INPUT', '-i', self.nic, '-m', 'conntrack', '--ctstate',
                                     'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-A', 'OUTPUT', '-o', self.nic, '-m', 'conntrack', '--ctstate',
                                     'ESTABLISHED,RELATED', '-j', 'ACCEPT'],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -A INPUT -i ' + self.nic + ' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
                    iptables_version + ' -A OUTPUT -o ' + self.nic + ' -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT']

    def accept_iptables(self, iptables_version):

        if self.action == 'deploy':

            call = subprocess.Popen([iptables_version, '-P', 'INPUT', 'ACCEPT'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-P', 'FORWARD', 'ACCEPT'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-P', 'OUTPUT', 'ACCEPT'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -P INPUT ACCEPT',
                    iptables_version + ' -P FORWARD ACCEPT',
                    iptables_version + ' -P OUTPUT ACCEPT']

    def final_drop_iptables(self, iptables_version):

        if self.action == 'deploy':

            call = subprocess.Popen([iptables_version, '-P', 'INPUT', 'DROP'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-P', 'FORWARD', 'DROP'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

            call = subprocess.Popen([iptables_version, '-P', 'OUTPUT', 'DROP'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            response, err = call.communicate()
            exit_code = call.wait()
            self.check_state(response, err, exit_code)

        elif self.action == 'simulate':
            return [iptables_version + ' -P INPUT DROP',
                    iptables_version + ' -P FORWARD DROP',
                    iptables_version + ' -P OUTPUT DROP']

    def perform_action(self):
        """
        This method calls almost all the other methods to apply the default configuration on a machine.
        If the member 'self.action' is 'deploy' it creates and run all the rules specified above.
        If the member 'self.action' is 'simulate' it creates a list with all the rules that will be applied in case you
        make 'self.action' deploy
        :return: Void or list of rules to be applied
        """

        ipv4_command = self.read_config_file('iptables_command')
        ipv6_command = self.read_config_file('ip6tables_command')

        if self.action != 'simulate':
            # print self.read_cfg_files(self.path)
            # self.allow_admin_workstations(self.ipv4)
            self.drop_portscan(ipv4_command)
            self.drop_bad_tcp_flags(ipv4_command)
            self.drop_strange_size(ipv4_command)
            self.drop_invalid(ipv4_command)
            self.syn_flood(ipv4_command)
            self.odd_ports(ipv4_command)
            self.silently_drops(ipv4_command)
            self.new_not_syn(ipv4_command)
            self.tcp_reset(ipv4_command)
            self.allow_icmp(ipv4_command)
            self.allow_localhost(ipv4_command)
            self.allow_dhcp(ipv4_command)
            # self.allow_interfaces(self.ipv4)
            self.state_tracking(ipv4_command)
            self.iptables_save(ipv4_command)

            #########################

            # print self.read_cfg_files(self.path)
            # self.allow_admin_workstations(self.ipv6)
            self.drop_portscan(ipv6_command)
            self.drop_bad_tcp_flags(ipv6_command)
            self.drop_strange_size(ipv6_command)
            self.drop_invalid(ipv6_command)
            self.syn_flood(ipv6_command)
            self.odd_ports(ipv6_command)
            self.silently_drops(ipv6_command)
            self.new_not_syn(ipv6_command)
            self.tcp_reset(ipv6_command)
            self.allow_icmp(ipv6_command)
            self.allow_localhost(ipv6_command)
            self.allow_dhcp(ipv6_command)
            # self.allow_interfaces(ipv6_command)
            self.state_tracking(ipv6_command)
            self.iptables_save(ipv6_command)

        elif self.action == 'simulate':
            command_list = []
            command_list.extend(self.drop_portscan(ipv4_command))
            command_list.extend(self.drop_bad_tcp_flags(ipv4_command))
            command_list.extend(self.drop_strange_size(ipv4_command))
            command_list.extend(self.drop_invalid(ipv4_command))
            command_list.extend(self.syn_flood(ipv4_command))
            command_list.extend(self.odd_ports(ipv4_command))
            command_list.extend(self.silently_drops(ipv4_command))
            command_list.append(self.new_not_syn(ipv4_command))
            command_list.append(self.tcp_reset(ipv4_command))
            command_list.extend(self.allow_icmp(ipv4_command))
            command_list.extend(self.allow_localhost(ipv4_command))
            command_list.append(self.allow_dhcp(ipv4_command))
            # command_list.extend(self.allow_interfaces(ipv4_command))
            command_list.extend(self.state_tracking(ipv4_command))
            command_list.extend(self.iptables_save(ipv4_command))

            #########################

            # print self.read_cfg_files(self.path)
            # self.allow_admin_workstations(self.ipv6)
            command_list.extend(self.drop_portscan(ipv6_command))
            command_list.extend(self.drop_bad_tcp_flags(ipv6_command))
            command_list.extend(self.drop_strange_size(ipv6_command))
            command_list.extend(self.drop_invalid(ipv6_command))
            command_list.extend(self.syn_flood(ipv6_command))
            command_list.extend(self.odd_ports(ipv6_command))
            command_list.extend(self.silently_drops(ipv6_command))
            command_list.append(self.new_not_syn(ipv6_command))
            command_list.append(self.tcp_reset(ipv6_command))
            command_list.extend(self.allow_icmp(ipv6_command))
            command_list.extend(self.allow_localhost(ipv6_command))
            command_list.extend(self.allow_dhcp(ipv6_command))
            # command_list.extend(self.allow_interfaces(self.ipv6))
            command_list.extend(self.state_tracking(ipv6_command))
            command_list.extend(self.iptables_save(ipv6_command))

            return command_list

