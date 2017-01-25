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
import sys
import configparser
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class RuleVisualMapBuilder(object):

    """
    This class creates  .dot files with which you can see all the section-rules of a specific file
    """

    def __init__(self):

        # self.parser = configparser.ConfigParser()
        self.graph = []
        self.subgraph = []
        self.connections = []
        self.no_edge_connections = []
        self.no_edge_connections.append('{ edge[style=invis]')

    def rule_map_builder(self, parser, sections):

        self.graph.append('digraph G {')
        self.graph.append('node [shape=record, style=filled];')

        counter = 0
        last_section_element = ''
        current_section_element = ''
        custom_chain = ''
        for sect in sections:
            if parser.get(sect, 'section_type').encode("utf-8") == 'general':
                self.subgraph.append(sect + '[fillcolor="green", fontcolor="yellow",label="' + sect + '"]')
                self.subgraph.append('subgraph cluster_' + sect + '{')
                self.subgraph.append('ranksep="1.0"')

                action = eval(parser.get(sect, 'action'))

                if len(action) == 1:
                    default_chain = parser.get(sect, "default_chain").encode("utf-8")
                    jump_chain = action[0].upper()

                elif len(action) == 2:
                    try:
                        custom_chain = parser.get(sect, 'custom_chain').encode('utf-8')
                    except configparser.NoOptionError:
                        custom_chain = ''

                    default_chain = parser.get(sect, "default_chain").encode("utf-8")

                    if custom_chain != '':
                        jump_chain = custom_chain
                    else:
                        jump_chain = action[0].upper() + " , " + action[1].upper()

                elif len(action) == 3:
                    default_chain = "INPUT,OUTPUT"

                try:
                    desc = parser.get(sect, 'description').encode('utf-8')
                except configparser.NoOptionError:
                    desc = None

                if desc is not None:
                    self.subgraph.append(sect + '_cluster_desc[fillcolor="darkslategray", fontcolor="yellow", label="{Description |' + desc + '}"];')
                else:
                    self.subgraph.append(sect + '_cluster_desc[fillcolor="darkslategray", fontcolor="yellow", label="{Description | -}"];')

                str_no_edge_connection = '{' + sect + '_cluster_desc}'
                current_section_element = 'desc'

                ip_version = parser.get(sect, 'ip_version')
                if ip_version == 'both':
                    ip_version = 'IPv4,IPv6'

                try:
                    nic = parser.get(sect, 'interface').encode('utf-8')
                except configparser.NoOptionError:
                    nic = '-'

                try:
                    protocol = parser.get(sect, 'protocol').encode('utf-8')
                except configparser.NoOptionError:
                    protocol = '-'

                try:
                    ports = parser.get(sect, 'ports').encode('utf-8')
                except configparser.NoOptionError:
                    ports = '-'

                try:
                    set_directions = parser.get(sect, 'set_directions').encode('utf-8')
                except configparser.NoOptionError:
                    set_directions = '-'

                try:
                    ipset = parser.get(sect, 'set').encode('utf-8')

                    str_ipset = sect + '_cluster_ipset[fillcolor="peru", fontcolor="black", label='

                    ipset_type = parser.get(ipset, 'ipset_type').encode('utf-8')
                    str_ipset +='"{TYPE | ' + ipset_type + '}'

                    try:
                        set_name = eval(parser.get(ipset, 'set_name').encode('utf-8'))
                        set_name[0] = set_name[0].replace(' ', '_')
                        str_ipset += ' | {Set Name | ' + set_name[0] + ' }'
                    except configparser.NoOptionError:
                        set_name = '-'

                    try:
                        netgroup_list = eval(parser.get(ipset, 'netgroup_set_list').encode('utf-8'))
                        str_ipset += ' | {Netgroup List '
                        if type(netgroup_list) is list:
                            for ngl in netgroup_list:
                                str_ipset += ' | ' + ngl
                        else:
                            str_ipset += ' | ' + netgroup_list
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        hostnames = eval(parser.get(ipset, 'set_hostnames').encode('utf-8'))
                        str_ipset += ' | {Hostnames '
                        if type(hostnames) is list:
                            for hst in hostnames:
                                str_ipset += ' | ' + hst
                        else:
                            str_ipset += ' | ' + hostnames
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        ips_v4 = eval(parser.get(ipset, 'set_ips_v4').encode('utf-8'))
                        str_ipset += ' | {IPv4 addresses '
                        if type(ips_v4) is list:
                            for _ip_ in ips_v4:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + ips_v4
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        ips_v6 = eval(parser.get(ipset, 'set_ips_v6').encode('utf-8'))
                        str_ipset += ' | {IPv6 addresses '
                        if type(ips_v6) is list:
                            for _ip_ in ips_v6:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + ips_v6
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        net_v4 = eval(parser.get(ipset, 'set_net_ranges_v4').encode('utf-8'))
                        str_ipset += ' | {IPv4 Net Ranges '
                        if type(net_v4) is list:
                            for _ip_ in net_v4:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + net_v4
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        net_v6 = eval(parser.get(ipset, 'set_net_ranges_v6').encode('utf-8'))
                        str_ipset += ' | {IPv6 Net Ranges '
                        if type(net_v6) is list:
                            for _ip_ in net_v6:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + net_v6
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        ip_port_ip_v4 = eval(parser.get(ipset, 'set_ip_port_ip_v4').encode('utf-8'))
                        str_ipset += ' | {IPv4 IP,Port,IP '
                        if type(ip_port_ip_v4) is list:
                            for _ip_ in ip_port_ip_v4:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + ip_port_ip_v4
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        ip_port_ip_v6 = eval(parser.get(ipset, 'set_ip_port_ip_v6').encode('utf-8'))
                        str_ipset += ' | {IPv6 IP,Port,IP '
                        if type(ip_port_ip_v6) is list:
                            for _ip_ in ip_port_ip_v6:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + ip_port_ip_v6
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        ip_port_net_v4 = eval(parser.get(ipset, 'set_ip_port_net_v4').encode('utf-8'))
                        str_ipset += ' | {IPv4 IP,Port,Net '
                        if type(ip_port_net_v4) is list:
                            for _ip_ in ip_port_net_v4:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + ip_port_net_v4
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        ip_port_net_v6 = eval(parser.get(ipset, 'set_ip_port_net_v6').encode('utf-8'))
                        str_ipset += ' | {IPv6 IP,Port,Net '
                        if type(ip_port_net_v6) is list:
                            for _ip_ in ip_port_net_v6:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + ip_port_net_v6
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    try:
                        list_sections = eval(parser.get(ipset, 'list_set_sections').encode('utf-8'))
                        str_ipset += ' | { Sections List '
                        if type(list_sections) is list:
                            for _ip_ in list_sections:
                                str_ipset += ' | ' + _ip_
                        else:
                            str_ipset += ' | ' + list_sections
                        str_ipset += '}'
                    except configparser.NoOptionError:
                        pass

                    str_ipset += '"];'
                    ipset = set_name[0]
                except configparser.NoOptionError:
                    ipset = '-'

                if 'INPUT' in default_chain.upper():
                    str_label = '{IP version | ' + ip_version + '} | {Interface | ' + nic + '} | {Protocol | ' + protocol + '} | {Port | ' + ports + '}'
                    state = ''
                    if len(action) == 3:
                        jump_chain = action[0].upper()
                        if action[1] == 'in' and action[2] == 'out':
                            state = 'NEW , ESTABLISHED'
                        else:
                            state = 'ESTABLISHED'
                    if state != '':
                        str_label += ' | {STATE | ' + state + '} | {IPset | ' + ipset + '} | { IPset Direction | ' + set_directions + '} | {Jump Chain | ' + jump_chain + '}"];'
                    else:
                        str_label += ' | {IPset | ' + ipset + '} | { IPset Direction | ' + set_directions + '} | {Jump Chain | ' + jump_chain + '}"];'
                    str_input = sect + '_cluster_input[fillcolor="darkslategray", fontcolor="yellow",label="{Direction | INPUT} |' + str_label
                    self.subgraph.append(str_input)
                    current_section_element = 'input'
                    str_no_edge_connection += ' -> {' + sect + '_cluster_input}'

                if 'OUTPUT' in default_chain.upper():
                    str_label = '{IP version | ' + ip_version + '} | {Interface | ' + nic + '} | {Protocol | ' + protocol + '} | {Port | ' + ports + '}'
                    state = ''
                    if len(action) == 3:
                        jump_chain = action[0].upper()
                        if action[1] == 'out' and action[2] == 'in':
                            state = 'NEW , ESTABLISHED'
                        else:
                            state = 'ESTABLISHED'
                    if state != '':
                        str_label += ' | {STATE | ' + state + '} | {IPset | ' + ipset + '} | { IPset Direction | ' + set_directions + '} | {Jump Chain | ' + jump_chain + '}"];'
                    else:
                        str_label += ' | {IPset | ' + ipset + '} | { IPset Direction | ' + set_directions + '} | {Jump Chain | ' + jump_chain + '}"];'
                    str_output = sect + '_cluster_output[fillcolor="orange", fontcolor="blue",label="{Direction | OUTPUT} |' + str_label
                    self.subgraph.append(str_output)
                    current_section_element = 'output'
                    str_no_edge_connection += ' -> {' + sect + '_cluster_output}'

                if custom_chain != '':
                    jump_chain = action[0].upper() + " , " + action[1].upper()
                    str_label_custom = '{IP version | ' + ip_version + '} | {Interface | ' + nic + '} | {Protocol | ' + protocol + '} | {Port | ' + ports + '}'
                    str_label_custom += ' | {IPset | ' + ipset + '} | { IPset Direction | ' + set_directions + '} | {Jump Chain | ' + jump_chain + '}"];'
                    str_custom = sect + '_cluster_custom[fillcolor="grey", fontcolor="blue",label="{Jump from | INPUT,OUTPUT} |' + str_label_custom
                    self.subgraph.append(str_custom)
                    current_section_element = 'custom'
                    str_no_edge_connection += ' -> {' + sect + '_cluster_custom}'

                if ipset != '-':
                    self.subgraph.append(str_ipset)
                    current_section_element = 'ipset'
                    str_no_edge_connection += ' -> {' + sect + '_cluster_ipset}'

                self.subgraph.append('}')

                self.no_edge_connections.append(str_no_edge_connection)

                if counter > 0:
                    self.no_edge_connections.append('{ ' + sections[counter - 1] + '_cluster_' + last_section_element + '} -> {' + sect + '}')

                last_section_element = current_section_element
                counter += 1
                self.connections.append('{' + sect + '} -> {' + sect + '_cluster_desc}')

        self.graph.extend(self.subgraph)
        self.no_edge_connections.append('}')
        self.graph.extend(self.no_edge_connections)
        self.graph.extend(self.connections)
        self.graph.append('}')

        # Write the code in the file
        file_path = "/var/tmp/firewall_files"
        if not os.path.exists(file_path):
            try:
                os.mkdir(file_path)
            except:
                print "Cannot create directory ", file_path
                sys.exit(1)

        try:
            file_path = "/var/tmp/firewall_files"
            with open(file_path + '/rules_map.dot', 'w') as file_handler:
                file_handler.write("# Generated by iptables_manager.py\n")
                file_handler.write("#Use with https://mdaines.github.io/viz.js/\n")
                for line in self.graph:
                    file_handler.write(line + '\n')
            file_handler.close()
            print "File is located at " + file_path + '/rules_map.dot'
        except:
            print "Cannot write host map file!!!!!"
            sys.exit(1)
